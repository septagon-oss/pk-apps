// Package starterapp — extension_test.go proves the WithModules seam: a
// contributed module joins the app, its routes mount behind the shared
// middleware (anonymous access is blocked by the same mutation gate as the
// built-ins), and an authenticated caller reaches it.
//
// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
package starterapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
	pkmodule "github.com/septagon-oss/pk-core/pkg/module"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-modules/pkg/audit"
	"github.com/septagon-oss/pk-modules/pkg/portslib"
)

const extWidgetReadScope = "widgets:read"

func extTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", filepath.Join(t.TempDir(), "pk.db"))
	cfg.HTTP.Addr = ":0"
	return cfg
}

// widgetHandler is a minimal contributed module: one authenticated route that
// echoes the caller's tenant, proving RequestActor sees the resolved principal.
type widgetHandler struct{}

func (widgetHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/widgets", func(w http.ResponseWriter, r *http.Request) {
		tenant, subject, ok := portslib.RequestActor(w, r)
		if !ok {
			return // 401 already written by RequestActor
		}
		principal := identity.PrincipalFromContext(r.Context())
		if !principal.HasScope("admin") && !principal.HasScope(extWidgetReadScope) {
			http.Error(w, "forbidden: "+extWidgetReadScope+" scope required", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "widget for %s/%s", tenant, subject)
	})
}

func TestWithModulesContributesAModule(t *testing.T) {
	t.Parallel()
	cfg := extTestConfig(t)

	widget := func(env ModuleEnv) (ModulePlugin, error) {
		if env.DB == nil || env.Admin == nil || env.Health == nil || env.Audit == nil {
			return ModulePlugin{}, fmt.Errorf("env not fully wired")
		}
		return ModulePlugin{
			ID:             "widget",
			RegisterRoutes: widgetHandler{}.RegisterRoutes,
			APIKeyScopes:   []string{extWidgetReadScope},
			OpenAPI: []OpenAPIOperation{{
				OperationID: "widgets.list",
				Method:      http.MethodGet,
				Path:        "/api/v1/widgets",
				Summary:     "List widgets",
				Tags:        []string{"widgets"},
			}},
		}, nil
	}

	app, err := BuildApp(context.Background(), cfg, WithModules(widget))
	if err != nil {
		t.Fatalf("BuildApp with module: %v", err)
	}
	defer app.Close()
	srv := httptest.NewServer(mustMux(t, app))
	defer srv.Close()

	// Anonymous hit → blocked by the same perimeter the built-ins sit behind.
	anon, err := http.Get(srv.URL + "/api/v1/widgets")
	if err != nil {
		t.Fatalf("anon get: %v", err)
	}
	anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous widget = %d, want 401 (must inherit the identity/mutation gate)", anon.StatusCode)
	}

	// Authenticated → reaches the contributed handler, which sees the tenant.
	sid := loginSeeded(t, srv)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/widgets", nil)
	req.Header.Set("Authorization", "Bearer "+sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("auth get: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "widget for "+seed.TenantID+"/") {
		t.Fatalf("authenticated widget body = %q, want it to see the caller's tenant", b)
	}

	if _, _, err := app.apiKey.Service().Issue(
		context.Background(),
		seed.TenantID,
		seed.UserID,
		"widget-reader",
		[]string{extWidgetReadScope},
		0,
	); err != nil {
		t.Fatalf("issue declared extension scope: %v", err)
	}
	if _, _, err := app.apiKey.Service().Issue(
		context.Background(),
		seed.TenantID,
		seed.UserID,
		"typo",
		[]string{"widgets:reed"},
		0,
	); err == nil || !strings.Contains(err.Error(), "unknown scope") {
		t.Fatalf("issue undeclared extension scope error = %v, want unknown scope", err)
	}

	specResp, err := http.Get(srv.URL + "/openapi/extensions.json")
	if err != nil {
		t.Fatalf("OpenAPI get: %v", err)
	}
	defer specResp.Body.Close()
	var spec struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.NewDecoder(specResp.Body).Decode(&spec); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	if spec.OpenAPI != "3.1.0" ||
		spec.Paths["/api/v1/widgets"]["get"].OperationID != "widgets.list" {
		t.Fatalf("unexpected extension OpenAPI document: %+v", spec)
	}
}

func TestWithModulesUsesPublishedPortContractVersions(t *testing.T) {
	t.Parallel()

	plugin := func(ModuleEnv) (ModulePlugin, error) {
		return ModulePlugin{
			ID: "published_contract_consumer",
			Compose: func() pkmodule.Composable {
				return pkmodule.Must(
					pkmodule.Metadata{ID: "published_contract_consumer", Version: "0.0.0"},
					pkmodule.WithDependencies(
						pkmodule.RequiresPort[audit.AuditService](pkmodule.PortSpec{
							Version:           audit.ModuleVersion,
							Purpose:           "Consume the published audit contract.",
							PreferredProvider: "audit_management",
						}),
						pkmodule.RequiresPort[portslib.AdminRegistrar](pkmodule.PortSpec{
							Version:           portslib.AdminRegistrarContractVersion,
							Purpose:           "Consume the published admin contract.",
							PreferredProvider: "admin_management",
						}),
					),
				)
			},
			RegisterRoutes: func(*http.ServeMux) {},
		}, nil
	}

	app, err := BuildApp(
		context.Background(),
		extTestConfig(t),
		WithModules(plugin),
	)
	if err != nil {
		t.Fatalf("BuildApp with published port contracts: %v", err)
	}
	defer app.Close()
}

func TestWithModulesPublicRoutesBypassTheGate(t *testing.T) {
	t.Parallel()
	cfg := extTestConfig(t)

	// A module with BOTH surfaces: an anonymous public join and an
	// authenticated owner view.
	plugin := func(env ModuleEnv) (ModulePlugin, error) {
		return ModulePlugin{
			ID: "signups",
			RegisterPublicRoutes: func(mux *http.ServeMux) {
				mux.HandleFunc("/join/", func(w http.ResponseWriter, r *http.Request) {
					// Anonymous POST — would be 401 under the mutation gate.
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte("joined"))
				})
			},
			RegisterRoutes: func(mux *http.ServeMux) {
				mux.HandleFunc("/api/v1/signups", func(w http.ResponseWriter, r *http.Request) {
					if _, _, ok := portslib.RequestActor(w, r); !ok {
						return
					}
					_, _ = w.Write([]byte("owner-view"))
				})
			},
		}, nil
	}

	app, err := BuildApp(context.Background(), cfg, WithModules(plugin))
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	defer app.Close()
	srv := httptest.NewServer(mustMux(t, app))
	defer srv.Close()

	// Public POST works anonymously (the whole point).
	resp, err := http.Post(srv.URL+"/join/example-org", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("public post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("public POST /join = %d, want 201 (public route must bypass the mutation gate)", resp.StatusCode)
	}

	// The authenticated route is still gated: anonymous → 401.
	anon, err := http.Get(srv.URL + "/api/v1/signups")
	if err != nil {
		t.Fatalf("anon get: %v", err)
	}
	anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous owner view = %d, want 401 (authenticated routes stay gated)", anon.StatusCode)
	}

	// A built-in mutation is still gated too (defense in depth intact).
	bad, err := http.Post(srv.URL+"/api/v1/users", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("anon builtin post: %v", err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous POST /api/v1/users = %d, want 401 (public mux must not disarm the gate)", bad.StatusCode)
	}
}

func TestWithModulesRejectsBuiltinIDCollision(t *testing.T) {
	t.Parallel()
	clash := func(env ModuleEnv) (ModulePlugin, error) {
		return ModulePlugin{ID: "user_management", RegisterRoutes: func(*http.ServeMux) {}}, nil
	}
	_, err := BuildApp(context.Background(), extTestConfig(t), WithModules(clash))
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected a built-in ID collision error, got %v", err)
	}
}

func TestWithModulesRejectsReservedAPIKeyScope(t *testing.T) {
	t.Parallel()
	plugin := func(ModuleEnv) (ModulePlugin, error) {
		return ModulePlugin{
			ID:             "unsafe_scope",
			RegisterRoutes: func(*http.ServeMux) {},
			APIKeyScopes:   []string{"admin"},
		}, nil
	}
	_, err := BuildApp(context.Background(), extTestConfig(t), WithModules(plugin))
	if err == nil || !strings.Contains(err.Error(), "reserved for interactive authorization") {
		t.Fatalf("expected reserved-scope error, got %v", err)
	}
}

func TestWithModulesRequiresRoutes(t *testing.T) {
	t.Parallel()
	noRoutes := func(env ModuleEnv) (ModulePlugin, error) {
		return ModulePlugin{ID: "widget"}, nil // RegisterRoutes nil
	}
	_, err := BuildApp(context.Background(), extTestConfig(t), WithModules(noRoutes))
	if err == nil || !strings.Contains(err.Error(), "RegisterRoutes or RegisterPublicRoutes is required") {
		t.Fatalf("expected routes-required error, got %v", err)
	}
}

func TestWithModulesRejectsInvalidOrDuplicateOpenAPI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ops  []OpenAPIOperation
		want string
	}{
		{
			name: "invalid method",
			ops:  []OpenAPIOperation{{OperationID: "widget.read", Method: "TRACE", Path: "/widgets", Summary: "Read"}},
			want: "unsupported method",
		},
		{
			name: "invalid path",
			ops:  []OpenAPIOperation{{OperationID: "widget.read", Method: "GET", Path: "widgets", Summary: "Read"}},
			want: "invalid canonical path",
		},
		{
			name: "missing summary",
			ops:  []OpenAPIOperation{{OperationID: "widget.read", Method: "GET", Path: "/widgets"}},
			want: "summary is required",
		},
		{
			name: "duplicate route",
			ops: []OpenAPIOperation{
				{OperationID: "widget.read", Method: "GET", Path: "/widgets", Summary: "Read"},
				{OperationID: "widget.readAgain", Method: "GET", Path: "/widgets", Summary: "Read again"},
			},
			want: "duplicates GET /widgets",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plugin := func(ModuleEnv) (ModulePlugin, error) {
				return ModulePlugin{
					ID:             "widget",
					RegisterRoutes: func(*http.ServeMux) {},
					OpenAPI:        tc.ops,
				}, nil
			}
			_, err := BuildApp(context.Background(), extTestConfig(t), WithModules(plugin))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildApp error = %v, want text %q", err, tc.want)
			}
		})
	}
}
