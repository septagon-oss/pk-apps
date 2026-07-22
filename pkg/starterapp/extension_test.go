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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/septagon-oss/pk-modules/pkg/portslib"
)

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
		fmt.Fprintf(w, "widget for %s/%s", tenant, subject)
	})
}

func TestWithModulesContributesAModule(t *testing.T) {
	t.Parallel()
	cfg := extTestConfig(t)

	widget := func(env ModuleEnv) (ModulePlugin, error) {
		if env.DB == nil || env.Admin == nil || env.Health == nil {
			return ModulePlugin{}, fmt.Errorf("env not fully wired")
		}
		return ModulePlugin{ID: "widget", RegisterRoutes: widgetHandler{}.RegisterRoutes}, nil
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
	if !strings.Contains(string(b), "widget for tenant_acme/") {
		t.Fatalf("authenticated widget body = %q, want it to see the caller's tenant", b)
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

func TestWithModulesRequiresRoutes(t *testing.T) {
	t.Parallel()
	noRoutes := func(env ModuleEnv) (ModulePlugin, error) {
		return ModulePlugin{ID: "widget"}, nil // RegisterRoutes nil
	}
	_, err := BuildApp(context.Background(), extTestConfig(t), WithModules(noRoutes))
	if err == nil || !strings.Contains(err.Error(), "RegisterRoutes is required") {
		t.Fatalf("expected RegisterRoutes-required error, got %v", err)
	}
}
