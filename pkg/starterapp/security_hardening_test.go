// Package starterapp — security_hardening_test.go guards the v0.2.1 hardening
// controls the adversarial review flagged as untested: the seed environment
// default (fail-closed for a configured deployment), the mutation-gate
// exemption (only login is anonymous), guardAdmin (interactive sessions only),
// and that a spoofed body tenant_id is ignored in favor of the principal's
// tenant. An untested control is the next regression; these are the tests that
// were missing.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

// Validates: REQ-005.
// Per: ADR-0009.
// Discipline: C-14.
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/septagon-oss/pk-core/pkg/security/identity"

	_ "modernc.org/sqlite"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
	"github.com/septagon-oss/pk-modules/pkg/content"
)

// TestResolveSeedParamsFailsClosedOutsideDevelopment covers the composition rule
// the review found untested: development repairs the demo password, but any
// other environment REQUIRES seed.admin_password and never repairs.
func TestResolveSeedParamsFailsClosedOutsideDevelopment(t *testing.T) {
	t.Parallel()

	dev := &Config{Environment: "development"}
	p, err := resolveSeedParams(dev)
	if err != nil {
		t.Fatalf("development resolveSeedParams: %v", err)
	}
	if !p.RepairPassword || p.AdminPassword != seed.UserPass {
		t.Fatalf("development must repair the demo password, got %+v", p)
	}

	// Non-development with no password → error (fail closed).
	for _, env := range []string{"", "production", "staging", "Development"} {
		if _, err := resolveSeedParams(&Config{Environment: env}); err == nil {
			t.Fatalf("environment %q with no seed.admin_password must error", env)
		}
	}

	// Non-development WITH a password → no repair.
	prod, err := resolveSeedParams(&Config{Environment: "production", Seed: SeedConfig{AdminPassword: "strong-pw"}})
	if err != nil {
		t.Fatalf("production with password: %v", err)
	}
	if prod.RepairPassword {
		t.Fatal("production must never repair (re-assert) the password")
	}
}

// TestLoadConfigOmittedEnvironmentFailsClosed proves the fail-open foot-gun is
// closed: a config file that omits environment defaults to production (not the
// development demo), so a real deployment that forgets to declare it fails
// closed instead of silently running the re-asserted demo password.
func TestLoadConfigOmittedEnvironmentFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	omit := filepath.Join(dir, "omit.yaml")
	if err := os.WriteFile(omit, []byte("http:\n  addr: \":9999\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(omit)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Environment != "production" {
		t.Fatalf("config omitting environment must default to production, got %q", cfg.Environment)
	}

	// A missing file is the zero-config demo path and stays development.
	cfg2, err := LoadConfig(filepath.Join(dir, "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig(missing): %v", err)
	}
	if cfg2.Environment != "development" {
		t.Fatalf("missing config (demo path) should stay development, got %q", cfg2.Environment)
	}

	// An explicit environment in the file wins.
	dev := filepath.Join(dir, "dev.yaml")
	if err := os.WriteFile(dev, []byte("environment: development\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg3, _ := LoadConfig(dev)
	if cfg3.Environment != "development" {
		t.Fatalf("explicit environment should win, got %q", cfg3.Environment)
	}
}

// TestMutationGateExemptsOnlyLogin proves the gate exempts exactly the login
// POST and nothing else under /api/v1/auth/ — so anonymous logout is blocked.
func TestMutationGateExemptsOnlyLogin(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := requireAuthenticatedMutations(next)

	check := func(method, path string, wantPass bool) {
		req := httptest.NewRequest(method, path, nil) // anonymous: no principal
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		passed := rec.Code == http.StatusOK
		if passed != wantPass {
			t.Fatalf("%s %s: passed=%v want %v (code %d)", method, path, passed, wantPass, rec.Code)
		}
	}
	check(http.MethodPost, "/api/v1/auth/sessions", true)        // login — exempt
	check(http.MethodDelete, "/api/v1/auth/sessions/abc", false) // anonymous logout — BLOCKED
	check(http.MethodPost, "/api/v1/content", false)             // anonymous write — blocked
	check(http.MethodGet, "/api/v1/content", true)               // reads pass the gate (handlers enforce)
}

// TestGuardAdminRequiresSession proves /admin admits only interactive session
// principals: anonymous and API-key credentials are redirected to login.
func TestGuardAdminRequiresSession(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := guardAdmin(next)

	drive := func(p *identity.Principal) int {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		if p != nil {
			req = req.WithContext(identity.ContextWithPrincipal(req.Context(), *p))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := drive(nil); code != http.StatusSeeOther {
		t.Fatalf("anonymous /admin = %d, want 303 redirect", code)
	}
	if code := drive(&identity.Principal{Subject: "svc", TenantID: "t", AuthMethod: "api_key"}); code != http.StatusSeeOther {
		t.Fatalf("api-key /admin = %d, want 303 redirect (machine creds excluded)", code)
	}
	if code := drive(&identity.Principal{Subject: "u", TenantID: "t", AuthMethod: "session"}); code != http.StatusOK {
		t.Fatalf("session /admin = %d, want 200", code)
	}
}

// TestSpoofedBodyTenantIsIgnored is the reviewer's headline gap: the "body
// tenant_id is ignored" property was unguarded. It logs in as the seeded admin
// (tenant_acme) and POSTs content whose body claims a DIFFERENT tenant; the
// created row must land in the caller's tenant, and nothing must appear in the
// spoofed tenant.
func TestSpoofedBodyTenantIsIgnored(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	ctx := context.Background()
	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	defer app.Close()
	srv := httptest.NewServer(mustMux(t, app))
	defer srv.Close()

	sid := loginSeeded(t, srv)
	body := `{"tenant_id":"tenant_spoofed","kind":"post","slug":"spoof","title":"spoof","body":"x"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/content", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sid)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var created content.Content
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}
	if created.TenantID != seed.TenantID {
		t.Fatalf("spoofed body tenant_id was honored: row tenant = %q, want %q", created.TenantID, seed.TenantID)
	}
	// Nothing should exist in the spoofed tenant.
	if got, err := app.contentMod.Service().Get(ctx, "tenant_spoofed", created.ID); err == nil {
		t.Fatalf("content leaked into spoofed tenant: %+v", got)
	}
}

func mustMux(t *testing.T, app *App) http.Handler {
	t.Helper()
	mux, err := app.Mux()
	if err != nil {
		t.Fatalf("Mux: %v", err)
	}
	return mux
}

func loginSeeded(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body := fmt.Sprintf(`{"tenant_id":%q,"email":%q,"password":%q}`, seed.TenantID, seed.UserEmail, seed.UserPass)
	resp, err := http.Post(srv.URL+"/api/v1/auth/sessions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("login status = %d: %s", resp.StatusCode, b)
	}
	var s struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &s); err != nil || s.ID == "" {
		t.Fatalf("no session id: %v %s", err, b)
	}
	return s.ID
}
