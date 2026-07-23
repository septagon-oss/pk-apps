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
	"github.com/septagon-oss/pk-modules/pkg/auth"
	"github.com/septagon-oss/pk-modules/pkg/content"
	"github.com/septagon-oss/pk-modules/pkg/user"
)

// TestResolveSeedParamsFailsClosedOutsideDevelopment covers the composition rule
// the review found untested: development repairs the local password, but any
// other environment REQUIRES seed.admin_password and never repairs.
func TestResolveSeedParamsFailsClosedOutsideDevelopment(t *testing.T) {
	t.Parallel()

	dev := &Config{Environment: "development"}
	p, err := resolveSeedParams(dev)
	if err != nil {
		t.Fatalf("development resolveSeedParams: %v", err)
	}
	if !p.RepairPassword || p.AdminPassword != seed.UserPass {
		t.Fatalf("development must repair the local password, got %+v", p)
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
// local development), so a real deployment that forgets to declare it fails
// closed instead of silently running the re-asserted local password.
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

	// A missing requested config fails closed to production.
	cfg2, err := LoadConfig(filepath.Join(dir, "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig(missing): %v", err)
	}
	if cfg2.Environment != "production" {
		t.Fatalf("missing config must fail closed to production, got %q", cfg2.Environment)
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

func TestBuiltinAPIAuthorizationEnforcesReadAndWriteScopes(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := authorizeBuiltinAPI(next)
	drive := func(method, path string, principal identity.Principal) int {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(identity.ContextWithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	ordinary := identity.Principal{
		Subject: "user", TenantID: "tenant", Scopes: []string{scopeAuthenticated},
	}
	if got := drive(http.MethodGet, "/api/v1/content", ordinary); got != http.StatusForbidden {
		t.Fatalf("ordinary content read = %d, want 403", got)
	}

	reader := identity.Principal{
		Subject: "reader", TenantID: "tenant", Scopes: []string{"content:read"},
	}
	if got := drive(http.MethodGet, "/api/v1/content", reader); got != http.StatusNoContent {
		t.Fatalf("scoped content read = %d, want 204", got)
	}
	if got := drive(http.MethodPost, "/api/v1/content", reader); got != http.StatusForbidden {
		t.Fatalf("read-only content write = %d, want 403", got)
	}
	if got := drive(http.MethodPost, "/api/v1/notification-subscriptions", reader); got != http.StatusForbidden {
		t.Fatalf("unrelated scope subscription write = %d, want 403", got)
	}

	writer := identity.Principal{
		Subject: "writer", TenantID: "tenant", Scopes: []string{"content:write"},
	}
	if got := drive(http.MethodPost, "/api/v1/content", writer); got != http.StatusNoContent {
		t.Fatalf("scoped content write = %d, want 204", got)
	}
	notificationWriter := identity.Principal{
		Subject: "notifier", TenantID: "tenant", Scopes: []string{"notifications:write"},
	}
	if got := drive(http.MethodDelete, "/api/v1/notification-subscriptions/id", notificationWriter); got != http.StatusNoContent {
		t.Fatalf("scoped subscription write = %d, want 204", got)
	}

	admin := identity.Principal{
		Subject: "admin", TenantID: "tenant", Scopes: []string{scopeAdmin},
	}
	if got := drive(http.MethodDelete, "/api/v1/users/id", admin); got != http.StatusNoContent {
		t.Fatalf("administrator write = %d, want 204", got)
	}

	// Extension capabilities remain owned by the extension's handler.
	if got := drive(http.MethodGet, "/api/v1/custom-resources", ordinary); got != http.StatusNoContent {
		t.Fatalf("contributed route was intercepted by built-in authorization: %d", got)
	}
}

func TestMetricsRequiresExplicitScope(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := requireMetricsAccess(next)
	drive := func(principal identity.Principal) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req = req.WithContext(identity.ContextWithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := drive(identity.Principal{}); got != http.StatusUnauthorized {
		t.Fatalf("anonymous metrics = %d, want 401", got)
	}
	if got := drive(identity.Principal{
		Subject: "user", TenantID: "tenant", Scopes: []string{scopeAuthenticated},
	}); got != http.StatusForbidden {
		t.Fatalf("ordinary metrics = %d, want 403", got)
	}
	if got := drive(identity.Principal{
		Subject: "scraper", TenantID: "tenant", Scopes: []string{"metrics:read"},
	}); got != http.StatusNoContent {
		t.Fatalf("scoped metrics = %d, want 204", got)
	}
}

// TestGuardAdminRequiresExplicitConsoleScopes proves /admin redirects anonymous
// visitors and rejects signed-in users that lack console capabilities.
func TestGuardAdminRequiresExplicitConsoleScopes(t *testing.T) {
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
	if code := drive(&identity.Principal{
		Subject: "user", TenantID: "t", AuthMethod: "session", Scopes: []string{scopeAuthenticated},
	}); code != http.StatusForbidden {
		t.Fatalf("ordinary session /admin = %d, want 403", code)
	}
	if code := drive(&identity.Principal{
		Subject: "admin", TenantID: "t", AuthMethod: "session",
		Scopes: []string{scopeAuthenticated, scopeAdmin, scopeConsoleAccess},
	}); code != http.StatusOK {
		t.Fatalf("scoped admin session /admin = %d, want 200", code)
	}
}

func TestOrdinarySessionCannotOpenAdmin(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", filepath.Join(t.TempDir(), "pk.db"))
	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	defer app.Close()

	ordinary := &user.User{
		ID:          "user_ordinary",
		TenantID:    seed.TenantID,
		Email:       "ordinary@example.test",
		Username:    "ordinary",
		DisplayName: "Ordinary User",
		Active:      true,
	}
	if err := app.user.Service().Create(context.Background(), ordinary); err != nil {
		t.Fatalf("create ordinary user: %v", err)
	}
	if err := app.user.Service().SetPassword(
		context.Background(),
		ordinary.TenantID,
		ordinary.ID,
		"ordinary-password",
	); err != nil {
		t.Fatalf("set ordinary password: %v", err)
	}
	session, err := app.authMod.Service().Login(context.Background(), ordinary.TenantID, auth.Credentials{
		Email:    ordinary.Email,
		Password: "ordinary-password",
	})
	if err != nil {
		t.Fatalf("ordinary login: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+session.ID)
	rec := httptest.NewRecorder()
	mustMux(t, app).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ordinary session /admin = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "insufficient scope") {
		t.Fatalf("403 page lacks actionable scope message: %q", rec.Body.String())
	}
}

func TestAdminLoginIsResponsiveAccessibleAndDoesNotExposePassword(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", filepath.Join(t.TempDir(), "pk.db"))
	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	defer app.Close()
	handler := mustMux(t, app)

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, adminLoginPath, nil))
	body := get.Body.String()
	for _, marker := range []string{
		`name="viewport"`,
		`min-width: 320px`,
		`prefers-reduced-motion`,
		`aria-labelledby="signin-title"`,
		`required autofocus`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("login page missing %q", marker)
		}
	}
	if strings.Contains(body, seed.UserPass) {
		t.Fatal("login page must not expose the development password")
	}

	post := httptest.NewRequest(
		http.MethodPost,
		adminLoginPath,
		strings.NewReader("tenant_id="+seed.TenantID+"&email=remember%40example.test&password=wrong"),
	)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	failed := httptest.NewRecorder()
	handler.ServeHTTP(failed, post)
	if failed.Code != http.StatusUnauthorized {
		t.Fatalf("failed login status = %d, want 401", failed.Code)
	}
	failedBody := failed.Body.String()
	if !strings.Contains(failedBody, `role="alert"`) ||
		!strings.Contains(failedBody, `value="remember@example.test"`) {
		t.Fatalf("failed login must expose an accessible error and retain the email: %q", failedBody)
	}
	if strings.Contains(failedBody, `value="wrong"`) {
		t.Fatal("failed login must never repopulate the password")
	}
}

// TestSpoofedBodyTenantIsIgnored is the reviewer's headline gap: the "body
// tenant_id is ignored" property was unguarded. It logs in as the seeded admin
// and POSTs content whose body claims a different tenant; the
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

// TestRequestBodyIsCapped is the v0.2.2 regression for the unbounded-body
// memory-exhaustion DoS: a request body larger than maxRequestBodyBytes must be
// rejected rather than fully buffered and processed. The payload is valid JSON
// that would create content if it fit under the cap, so a non-2xx status proves
// the cap — not a parse error — did the rejecting.
func TestRequestBodyIsCapped(t *testing.T) {
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
	huge := strings.Repeat("a", int(maxRequestBodyBytes)+(1<<20)) // ~2 MiB, over the 1 MiB cap
	body := fmt.Sprintf(`{"kind":"post","slug":"big","title":"big","body":%q}`, huge)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/content", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sid)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("oversized create: %v", err)
	}
	resp.Body.Close()
	// A declared over-cap Content-Length must produce a clear 413, not a
	// misleading 400 "invalid JSON" from a truncated read.
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, want 413 Request Entity Too Large", resp.StatusCode)
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
