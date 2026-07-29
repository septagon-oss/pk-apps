// Package starterapp — branding_e2e_test.go owns the boot-and-request spine
// for the composed branding_management module: the seed.branding_* config keys
// parse, a cold boot walks the whole first-login setup flow (login → gate 303
// → setup page → multipart save → branded chrome → per-tenant stylesheet) and
// the gate never re-fires after a restart against the same database, a seeded
// boot bypasses the gate entirely, and an explicit skip closes the gate with
// the fallback workspace name. These tests drive the real mux over
// net/http/httptest exactly like the security E2E tests, so the flow under
// test is byte-for-byte what a browser sees.
//
// ADR: ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// TestLoadConfigBrandingSeedKeys proves the flat branding_* keys under seed:
// fill cfg.Seed.Branding and that unknown seed keys still fail loudly.
func TestLoadConfigBrandingSeedKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	path := filepath.Join(dir, "config.yaml")
	yaml := `seed:
  branding_display_name: "Acme Inc"
  branding_primary_color: "#14b8a6"
  branding_font: "plex"
  branding_logo_path: "./logo.png"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := BrandingSeedConfig{
		DisplayName:  "Acme Inc",
		PrimaryColor: "#14b8a6",
		FontKey:      "plex",
		LogoPath:     "./logo.png",
	}
	if cfg.Seed.Branding != want {
		t.Fatalf("Seed.Branding = %+v, want %+v", cfg.Seed.Branding, want)
	}

	// Unknown seed keys must still error — typos stay loud.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("seed:\n  branding_bogus: \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil {
		t.Fatal("LoadConfig accepted unknown seed key branding_bogus")
	}
}

// TestBrandingSeedRequiresDisplayName proves the loud-config rule: ride-along
// branding seed keys (color, font, logo path) WITHOUT branding_display_name
// fail boot with a clear error instead of silently seeding nothing.
func TestBrandingSeedRequiresDisplayName(t *testing.T) {
	t.Parallel()

	cases := map[string]BrandingSeedConfig{
		"color only": {PrimaryColor: "#14b8a6"},
		"font only":  {FontKey: "plex"},
		"logo only":  {LogoPath: "./logo.png"},
	}
	for name, seedCfg := range cases {
		cfg := DefaultConfig()
		cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc",
			filepath.Join(t.TempDir(), "pk.db"))
		cfg.HTTP.Addr = ":0"
		cfg.Seed.Branding = seedCfg

		app, err := BuildApp(context.Background(), cfg)
		if err == nil {
			app.Close()
			t.Fatalf("%s: BuildApp accepted branding seed keys without a display name", name)
		}
		if !strings.Contains(err.Error(), "branding_display_name") {
			t.Fatalf("%s: error %q does not name seed.branding_display_name", name, err)
		}
	}
}

// brandingTestClient wraps the browser-shaped requests the branding E2E flow
// needs: form login capturing the session cookie, cookie-carrying GETs, and a
// same-origin multipart POST — all with redirects surfaced, never followed,
// so the tests can assert each 303 hop explicitly.
type brandingTestClient struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	cookie *http.Cookie
}

func newBrandingClient(t *testing.T, srv *httptest.Server) *brandingTestClient {
	t.Helper()
	return &brandingTestClient{
		t:   t,
		srv: srv,
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// login drives the browser form-login flow with the seeded demo credentials
// and captures the session cookie for subsequent requests.
func (c *brandingTestClient) login() {
	c.t.Helper()
	form := url.Values{
		"tenant_id": {seed.TenantID},
		"email":     {seed.UserEmail},
		"password":  {seed.UserPass},
	}
	resp, err := c.client.PostForm(c.srv.URL+"/admin/login", form)
	if err != nil {
		c.t.Fatalf("POST /admin/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		c.t.Fatalf("form login status = %d, want 303", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookieName() {
			c.cookie = ck
			return
		}
	}
	c.t.Fatalf("form login set no %q cookie", sessionCookieName())
}

// get performs a cookie-authenticated GET and returns status, Location, body.
func (c *brandingTestClient) get(path string) (int, string, string) {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.srv.URL+path, nil)
	if err != nil {
		c.t.Fatalf("GET %s: %v", path, err)
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatalf("GET %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), string(body)
}

// postBrandingForm submits the setup form as a browser would: multipart, the
// session cookie, and a same-origin Origin header. Returns status + Location.
func (c *brandingTestClient) postBrandingForm(fields map[string]string) (int, string) {
	c.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			c.t.Fatalf("write field %s: %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		c.t.Fatalf("close multipart: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.srv.URL+"/api/v1/branding", &buf)
	if err != nil {
		c.t.Fatalf("POST /api/v1/branding: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", c.srv.URL)
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatalf("POST /api/v1/branding: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// bootBrandingApp builds the app + test server for cfg and registers cleanup.
func bootBrandingApp(t *testing.T, cfg *Config) (*App, *httptest.Server) {
	t.Helper()
	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	t.Cleanup(func() { app.Close() })
	mux, err := app.Mux()
	if err != nil {
		t.Fatalf("Mux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return app, srv
}

// TestBrandingFirstLoginSetupFlow is the E2E spine: cold boot, login, gate
// redirect, setup page, multipart save, branded chrome + stylesheet, then a
// reboot against the same database proving the gate never re-fires.
func TestBrandingFirstLoginSetupFlow(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	app, srv := bootBrandingApp(t, cfg)
	c := newBrandingClient(t, srv)

	// The pre-auth login page carries cfg.AppName, not a hardcoded product
	// name (title + "<AppName> admin" sub — the de-hardcoded chrome).
	code, _, body := c.get("/admin/login")
	if code != http.StatusOK || !strings.Contains(body, cfg.AppName+" admin") {
		t.Fatalf("login page = %d, want 200 carrying %q; body:\n%s", code, cfg.AppName+" admin", body)
	}

	c.login()

	// First authenticated visit: the gate fires — 303 to the branding page.
	code, loc, _ := c.get("/admin")
	if code != http.StatusSeeOther || loc != "/admin/branding" {
		t.Fatalf("first GET /admin = %d → %q, want 303 → /admin/branding", code, loc)
	}

	// The branding page renders the first-login setup copy.
	code, _, body = c.get("/admin/branding")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/branding = %d, want 200", code)
	}
	if !strings.Contains(body, "Set up your workspace") {
		t.Fatalf("branding setup page missing first-login copy; body:\n%s", body)
	}

	// Save: display name + custom color. 303 back to the branding page.
	code, loc = c.postBrandingForm(map[string]string{
		"action":        "save",
		"display_name":  "Acme Ops",
		"color_mode":    "custom",
		"primary_color": "#14b8a6",
	})
	if code != http.StatusSeeOther {
		t.Fatalf("branding save = %d → %q, want 303", code, loc)
	}

	// The gate is closed and the chrome is branded.
	code, _, body = c.get("/admin")
	if code != http.StatusOK {
		t.Fatalf("GET /admin after save = %d, want 200", code)
	}
	if !strings.Contains(body, "Acme Ops") {
		t.Fatalf("admin home missing saved display name; body:\n%s", body)
	}
	if !strings.Contains(body, "_branding.css") {
		t.Fatalf("admin home missing _branding.css link; body:\n%s", body)
	}

	// The per-tenant stylesheet carries the derived accent token.
	code, _, css := c.get("/admin/static/_branding.css")
	if code != http.StatusOK {
		t.Fatalf("GET _branding.css = %d, want 200", code)
	}
	if !strings.Contains(css, "--pk-color-accent-default") {
		t.Fatalf("_branding.css missing --pk-color-accent-default; body:\n%s", css)
	}

	// REBOOT against the same database: the gate must never re-fire. Real
	// restart semantics — the first instance is fully shut down (server, then
	// the shared *sql.DB) before the second boots on the same file, so this
	// cannot lean on shared-cache visibility between two live handles.
	srv.Close()
	if err := app.Close(); err != nil {
		t.Fatalf("close first app: %v", err)
	}
	_, srv2 := bootBrandingApp(t, cfg)
	c2 := newBrandingClient(t, srv2)
	c2.login()
	code, _, body = c2.get("/admin")
	if code != http.StatusOK {
		t.Fatalf("GET /admin after reboot = %d, want 200 (gate re-fired?)", code)
	}
	if !strings.Contains(body, "Acme Ops") {
		t.Fatalf("branding lost across reboot; body:\n%s", body)
	}
}

// TestBrandingSeededBootBypassesGate proves seed.branding_* pre-completes
// setup: the very first authenticated GET /admin is already 200 and branded,
// and a config-seeded logo is resolvable.
func TestBrandingSeededBootBypassesGate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	// http.DetectContentType keys on the 8-byte PNG signature; Save never
	// decodes the image, so a signature plus padding is a valid seed logo.
	logo := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x00}, 16)...)
	if err := os.WriteFile(logoPath, logo, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", filepath.Join(dir, "pk.db"))
	cfg.HTTP.Addr = ":0"
	cfg.Seed.Branding = BrandingSeedConfig{
		DisplayName:  "Seeded Inc",
		PrimaryColor: "#14b8a6",
		FontKey:      "plex",
		LogoPath:     logoPath,
	}

	app, srv := bootBrandingApp(t, cfg)
	c := newBrandingClient(t, srv)
	c.login()

	code, loc, body := c.get("/admin")
	if code != http.StatusOK {
		t.Fatalf("seeded first GET /admin = %d → %q, want 200 (no gate)", code, loc)
	}
	if !strings.Contains(body, "Seeded Inc") {
		t.Fatalf("seeded admin home missing display name; body:\n%s", body)
	}

	// The seeded logo is on record and served back.
	code, _, profile := c.get("/api/v1/branding")
	if code != http.StatusOK || !strings.Contains(profile, "/api/v1/branding/logo") {
		t.Fatalf("seeded branding profile missing logo_url: %d %s", code, profile)
	}

	// A second boot against the same DB must NOT re-assert the seed: save an
	// edit, reboot, and the edit survives (seed only applies to a bare tenant).
	if code, _ := c.postBrandingForm(map[string]string{
		"action":       "save",
		"display_name": "Edited Inc",
		"color_mode":   "default",
	}); code != http.StatusSeeOther {
		t.Fatalf("edit save = %d, want 303", code)
	}
	// Full restart (server + DB handle closed) before the second boot.
	srv.Close()
	if err := app.Close(); err != nil {
		t.Fatalf("close first app: %v", err)
	}
	_, srv2 := bootBrandingApp(t, cfg)
	c2 := newBrandingClient(t, srv2)
	c2.login()
	if _, _, body := c2.get("/admin"); !strings.Contains(body, "Edited Inc") {
		t.Fatalf("config seed re-asserted over a UI edit; body:\n%s", body)
	}
}

// TestBrandingSkipClosesGate proves the explicit skip path (formnovalidate,
// empty display name) completes setup with the fallback workspace name.
func TestBrandingSkipClosesGate(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", filepath.Join(t.TempDir(), "pk.db"))
	cfg.HTTP.Addr = ":0"

	_, srv := bootBrandingApp(t, cfg)
	c := newBrandingClient(t, srv)
	c.login()

	if code, loc, _ := c.get("/admin"); code != http.StatusSeeOther || loc != "/admin/branding" {
		t.Fatalf("pre-skip GET /admin = %d → %q, want 303 → /admin/branding", code, loc)
	}

	// Skip posts an empty display_name (the formnovalidate path).
	code, loc := c.postBrandingForm(map[string]string{
		"action":       "skip",
		"display_name": "",
	})
	if code != http.StatusSeeOther {
		t.Fatalf("skip = %d → %q, want 303", code, loc)
	}

	code, _, body := c.get("/admin")
	if code != http.StatusOK {
		t.Fatalf("GET /admin after skip = %d, want 200 (gate open?)", code)
	}
	// Exact-match the chrome title: Skip records the handler's "Workspace"
	// fallback as the display name, which replaces the shell title. A bare
	// substring check would false-pass on the unbranded chrome's "Workspace"
	// sidebar section label.
	if want := "<title>Overview · Workspace</title>"; !strings.Contains(body, want) {
		t.Fatalf("post-skip admin home missing exact fallback title %q; body:\n%s", want, body)
	}
}
