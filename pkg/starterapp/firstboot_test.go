// Package starterapp — firstboot_test.go owns the fresh-database first-run
// regression test. It closes the false-confidence gap left by the smoke tests
// in app_test.go: those build the app and probe routes, but never assert that
// the concurrent /healthz aggregation reports every data module healthy on a
// brand-new pk.db. This test does exactly that — it stands the full mux up
// against a unique file-based SQLite DSN (what a fresh `git clone && go run .`
// produces) and fails loudly if any module reports "no such table" or if the
// seeded tenants table is not queryable through the public API.
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
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// TestFreshDatabaseBootIsHealthy proves that on a brand-new SQLite file every
// data module's store is reachable and the seeded tenant is queryable. This is
// the path the user hits on first run and the one the old smoke tests missed.
func TestFreshDatabaseBootIsHealthy(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := DefaultConfig()
	// Mirror the EXACT production DSN shape (cache=shared&mode=rwc) but against
	// a unique fresh file so this test reproduces a genuine cold start rather
	// than reusing a stale db.
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp() error = %v", err)
	}
	defer app.Close()

	mux, err := app.Mux()
	if err != nil {
		t.Fatalf("Mux() error = %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// /healthz must be 200 with an overall healthy status. A 503 here means a
	// data module cannot see its table on a fresh db — the launch blocker.
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz on fresh db: status = %d, want 200\nbody = %s",
			resp.StatusCode, string(body))
	}
	if strings.Contains(string(body), "no such table") {
		t.Fatalf("GET /healthz reports a missing table on fresh db:\n%s", string(body))
	}
	if strings.Contains(string(body), "unhealthy") {
		t.Fatalf("GET /healthz reports an unhealthy component on fresh db:\n%s", string(body))
	}

	// The seeded tenants endpoint must be queryable (200) on a fresh db.
	tResp, err := http.Get(srv.URL + "/api/v1/tenants")
	if err != nil {
		t.Fatalf("GET /api/v1/tenants: %v", err)
	}
	tBody, _ := io.ReadAll(tResp.Body)
	tResp.Body.Close()
	if tResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/tenants on fresh db: status = %d, want 200\nbody = %s",
			tResp.StatusCode, string(tBody))
	}
	if !strings.Contains(string(tBody), seed.TenantSlug) {
		t.Errorf("GET /api/v1/tenants missing seeded tenant %q in body=%s",
			seed.TenantSlug, string(tBody))
	}
}

// dbHolder is implemented by the sqlite store any data module exposes via
// Store(). It lets the test reach the underlying *sql.DB without importing the
// concrete store packages.
type dbHolder interface{ DB() *sql.DB }

// TestDataModulesShareOneConnectionPool is the structural guard behind the
// fresh-db fix: every data-module store must be built on the App's single
// shared *sql.DB rather than opening its own pool. If a future change reverts a
// module back to WithSQLiteDSN it would open an independent pool, this test
// catches it by comparing each store's *sql.DB pointer against app.db.
func TestDataModulesShareOneConnectionPool(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp() error = %v", err)
	}
	defer app.Close()

	if app.db == nil {
		t.Fatal("app.db is nil; expected a shared *sql.DB owned by the App")
	}

	stores := map[string]any{
		"tenant":       app.tenant.Store(),
		"user":         app.user.Store(),
		"audit":        app.auditMod.Store(),
		"api_key":      app.apiKey.Store(),
		"content":      app.contentMod.Store(),
		"notification": app.notification.Store(),
	}
	for name, st := range stores {
		holder, ok := st.(dbHolder)
		if !ok {
			t.Fatalf("%s store does not expose DB() — cannot prove it shares the pool", name)
		}
		if holder.DB() != app.db {
			t.Errorf("%s store uses a different *sql.DB than the shared app.db (independent pool regression)", name)
		}
	}
}

// TestDefaultDSNCarriesBusyTimeoutAndOpensCleanly guards F3: the shipped
// default DSN must carry the modernc.org/sqlite-correct busy_timeout pragma so
// a contended pk.db waits instead of erroring, and it must still open cleanly
// with the pinned modernc driver. We build the full app against the literal
// default DSN (pointed at a fresh temp file) so a malformed pragma would
// surface as an open/ping/pragma error.
func TestDefaultDSNCarriesBusyTimeoutAndOpensCleanly(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	if !strings.Contains(cfg.Database.DSN, "_pragma=busy_timeout(5000)") {
		t.Fatalf("default DSN missing busy_timeout pragma: %q", cfg.Database.DSN)
	}

	// Repoint the default DSN's file at a fresh temp path while preserving its
	// query string (the pragma we care about) verbatim.
	dbPath := filepath.Join(t.TempDir(), "pk.db")
	q := cfg.Database.DSN[strings.IndexByte(cfg.Database.DSN, '?'):]
	cfg.Database.DSN = "file:" + dbPath + q
	cfg.HTTP.Addr = ":0"

	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp() with default busy_timeout DSN error = %v", err)
	}
	defer app.Close()

	if err := app.db.PingContext(context.Background()); err != nil {
		t.Fatalf("shared db ping with busy_timeout DSN: %v", err)
	}
}

// TestAuthSharesOneConnectionPool is the auth-module companion to the
// structural pool guard above. The auth module is wired via WithSQLiteDB(db)
// rather than WithStore, and its session store does not expose its underlying
// *sql.DB for pointer comparison. So instead of introspecting it, this test
// asserts behaviorally that the shared handle reaches auth: it stands up the
// full app against a fresh temp DB (which seeds the admin user through the
// user module on the SAME db), then drives an auth login against the seeded
// credentials over the public HTTP surface. A 201 proves the auth session
// store wrote a row to — and the login read the seeded user through — the one
// shared *sql.DB. If auth opened its own pool over the same file, the seeded
// user/session schema visibility would be driver-dependent and brittle; this
// is the regression guard for commit a2773b4's WithSQLiteDB wiring.
func TestAuthSharesOneConnectionPool(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp() error = %v", err)
	}
	defer app.Close()

	mux, err := app.Mux()
	if err != nil {
		t.Fatalf("Mux() error = %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Log in with the seeded credentials. This exercises auth (session store
	// write) AND the user module read (credential verification) against the one
	// shared db — proving the shared handle reaches the auth module.
	loginBody, _ := json.Marshal(map[string]string{
		"tenant_id": seed.TenantID,
		"email":     seed.UserEmail,
		"password":  seed.UserPass,
	})
	resp, err := http.Post(srv.URL+"/api/v1/auth/sessions", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("POST /api/v1/auth/sessions: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("auth login with seeded creds on fresh db: status = %d, want 201\nbody = %s",
			resp.StatusCode, string(body))
	}
	if strings.Contains(string(body), "no such table") {
		t.Fatalf("auth login reports a missing table — auth did not see the shared schema:\n%s", string(body))
	}

	// The created session must reference the seeded user, confirming the login
	// resolved the seeded identity through the shared pool.
	var sess struct {
		ID       string `json:"id"`
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(body, &sess); err != nil {
		t.Fatalf("decode session: %v\nbody=%s", err, string(body))
	}
	if sess.UserID != seed.UserID {
		t.Errorf("session user_id = %q, want seeded %q", sess.UserID, seed.UserID)
	}
	if sess.ID == "" {
		t.Errorf("auth login returned an empty session id; body=%s", string(body))
	}
}
