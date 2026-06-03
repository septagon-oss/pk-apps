// Package main — firstboot_test.go owns the fresh-database first-run
// regression test. It closes the false-confidence gap left by the smoke tests
// in main_test.go: those build the app and probe routes, but never assert that
// the concurrent /healthz aggregation reports every data module healthy on a
// brand-new pk.db. This test does exactly that — it stands the full mux up
// against a unique file-based SQLite DSN (what a fresh `git clone && go run .`
// produces) and fails loudly if any module reports "no such table" or if the
// seeded tenants table is not queryable through the public API.
//
// ADR: ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/septagon-oss/pk-apps/apps/starter-saas/seed"
)

// TestFreshDatabaseBootIsHealthy proves that on a brand-new SQLite file every
// data module's store is reachable and the seeded tenant is queryable. This is
// the path the user hits on first run and the one the old smoke tests missed.
func TestFreshDatabaseBootIsHealthy(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := defaultConfig()
	// Mirror the EXACT production DSN shape (cache=shared&mode=rwc) but against
	// a unique fresh file so this test reproduces a genuine cold start rather
	// than reusing a stale db.
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	app, err := buildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildApp() error = %v", err)
	}
	defer app.Close()

	mux, err := app.mux()
	if err != nil {
		t.Fatalf("mux() error = %v", err)
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
	cfg := defaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	app, err := buildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildApp() error = %v", err)
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
