// Package seed — seed_test.go owns the idempotency and self-repair regression
// tests for the first-boot seeder. The critical case is a partial first boot:
// the tenant gets created but the admin user does not (or loses its password).
// A clone-and-run starter must heal that on the next boot or the advertised
// default login is permanently stranded.
//
// ADR: ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package seed

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/septagon-oss/pk-modules/pkg/tenant"
	tenantsqlite "github.com/septagon-oss/pk-modules/pkg/tenant/store/sqlite"
	"github.com/septagon-oss/pk-modules/pkg/user"
	usersqlite "github.com/septagon-oss/pk-modules/pkg/user/store/sqlite"

	_ "modernc.org/sqlite"
)

// newSeedHarness builds a tenant + user module pair on one fresh SQLite file,
// mirroring how the app wires them, and returns their services for the test.
func newSeedHarness(t *testing.T) (tenant.TenantService, user.UserService) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "seed.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)&cache=shared&mode=rwc")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	tStore, err := tenantsqlite.New(db)
	if err != nil {
		t.Fatalf("tenant store: %v", err)
	}
	uStore, err := usersqlite.New(db)
	if err != nil {
		t.Fatalf("user store: %v", err)
	}

	tMod, err := tenant.NewModule(tenant.WithStore(tStore))
	if err != nil {
		t.Fatalf("tenant module: %v", err)
	}
	uMod, err := user.NewModule(
		user.WithStore(uStore),
		user.WithTenantService(tMod.Service()),
	)
	if err != nil {
		t.Fatalf("user module: %v", err)
	}
	return tMod.Service(), uMod.Service()
}

// TestRunIsIdempotent proves running Run twice in a row leaves exactly one
// tenant and one usable admin user (no duplicate-key errors, no duplicates).
func TestRunIsIdempotent(t *testing.T) {
	ctx := context.Background()
	tenantSvc, userSvc := newSeedHarness(t)

	if err := Run(ctx, tenantSvc, userSvc); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := Run(ctx, tenantSvc, userSvc); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	u, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err != nil {
		t.Fatalf("GetByEmail after double Run: %v", err)
	}
	if err := userSvc.VerifyPassword(ctx, u.ID, UserPass); err != nil {
		t.Fatalf("advertised login does not work after double Run: %v", err)
	}
}

// TestRunRepairsStrandedLogin is the self-repair regression: it simulates a
// partial first boot where the tenant exists but the admin user was lost
// (crash between tenant create and user create, or a wiped user row). Before
// the fix, Run gated all user work on "tenant did not yet exist", so the second
// Run saw the tenant and skipped repair — the advertised login was permanently
// stranded. This test must FAIL before the fix and pass after.
func TestRunRepairsStrandedLogin(t *testing.T) {
	ctx := context.Background()
	tenantSvc, userSvc := newSeedHarness(t)

	// (a) Run seed — full happy path creates tenant + admin user.
	if err := Run(ctx, tenantSvc, userSvc); err != nil {
		t.Fatalf("initial Run: %v", err)
	}

	// (b) Delete ONLY the admin user, leaving the tenant behind. This is the
	//     partial-boot / corrupted-credential state.
	u, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err != nil {
		t.Fatalf("GetByEmail before delete: %v", err)
	}
	if err := userSvc.Delete(ctx, u.ID); err != nil {
		t.Fatalf("delete admin user: %v", err)
	}
	if _, err := userSvc.GetByEmail(ctx, TenantID, UserEmail); err == nil {
		t.Fatal("admin user still present after delete; harness precondition failed")
	}

	// (c) Run seed again. The tenant already exists, so a tenant-only
	//     idempotency check would skip repair.
	if err := Run(ctx, tenantSvc, userSvc); err != nil {
		t.Fatalf("repair Run: %v", err)
	}

	// (d) The advertised credentials must work again.
	repaired, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err != nil {
		t.Fatalf("admin user was not recreated by repair Run: %v", err)
	}
	if err := userSvc.VerifyPassword(ctx, repaired.ID, UserPass); err != nil {
		t.Fatalf("advertised login does not work after repair Run: %v", err)
	}
}
