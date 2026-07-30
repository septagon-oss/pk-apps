// Package seed — seed_test.go owns the idempotency and self-repair regression
// tests for the first-boot seeder. The critical case is a partial first boot:
// the tenant gets created but the admin user does not (or loses its password).
// A clone-and-run starter must heal that on the next boot or the advertised
// default login is permanently stranded.
//
// ADR: ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package seed

// Validates: REQ-TENANT-003.
// Per: ADR-0017.
// Discipline: C-14.
import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
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

// devSeedParams is the development credential set used across the seed tests:
// the local login with password self-repair enabled, mirroring how BuildApp
// resolves params in a development environment.
func devSeedParams() Params {
	return Params{AdminEmail: UserEmail, AdminPassword: UserPass, RepairPassword: true}
}

// TestProductionParamsDoNotResetPassword is the backdoor regression: with
// RepairPassword=false (the production default), an admin whose password an
// operator has changed must NOT be reset to the seed password on a later boot.
// Before the fix the seed re-asserted the password unconditionally, silently
// reverting the operator's change.
func TestProductionParamsDoNotResetPassword(t *testing.T) {
	ctx := context.Background()
	tenantSvc, userSvc := newSeedHarness(t)

	prod := Params{AdminEmail: UserEmail, AdminPassword: "initial-strong-pw", RepairPassword: false}
	if _, err := Run(ctx, tenantSvc, userSvc, prod); err != nil {
		t.Fatalf("initial Run: %v", err)
	}
	u, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	// Operator rotates the password out of band.
	if err := userSvc.SetPassword(ctx, TenantID, u.ID, "operator-rotated-pw"); err != nil {
		t.Fatalf("rotate password: %v", err)
	}
	// A later production boot must NOT revert it.
	if _, err := Run(ctx, tenantSvc, userSvc, prod); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if err := userSvc.VerifyPassword(ctx, TenantID, u.ID, "operator-rotated-pw"); err != nil {
		t.Fatalf("operator's rotated password was reverted by seed (backdoor still present): %v", err)
	}
	if err := userSvc.VerifyPassword(ctx, TenantID, u.ID, "initial-strong-pw"); err == nil {
		t.Fatal("seed re-asserted the original password; backdoor still present")
	}
}

// TestRunRequiresPassword confirms Run refuses to seed without an admin
// password (the composition layer enforces the same in production).
func TestRunRequiresPassword(t *testing.T) {
	ctx := context.Background()
	tenantSvc, userSvc := newSeedHarness(t)
	if _, err := Run(ctx, tenantSvc, userSvc, Params{AdminEmail: UserEmail}); err == nil {
		t.Fatal("Run with empty AdminPassword should error")
	}
}

func TestRunRejectsInvalidParametersBeforeCreatingTenant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params Params
	}{
		{
			name: "invalid email",
			params: Params{
				AdminEmail:    "missing-at-sign",
				AdminPassword: "valid-password",
			},
		},
		{
			name: "missing email local part",
			params: Params{
				AdminEmail:    "@local.test",
				AdminPassword: "valid-password",
			},
		},
		{
			name: "missing email domain",
			params: Params{
				AdminEmail:    "operator@",
				AdminPassword: "valid-password",
			},
		},
		{
			name: "multiple email separators",
			params: Params{
				AdminEmail:    "operator@local@test",
				AdminPassword: "valid-password",
			},
		},
		{
			name: "overlong UTF-8 password",
			params: Params{
				AdminEmail:    UserEmail,
				AdminPassword: strings.Repeat("é", user.MaxPasswordBytes/2+1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tenantSvc, userSvc := newSeedHarness(t)
			if _, err := Run(context.Background(), tenantSvc, userSvc, tt.params); err == nil {
				t.Fatal("Run() accepted invalid bootstrap parameters")
			}
			if _, err := tenantSvc.Get(context.Background(), TenantID); !errors.Is(err, tenant.ErrNotFound) {
				t.Fatalf("invalid parameters mutated tenant state: %v", err)
			}
		})
	}
}

// TestRunIsIdempotent proves running Run twice in a row leaves exactly one
// tenant and one usable admin user (no duplicate-key errors, no duplicates).
func TestRunIsIdempotent(t *testing.T) {
	ctx := context.Background()
	tenantSvc, userSvc := newSeedHarness(t)

	if _, err := Run(ctx, tenantSvc, userSvc, devSeedParams()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if _, err := Run(ctx, tenantSvc, userSvc, devSeedParams()); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	u, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err != nil {
		t.Fatalf("GetByEmail after double Run: %v", err)
	}
	if err := userSvc.VerifyPassword(ctx, TenantID, u.ID, UserPass); err != nil {
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
	if _, err := Run(ctx, tenantSvc, userSvc, devSeedParams()); err != nil {
		t.Fatalf("initial Run: %v", err)
	}

	// (b) Delete ONLY the admin user, leaving the tenant behind. This is the
	//     partial-boot / corrupted-credential state.
	u, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err != nil {
		t.Fatalf("GetByEmail before delete: %v", err)
	}
	if err := userSvc.Delete(ctx, TenantID, u.ID); err != nil {
		t.Fatalf("delete admin user: %v", err)
	}
	if _, err := userSvc.GetByEmail(ctx, TenantID, UserEmail); err == nil {
		t.Fatal("admin user still present after delete; harness precondition failed")
	}

	// (c) Run seed again. The tenant already exists, so a tenant-only
	//     idempotency check would skip repair.
	if _, err := Run(ctx, tenantSvc, userSvc, devSeedParams()); err != nil {
		t.Fatalf("repair Run: %v", err)
	}

	// (d) The advertised credentials must work again.
	repaired, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err != nil {
		t.Fatalf("admin user was not recreated by repair Run: %v", err)
	}
	if err := userSvc.VerifyPassword(ctx, TenantID, repaired.ID, UserPass); err != nil {
		t.Fatalf("advertised login does not work after repair Run: %v", err)
	}
}
