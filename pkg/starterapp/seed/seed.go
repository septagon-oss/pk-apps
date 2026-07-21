// Package seed installs the first-boot tenant and admin user used by the
// starter-saas demo. It is idempotent and self-repairing: Run independently
// ensures BOTH the demo tenant AND the admin user (with the advertised
// password) exist, regardless of any partial prior state, and is safe to call
// on every boot.
//
// seed.go owns the first-boot seeding routine. The contract is intentionally
// narrow — Run only requires the public TenantService and UserService ports,
// so callers can substitute in-memory fakes for tests.
//
// Why self-repair: a clone-and-run starter can crash mid-seed (tenant created
// but admin user not yet, or a wiped credential row). A tenant-only "already
// seeded?" gate would then skip user repair forever, permanently stranding the
// advertised default login. Each entity is therefore checked by its own stable
// identity (tenant slug, user email) and created-or-repaired on its own.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package seed

// Implements: REQ-TENANT-003.
// Per: ADR-0017.
// Discipline: C-14.
import (
	"context"
	"errors"
	"fmt"

	"github.com/septagon-oss/pk-modules/pkg/tenant"
	"github.com/septagon-oss/pk-modules/pkg/user"
)

// Default seed values. Exported so tests and docs can reference the same
// strings the runtime prints in its startup banner.
const (
	TenantID    = "tenant_acme"
	TenantSlug  = "acme"
	TenantName  = "Acme Inc"
	UserID      = "user_admin"
	UserEmail   = "admin@local.test"
	UserName    = "admin"
	UserDisplay = "Demo Admin"
	UserPass    = "changeme"
)

// Params configures the first-boot seed. AdminEmail/AdminPassword set the
// credential for a NEWLY created admin. RepairPassword controls the one
// dangerous behavior: whether an EXISTING admin whose password no longer
// verifies gets reset back to AdminPassword. It must be true only in
// development — leaving it false in production is what removes the v0.1.0
// "password re-asserts to changeme on every boot" backdoor.
type Params struct {
	AdminEmail     string
	AdminPassword  string
	RepairPassword bool
}

// Result reports what the seed did, so callers can (for example) print a
// generated credential exactly once when a fresh admin was created.
type Result struct {
	TenantCreated bool
	AdminCreated  bool
}

// Run ensures the default tenant and admin user exist. It checks each entity by
// its stable identity and creates it independently, so a partial prior boot
// (tenant present but admin user missing) heals on the next call. It is safe to
// call on every boot and never produces duplicate rows. An existing admin's
// password is left untouched unless params.RepairPassword is set.
func Run(ctx context.Context, tenantSvc tenant.TenantService, userSvc user.UserService, params Params) (Result, error) {
	var res Result
	if tenantSvc == nil {
		return res, errors.New("seed: tenant service is required")
	}
	if userSvc == nil {
		return res, errors.New("seed: user service is required")
	}
	if params.AdminEmail == "" {
		return res, errors.New("seed: admin email is required")
	}
	if params.AdminPassword == "" {
		return res, errors.New("seed: admin password is required")
	}

	created, err := ensureTenant(ctx, tenantSvc)
	if err != nil {
		return res, err
	}
	res.TenantCreated = created

	adminCreated, err := ensureAdminUser(ctx, userSvc, params)
	if err != nil {
		return res, err
	}
	res.AdminCreated = adminCreated
	return res, nil
}

// ensureTenant creates the demo tenant if it is not already present, keyed on
// its stable slug. An existing tenant is left untouched. It reports whether it
// created the tenant.
func ensureTenant(ctx context.Context, tenantSvc tenant.TenantService) (bool, error) {
	existing, err := tenantSvc.GetBySlug(ctx, TenantSlug)
	if err == nil && existing != nil {
		return false, nil
	}
	t := &tenant.Tenant{
		ID:   TenantID,
		Slug: TenantSlug,
		Name: TenantName,
	}
	if err := tenantSvc.Create(ctx, t); err != nil {
		return false, fmt.Errorf("seed: create tenant: %w", err)
	}
	return true, nil
}

// ensureAdminUser guarantees the admin user exists (keyed on its tenant-scoped
// email). A NEW admin is created with params.AdminPassword. An EXISTING admin
// is left as-is — its password is only reset when params.RepairPassword is set
// (development self-heal). This is the fix for the v0.1.0 backdoor where the
// password was re-asserted unconditionally on every boot, silently reverting an
// operator's change. It reports whether it created the admin.
func ensureAdminUser(ctx context.Context, userSvc user.UserService, params Params) (bool, error) {
	existing, err := userSvc.GetByEmail(ctx, TenantID, params.AdminEmail)
	if err == nil && existing != nil {
		if params.RepairPassword {
			if vErr := userSvc.VerifyPassword(ctx, TenantID, existing.ID, params.AdminPassword); vErr != nil {
				if sErr := userSvc.SetPassword(ctx, TenantID, existing.ID, params.AdminPassword); sErr != nil {
					return false, fmt.Errorf("seed: repair admin password: %w", sErr)
				}
			}
		}
		return false, nil
	}

	u := &user.User{
		ID:          UserID,
		TenantID:    TenantID,
		Email:       params.AdminEmail,
		Username:    UserName,
		DisplayName: UserDisplay,
		Active:      true,
	}
	if err := userSvc.Create(ctx, u); err != nil {
		return false, fmt.Errorf("seed: create user: %w", err)
	}
	if err := userSvc.SetPassword(ctx, TenantID, u.ID, params.AdminPassword); err != nil {
		return false, fmt.Errorf("seed: set admin password: %w", err)
	}
	return true, nil
}
