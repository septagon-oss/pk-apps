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

// Run ensures the default tenant and admin user exist with the advertised
// password. It checks each entity by its stable identity and creates or
// repairs it independently, so a partial prior boot (tenant present but admin
// user missing or password-less) heals on the next call. It is safe to call on
// every boot and never produces duplicate rows.
func Run(ctx context.Context, tenantSvc tenant.TenantService, userSvc user.UserService) error {
	if tenantSvc == nil {
		return errors.New("seed: tenant service is required")
	}
	if userSvc == nil {
		return errors.New("seed: user service is required")
	}

	if err := ensureTenant(ctx, tenantSvc); err != nil {
		return err
	}
	return ensureAdminUser(ctx, userSvc)
}

// ensureTenant creates the demo tenant if it is not already present, keyed on
// its stable slug. An existing tenant is left untouched.
func ensureTenant(ctx context.Context, tenantSvc tenant.TenantService) error {
	existing, err := tenantSvc.GetBySlug(ctx, TenantSlug)
	if err == nil && existing != nil {
		return nil
	}
	t := &tenant.Tenant{
		ID:   TenantID,
		Slug: TenantSlug,
		Name: TenantName,
	}
	if err := tenantSvc.Create(ctx, t); err != nil {
		return fmt.Errorf("seed: create tenant: %w", err)
	}
	return nil
}

// ensureAdminUser guarantees the admin user exists (keyed on its tenant-scoped
// email) and that the advertised password verifies. It is independent of
// whether the tenant was just created, so it repairs a user that a prior boot
// failed to create. The password is re-set unconditionally so a user row that
// exists without a usable credential is healed.
func ensureAdminUser(ctx context.Context, userSvc user.UserService) error {
	existing, err := userSvc.GetByEmail(ctx, TenantID, UserEmail)
	if err == nil && existing != nil {
		// User already present — make sure the advertised credential works even
		// if a prior boot created the row but never set (or corrupted) it.
		if vErr := userSvc.VerifyPassword(ctx, existing.ID, UserPass); vErr != nil {
			if sErr := userSvc.SetPassword(ctx, existing.ID, UserPass); sErr != nil {
				return fmt.Errorf("seed: repair admin password: %w", sErr)
			}
		}
		return nil
	}

	u := &user.User{
		ID:          UserID,
		TenantID:    TenantID,
		Email:       UserEmail,
		Username:    UserName,
		DisplayName: UserDisplay,
		Active:      true,
	}
	if err := userSvc.Create(ctx, u); err != nil {
		return fmt.Errorf("seed: create user: %w", err)
	}
	if err := userSvc.SetPassword(ctx, u.ID, UserPass); err != nil {
		return fmt.Errorf("seed: set admin password: %w", err)
	}
	return nil
}
