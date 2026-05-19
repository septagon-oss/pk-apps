// Package seed installs the first-boot tenant and admin user used by the
// starter-saas demo. It is idempotent: running Run twice is a no-op once the
// seed tenant exists.
//
// seed.go owns the first-boot seeding routine. The contract is intentionally
// narrow — Run only requires the public TenantService and UserService ports,
// so callers can substitute in-memory fakes for tests.
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

// Run creates the default tenant and admin user if the seed tenant does not
// already exist. It is safe to call on every boot.
func Run(ctx context.Context, tenantSvc tenant.TenantService, userSvc user.UserService) error {
	if tenantSvc == nil {
		return errors.New("seed: tenant service is required")
	}
	if userSvc == nil {
		return errors.New("seed: user service is required")
	}

	existing, err := tenantSvc.GetBySlug(ctx, TenantSlug)
	if err == nil && existing != nil {
		// Already seeded — nothing to do.
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

	u := &user.User{
		ID:          UserID,
		TenantID:    t.ID,
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
