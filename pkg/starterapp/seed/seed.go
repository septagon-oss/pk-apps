// Package seed installs the first-boot tenant and administrator used by the
// canonical starter. It is idempotent: Run independently ensures both records
// exist regardless of partial prior state. Password repair is explicitly
// limited to local development.
//
// seed.go owns the first-boot seeding routine. The contract is intentionally
// narrow — Run only requires the public TenantService and UserService ports,
// so callers can substitute in-memory fakes for tests.
//
// Why self-repair: a clone-and-run starter can crash mid-seed (tenant created
// but admin user not yet, or a wiped credential row). A tenant-only "already
// seeded?" gate would then skip user repair forever, permanently stranding the
// advertised default login. Each entity is therefore checked by its selected
// durable ID and created-or-repaired on its own.
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
	"strings"

	"github.com/septagon-oss/pk-modules/pkg/tenant"
	"github.com/septagon-oss/pk-modules/pkg/user"
	userstore "github.com/septagon-oss/pk-modules/pkg/user/store"
)

// Default seed values. Exported so tests and docs can reference the same
// strings the runtime prints in its startup banner.
const (
	TenantID    = "tenant_local"
	TenantSlug  = "local"
	TenantName  = "Local Workspace"
	UserID      = "user_operator"
	UserEmail   = "operator@local.test"
	UserName    = "operator"
	UserDisplay = "Local Administrator"
	UserPass    = "local-development-only"
)

// Params configures the first-boot seed. AdminEmail/AdminPassword set the
// credential for a NEWLY created admin. RepairPassword controls the one
// dangerous behavior: whether an EXISTING admin whose password no longer
// verifies gets reset back to AdminPassword. It must be true only in
// development — leaving it false in production is what removes the v0.1.0
// "password re-asserts on every boot" backdoor.
type Params struct {
	AdminEmail     string
	AdminPassword  string
	RepairPassword bool
	// TenantID and UserID override the fresh-install identifiers when an
	// upgrade must preserve durable bootstrap IDs already referenced by
	// downstream module tables. Empty values use TenantID and UserID above.
	TenantID string
	UserID   string
}

// Result reports what the seed did, so callers can (for example) print a
// generated credential exactly once when a fresh admin was created.
type Result struct {
	TenantCreated bool
	AdminCreated  bool
}

// Run ensures the selected bootstrap tenant and administrator exist. Empty ID
// overrides select the neutral fresh-install constants; upgrades can provide
// released durable IDs so downstream references remain valid. Each entity is
// created independently, so a partial prior boot heals on the next call. An
// existing administrator's password is left untouched unless
// params.RepairPassword is set.
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
	tenantID := params.TenantID
	if tenantID == "" {
		tenantID = TenantID
	}
	userID := params.UserID
	if userID == "" {
		userID = UserID
	}

	created, err := ensureTenant(ctx, tenantSvc, tenantID)
	if err != nil {
		return res, err
	}
	res.TenantCreated = created

	adminCreated, err := ensureAdminUser(ctx, userSvc, params, tenantID, userID)
	if err != nil {
		return res, err
	}
	res.AdminCreated = adminCreated
	return res, nil
}

// ensureTenant creates the bootstrap tenant if it is not already present,
// keyed first on its stable ID. Looking up the ID before the default slug
// preserves an operator-customized slug across upgrades. An existing tenant is
// left untouched. It reports whether it created the tenant.
func ensureTenant(ctx context.Context, tenantSvc tenant.TenantService, tenantID string) (bool, error) {
	existing, err := tenantSvc.Get(ctx, tenantID)
	if err == nil && existing != nil {
		return false, nil
	}
	if err != nil && !errors.Is(err, tenant.ErrNotFound) {
		return false, fmt.Errorf("seed: inspect bootstrap tenant %q: %w", tenantID, err)
	}

	slug := TenantSlug
	for suffix := 0; ; suffix++ {
		existing, err = tenantSvc.GetBySlug(ctx, slug)
		switch {
		case err == nil && existing != nil && existing.ID == tenantID:
			return false, nil
		case err == nil && existing != nil:
			if suffix == 0 {
				slug = "platformkit-local"
				continue
			}
			slug = fmt.Sprintf("platformkit-local-%d", suffix+1)
			continue
		case errors.Is(err, tenant.ErrNotFound):
			// The candidate is available.
		case err != nil:
			return false, fmt.Errorf("seed: inspect bootstrap slug %q: %w", slug, err)
		default:
			return false, fmt.Errorf("seed: bootstrap slug lookup %q returned no tenant and no error", slug)
		}
		break
	}
	t := &tenant.Tenant{
		ID:   tenantID,
		Slug: slug,
		Name: TenantName,
	}
	if err := tenantSvc.Create(ctx, t); err != nil {
		return false, fmt.Errorf("seed: create tenant: %w", err)
	}
	return true, nil
}

// ensureAdminUser guarantees the stable bootstrap user exists. A NEW admin is
// created with params.AdminPassword. An EXISTING admin is left as-is — its
// password is only reset when params.RepairPassword is set (development
// self-heal). Looking up the stable ID preserves a customized email across
// upgrades. This is the fix for the v0.1.0 backdoor where the password was
// re-asserted unconditionally on every boot, silently reverting an operator's
// change. It reports whether it created the admin.
func ensureAdminUser(
	ctx context.Context,
	userSvc user.UserService,
	params Params,
	tenantID string,
	userID string,
) (bool, error) {
	existing, err := userSvc.Get(ctx, tenantID, userID)
	if err == nil && existing != nil {
		if params.RepairPassword {
			if vErr := userSvc.VerifyPassword(ctx, tenantID, existing.ID, params.AdminPassword); vErr != nil {
				if sErr := userSvc.SetPassword(ctx, tenantID, existing.ID, params.AdminPassword); sErr != nil {
					return false, fmt.Errorf("seed: repair admin password: %w", sErr)
				}
			}
		}
		return false, nil
	}
	if err != nil && !errors.Is(err, userstore.ErrNotFound) {
		return false, fmt.Errorf("seed: inspect bootstrap administrator %q: %w", userID, err)
	}

	email, err := availableAdminEmail(ctx, userSvc, tenantID, userID, params.AdminEmail)
	if err != nil {
		return false, err
	}
	username, err := availableAdminUsername(ctx, userSvc, tenantID, userID)
	if err != nil {
		return false, err
	}
	u := &user.User{
		ID:          userID,
		TenantID:    tenantID,
		Email:       email,
		Username:    username,
		DisplayName: UserDisplay,
		Active:      true,
	}
	if err := userSvc.Create(ctx, u); err != nil {
		return false, fmt.Errorf("seed: create user: %w", err)
	}
	if err := userSvc.SetPassword(ctx, tenantID, u.ID, params.AdminPassword); err != nil {
		return false, fmt.Errorf("seed: set admin password: %w", err)
	}
	return true, nil
}

func availableAdminEmail(
	ctx context.Context,
	userSvc user.UserService,
	tenantID string,
	userID string,
	preferred string,
) (string, error) {
	at := strings.LastIndex(preferred, "@")
	if at <= 0 || at == len(preferred)-1 {
		return "", fmt.Errorf("seed: configured admin email %q is invalid", preferred)
	}
	local, domain := preferred[:at], preferred[at+1:]
	candidate := preferred
	for suffix := 0; ; suffix++ {
		existing, err := userSvc.GetByEmail(ctx, tenantID, candidate)
		switch {
		case err == nil && existing != nil && existing.ID == userID:
			return candidate, nil
		case err == nil && existing != nil:
			if suffix == 0 {
				candidate = local + "+platformkit@" + domain
				continue
			}
			candidate = fmt.Sprintf("%s+platformkit-%d@%s", local, suffix+1, domain)
			continue
		case errors.Is(err, userstore.ErrNotFound):
			return candidate, nil
		case err != nil:
			return "", fmt.Errorf("seed: inspect bootstrap email %q: %w", candidate, err)
		default:
			return "", fmt.Errorf("seed: bootstrap email lookup %q returned no user and no error", candidate)
		}
	}
}

func availableAdminUsername(
	ctx context.Context,
	userSvc user.UserService,
	tenantID string,
	userID string,
) (string, error) {
	candidate := UserName
	for suffix := 0; ; suffix++ {
		existing, err := userSvc.GetByUsername(ctx, tenantID, candidate)
		switch {
		case err == nil && existing != nil && existing.ID == userID:
			return candidate, nil
		case err == nil && existing != nil:
			if suffix == 0 {
				candidate = "platformkit-operator"
				continue
			}
			candidate = fmt.Sprintf("platformkit-operator-%d", suffix+1)
			continue
		case errors.Is(err, userstore.ErrNotFound):
			return candidate, nil
		case err != nil:
			return "", fmt.Errorf("seed: inspect bootstrap username %q: %w", candidate, err)
		default:
			return "", fmt.Errorf("seed: bootstrap username lookup %q returned no user and no error", candidate)
		}
	}
}
