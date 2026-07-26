// Implements: REQ-016.
// Per: ADR-0017, ADR-0029.
// Discipline: C-14.

package starterapp

// bootstrap.go owns the durable bootstrap identity: the tenant ID and user ID
// this database's seeded administrator holds for the life of the database.
//
// Why record it at all, when the IDs come from constants in package seed? Because
// downstream applications extend the starter through WithModules, and their
// tables may reference either ID with no foreign key back to ours. Once a
// database has rows pointing at a tenant or user ID, that ID is load-bearing:
// picking a different one on a later boot would silently orphan them. The
// ledger makes the choice explicit and permanent — resolve reads it, boot
// records it, and the pair never drifts.
//
// The ledger is written in the SQLite dialect and translated for Postgres at
// the boundDB seam (see dialect.go), so there is one spelling of each
// statement here.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// bootstrapIdentityTable is the one-row ledger naming this database's durable
// bootstrap tenant and administrator.
const bootstrapIdentityTable = "starterapp_bootstrap_identity"

// bootstrapIdentity is the durable tenant/user key pair for this database.
type bootstrapIdentity struct {
	TenantID string
	UserID   string
}

// resolveBootstrapIdentity returns the identity to seed against, before any
// module binds tenant-scoped behavior.
//
//   - A database with a ledger uses exactly what the ledger records.
//   - A database without one is fresh, and takes the neutral IDs from package
//     seed — unless rows already carry those IDs, which means something created
//     them outside this boot path. That is an anomaly worth refusing rather than
//     adopting: booting on top of it would hand an unknown tenant and user
//     administrator rights.
func resolveBootstrapIdentity(ctx context.Context, db boundDB) (bootstrapIdentity, error) {
	if db.db == nil {
		return bootstrapIdentity{}, errors.New("starterapp: resolve bootstrap identity requires a database")
	}

	ledgerExists, err := db.tableExists(ctx, bootstrapIdentityTable)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect bootstrap identity ledger: %w", err)
	}
	if ledgerExists {
		var recorded bootstrapIdentity
		err := db.QueryRowContext(
			ctx,
			`SELECT tenant_id, user_id FROM `+bootstrapIdentityTable+` WHERE id = 'active'`,
		).Scan(&recorded.TenantID, &recorded.UserID)
		switch {
		case err == nil:
			if recorded.TenantID == "" || recorded.UserID == "" {
				return bootstrapIdentity{}, errors.New("starterapp: recorded bootstrap identity contains an empty ID")
			}
			// The recorded administrator must still belong to the recorded
			// tenant. A mismatch means the row was moved or rewritten out of
			// band, and seeding against it would grant the wrong tenant's user
			// administrator rights.
			tenantID, exists, lookupErr := bootstrapUserTenant(ctx, db, recorded.UserID)
			if lookupErr != nil {
				return bootstrapIdentity{}, fmt.Errorf("starterapp: validate recorded bootstrap administrator: %w", lookupErr)
			}
			if exists && tenantID != recorded.TenantID {
				return bootstrapIdentity{}, fmt.Errorf(
					"starterapp: recorded bootstrap administrator %q belongs to tenant %q, not %q",
					recorded.UserID, tenantID, recorded.TenantID,
				)
			}
			return recorded, nil
		case !errors.Is(err, sql.ErrNoRows):
			return bootstrapIdentity{}, fmt.Errorf("starterapp: read bootstrap identity ledger: %w", err)
		}
		// An empty ledger falls through to the fresh-database path below, which
		// records the identity this boot selects.
	}

	tenantExists, err := bootstrapRowExists(ctx, db, `SELECT COUNT(*) FROM tenants WHERE id = ?`, seed.TenantID)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect bootstrap tenant: %w", err)
	}
	userTenantID, userExists, err := bootstrapUserTenant(ctx, db, seed.UserID)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect bootstrap administrator: %w", err)
	}
	if tenantExists || userExists {
		return bootstrapIdentity{}, fmt.Errorf(
			"starterapp: unrecorded bootstrap ID collision: tenant %q exists=%t; user %q exists=%t under tenant %q",
			seed.TenantID, tenantExists, seed.UserID, userExists, userTenantID,
		)
	}
	return bootstrapIdentity{TenantID: seed.TenantID, UserID: seed.UserID}, nil
}

// recordBootstrapIdentity persists the resolved identity, creating the ledger
// on first boot. It is idempotent: a second boot re-reads the same row and
// verifies it still matches, so a ledger that disagrees with the resolved
// identity fails the boot instead of quietly re-seeding a different admin.
func recordBootstrapIdentity(ctx context.Context, db boundDB, identity bootstrapIdentity) error {
	if db.db == nil {
		return errors.New("starterapp: record bootstrap identity requires a database")
	}
	if identity.TenantID == "" || identity.UserID == "" {
		return errors.New("starterapp: record bootstrap identity requires durable IDs")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starterapp: begin bootstrap identity record: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS `+bootstrapIdentityTable+` (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			user_id TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("starterapp: create bootstrap identity ledger: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO `+bootstrapIdentityTable+` (id, tenant_id, user_id) VALUES ('active', ?, ?)`,
		identity.TenantID, identity.UserID,
	); err != nil {
		return fmt.Errorf("starterapp: record durable bootstrap identity: %w", err)
	}

	var recorded bootstrapIdentity
	if err := tx.QueryRowContext(
		ctx,
		`SELECT tenant_id, user_id FROM `+bootstrapIdentityTable+` WHERE id = 'active'`,
	).Scan(&recorded.TenantID, &recorded.UserID); err != nil {
		return fmt.Errorf("starterapp: read durable bootstrap identity: %w", err)
	}
	if recorded != identity {
		return fmt.Errorf(
			"starterapp: bootstrap identity ledger mismatch: recorded tenant=%q user=%q, resolved tenant=%q user=%q",
			recorded.TenantID, recorded.UserID, identity.TenantID, identity.UserID,
		)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("starterapp: commit bootstrap identity record: %w", err)
	}
	return nil
}

// bootstrapRowExists reports whether a COUNT(*) query matches any row.
func bootstrapRowExists(ctx context.Context, db boundDB, query string, args ...any) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, err
	}
	return count != 0, nil
}

// bootstrapUserTenant returns the tenant owning a user, and whether the user
// exists at all.
func bootstrapUserTenant(ctx context.Context, db boundDB, userID string) (string, bool, error) {
	var tenantID string
	err := db.QueryRowContext(ctx, `SELECT tenant_id FROM users WHERE id = ?`, userID).Scan(&tenantID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	default:
		return tenantID, true, nil
	}
}
