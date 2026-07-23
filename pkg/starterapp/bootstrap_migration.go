// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package starterapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// These values identify durable bootstrap rows written by releases before the
// generic local identity was introduced. They are migration input only: new
// databases and current runtime behavior use the constants in package seed.
const (
	bootstrapIdentityMigrationID = "20260723_bootstrap_labels_v3"

	legacyBootstrapTenantID     = "tenant_acme"
	legacyBootstrapTenantSlug   = "acme"
	legacyBootstrapTenantName   = "Acme Inc"
	legacyBootstrapUserID       = "user_admin"
	legacyBootstrapUserEmail    = "admin@local.test"
	legacyBootstrapUserName     = "admin"
	legacyBootstrapUserDisplay  = "Demo Admin"
	legacyBootstrapUserPassword = "changeme"
)

// bootstrapIdentity is the actual durable tenant/user key pair for this
// database. Fresh databases use package seed's neutral IDs. Upgraded databases
// retain the released IDs because downstream module tables may reference them.
type bootstrapIdentity struct {
	TenantID string
	UserID   string
}

type bootstrapPasswordHasher interface {
	Hash(plaintext string) (string, error)
	Verify(plaintext, encoded string) error
}

// resolveBootstrapIdentity chooses the IDs to use before any module binds
// tenant-scoped behavior. Renaming a released tenant or user ID is unsafe:
// starterapp.WithModules permits downstream tables unknown to this repository,
// and those tables may persist either ID without a foreign-key cascade.
func resolveBootstrapIdentity(
	ctx context.Context,
	db *sql.DB,
	adminEmail string,
	adminEmailConfigured bool,
) (bootstrapIdentity, error) {
	if db == nil {
		return bootstrapIdentity{}, errors.New("starterapp: resolve bootstrap identity requires a database")
	}
	if adminEmail == "" {
		return bootstrapIdentity{}, errors.New("starterapp: resolve bootstrap identity requires an admin email")
	}

	rowExists := func(query string, args ...any) (bool, error) {
		var count int
		if err := db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
			return false, err
		}
		return count != 0, nil
	}
	userTenant := func(id string) (string, bool, error) {
		var tenantID string
		err := db.QueryRowContext(ctx, `SELECT tenant_id FROM users WHERE id = ?`, id).Scan(&tenantID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return "", false, nil
		case err != nil:
			return "", false, err
		default:
			return tenantID, true, nil
		}
	}

	identityTableExists, err := rowExists(
		`SELECT COUNT(*)
		 FROM sqlite_master
		 WHERE type = 'table' AND name = 'starterapp_bootstrap_identity'`,
	)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect bootstrap identity ledger: %w", err)
	}
	if identityTableExists {
		var recorded bootstrapIdentity
		err := db.QueryRowContext(
			ctx,
			`SELECT tenant_id, user_id
			 FROM starterapp_bootstrap_identity
			 WHERE id = 'active'`,
		).Scan(&recorded.TenantID, &recorded.UserID)
		switch {
		case err == nil:
			if recorded.TenantID == "" || recorded.UserID == "" {
				return bootstrapIdentity{}, errors.New("starterapp: recorded bootstrap identity contains an empty ID")
			}
			if userTenantID, exists, lookupErr := userTenant(recorded.UserID); lookupErr != nil {
				return bootstrapIdentity{}, fmt.Errorf("starterapp: validate recorded bootstrap administrator: %w", lookupErr)
			} else if exists && userTenantID != recorded.TenantID {
				return bootstrapIdentity{}, fmt.Errorf(
					"starterapp: recorded bootstrap administrator %q belongs to tenant %q, not %q",
					recorded.UserID,
					userTenantID,
					recorded.TenantID,
				)
			}
			return recorded, nil
		case !errors.Is(err, sql.ErrNoRows):
			return bootstrapIdentity{}, fmt.Errorf("starterapp: read bootstrap identity ledger: %w", err)
		}
	}

	legacyTenantExists, err := rowExists(
		`SELECT COUNT(*) FROM tenants WHERE id = ?`,
		legacyBootstrapTenantID,
	)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect released bootstrap tenant: %w", err)
	}
	currentTenantExists, err := rowExists(
		`SELECT COUNT(*) FROM tenants WHERE id = ?`,
		seed.TenantID,
	)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect current bootstrap tenant: %w", err)
	}

	legacyUserTenant, legacyUserExists, err := userTenant(legacyBootstrapUserID)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect released bootstrap administrator: %w", err)
	}
	currentUserTenant, currentUserExists, err := userTenant(seed.UserID)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect current bootstrap administrator: %w", err)
	}

	if legacyTenantExists {
		legacyUserBelongsToTenant := legacyUserExists && legacyUserTenant == legacyBootstrapTenantID
		if legacyUserBelongsToTenant {
			return bootstrapIdentity{
				TenantID: legacyBootstrapTenantID,
				UserID:   legacyBootstrapUserID,
			}, nil
		}

		// A replacement bootstrap administrator may have been provisioned
		// under an application-owned ID. Resolve that identity by the released
		// email or an explicitly configured email before considering any new
		// ID: previous releases did not reserve seed.UserID or seed.UserEmail,
		// so an unrelated account may legitimately own either default.
		query := `SELECT id
			FROM users
			WHERE (tenant_id = ? AND email = ?)`
		args := []any{legacyBootstrapTenantID, legacyBootstrapUserEmail}
		if adminEmailConfigured && adminEmail != legacyBootstrapUserEmail {
			query += ` OR (tenant_id = ? AND email = ?)`
			args = append(args, legacyBootstrapTenantID, adminEmail)
		}
		query += ` ORDER BY id`
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return bootstrapIdentity{}, fmt.Errorf("starterapp: find prior email-keyed administrator: %w", err)
		}
		var emailKeyedIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return bootstrapIdentity{}, fmt.Errorf("starterapp: scan prior email-keyed administrator: %w", err)
			}
			emailKeyedIDs = append(emailKeyedIDs, id)
		}
		if err := rows.Err(); err != nil {
			return bootstrapIdentity{}, fmt.Errorf("starterapp: list prior email-keyed administrators: %w", err)
		}
		if err := rows.Close(); err != nil {
			return bootstrapIdentity{}, fmt.Errorf("starterapp: close prior administrator lookup: %w", err)
		}
		switch len(emailKeyedIDs) {
		case 1:
			return bootstrapIdentity{
				TenantID: legacyBootstrapTenantID,
				UserID:   emailKeyedIDs[0],
			}, nil
		case 0:
			// A partial prior boot may have created the tenant but not the
			// administrator. Recreate the released durable user ID when it is
			// still available so contributed-module references remain valid.
		default:
			return bootstrapIdentity{}, fmt.Errorf(
				"starterapp: ambiguous prior email-keyed administrators under tenant %q: %v",
				legacyBootstrapTenantID,
				emailKeyedIDs,
			)
		}

		// No released administrator survived (for example, a partial old
		// bootstrap created only the tenant). Prefer the released durable ID,
		// then select an unused current ID instead of granting privileges to an
		// account that happens to own either candidate.
		candidate := legacyBootstrapUserID
		for attempt := 0; ; attempt++ {
			exists, lookupErr := rowExists(`SELECT COUNT(*) FROM users WHERE id = ?`, candidate)
			if lookupErr != nil {
				return bootstrapIdentity{}, fmt.Errorf("starterapp: select bootstrap administrator ID: %w", lookupErr)
			}
			if !exists {
				return bootstrapIdentity{
					TenantID: legacyBootstrapTenantID,
					UserID:   candidate,
				}, nil
			}
			switch attempt {
			case 0:
				candidate = seed.UserID
			case 1:
				candidate = seed.UserID + "_bootstrap"
			default:
				candidate = fmt.Sprintf("%s_bootstrap_%d", seed.UserID, attempt)
			}
		}
	}

	if legacyUserExists {
		if legacyUserTenant == legacyBootstrapTenantID {
			// The old seed created tenant and user independently. If only the
			// tenant row was lost, keep the released IDs so seed.Run can heal
			// the tenant without orphaning surviving tenant-owned data.
			return bootstrapIdentity{
				TenantID: legacyBootstrapTenantID,
				UserID:   legacyBootstrapUserID,
			}, nil
		}
		return bootstrapIdentity{}, fmt.Errorf(
			"starterapp: released bootstrap administrator %q exists under tenant %q without released tenant %q",
			legacyBootstrapUserID,
			legacyUserTenant,
			legacyBootstrapTenantID,
		)
	}
	legacyReferencesExist, err := releasedBootstrapReferencesExist(ctx, db)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect released bootstrap references: %w", err)
	}
	if legacyReferencesExist {
		// Both bootstrap rows can be deleted independently while tenant-owned
		// rows survive because neither built-in nor contributed tables require
		// foreign-key cascades. Recreate the released keys so those rows remain
		// attached to the administrator instead of recording a fresh identity.
		return bootstrapIdentity{
			TenantID: legacyBootstrapTenantID,
			UserID:   legacyBootstrapUserID,
		}, nil
	}
	if currentTenantExists || currentUserExists {
		return bootstrapIdentity{}, fmt.Errorf(
			"starterapp: unrecorded bootstrap ID collision: tenant %q exists=%t; user %q exists=%t under tenant %q",
			seed.TenantID,
			currentTenantExists,
			seed.UserID,
			currentUserExists,
			currentUserTenant,
		)
	}
	return bootstrapIdentity{TenantID: seed.TenantID, UserID: seed.UserID}, nil
}

// releasedBootstrapReferencesExist searches every SQLite application table for
// the exact durable IDs shipped by earlier releases. WithModules tables are
// intentionally unknown to starterapp, so a fixed list of built-in foreign-key
// columns would silently orphan downstream data when both identity rows are
// absent. This scan runs only during the one-time, pre-ledger resolution path.
func releasedBootstrapReferencesExist(ctx context.Context, db *sql.DB) (bool, error) {
	quoteIdentifier := func(value string) string {
		return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT name
		 FROM sqlite_master
		 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
		 ORDER BY name`,
	)
	if err != nil {
		return false, err
	}
	var tableNames []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			_ = rows.Close()
			return false, err
		}
		tableNames = append(tableNames, tableName)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}

	for _, tableName := range tableNames {
		columnRows, err := db.QueryContext(
			ctx,
			`PRAGMA table_info(`+quoteIdentifier(tableName)+`)`,
		)
		if err != nil {
			return false, err
		}
		var columnNames []string
		for columnRows.Next() {
			var (
				columnID    int
				columnName  string
				columnType  string
				notNull     int
				defaultExpr any
				primaryKey  int
			)
			if err := columnRows.Scan(
				&columnID,
				&columnName,
				&columnType,
				&notNull,
				&defaultExpr,
				&primaryKey,
			); err != nil {
				_ = columnRows.Close()
				return false, err
			}
			columnNames = append(columnNames, columnName)
		}
		if err := columnRows.Err(); err != nil {
			_ = columnRows.Close()
			return false, err
		}
		if err := columnRows.Close(); err != nil {
			return false, err
		}
		if len(columnNames) == 0 {
			continue
		}

		predicates := make([]string, 0, len(columnNames)*2)
		args := make([]any, 0, len(columnNames)*2)
		for _, columnName := range columnNames {
			column := quoteIdentifier(columnName)
			predicates = append(predicates, column+" = ?", column+" = ?")
			args = append(
				args,
				legacyBootstrapTenantID,
				legacyBootstrapUserID,
			)
		}
		query := `SELECT 1
			FROM ` + quoteIdentifier(tableName) + `
			WHERE ` + strings.Join(predicates, " OR ") + `
			LIMIT 1`
		var found int
		err = db.QueryRowContext(ctx, query, args...).Scan(&found)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, sql.ErrNoRows):
			continue
		default:
			return false, err
		}
	}
	return false, nil
}

// migrateBootstrapIdentity neutralizes visible defaults from older releases
// without renaming durable tenant or user IDs. Preserving those keys is
// essential for contributed modules: the starter cannot discover every
// downstream table that may contain tenant_id, owner_id, or another reference.
//
// Customized names, administrator identities, rotated passwords, timestamps,
// and all tenant-owned rows remain unchanged. When the released default
// password is still present, it is replaced with the current configured
// password and sessions issued under it are revoked in the same transaction.
func migrateBootstrapIdentity(
	ctx context.Context,
	db *sql.DB,
	hasher bootstrapPasswordHasher,
	adminEmail string,
	adminPassword string,
	identity bootstrapIdentity,
) error {
	if db == nil {
		return errors.New("starterapp: bootstrap identity migration requires a database")
	}
	if hasher == nil {
		return errors.New("starterapp: bootstrap identity migration requires a password hasher")
	}
	if adminEmail == "" {
		return errors.New("starterapp: bootstrap identity migration requires an admin email")
	}
	if adminPassword == "" {
		return errors.New("starterapp: bootstrap identity migration requires an admin password")
	}
	if identity.TenantID == "" || identity.UserID == "" {
		return errors.New("starterapp: bootstrap identity migration requires durable IDs")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starterapp: begin bootstrap identity migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS starterapp_migrations (
			id TEXT PRIMARY KEY,
			applied_at DATETIME NOT NULL
		);
		CREATE TABLE IF NOT EXISTS starterapp_bootstrap_identity (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			user_id TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("starterapp: create migration ledger: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO starterapp_bootstrap_identity (id, tenant_id, user_id)
		 VALUES ('active', ?, ?)`,
		identity.TenantID,
		identity.UserID,
	); err != nil {
		return fmt.Errorf("starterapp: record durable bootstrap identity: %w", err)
	}
	var recorded bootstrapIdentity
	if err := tx.QueryRowContext(
		ctx,
		`SELECT tenant_id, user_id
		 FROM starterapp_bootstrap_identity
		 WHERE id = 'active'`,
	).Scan(&recorded.TenantID, &recorded.UserID); err != nil {
		return fmt.Errorf("starterapp: read durable bootstrap identity: %w", err)
	}
	if recorded != identity {
		return fmt.Errorf(
			"starterapp: bootstrap identity ledger mismatch: recorded tenant=%q user=%q, resolved tenant=%q user=%q",
			recorded.TenantID,
			recorded.UserID,
			identity.TenantID,
			identity.UserID,
		)
	}

	var selectedTenantCount, selectedUserCount int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM tenants WHERE id = ?`,
		identity.TenantID,
	).Scan(&selectedTenantCount); err != nil {
		return fmt.Errorf("starterapp: inspect selected bootstrap tenant: %w", err)
	}
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE id = ? AND tenant_id = ?`,
		identity.UserID,
		identity.TenantID,
	).Scan(&selectedUserCount); err != nil {
		return fmt.Errorf("starterapp: inspect selected bootstrap administrator: %w", err)
	}
	identityIncomplete := selectedTenantCount == 0 || selectedUserCount == 0
	now := time.Now().UTC()
	revokeRecreatedIdentityCredentials := func() error {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE auth_sessions
			 SET revoked_at = ?
			 WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL`,
			now,
			identity.TenantID,
			identity.UserID,
		); err != nil {
			return fmt.Errorf("starterapp: revoke sessions for recreated bootstrap identity: %w", err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE api_keys
			 SET revoked_at = ?
			 WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL`,
			now,
			identity.TenantID,
			identity.UserID,
		); err != nil {
			return fmt.Errorf("starterapp: revoke API keys for recreated bootstrap identity: %w", err)
		}
		return nil
	}

	var alreadyApplied int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM starterapp_migrations WHERE id = ?`,
		bootstrapIdentityMigrationID,
	).Scan(&alreadyApplied); err != nil {
		return fmt.Errorf("starterapp: inspect migration ledger: %w", err)
	}
	if alreadyApplied != 0 {
		if identityIncomplete {
			if err := revokeRecreatedIdentityCredentials(); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("starterapp: finish applied bootstrap identity migration: %w", err)
		}
		return nil
	}

	var (
		legacyTenantSlug string
		legacyTenantName string
	)
	legacyTenantExists := true
	err = tx.QueryRowContext(
		ctx,
		`SELECT slug, name FROM tenants WHERE id = ?`,
		legacyBootstrapTenantID,
	).Scan(&legacyTenantSlug, &legacyTenantName)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		legacyTenantExists = false
	case err != nil:
		return fmt.Errorf("starterapp: inspect released bootstrap tenant: %w", err)
	}

	var (
		legacyUserEmail   string
		legacyUserName    string
		legacyUserDisplay string
		legacyPassHash    string
	)
	legacyUserExists := true
	err = tx.QueryRowContext(
		ctx,
		`SELECT email, username, display_name, pass_hash
		 FROM users
		 WHERE id = ? AND tenant_id = ?`,
		identity.UserID,
		identity.TenantID,
	).Scan(&legacyUserEmail, &legacyUserName, &legacyUserDisplay, &legacyPassHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		legacyUserExists = false
	case err != nil:
		return fmt.Errorf("starterapp: inspect released bootstrap administrator: %w", err)
	}

	countRows := func(query string, args ...any) (int, error) {
		var count int
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
			return 0, err
		}
		return count, nil
	}
	availableTenantSlug := func(preferred string) (string, error) {
		candidate := preferred
		for suffix := 0; ; suffix++ {
			count, err := countRows(
				`SELECT COUNT(*) FROM tenants WHERE slug = ? AND id <> ?`,
				candidate,
				identity.TenantID,
			)
			if err != nil {
				return "", err
			}
			if count == 0 {
				return candidate, nil
			}
			if suffix == 0 {
				candidate = "platformkit-local"
				continue
			}
			candidate = fmt.Sprintf("platformkit-local-%d", suffix+1)
		}
	}
	availableUsername := func(preferred string) (string, error) {
		candidate := preferred
		for suffix := 0; ; suffix++ {
			count, err := countRows(
				`SELECT COUNT(*)
				 FROM users
				 WHERE tenant_id = ? AND username = ? AND id <> ?`,
				identity.TenantID,
				candidate,
				identity.UserID,
			)
			if err != nil {
				return "", err
			}
			if count == 0 {
				return candidate, nil
			}
			if suffix == 0 {
				candidate = "platformkit-operator"
				continue
			}
			candidate = fmt.Sprintf("platformkit-operator-%d", suffix+1)
		}
	}
	availableEmail := func(preferred string) (string, error) {
		at := strings.LastIndex(preferred, "@")
		if at <= 0 || at == len(preferred)-1 {
			return "", fmt.Errorf("configured bootstrap email %q is invalid", preferred)
		}
		local, domain := preferred[:at], preferred[at+1:]
		candidate := preferred
		for suffix := 0; ; suffix++ {
			count, err := countRows(
				`SELECT COUNT(*)
				 FROM users
				 WHERE tenant_id = ? AND email = ? AND id <> ?`,
				identity.TenantID,
				candidate,
				identity.UserID,
			)
			if err != nil {
				return "", err
			}
			if count == 0 {
				return candidate, nil
			}
			if suffix == 0 {
				candidate = local + "+platformkit@" + domain
				continue
			}
			candidate = fmt.Sprintf("%s+platformkit-%d@%s", local, suffix+1, domain)
		}
	}

	replacementSlug := legacyTenantSlug
	replacementTenantName := legacyTenantName
	if legacyTenantExists {
		if legacyTenantSlug == legacyBootstrapTenantSlug {
			replacementSlug, err = availableTenantSlug(seed.TenantSlug)
			if err != nil {
				return fmt.Errorf("starterapp: inspect replacement bootstrap slug: %w", err)
			}
		}
		if legacyTenantName == legacyBootstrapTenantName {
			replacementTenantName = seed.TenantName
		}
	}

	replacementEmail := legacyUserEmail
	replacementName := legacyUserName
	replacementDisplay := legacyUserDisplay
	replacementPassHash := legacyPassHash
	legacyPasswordWasDefault := false
	if legacyUserExists {
		if legacyUserEmail == legacyBootstrapUserEmail {
			replacementEmail, err = availableEmail(adminEmail)
			if err != nil {
				return fmt.Errorf("starterapp: select replacement bootstrap email: %w", err)
			}
		}
		if legacyUserName == legacyBootstrapUserName {
			replacementName, err = availableUsername(seed.UserName)
			if err != nil {
				return fmt.Errorf("starterapp: select replacement bootstrap username: %w", err)
			}
		}
		if legacyUserDisplay == legacyBootstrapUserDisplay {
			replacementDisplay = seed.UserDisplay
		}

		if hasher.Verify(legacyBootstrapUserPassword, legacyPassHash) == nil {
			legacyPasswordWasDefault = true
			replacementPassHash, err = hasher.Hash(adminPassword)
			if err != nil {
				return fmt.Errorf("starterapp: hash replacement bootstrap password: %w", err)
			}
		}
	}

	if legacyTenantExists {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE tenants SET slug = ?, name = ? WHERE id = ?`,
			replacementSlug,
			replacementTenantName,
			legacyBootstrapTenantID,
		); err != nil {
			return fmt.Errorf("starterapp: neutralize bootstrap tenant labels: %w", err)
		}
	}
	if legacyUserExists {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE users
			 SET email = ?, username = ?, display_name = ?, pass_hash = ?
			 WHERE id = ? AND tenant_id = ?`,
			replacementEmail,
			replacementName,
			replacementDisplay,
			replacementPassHash,
			identity.UserID,
			identity.TenantID,
		); err != nil {
			return fmt.Errorf("starterapp: neutralize bootstrap administrator labels: %w", err)
		}
	}
	if identityIncomplete {
		if err := revokeRecreatedIdentityCredentials(); err != nil {
			return err
		}
	} else if legacyPasswordWasDefault {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE auth_sessions
			 SET revoked_at = ?
			 WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL`,
			now,
			identity.TenantID,
			identity.UserID,
		); err != nil {
			return fmt.Errorf("starterapp: revoke sessions for migrated bootstrap administrator: %w", err)
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO starterapp_migrations (id, applied_at) VALUES (?, ?)`,
		bootstrapIdentityMigrationID,
		now,
	); err != nil {
		return fmt.Errorf("starterapp: record bootstrap identity migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("starterapp: commit bootstrap identity migration: %w", err)
	}
	return nil
}
