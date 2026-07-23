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
	bootstrapIdentityMigrationID = "20260723_bootstrap_labels_v4"

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

	type priorAdministratorCandidates struct {
		historicalID string
		configuredID string
	}
	findEmailOwner := func(email string) (string, error) {
		var id string
		err := db.QueryRowContext(
			ctx,
			`SELECT id FROM users WHERE tenant_id = ? AND email = ?`,
			legacyBootstrapTenantID,
			email,
		).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return "", nil
		case err != nil:
			return "", err
		default:
			return id, nil
		}
	}
	findPriorAdministrators := func() (priorAdministratorCandidates, error) {
		// Keep the released-email signal separate from the operator's explicit
		// configured-email signal. Combining them into one slice made the
		// released ID win whenever it still owned the historical address, even
		// when a different account was the configured administrator.
		historicalID, err := findEmailOwner(legacyBootstrapUserEmail)
		if err != nil {
			return priorAdministratorCandidates{}, err
		}
		candidates := priorAdministratorCandidates{historicalID: historicalID}
		if adminEmailConfigured {
			configuredID, lookupErr := findEmailOwner(adminEmail)
			if lookupErr != nil {
				return priorAdministratorCandidates{}, lookupErr
			}
			candidates.configuredID = configuredID
		}
		return candidates, nil
	}
	selectPriorAdministrator := func(
		candidates priorAdministratorCandidates,
		legacyUserBelongsToTenant bool,
	) (string, bool, error) {
		// An explicitly configured address is the operator's authoritative
		// selection. Preserve its current owner rather than moving authority to
		// an account that merely retained the released default address.
		if candidates.configuredID != "" {
			return candidates.configuredID, true, nil
		}
		if legacyUserBelongsToTenant {
			switch candidates.historicalID {
			case "", legacyBootstrapUserID:
				// The durable released ID either owns the historical address or
				// has a customized address with no conflicting historical owner.
				return legacyBootstrapUserID, true, nil
			default:
				return "", false, fmt.Errorf(
					"released bootstrap administrator %q conflicts with historical-email owner %q",
					legacyBootstrapUserID,
					candidates.historicalID,
				)
			}
		}
		if candidates.historicalID != "" {
			return candidates.historicalID, true, nil
		}
		return "", false, nil
	}

	if legacyTenantExists {
		legacyUserBelongsToTenant := legacyUserExists && legacyUserTenant == legacyBootstrapTenantID
		candidates, err := findPriorAdministrators()
		if err != nil {
			return bootstrapIdentity{}, fmt.Errorf("starterapp: find prior email-keyed administrator: %w", err)
		}
		priorUserID, found, selectErr := selectPriorAdministrator(candidates, legacyUserBelongsToTenant)
		if selectErr != nil {
			return bootstrapIdentity{}, fmt.Errorf(
				"starterapp: conflicting released bootstrap administrator under tenant %q: %w",
				legacyBootstrapTenantID,
				selectErr,
			)
		}
		if found {
			return bootstrapIdentity{
				TenantID: legacyBootstrapTenantID,
				UserID:   priorUserID,
			}, nil
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
		if legacyUserTenant != legacyBootstrapTenantID {
			return bootstrapIdentity{}, fmt.Errorf(
				"starterapp: released bootstrap administrator %q exists under tenant %q without released tenant %q",
				legacyBootstrapUserID,
				legacyUserTenant,
				legacyBootstrapTenantID,
			)
		}
	}
	legacyReferencesExist, err := releasedBootstrapReferencesExist(ctx, db)
	if err != nil {
		return bootstrapIdentity{}, fmt.Errorf("starterapp: inspect released bootstrap references: %w", err)
	}
	if legacyReferencesExist {
		// The tenant row can disappear after an application already re-keyed
		// its bootstrap administrator. Recover that administrator before
		// falling back to the released user ID, or boot would create a second
		// privileged user and detach the surviving references from the owner.
		candidates, lookupErr := findPriorAdministrators()
		if lookupErr != nil {
			return bootstrapIdentity{}, fmt.Errorf(
				"starterapp: find prior email-keyed administrator without tenant row: %w",
				lookupErr,
			)
		}
		priorUserID, found, selectErr := selectPriorAdministrator(
			candidates,
			legacyUserExists && legacyUserTenant == legacyBootstrapTenantID,
		)
		if selectErr != nil {
			return bootstrapIdentity{}, fmt.Errorf(
				"starterapp: conflicting released bootstrap administrator under missing tenant %q: %w",
				legacyBootstrapTenantID,
				selectErr,
			)
		}
		if found {
			return bootstrapIdentity{
				TenantID: legacyBootstrapTenantID,
				UserID:   priorUserID,
			}, nil
		}
		// Both bootstrap rows can be deleted independently while tenant-owned
		// rows survive. Recreate the released keys so those rows remain attached
		// instead of selecting fresh-install IDs.
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

// releasedBootstrapReferencesExist searches identity-reference columns in every
// SQLite application table for the exact durable IDs shipped by earlier
// releases. WithModules tables are intentionally unknown to starterapp, so the
// scan recognizes the published tenant_id/user_id/owner_id conventions and
// declared foreign keys instead of relying on a fixed table list. Arbitrary
// text columns are excluded: content that merely mentions an old ID is not
// durable identity evidence. This runs only during pre-ledger resolution.
func releasedBootstrapReferencesExist(ctx context.Context, db *sql.DB) (bool, error) {
	quoteIdentifier := func(value string) string {
		return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
	}
	referenceValuesForColumn := func(columnName string) []string {
		switch strings.ToLower(strings.TrimSpace(columnName)) {
		case "tenant_id", "workspace_id", "organization_id", "organisation_id":
			return []string{legacyBootstrapTenantID}
		case "user_id", "owner_id", "author_id", "actor_id", "subject_id",
			"principal_id", "administrator_id", "created_by", "updated_by", "actor":
			return []string{legacyBootstrapUserID}
		default:
			return nil
		}
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
		referenceValues := map[string][]string{}
		columnRows, err := db.QueryContext(
			ctx,
			`PRAGMA table_info(`+quoteIdentifier(tableName)+`)`,
		)
		if err != nil {
			return false, err
		}
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
			if values := referenceValuesForColumn(columnName); len(values) != 0 {
				referenceValues[columnName] = values
			}
		}
		if err := columnRows.Err(); err != nil {
			_ = columnRows.Close()
			return false, err
		}
		if err := columnRows.Close(); err != nil {
			return false, err
		}
		foreignKeyRows, err := db.QueryContext(
			ctx,
			`PRAGMA foreign_key_list(`+quoteIdentifier(tableName)+`)`,
		)
		if err != nil {
			return false, err
		}
		for foreignKeyRows.Next() {
			var (
				id, sequence              int
				targetTable, sourceColumn string
				targetColumn              sql.NullString
				onUpdate, onDelete, match string
			)
			if err := foreignKeyRows.Scan(
				&id,
				&sequence,
				&targetTable,
				&sourceColumn,
				&targetColumn,
				&onUpdate,
				&onDelete,
				&match,
			); err != nil {
				_ = foreignKeyRows.Close()
				return false, err
			}
			switch strings.ToLower(targetTable) {
			case "tenants":
				referenceValues[sourceColumn] = []string{legacyBootstrapTenantID}
			case "users":
				referenceValues[sourceColumn] = []string{legacyBootstrapUserID}
			}
		}
		if err := foreignKeyRows.Err(); err != nil {
			_ = foreignKeyRows.Close()
			return false, err
		}
		if err := foreignKeyRows.Close(); err != nil {
			return false, err
		}

		for columnName, values := range referenceValues {
			for _, value := range values {
				var found int
				err = db.QueryRowContext(
					ctx,
					`SELECT 1 FROM `+quoteIdentifier(tableName)+
						` WHERE `+quoteIdentifier(columnName)+` = ? LIMIT 1`,
					value,
				).Scan(&found)
				switch {
				case err == nil:
					return true, nil
				case errors.Is(err, sql.ErrNoRows):
					continue
				default:
					return false, err
				}
			}
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
	revokeCredentials := func(tenantID, userID string) error {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE auth_sessions
			 SET revoked_at = ?
			 WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL`,
			now,
			tenantID,
			userID,
		); err != nil {
			return fmt.Errorf("starterapp: revoke bootstrap identity sessions: %w", err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE api_keys
			 SET revoked_at = ?
			 WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL`,
			now,
			tenantID,
			userID,
		); err != nil {
			return fmt.Errorf("starterapp: revoke bootstrap identity API keys: %w", err)
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
			if err := revokeCredentials(identity.TenantID, identity.UserID); err != nil {
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
	if identityIncomplete || legacyPasswordWasDefault {
		// The released password was public. Any long-lived API key minted
		// through it must be treated as compromised alongside browser sessions.
		// Recreated identity rows require the same fail-closed invalidation.
		if err := revokeCredentials(identity.TenantID, identity.UserID); err != nil {
			return err
		}
	}
	releasedIdentity := bootstrapIdentity{
		TenantID: legacyBootstrapTenantID,
		UserID:   legacyBootstrapUserID,
	}
	if identity != releasedIdentity {
		// A replacement or collision-safe identity must not leave credentials
		// for the released pair usable. The old session can still authenticate
		// to contributed routes, and an old API key can retain data scopes even
		// though neither credential receives administrator scope.
		if err := revokeCredentials(releasedIdentity.TenantID, releasedIdentity.UserID); err != nil {
			return err
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
