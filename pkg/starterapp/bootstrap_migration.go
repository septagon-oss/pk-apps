// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package starterapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// These values identify durable bootstrap rows written by releases before the
// generic local identity was introduced. They are migration input only: new
// databases and current runtime behavior use the constants in package seed.
const (
	bootstrapIdentityMigrationID = "20260723_bootstrap_identity_v2"

	legacyBootstrapTenantID     = "tenant_acme"
	legacyBootstrapTenantSlug   = "acme"
	legacyBootstrapTenantName   = "Acme Inc"
	legacyBootstrapUserID       = "user_admin"
	legacyBootstrapUserEmail    = "admin@local.test"
	legacyBootstrapUserName     = "admin"
	legacyBootstrapUserDisplay  = "Demo Admin"
	legacyBootstrapUserPassword = "changeme"
)

type bootstrapPasswordHasher interface {
	Hash(plaintext string) (string, error)
	Verify(plaintext, encoded string) error
}

// migrateBootstrapIdentity applies the one forward-only durable-state change
// needed when an existing starter database moves to the generic local
// bootstrap identity. It preserves tenant-owned rows, customized names,
// customized administrator identities, rotated passwords, and timestamps.
// Only values still equal to the old built-in defaults are renamed. If the old
// built-in password is still present, it is replaced with the current
// configured password and sessions issued under it are revoked inside the same
// transaction.
func migrateBootstrapIdentity(
	ctx context.Context,
	db *sql.DB,
	hasher bootstrapPasswordHasher,
	adminEmail string,
	adminPassword string,
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

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starterapp: begin bootstrap identity migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS starterapp_migrations (
			id TEXT PRIMARY KEY,
			applied_at DATETIME NOT NULL
		)`); err != nil {
		return fmt.Errorf("starterapp: create migration ledger: %w", err)
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
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("starterapp: finish applied bootstrap identity migration: %w", err)
		}
		return nil
	}

	var legacyTenantSlug string
	legacyTenantExists := true
	err = tx.QueryRowContext(
		ctx,
		`SELECT slug FROM tenants WHERE id = ?`,
		legacyBootstrapTenantID,
	).Scan(&legacyTenantSlug)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		legacyTenantExists = false
	case err != nil:
		return fmt.Errorf("starterapp: inspect legacy bootstrap tenant: %w", err)
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
		legacyBootstrapUserID,
		legacyBootstrapTenantID,
	).Scan(&legacyUserEmail, &legacyUserName, &legacyUserDisplay, &legacyPassHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		legacyUserExists = false
	case err != nil:
		return fmt.Errorf("starterapp: inspect legacy bootstrap administrator: %w", err)
	}

	countRows := func(query string, args ...any) (int, error) {
		var count int
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
			return 0, err
		}
		return count, nil
	}

	if legacyTenantExists {
		count, err := countRows(
			`SELECT COUNT(*) FROM tenants WHERE id = ?`,
			seed.TenantID,
		)
		if err != nil {
			return fmt.Errorf("starterapp: inspect destination bootstrap tenant: %w", err)
		}
		if count != 0 {
			return fmt.Errorf(
				"starterapp: cannot migrate bootstrap tenant %q: destination ID %q already exists",
				legacyBootstrapTenantID,
				seed.TenantID,
			)
		}

		if legacyTenantSlug == legacyBootstrapTenantSlug {
			count, err = countRows(
				`SELECT COUNT(*) FROM tenants WHERE slug = ? AND id <> ?`,
				seed.TenantSlug,
				legacyBootstrapTenantID,
			)
			if err != nil {
				return fmt.Errorf("starterapp: inspect destination bootstrap slug: %w", err)
			}
			if count != 0 {
				return fmt.Errorf(
					"starterapp: cannot migrate bootstrap tenant: destination slug %q already exists",
					seed.TenantSlug,
				)
			}
		}
	}

	replacementEmail := legacyUserEmail
	replacementName := legacyUserName
	replacementDisplay := legacyUserDisplay
	replacementPassHash := legacyPassHash
	legacyPasswordWasDefault := false
	if legacyUserExists {
		count, err := countRows(
			`SELECT COUNT(*) FROM users WHERE id = ?`,
			seed.UserID,
		)
		if err != nil {
			return fmt.Errorf("starterapp: inspect destination bootstrap administrator: %w", err)
		}
		if count != 0 {
			return fmt.Errorf(
				"starterapp: cannot migrate bootstrap administrator %q: destination ID %q already exists",
				legacyBootstrapUserID,
				seed.UserID,
			)
		}

		if legacyUserEmail == legacyBootstrapUserEmail {
			replacementEmail = adminEmail
		}
		if legacyUserName == legacyBootstrapUserName {
			replacementName = seed.UserName
		}
		if legacyUserDisplay == legacyBootstrapUserDisplay {
			replacementDisplay = seed.UserDisplay
		}

		count, err = countRows(
			`SELECT COUNT(*)
			 FROM users
			 WHERE id <> ?
			   AND tenant_id IN (?, ?)
			   AND (email = ? OR username = ?)`,
			legacyBootstrapUserID,
			legacyBootstrapTenantID,
			seed.TenantID,
			replacementEmail,
			replacementName,
		)
		if err != nil {
			return fmt.Errorf("starterapp: inspect bootstrap administrator identity conflicts: %w", err)
		}
		if count != 0 {
			return fmt.Errorf(
				"starterapp: cannot migrate bootstrap administrator: email %q or username %q is already in use",
				replacementEmail,
				replacementName,
			)
		}

		if hasher.Verify(legacyBootstrapUserPassword, legacyPassHash) == nil {
			legacyPasswordWasDefault = true
			replacementPassHash, err = hasher.Hash(adminPassword)
			if err != nil {
				return fmt.Errorf("starterapp: hash replacement bootstrap password: %w", err)
			}
		}
	}

	now := time.Now().UTC()
	updates := []struct {
		name  string
		query string
		args  []any
	}{
		{
			name: "sessions",
			query: `UPDATE auth_sessions
				SET tenant_id = ?,
				    user_id = CASE WHEN user_id = ? THEN ? ELSE user_id END
				WHERE tenant_id = ?`,
			args: []any{seed.TenantID, legacyBootstrapUserID, seed.UserID, legacyBootstrapTenantID},
		},
		{
			name: "API keys",
			query: `UPDATE api_keys
				SET tenant_id = ?,
				    user_id = CASE WHEN user_id = ? THEN ? ELSE user_id END
				WHERE tenant_id = ?`,
			args: []any{seed.TenantID, legacyBootstrapUserID, seed.UserID, legacyBootstrapTenantID},
		},
		{
			name: "audit events",
			query: `UPDATE audit_events
				SET tenant_id = ?,
				    actor = CASE WHEN actor = ? THEN ? ELSE actor END
				WHERE tenant_id = ?`,
			args: []any{seed.TenantID, legacyBootstrapUserID, seed.UserID, legacyBootstrapTenantID},
		},
		{
			name: "content",
			query: `UPDATE content
				SET tenant_id = ?,
				    author_id = CASE WHEN author_id = ? THEN ? ELSE author_id END
				WHERE tenant_id = ?`,
			args: []any{seed.TenantID, legacyBootstrapUserID, seed.UserID, legacyBootstrapTenantID},
		},
		{
			name: "notifications",
			query: `UPDATE notifications
				SET tenant_id = ?,
				    user_id = CASE WHEN user_id = ? THEN ? ELSE user_id END
				WHERE tenant_id = ?`,
			args: []any{seed.TenantID, legacyBootstrapUserID, seed.UserID, legacyBootstrapTenantID},
		},
		{
			name: "notification subscriptions",
			query: `UPDATE notification_subscriptions
				SET tenant_id = ?,
				    user_id = CASE WHEN user_id = ? THEN ? ELSE user_id END
				WHERE tenant_id = ?`,
			args: []any{seed.TenantID, legacyBootstrapUserID, seed.UserID, legacyBootstrapTenantID},
		},
		{
			name: "users",
			query: `UPDATE users
				SET tenant_id = ?,
				    id = CASE WHEN id = ? THEN ? ELSE id END,
				    email = CASE WHEN id = ? THEN ? ELSE email END,
				    username = CASE WHEN id = ? THEN ? ELSE username END,
				    display_name = CASE WHEN id = ? THEN ? ELSE display_name END,
				    pass_hash = CASE WHEN id = ? THEN ? ELSE pass_hash END
				WHERE tenant_id = ?`,
			args: []any{
				seed.TenantID,
				legacyBootstrapUserID, seed.UserID,
				legacyBootstrapUserID, replacementEmail,
				legacyBootstrapUserID, replacementName,
				legacyBootstrapUserID, replacementDisplay,
				legacyBootstrapUserID, replacementPassHash,
				legacyBootstrapTenantID,
			},
		},
		{
			name: "tenant",
			query: `UPDATE tenants
				SET id = ?,
				    slug = CASE WHEN slug = ? THEN ? ELSE slug END,
				    name = CASE WHEN name = ? THEN ? ELSE name END
				WHERE id = ?`,
			args: []any{
				seed.TenantID,
				legacyBootstrapTenantSlug, seed.TenantSlug,
				legacyBootstrapTenantName, seed.TenantName,
				legacyBootstrapTenantID,
			},
		},
	}
	if legacyPasswordWasDefault {
		updates = append(updates, struct {
			name  string
			query string
			args  []any
		}{
			name: "sessions issued under the historical default password",
			query: `UPDATE auth_sessions
				SET revoked_at = ?
				WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL`,
			args: []any{now, seed.TenantID, seed.UserID},
		})
	}
	for _, update := range updates {
		if _, err := tx.ExecContext(ctx, update.query, update.args...); err != nil {
			return fmt.Errorf("starterapp: migrate bootstrap %s: %w", update.name, err)
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
