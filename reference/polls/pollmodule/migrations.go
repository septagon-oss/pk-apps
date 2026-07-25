// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type schemaMigration struct {
	version int
	name    string
	sql     string
}

func migratePollSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("poll: enable foreign keys: %w", err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS poll_schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("poll: create migration ledger: %w", err)
	}

	migrations, err := readMigrations()
	if err != nil {
		return err
	}
	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return err
	}
	if err := rejectNewerSchema(applied, migrations); err != nil {
		return err
	}
	if err := adoptLegacySchema(ctx, db, applied); err != nil {
		return err
	}

	for _, migration := range migrations {
		if applied[migration.version] {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("poll: begin migration %s: %w", migration.name, err)
		}
		if _, err := tx.ExecContext(ctx, migration.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("poll: apply migration %s: %w", migration.name, err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO poll_schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
			migration.version,
			migration.name,
			time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("poll: record migration %s: %w", migration.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("poll: commit migration %s: %w", migration.name, err)
		}
		applied[migration.version] = true
	}
	return nil
}

func readMigrations() ([]schemaMigration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("poll: read embedded migrations: %w", err)
	}
	migrations := make([]schemaMigration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("poll: invalid migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("poll: invalid migration version in %q", entry.Name())
		}
		body, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("poll: read migration %q: %w", entry.Name(), err)
		}
		migrations = append(migrations, schemaMigration{
			version: version,
			name:    entry.Name(),
			sql:     string(body),
		})
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].version == migrations[i].version {
			return nil, fmt.Errorf("poll: duplicate migration version %d", migrations[i].version)
		}
	}
	return migrations, nil
}

func appliedMigrations(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM poll_schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("poll: read migration ledger: %w", err)
	}
	defer rows.Close()
	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("poll: scan migration ledger: %w", err)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("poll: iterate migration ledger: %w", err)
	}
	return applied, nil
}

func rejectNewerSchema(applied map[int]bool, migrations []schemaMigration) error {
	maxKnown := 0
	if len(migrations) > 0 {
		maxKnown = migrations[len(migrations)-1].version
	}
	for version := range applied {
		if version > maxKnown {
			return fmt.Errorf(
				"poll: database schema version %d is newer than this binary supports (%d)",
				version,
				maxKnown,
			)
		}
	}
	return nil
}

// adoptLegacySchema handles the one historical durable state produced before
// the example gained a migration ledger. It validates the known v1 shape,
// rejects ambiguous duplicate public slugs with an actionable error, and
// records v1 so the append-only v2 migration can upgrade it.
func adoptLegacySchema(ctx context.Context, db *sql.DB, applied map[int]bool) error {
	if applied[1] {
		return nil
	}
	exists, err := tableExists(ctx, db, "poll_polls")
	if err != nil || !exists {
		return err
	}
	required := []string{"id", "tenant_id", "slug", "title", "options", "author_id", "created_at"}
	columns, err := pollTableColumns(ctx, db)
	if err != nil {
		return err
	}
	for _, column := range required {
		if !columns[column] {
			return fmt.Errorf(
				"poll: legacy poll_polls table is missing required column %q; restore a v0.1 schema before upgrading",
				column,
			)
		}
	}
	var duplicateSlug string
	var duplicateCount int
	err = db.QueryRowContext(ctx, `
		SELECT slug, COUNT(*)
		  FROM poll_polls
		 GROUP BY slug
		HAVING COUNT(*) > 1
		 ORDER BY COUNT(*) DESC, slug
		 LIMIT 1
	`).Scan(&duplicateSlug, &duplicateCount)
	switch {
	case err == nil:
		return fmt.Errorf(
			"poll: migration blocked: public slug %q appears %d times; rename duplicate slugs before restarting",
			duplicateSlug,
			duplicateCount,
		)
	case errors.Is(err, sql.ErrNoRows):
	default:
		return fmt.Errorf("poll: inspect legacy public slugs: %w", err)
	}
	v1, err := migrationFiles.ReadFile("migrations/0001_initial.up.sql")
	if err != nil {
		return fmt.Errorf("poll: read v1 migration for legacy adoption: %w", err)
	}
	if _, err := db.ExecContext(ctx, string(v1)); err != nil {
		return fmt.Errorf("poll: normalize adopted v1 schema: %w", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO poll_schema_migrations (version, name, applied_at) VALUES (1, ?, ?)`,
		"0001_initial.up.sql (adopted)",
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("poll: record adopted v1 schema: %w", err)
	}
	applied[1] = true
	return nil
}

func tableExists(ctx context.Context, db *sql.DB, table string) (bool, error) {
	var name string
	err := db.QueryRowContext(
		ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`,
		table,
	).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("poll: inspect table %q: %w", table, err)
	}
	return true, nil
}

func pollTableColumns(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(poll_polls)`)
	if err != nil {
		return nil, fmt.Errorf("poll: inspect columns for poll_polls: %w", err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var (
			cid        int
			name       string
			dataType   string
			notNull    int
			defaultV   any
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultV, &primaryKey); err != nil {
			return nil, fmt.Errorf("poll: scan columns for poll_polls: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("poll: iterate columns for poll_polls: %w", err)
	}
	return columns, nil
}
