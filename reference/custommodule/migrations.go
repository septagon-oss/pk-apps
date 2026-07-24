// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package main

// migrations.go is the reference module's append-only migration runner. Each
// embedded SQL file is applied once in lexical order and recorded in the same
// shared database as the starter.

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var widgetMigrationFiles embed.FS

func applyWidgetMigrations(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS widget_schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("widget migrations ledger: %w", err)
	}
	entries, err := fs.ReadDir(widgetMigrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("widget migrations list: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		var applied int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM widget_schema_migrations WHERE name = ?`,
			entry.Name(),
		).Scan(&applied); err != nil {
			return fmt.Errorf("widget migration %s lookup: %w", entry.Name(), err)
		}
		if applied != 0 {
			continue
		}
		statement, err := widgetMigrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("widget migration %s read: %w", entry.Name(), err)
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("widget migration %s begin: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(string(statement)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("widget migration %s apply: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(
			`INSERT INTO widget_schema_migrations (name, applied_at) VALUES (?, ?)`,
			entry.Name(),
			time.Now().UTC(),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("widget migration %s record: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("widget migration %s commit: %w", entry.Name(), err)
		}
	}
	return nil
}
