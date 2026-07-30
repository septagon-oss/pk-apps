// Implements: REQ-016.
// Per: ADR-0017, ADR-0029.
// Discipline: C-14.

package starterapp

// dialect.go carries the SQL differences the composition layer itself has to
// know about. The module stores do not need this — each ships an adapter per
// engine — but the starter runs a little SQL of its own during boot (the
// bootstrap-identity ledger), and that SQL has to work on both engines.
//
// Every statement is written out per engine, deliberately. An earlier version
// kept one SQLite spelling and rewrote it for Postgres at runtime —
// renumbering `?` to `$N`, swapping type names, converting INSERT OR IGNORE to
// ON CONFLICT. That is string surgery on a language with string literals and
// comments in it, and it was wrong in three ways a probe found immediately:
//
//   - a `?` inside a comment consumed a placeholder number, so the real
//     placeholders numbered past the argument count;
//   - a blanket type-name replacement corrupted any identifier that merely
//     contained the word (`last_datetime` became `last_TIMESTAMPTZ`);
//   - appending ON CONFLICT DO NOTHING to a statement ending in a comment put
//     the clause inside the comment, silently dropping the insert-if-absent
//     semantics — a semantic change with no error.
//
// None of those could fire on the five statements below, but they were
// landmines for whoever added the sixth. Two explicit spellings of five short
// statements cost less than a rewriter that has to be correct about SQL
// lexing, and it matches how the rest of the project handles engines: an
// adapter per engine, never a translation at runtime.

import (
	"context"
	"database/sql"
)

// bootstrapStatements is the boot-path SQL for one engine. The ledger table
// name is interpolated by the constructors below, never by a caller.
type bootstrapStatements struct {
	// selectLedger reads the recorded identity ('active' row).
	selectLedger string
	// createLedger creates the ledger table if absent.
	createLedger string
	// insertLedger records the identity, ignoring an existing row.
	insertLedger string
	// countTenant counts tenants with a given id (1 argument).
	countTenant string
	// userTenant reads the tenant owning a given user id (1 argument).
	userTenant string
	// tableExists counts tables with a given name (1 argument), asking
	// whichever catalog the engine keeps.
	tableExists string
}

func sqliteStatements() bootstrapStatements {
	return bootstrapStatements{
		selectLedger: `SELECT tenant_id, user_id FROM ` + bootstrapIdentityTable + ` WHERE id = 'active'`,
		createLedger: `CREATE TABLE IF NOT EXISTS ` + bootstrapIdentityTable + ` (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			user_id TEXT NOT NULL
		)`,
		insertLedger: `INSERT OR IGNORE INTO ` + bootstrapIdentityTable + ` (id, tenant_id, user_id) VALUES ('active', ?, ?)`,
		countTenant:  `SELECT COUNT(*) FROM tenants WHERE id = ?`,
		userTenant:   `SELECT tenant_id FROM users WHERE id = ?`,
		tableExists:  `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
	}
}

func postgresStatements() bootstrapStatements {
	return bootstrapStatements{
		selectLedger: `SELECT tenant_id, user_id FROM ` + bootstrapIdentityTable + ` WHERE id = 'active'`,
		createLedger: `CREATE TABLE IF NOT EXISTS ` + bootstrapIdentityTable + ` (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			user_id TEXT NOT NULL
		)`,
		insertLedger: `INSERT INTO ` + bootstrapIdentityTable + ` (id, tenant_id, user_id) VALUES ('active', $1, $2)
			ON CONFLICT DO NOTHING`,
		countTenant: `SELECT COUNT(*) FROM tenants WHERE id = $1`,
		userTenant:  `SELECT tenant_id FROM users WHERE id = $1`,
		// Scoped to the schemas on the connection's search_path, so it matches
		// what an unqualified query would actually resolve to.
		tableExists: `SELECT COUNT(*) FROM information_schema.tables
			WHERE table_name = $1 AND table_schema = ANY(current_schemas(false))`,
	}
}

// boundDB is the shared handle plus the statement set for its engine. It
// forwards to database/sql unchanged — no statement is rewritten in flight.
type boundDB struct {
	db       *sql.DB
	postgres bool
	sql      bootstrapStatements
}

// bind returns a boundDB for the configured driver.
func bind(db *sql.DB, driver string) boundDB {
	if isPostgres(driver) {
		return boundDB{db: db, postgres: true, sql: postgresStatements()}
	}
	return boundDB{db: db, sql: sqliteStatements()}
}

func (b boundDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return b.db.QueryRowContext(ctx, query, args...)
}

func (b boundDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return b.db.QueryContext(ctx, query, args...)
}

func (b boundDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return b.db.ExecContext(ctx, query, args...)
}

// BeginTx starts a transaction carrying the same statement set.
func (b boundDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (boundTx, error) {
	tx, err := b.db.BeginTx(ctx, opts)
	if err != nil {
		return boundTx{}, err
	}
	return boundTx{tx: tx, sql: b.sql}, nil
}

// boundTx is the transaction counterpart of boundDB.
type boundTx struct {
	tx  *sql.Tx
	sql bootstrapStatements
}

func (b boundTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return b.tx.QueryRowContext(ctx, query, args...)
}

func (b boundTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return b.tx.ExecContext(ctx, query, args...)
}

func (b boundTx) Commit() error   { return b.tx.Commit() }
func (b boundTx) Rollback() error { return b.tx.Rollback() }

// tableExists reports whether a table of that name exists.
func (b boundDB) tableExists(ctx context.Context, name string) (bool, error) {
	var count int
	if err := b.QueryRowContext(ctx, b.sql.tableExists, name).Scan(&count); err != nil {
		return false, err
	}
	return count != 0, nil
}
