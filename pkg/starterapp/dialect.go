// Implements: REQ-016.
// Per: ADR-0017, ADR-0029.
// Discipline: C-14.

package starterapp

// dialect.go carries the SQL differences the composition layer itself has to
// know about. The module stores do not need this — each ships an adapter per
// engine — but the starter runs a little SQL of its own during boot (the
// bootstrap-identity ledger), and that SQL has to work on both engines.
//
// Four differences matter:
//
//   - Placeholders. SQLite binds with `?`, Postgres with `$1..$N`. Queries in
//     this package are written the SQLite way and rebound when the engine is
//     Postgres, so there is exactly one spelling of each query in the source.
//   - Catalog introspection. "Does this table exist?" is `sqlite_master` on
//     SQLite and `information_schema.tables` on Postgres.
//   - Timestamp columns. SQLite's `DATETIME` is Postgres's `TIMESTAMPTZ`.
//   - Insert-if-absent. SQLite spells it `INSERT OR IGNORE`, Postgres
//     `INSERT ... ON CONFLICT DO NOTHING`.
//
// ADR: ADR-0017 (composition through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// boundDB wraps the shared handle with the engine's binding rules. It exposes
// the same three methods the boot path uses, so call sites read identically to
// the *sql.DB versions they replaced.
type boundDB struct {
	db       *sql.DB
	postgres bool
}

// bind returns a boundDB for the configured driver.
func bind(db *sql.DB, driver string) boundDB {
	return boundDB{db: db, postgres: isPostgres(driver)}
}

// adapt translates one statement written in the SQLite dialect into the
// engine's dialect: statement-level rewrites first, then placeholders. On
// SQLite it is the identity function, so the embedded path pays nothing.
func adapt(query string, postgres bool) string {
	if !postgres {
		return query
	}
	// `INSERT OR IGNORE INTO t (...) VALUES (...)` becomes
	// `INSERT INTO t (...) VALUES (...) ON CONFLICT DO NOTHING`. The clause goes
	// at the end, so this is a prefix swap plus a suffix.
	if idx := indexFold(query, "insert or ignore into"); idx >= 0 {
		query = query[:idx] + "INSERT INTO" + query[idx+len("insert or ignore into"):]
		query = strings.TrimRight(query, " \t\n") + " ON CONFLICT DO NOTHING"
	}
	// Column types inside CREATE TABLE. Postgres has no DATETIME.
	query = replaceFold(query, "DATETIME", "TIMESTAMPTZ")
	return rebindPlaceholders(query)
}

// indexFold is a case-insensitive strings.Index.
func indexFold(s, substr string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(substr))
}

// replaceFold replaces every case-insensitive occurrence of old with new.
func replaceFold(s, old, new string) string {
	var out strings.Builder
	for {
		i := indexFold(s, old)
		if i < 0 {
			out.WriteString(s)
			return out.String()
		}
		out.WriteString(s[:i])
		out.WriteString(new)
		s = s[i+len(old):]
	}
}

// rebind translates a statement for this connection's engine.
func (b boundDB) rebind(query string) string { return adapt(query, b.postgres) }

// rebindPlaceholders rewrites `?` placeholders as `$1..$N`. Question marks
// inside single-quoted string literals are left alone — the boot SQL contains
// literals such as `id = 'active'`.
func rebindPlaceholders(query string) string {
	if !strings.Contains(query, "?") {
		return query
	}
	var (
		out     strings.Builder
		n       int
		inQuote bool
	)
	out.Grow(len(query) + 8)
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'':
			// Doubled '' is an escaped quote inside a literal; either way the
			// toggle below tracks literal boundaries correctly.
			inQuote = !inQuote
			out.WriteByte(c)
		case c == '?' && !inQuote:
			n++
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(n))
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

func (b boundDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return b.db.QueryRowContext(ctx, b.rebind(query), args...)
}

func (b boundDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return b.db.QueryContext(ctx, b.rebind(query), args...)
}

func (b boundDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return b.db.ExecContext(ctx, b.rebind(query), args...)
}

// BeginTx starts a transaction whose statements are translated the same way.
func (b boundDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (boundTx, error) {
	tx, err := b.db.BeginTx(ctx, opts)
	if err != nil {
		return boundTx{}, err
	}
	return boundTx{tx: tx, postgres: b.postgres}, nil
}

// boundTx is the transaction counterpart of boundDB.
type boundTx struct {
	tx       *sql.Tx
	postgres bool
}

func (b boundTx) rebind(query string) string { return adapt(query, b.postgres) }

func (b boundTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return b.tx.QueryRowContext(ctx, b.rebind(query), args...)
}

func (b boundTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return b.tx.QueryContext(ctx, b.rebind(query), args...)
}

func (b boundTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return b.tx.ExecContext(ctx, b.rebind(query), args...)
}

func (b boundTx) Commit() error   { return b.tx.Commit() }
func (b boundTx) Rollback() error { return b.tx.Rollback() }

// tableExists reports whether a table of that name exists, asking whichever
// catalog the engine keeps. On Postgres the search is scoped to the schemas on
// the connection's search_path, so it matches what an unqualified query would
// actually resolve to.
func (b boundDB) tableExists(ctx context.Context, name string) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`
	if b.postgres {
		query = `SELECT COUNT(*) FROM information_schema.tables
		         WHERE table_name = ? AND table_schema = ANY(current_schemas(false))`
	}
	if err := b.QueryRowContext(ctx, query, name).Scan(&count); err != nil {
		return false, err
	}
	return count != 0, nil
}
