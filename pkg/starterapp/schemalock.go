// Implements: REQ-016.
// Per: ADR-0017, ADR-0029.
// Discipline: C-14.

package starterapp

// schemalock.go serializes schema creation across processes.
//
// Every module store runs CREATE TABLE IF NOT EXISTS when it is constructed.
// That reads as idempotent, and on one process it is — but on Postgres it is
// NOT concurrency-safe: two backends creating the same table at the same
// instant race inside the system catalog and one loses with
//
//	duplicate key value violates unique constraint "pg_type_typname_nsp_index"
//
// which is a Postgres implementation detail leaking through IF NOT EXISTS.
// Measured before this existed: six replicas booting simultaneously against a
// virgin database produced one success and five failures. A rollout that starts
// several pods at once would have most of them crash-loop until one happened to
// finish first — a broken first deploy for exactly the profile that is supposed
// to be the production one.
//
// The fix is a session-scoped Postgres advisory lock held across the whole
// store-construction phase, so schema creation happens once and the other
// replicas wait rather than collide. It costs one connection for the duration of
// boot and nothing afterwards.
//
// SQLite needs no equivalent: the embedded profile is a single process over one
// file, and the shared handle is already pinned to one connection.
//
// This is the narrow, measured fix for a real failure — not a migration
// framework. Schema EVOLUTION (altering shipped tables across releases) still
// has no mechanism and is the next piece of work; this lock is the concurrency
// half, and a future migration runner takes the same lock.

import (
	"context"
	"database/sql"
	"fmt"
)

// schemaLockKey identifies the advisory lock. Postgres advisory locks live in a
// single global 64-bit namespace shared with every other user of the database,
// so the value is arbitrary but must be stable across releases and unlikely to
// collide: "pkschema" as ASCII bytes.
const schemaLockKey int64 = 0x706b_7363_68_65_6d_61

// acquireSchemaLock takes the schema lock and returns the release function.
// On any engine but Postgres it is a no-op returning a no-op release.
//
// The caller holds this for the WHOLE boot, not just around one call, because
// schema is created in three separate places: the built-in module stores, the
// bootstrap-identity ledger, and every contributed module's own constructor
// (WithModules runs arbitrary DDL this package cannot see). Locking them
// individually would leave whichever site is added next unprotected — the
// invariant worth holding is "a booting replica creates schema alone", so the
// lock spans the phase rather than the statement. Seeding lands inside it too,
// which serializes first-boot inserts as a free side effect.
//
// The lock is taken on a single pinned connection because Postgres advisory
// locks are session-scoped: acquiring on one pooled connection and releasing on
// another would leak the lock until that session ended.
func acquireSchemaLock(ctx context.Context, db *sql.DB, postgres bool) (release func(), err error) {
	if !postgres {
		return func() {}, nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("starterapp: acquire connection for schema lock: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaLockKey); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("starterapp: acquire schema lock: %w", err)
	}
	return func() {
		// Best effort: a failed unlock is not worth failing a successful boot
		// over, and returning the connection releases a session-scoped lock
		// regardless.
		_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, schemaLockKey)
		_ = conn.Close()
	}, nil
}
