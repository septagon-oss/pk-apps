// Implements: REQ-016.
// Per: ADR-0009, ADR-0017, ADR-0029.
// Discipline: C-14.

package starterapp

// stores.go owns the one decision that makes PlatformKit deployable beyond a
// single machine: which persistence adapter each module gets. Every module
// takes a store.Store interface, so the driver is a composition-time choice
// and no module knows which engine backs it.
//
//   - sqlite (default) — the embedded profile. One process, one file, zero
//     setup: the right answer for local development and small single-node
//     deployments.
//   - postgres — the production profile. A real connection pool, concurrent
//     writers, and the operational tooling (backup, replication, PITR) that a
//     business keeps customer data on.
//
// Both adapter sets pass the SAME store conformance suite in pk-modules
// (tenant-scoped list, tenant immutability on update, retired rows hidden), so
// switching engines cannot silently weaken tenant isolation — the guarantee is
// held by an executable check on both sides rather than by review.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0017 (composition
// through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	apikeystore "github.com/septagon-oss/pk-modules/pkg/apikey/store"
	apikeypostgres "github.com/septagon-oss/pk-modules/pkg/apikey/store/postgres"
	apikeysqlite "github.com/septagon-oss/pk-modules/pkg/apikey/store/sqlite"
	auditstore "github.com/septagon-oss/pk-modules/pkg/audit/store"
	auditpostgres "github.com/septagon-oss/pk-modules/pkg/audit/store/postgres"
	auditsqlite "github.com/septagon-oss/pk-modules/pkg/audit/store/sqlite"
	authstore "github.com/septagon-oss/pk-modules/pkg/auth/store"
	authpostgres "github.com/septagon-oss/pk-modules/pkg/auth/store/postgres"
	authsqlite "github.com/septagon-oss/pk-modules/pkg/auth/store/sqlite"
	contentstore "github.com/septagon-oss/pk-modules/pkg/content/store"
	contentpostgres "github.com/septagon-oss/pk-modules/pkg/content/store/postgres"
	contentsqlite "github.com/septagon-oss/pk-modules/pkg/content/store/sqlite"
	notificationstore "github.com/septagon-oss/pk-modules/pkg/notification/store"
	notificationpostgres "github.com/septagon-oss/pk-modules/pkg/notification/store/postgres"
	notificationsqlite "github.com/septagon-oss/pk-modules/pkg/notification/store/sqlite"
	tenantstore "github.com/septagon-oss/pk-modules/pkg/tenant/store"
	tenantpostgres "github.com/septagon-oss/pk-modules/pkg/tenant/store/postgres"
	tenantsqlite "github.com/septagon-oss/pk-modules/pkg/tenant/store/sqlite"
	userstore "github.com/septagon-oss/pk-modules/pkg/user/store"
	userpostgres "github.com/septagon-oss/pk-modules/pkg/user/store/postgres"
	usersqlite "github.com/septagon-oss/pk-modules/pkg/user/store/sqlite"
)

// Supported database drivers. The value is matched case-insensitively against
// cfg.Database.Driver, which is also the name passed to sql.Open — so the host
// application must have registered a driver under exactly that name (e.g.
// `_ "modernc.org/sqlite"` or `_ "github.com/jackc/pgx/v5/stdlib"`).
const (
	driverSQLite   = "sqlite"
	driverPostgres = "postgres"
	// pgx is the driver name registered by github.com/jackc/pgx/v5/stdlib. It
	// selects the same Postgres adapters; the distinction is only which driver
	// name sql.Open receives.
	driverPGX = "pgx"
)

// Connection-pool defaults for the Postgres profile. They are deliberately
// modest: a starter monolith behind a typical Postgres (default
// max_connections = 100) may run several replicas, so a small per-process pool
// leaves headroom rather than exhausting the server from one instance. The
// lifetime cap keeps connections rotating through proxies and failovers that
// silently drop long-lived sockets.
const (
	defaultPostgresMaxOpenConns    = 20
	defaultPostgresMaxIdleConns    = 5
	defaultPostgresConnMaxLifetime = 30 * time.Minute
)

// moduleStores is the set of persistence adapters the data modules consume.
// Every field is an interface, so the concrete engine stops mattering above
// this line.
type moduleStores struct {
	tenant       tenantstore.Store
	authSession  authstore.Store
	user         userstore.Store
	audit        auditstore.Store
	apiKey       apikeystore.Store
	content      contentstore.Store
	notification notificationstore.Store
}

// isPostgres reports whether the configured driver selects the Postgres
// adapters. Both the "postgres" alias and pgx's registered "pgx" name qualify.
func isPostgres(driver string) bool {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case driverPostgres, driverPGX:
		return true
	default:
		return false
	}
}

// resolveSQLDriver maps the configured driver name onto a driver actually
// registered with database/sql. Operators write `driver: postgres` because
// that is the engine's name, but the registered name depends on which package
// the host application imported — pgx registers "pgx", lib/pq registers
// "postgres". Rather than make the config depend on that build-time detail,
// resolve to whichever equivalent name is present. An exact match always wins;
// this only ever substitutes an alias for the SAME engine.
func resolveSQLDriver(driver string) string {
	name := strings.ToLower(strings.TrimSpace(driver))
	registered := sql.Drivers()
	has := func(want string) bool {
		for _, d := range registered {
			if d == want {
				return true
			}
		}
		return false
	}
	if has(name) {
		return name
	}
	if isPostgres(name) {
		// Try the other spelling of the same engine.
		for _, alias := range []string{driverPGX, driverPostgres} {
			if has(alias) {
				return alias
			}
		}
	}
	// No equivalent registered: return the configured name so sql.Open produces
	// its own "unknown driver" error naming exactly what the operator asked for.
	return name
}

// openModuleStores builds every module's store on the shared handle using the
// adapter set the driver selects. Each constructor runs its own
// CREATE TABLE IF NOT EXISTS, so by the time the modules are built every table
// exists. A failure returns the first error with the module named, and the
// caller owns closing the handle.
func openModuleStores(db *sql.DB, driver string) (moduleStores, error) {
	var (
		s   moduleStores
		err error
	)
	if isPostgres(driver) {
		if s.tenant, err = tenantpostgres.New(db); err != nil {
			return s, fmt.Errorf("tenant store: %w", err)
		}
		if s.user, err = userpostgres.New(db); err != nil {
			return s, fmt.Errorf("user store: %w", err)
		}
		if s.audit, err = auditpostgres.New(db); err != nil {
			return s, fmt.Errorf("audit store: %w", err)
		}
		if s.apiKey, err = apikeypostgres.New(db); err != nil {
			return s, fmt.Errorf("api_key store: %w", err)
		}
		if s.content, err = contentpostgres.New(db); err != nil {
			return s, fmt.Errorf("content store: %w", err)
		}
		if s.notification, err = notificationpostgres.New(db); err != nil {
			return s, fmt.Errorf("notification store: %w", err)
		}
		if s.authSession, err = authpostgres.New(db); err != nil {
			return s, fmt.Errorf("auth session store: %w", err)
		}
		return s, nil
	}

	if s.tenant, err = tenantsqlite.New(db); err != nil {
		return s, fmt.Errorf("tenant store: %w", err)
	}
	if s.user, err = usersqlite.New(db); err != nil {
		return s, fmt.Errorf("user store: %w", err)
	}
	if s.audit, err = auditsqlite.New(db); err != nil {
		return s, fmt.Errorf("audit store: %w", err)
	}
	if s.apiKey, err = apikeysqlite.New(db); err != nil {
		return s, fmt.Errorf("api_key store: %w", err)
	}
	if s.content, err = contentsqlite.New(db); err != nil {
		return s, fmt.Errorf("content store: %w", err)
	}
	if s.notification, err = notificationsqlite.New(db); err != nil {
		return s, fmt.Errorf("notification store: %w", err)
	}
	if s.authSession, err = authsqlite.New(db); err != nil {
		return s, fmt.Errorf("auth session store: %w", err)
	}
	return s, nil
}
