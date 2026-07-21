// Package starterapp is the importable single source of truth for the
// PlatformKit OSS "git clone and go run ." starter monolith. It composes all
// nine OSS PlatformKit modules (tenant, user, audit, health, auth, api_key,
// content, notification, admin) against a single SQLite database and exposes
// them through one http.Handler.
//
// This package exists so the application's construction graph has exactly ONE
// home. Both pk-apps's own `apps/starter-saas` binary and the public front-door
// repo (github.com/septagon-oss/platformkit) are thin ~10-line main() wrappers
// over BuildApp + App.Mux + App.Serve here. There is no logic duplication
// between the two runnable entry points: change the graph once, here, and every
// wrapper inherits it.
//
// app.go owns the application assembly graph. BuildApp opens ONE shared *sql.DB
// over the configured SQLite file, then constructs the admin shell and every
// business module against that single connection pool, the audit emitter
// forwarded into security-sensitive modules, the seed routine that populates
// the demo tenant + admin user, the pk-core module catalog that proves the
// composition is valid, and the pk-runtime host that surfaces /live and /ready.
//
// Why one shared *sql.DB: SQLite is a single-writer embedded engine. Giving
// each module its own handle would fan out into N independent database/sql
// pools over one file, which invites SQLITE_BUSY contention and makes startup
// schema visibility depend on driver-specific shared-cache quirks. Opening one
// *sql.DB with SetMaxOpenConns(1) serializes all access through a single
// connection, so the schema each module's store creates at construction is
// unconditionally visible to every later query — the first-run-on-a-fresh-db
// guarantee the starter promises.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0017 (composition
// through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
import (
	"context"
	"database/sql"
	"expvar"
	"fmt"
	"net/http"

	pkmodule "github.com/septagon-oss/pk-core/pkg/module"
	"github.com/septagon-oss/pk-core/pkg/security/cookies"
	"github.com/septagon-oss/pk-core/pkg/security/identity"

	"github.com/septagon-oss/pk-modules/pkg/admin"
	"github.com/septagon-oss/pk-modules/pkg/apikey"
	apikeysqlite "github.com/septagon-oss/pk-modules/pkg/apikey/store/sqlite"
	"github.com/septagon-oss/pk-modules/pkg/audit"
	auditsqlite "github.com/septagon-oss/pk-modules/pkg/audit/store/sqlite"
	"github.com/septagon-oss/pk-modules/pkg/auth"
	"github.com/septagon-oss/pk-modules/pkg/content"
	contentsqlite "github.com/septagon-oss/pk-modules/pkg/content/store/sqlite"
	healthmod "github.com/septagon-oss/pk-modules/pkg/health"
	"github.com/septagon-oss/pk-modules/pkg/notification"
	notificationsqlite "github.com/septagon-oss/pk-modules/pkg/notification/store/sqlite"
	"github.com/septagon-oss/pk-modules/pkg/tenant"
	tenantsqlite "github.com/septagon-oss/pk-modules/pkg/tenant/store/sqlite"
	"github.com/septagon-oss/pk-modules/pkg/user"
	usersqlite "github.com/septagon-oss/pk-modules/pkg/user/store/sqlite"

	"github.com/septagon-oss/pk-runtime/pkg/host"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// BundleName is the catalog bundle ID for the starter monolith. Exported so
// catalog assertions in tests and front-door wrappers remain stable.
const BundleName = "platformkit.starter-saas"

// App holds every constructed module plus the composed catalog so callers
// (binaries and tests) can introspect the runtime without re-running boot.
//
// Fields stay unexported to keep the construction graph encapsulated; the
// accessors below expose exactly what wrappers and tests legitimately need
// (HTTP handler, lifecycle, banner data, catalog and store introspection).
type App struct {
	admin        *admin.Module
	tenant       *tenant.Module
	user         *user.Module
	auditMod     *audit.Module
	health       *healthmod.Module
	authMod      *auth.Module
	apiKey       *apikey.Module
	contentMod   *content.Module
	notification *notification.Module

	catalog *pkmodule.Catalog
	host    *host.Host

	// db is the single shared SQLite connection pool every data module's store
	// is built on. App owns its lifecycle and closes it in Close().
	db *sql.DB

	modules       []string
	adminBasePath string
	seedEmail     string
	seedPassword  string
}

// BuildApp constructs every module against the shared SQLite DSN and runs the
// first-boot seed. It is the single source of truth for the application's
// dependency graph and is used by every runnable wrapper and by tests.
func BuildApp(ctx context.Context, cfg *Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("starterapp: nil config")
	}
	dsn := cfg.Database.DSN
	if dsn == "" {
		return nil, fmt.Errorf("starterapp: database.dsn is required")
	}
	driver := cfg.Database.Driver
	if driver == "" {
		driver = "sqlite"
	}

	// 0. Open ONE shared SQLite connection pool. Every data module's store is
	//    built from this same *sql.DB so the schema each store creates at
	//    construction is visible to all later queries and writes serialize
	//    through a single connection (SQLite is single-writer). SetMaxOpenConns(1)
	//    eliminates SQLITE_BUSY and cross-pool table-visibility surprises on a
	//    fresh database. App owns this handle and closes it in Close().
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("starterapp: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("starterapp: ping sqlite: %w", err)
	}

	// Build each module's store on the shared handle. New() runs that store's
	// CREATE TABLE IF NOT EXISTS, so by the time the modules are constructed
	// every table already exists on the one connection they all share. If any
	// store fails we close the shared handle before returning so we never leak
	// the pool.
	tenantStore, err := tenantsqlite.New(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tenant store: %w", err)
	}
	userStore, err := usersqlite.New(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("user store: %w", err)
	}
	auditStore, err := auditsqlite.New(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit store: %w", err)
	}
	apiKeyStore, err := apikeysqlite.New(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("api_key store: %w", err)
	}
	contentStore, err := contentsqlite.New(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("content store: %w", err)
	}
	notificationStore, err := notificationsqlite.New(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("notification store: %w", err)
	}

	// closeOnErr closes the shared DB if module construction below fails, so a
	// partial boot does not leak the pool. Cleared once the App takes ownership.
	closeOnErr := func() { _ = db.Close() }
	defer func() {
		if closeOnErr != nil {
			closeOnErr()
		}
	}()

	// 1. Admin shell first — every other module wires AdminRegistrar into it.
	adminMod, err := admin.NewModule(
		admin.WithTitle(cfg.AppName+" Admin"),
		admin.WithBasePath("/admin"),
	)
	if err != nil {
		return nil, fmt.Errorf("admin module: %w", err)
	}
	adminReg := adminMod.Registrar()

	// 2. Health module — has no I/O at construction; supplies a HealthRegistrar
	//    that downstream modules call into via WithHealthRegistrar.
	healthMod, err := healthmod.NewModule(
		healthmod.WithAdminRegistrar(adminReg),
	)
	if err != nil {
		return nil, fmt.Errorf("create health module: %w", err)
	}
	healthReg := healthMod.Registrar()

	// 3. Tenant first among data modules — user_management and content can both
	//    consume tenant.TenantService.
	tenantMod, err := tenant.NewModule(
		tenant.WithStore(tenantStore),
		tenant.WithAdminRegistrar(adminReg),
		tenant.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("tenant module: %w", err)
	}

	// 4. User_management — depends on tenant for validation hooks (optional).
	userMod, err := user.NewModule(
		user.WithStore(userStore),
		user.WithTenantService(tenantMod.Service()),
		user.WithAdminRegistrar(adminReg),
		user.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("user module: %w", err)
	}

	// 5. Audit_management — the AuditEmitter it returns is consumed by auth,
	//    apikey, content, and notification below.
	auditMod, err := audit.NewModule(
		audit.WithStore(auditStore),
		audit.WithAdminRegistrar(adminReg),
		audit.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("audit module: %w", err)
	}
	// The system-level audit emitter is bound to the seed tenant and a
	// synthetic actor so cross-cutting events have stable provenance.
	auditEmitter := audit.EmitterFor(auditMod.Service(), seed.TenantID, "system", "info")

	// 6. Auth_management — requires user_management's UserBoundaryReader.
	authMod, err := auth.NewModule(
		auth.WithSQLiteDB(db),
		auth.WithUserReader(userMod.Service()),
		auth.WithLoginPolicy(newLoginAttemptPolicy()),
		auth.WithAuditEmitter(auditEmitter),
		auth.WithAdminRegistrar(adminReg),
		auth.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("auth module: %w", err)
	}

	// 7. API_key_management — optional audit emitter.
	apiKeyMod, err := apikey.NewModule(
		apikey.WithStore(apiKeyStore),
		apikey.WithAuditEmitter(auditEmitter),
		apikey.WithAdminRegistrar(adminReg),
		apikey.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("api_key module: %w", err)
	}

	// 8. Content_management — optional tenant + audit dependencies.
	contentMod, err := content.NewModule(
		content.WithStore(contentStore),
		content.WithTenantService(tenantMod.Service()),
		content.WithAuditEmitter(auditEmitter),
		content.WithAdminRegistrar(adminReg),
		content.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("content module: %w", err)
	}

	// 9. Notification_management — optional user reader + audit.
	notificationMod, err := notification.NewModule(
		notification.WithStore(notificationStore),
		notification.WithUserReader(userMod.Service()),
		notification.WithAuditEmitter(auditEmitter),
		notification.WithAdminRegistrar(adminReg),
		notification.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("notification module: %w", err)
	}

	// Outside development, force Secure on all cookies. A production deployment
	// typically sits behind a TLS-terminating proxy that may not forward the
	// scheme, in which case the session cookie would otherwise ship without
	// Secure and be transmittable in cleartext. Development stays scheme-derived
	// so the local http demo works.
	if cfg.Environment != "development" {
		cookies.Configure(cookies.Settings{ForceSecure: true})
	}

	// Seed the demo tenant + admin user. Safe to call on every boot.
	seedParams, err := resolveSeedParams(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := seed.Run(ctx, tenantMod.Service(), userMod.Service(), seedParams); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}

	// Compose the catalog. Order in defaults matters only for human-friendly
	// listings; pk-core's compose pass topologically sorts on declared deps.
	modules := []string{
		admin.ModuleID,
		healthmod.ModuleID,
		tenant.ModuleID,
		user.ModuleID,
		audit.ModuleID,
		auth.ModuleID,
		apikey.ModuleID,
		content.ModuleID,
		notification.ModuleID,
	}
	bundle := pkmodule.NewBundle(
		BundleName,
		[]pkmodule.Entry{
			{ID: admin.ModuleID, New: adminMod.Compose},
			{ID: healthmod.ModuleID, New: healthMod.Compose},
			{ID: tenant.ModuleID, New: tenantMod.Compose},
			{ID: user.ModuleID, New: userMod.Compose},
			{ID: audit.ModuleID, New: auditMod.Compose},
			{ID: auth.ModuleID, New: authMod.Compose},
			{ID: apikey.ModuleID, New: apiKeyMod.Compose},
			{ID: content.ModuleID, New: contentMod.Compose},
			{ID: notification.ModuleID, New: notificationMod.Compose},
		},
		modules,
	)
	catalog, err := pkmodule.NewCatalog().Add(bundle).Build()
	if err != nil {
		return nil, fmt.Errorf("catalog build: %w", err)
	}

	// Build the runtime host so /live and /ready are wired against the same
	// composed plan we just constructed.
	runtimeHost, err := host.New(ctx, host.Input{
		Config: host.Config{
			Name:        cfg.AppName,
			Version:     cfg.AppVersion,
			Environment: cfg.Environment,
		},
		Catalog: catalog,
	})
	if err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}

	// Construction succeeded — the App now owns the shared *sql.DB, so disarm
	// the defer that would otherwise close it on the error path.
	closeOnErr = nil

	app := &App{
		admin:         adminMod,
		tenant:        tenantMod,
		user:          userMod,
		auditMod:      auditMod,
		health:        healthMod,
		authMod:       authMod,
		apiKey:        apiKeyMod,
		contentMod:    contentMod,
		notification:  notificationMod,
		catalog:       catalog,
		host:          runtimeHost,
		db:            db,
		modules:       modules,
		adminBasePath: adminMod.BasePath(),
	}
	app.seedEmail, app.seedPassword = seedBannerCredential(cfg, seedParams)
	return app, nil
}

// Close releases application-owned resources. The shared SQLite *sql.DB is
// owned by the App (not by the individual module stores, which all wrap this
// one handle), so Close is where the connection pool is released.
func (a *App) Close() error {
	if a == nil || a.db == nil {
		return nil
	}
	return a.db.Close()
}

// Mux assembles the public HTTP routing surface and returns the http.Handler
// to serve. Every wrapper and test uses this same routine so the routes under
// test exactly match the binary.
func (a *App) Mux() (http.Handler, error) {
	if a == nil {
		return nil, fmt.Errorf("starterapp: nil app")
	}
	mux := http.NewServeMux()

	// Browser login/logout for the admin shell. Registered before (and
	// outside) the guarded admin handler so an anonymous visitor can reach the
	// login form.
	a.registerAdminAuth(mux)

	// Admin shell at /admin (and /admin/...), behind guardAdmin so an
	// unauthenticated visitor is redirected to the login page instead of
	// seeing the dashboard. The handler owns its own matcher so we register
	// both the bare prefix and the trailing-slash form.
	guardedAdmin := guardAdmin(a.admin.HTTPHandler())
	mux.Handle(a.adminBasePath, guardedAdmin)
	mux.Handle(a.adminBasePath+"/", guardedAdmin)

	// Module CRUD APIs. Each module exposes RegisterRoutes(mux) which
	// publishes its canonical /api/v1/<entity> paths.
	a.tenant.HTTPHandler().RegisterRoutes(mux)
	a.user.HTTPHandler().RegisterRoutes(mux)
	a.auditMod.HTTPHandler().RegisterRoutes(mux)
	a.authMod.HTTPHandler().RegisterRoutes(mux)
	a.apiKey.HTTPHandler().RegisterRoutes(mux)
	a.contentMod.HTTPHandler().RegisterRoutes(mux)
	a.notification.HTTPHandler().RegisterRoutes(mux)

	// Health endpoint at /healthz (the module's APIPath constant).
	a.health.HTTPHandler().RegisterRoutes(mux)

	// /metrics — the standard library expvar registry, behind authentication.
	// expvar exposes cmdline and memstats, so an unauthenticated scrape is an
	// information disclosure; a scraper authenticates with an API key like any
	// other client. (/healthz, /live, /ready stay open for liveness probing.)
	mux.Handle("/metrics", requireAuthenticated(expvar.Handler()))

	// /live and /ready are owned by pk-runtime/host. Forward only those two
	// paths to the host so the rest of our mux stays in control.
	hostHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.host.ServeHTTP(w, r)
	})
	mux.Handle("/live", hostHandler)
	mux.Handle("/ready", hostHandler)

	// Root banner — useful for `curl localhost:8080/` smoke checks.
	mux.HandleFunc("/", a.indexHandler)

	// Wrap the whole surface: the identity middleware resolves an API-key or
	// session credential into a Principal on every request (anonymous when
	// none is presented), then the mutation gate blocks anonymous writes to
	// /api/v1 as defense in depth. Per-handler tenant scoping reads the
	// Principal the middleware attaches.
	resolver := identity.Chain(
		newAPIKeyResolver(a.apiKey.Service()),
		newSessionResolver(a.authMod.Service()),
	)
	// limitRequestBody is the OUTERMOST wrapper so it caps EVERY request body —
	// including the pre-auth login POST — before any handler reads it. Without
	// it, json.Decode buffers an unbounded body (an anonymous multi-GB login
	// body is a memory-exhaustion DoS).
	handler := limitRequestBody(maxRequestBodyBytes,
		identity.Middleware(resolver)(requireAuthenticatedMutations(mux)))
	return handler, nil
}

// indexHandler renders a minimal HTML index that points operators at the admin
// UI and lists the composed modules. Anything that is not the root path falls
// through to a 404 so we do not shadow module APIs.
func (a *App) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><head><title>starter-saas</title></head><body>
<h1>starter-saas</h1>
<p>PlatformKit OSS monolith composing %d modules.</p>
<ul>
  <li><a href="%s">Admin UI</a></li>
  <li><a href="/healthz">Health</a></li>
  <li><a href="/metrics">Metrics</a></li>
</ul>
<p>Default login: <code>%s</code> / <code>%s</code></p>
</body></html>`,
		len(a.modules), a.adminBasePath, a.seedEmail, a.seedPassword)
}

// ModuleIDs returns the human-ordered list of composed module IDs. Wrappers use
// it for their startup banner; tests use it to assert the composed surface.
func (a *App) ModuleIDs() []string { return a.modules }

// AdminBasePath is the mount path of the admin shell (e.g. "/admin").
func (a *App) AdminBasePath() string { return a.adminBasePath }

// SeedEmail and SeedPassword are the advertised first-boot credentials, exposed
// so a wrapper's banner prints the exact login the seed created.
func (a *App) SeedEmail() string    { return a.seedEmail }
func (a *App) SeedPassword() string { return a.seedPassword }

// Catalog exposes the composed pk-core catalog for introspection in tests and
// wrappers (e.g. listing module IDs). It is read-only by contract.
func (a *App) Catalog() *pkmodule.Catalog { return a.catalog }
