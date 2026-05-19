// Package main — app.go owns the application assembly graph for starter-saas.
// buildApp constructs the admin shell, every business module wired against a
// shared SQLite DSN, the audit emitter forwarded into security-sensitive
// modules, the seed routine that populates the demo tenant + admin user, the
// pk-core module catalog that proves the composition is valid, and the
// pk-runtime host that surfaces /live and /ready endpoints.
//
// The split between main.go and app.go exists so tests in main_test.go can
// exercise the same buildApp routine without performing I/O on the network or
// signal handlers.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0017 (composition
// through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package main

import (
	"context"
	"expvar"
	"fmt"
	"net/http"

	pkmodule "github.com/septagon-oss/pk-core/pkg/module"

	"github.com/septagon-oss/pk-modules/pkg/admin"
	"github.com/septagon-oss/pk-modules/pkg/apikey"
	"github.com/septagon-oss/pk-modules/pkg/audit"
	"github.com/septagon-oss/pk-modules/pkg/auth"
	"github.com/septagon-oss/pk-modules/pkg/content"
	healthmod "github.com/septagon-oss/pk-modules/pkg/health"
	"github.com/septagon-oss/pk-modules/pkg/notification"
	"github.com/septagon-oss/pk-modules/pkg/tenant"
	"github.com/septagon-oss/pk-modules/pkg/user"

	"github.com/septagon-oss/pk-runtime/pkg/host"

	"github.com/septagon-oss/pk-apps/apps/starter-saas/seed"
)

// bundleName is the catalog bundle ID for starter-saas. It is exported via
// constants only so that catalog assertions in main_test.go remain stable.
const bundleName = "platformkit.starter-saas"

// App holds every constructed module plus the composed catalog so callers
// (main and tests) can introspect the runtime without re-running boot.
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

	modules       []string
	adminBasePath string
	seedEmail     string
	seedPassword  string
}

// buildApp constructs every module against the shared SQLite DSN and runs the
// first-boot seed. It is the single source of truth for the application's
// dependency graph and is used by both main() and main_test.go.
func buildApp(ctx context.Context, cfg *Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("starter-saas: nil config")
	}
	dsn := cfg.Database.DSN
	if dsn == "" {
		return nil, fmt.Errorf("starter-saas: database.dsn is required")
	}

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
	healthMod := healthmod.NewModule(
		healthmod.WithAdminRegistrar(adminReg),
	)
	healthReg := healthMod.Registrar()

	// 3. Tenant first among data modules — user_management and content can both
	//    consume tenant.TenantService.
	tenantMod, err := tenant.NewModule(
		tenant.WithSQLiteDSN(dsn),
		tenant.WithAdminRegistrar(adminReg),
		tenant.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("tenant module: %w", err)
	}

	// 4. User_management — depends on tenant for validation hooks (optional).
	userMod, err := user.NewModule(
		user.WithSQLiteDSN(dsn),
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
		audit.WithSQLiteDSN(dsn),
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
		auth.WithSQLiteDSN(dsn),
		auth.WithUserReader(userMod.Service()),
		auth.WithAuditEmitter(auditEmitter),
		auth.WithAdminRegistrar(adminReg),
		auth.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("auth module: %w", err)
	}

	// 7. API_key_management — optional audit emitter.
	apiKeyMod, err := apikey.NewModule(
		apikey.WithSQLiteDSN(dsn),
		apikey.WithAuditEmitter(auditEmitter),
		apikey.WithAdminRegistrar(adminReg),
		apikey.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("api_key module: %w", err)
	}

	// 8. Content_management — optional tenant + audit dependencies.
	contentMod, err := content.NewModule(
		content.WithSQLiteDSN(dsn),
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
		notification.WithSQLiteDSN(dsn),
		notification.WithUserReader(userMod.Service()),
		notification.WithAuditEmitter(auditEmitter),
		notification.WithAdminRegistrar(adminReg),
		notification.WithHealthRegistrar(healthReg),
	)
	if err != nil {
		return nil, fmt.Errorf("notification module: %w", err)
	}

	// Seed the demo tenant + admin user. Safe to call on every boot.
	if err := seed.Run(ctx, tenantMod.Service(), userMod.Service()); err != nil {
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
	bundle := pkmodule.NewBundle(bundleName,
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

	return &App{
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
		modules:       modules,
		adminBasePath: adminMod.BasePath(),
		seedEmail:     seed.UserEmail,
		seedPassword:  seed.UserPass,
	}, nil
}

// Close releases any application-owned resources. Currently the SQLite
// connection is owned by each module's store and closed when the process
// exits, so Close is intentionally a no-op held for future use.
func (a *App) Close() error { return nil }

// mux assembles the public HTTP routing surface and returns the http.Handler
// to serve. Tests use this same routine so the routes under test exactly
// match the binary.
func (a *App) mux() (http.Handler, error) {
	if a == nil {
		return nil, fmt.Errorf("starter-saas: nil app")
	}
	mux := http.NewServeMux()

	// Admin shell at /admin (and /admin/...). The handler owns its own
	// matcher so we register both the bare prefix and the trailing-slash form.
	mux.Handle(a.adminBasePath, a.admin.HTTPHandler())
	mux.Handle(a.adminBasePath+"/", a.admin.HTTPHandler())

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

	// /metrics — expose the standard library expvar registry. This is the
	// canonical Go runtime metrics surface; observability vendors can scrape
	// it directly. expvar.Handler() registers its own JSON encoder.
	mux.Handle("/metrics", expvar.Handler())

	// /live and /ready are owned by pk-runtime/host. Forward only those two
	// paths to the host so the rest of our mux stays in control.
	hostHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.host.ServeHTTP(w, r)
	})
	mux.Handle("/live", hostHandler)
	mux.Handle("/ready", hostHandler)

	// Root banner — useful for `curl localhost:8080/` smoke checks.
	mux.HandleFunc("/", a.indexHandler)
	return mux, nil
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
