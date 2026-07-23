// Package starterapp — extension.go is the supported seam for adding your own
// modules to the batteries-included starter without rebuilding BuildApp.
//
// A contributed module is composed into the SAME catalog as the nine built-ins
// (so its declared dependencies and health checks are validated at compose
// time, not at runtime) and its routes are mounted on the SAME mux, behind the
// SAME identity, mutation-gate, and 1 MiB request-body-cap middleware — so a
// custom module inherits the full security perimeter for free.
//
// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
package starterapp

import (
	"database/sql"
	"net/http"

	pkmodule "github.com/septagon-oss/pk-core/pkg/module"

	"github.com/septagon-oss/pk-modules/pkg/audit"
	"github.com/septagon-oss/pk-modules/pkg/portslib"
)

// ModuleEnv hands a contributed module the resources the starter owns: the one
// shared SQLite pool (already at SetMaxOpenConns(1), so build your store on it
// rather than opening your own), and the admin/health registrars the built-in
// modules use. Admin and Health are never nil.
type ModuleEnv struct {
	DB     *sql.DB
	Admin  portslib.AdminRegistrar
	Health portslib.HealthRegistrar
	Audit  audit.AuditService
}

// OpenAPIOperation describes one HTTP operation contributed by an extension.
// The starter publishes these declarations as an OpenAPI 3.1 document at
// /openapi/extensions.json. It deliberately models the small common surface
// extensions need while allowing the module's own repository to carry richer
// request and response schemas when required.
type OpenAPIOperation struct {
	OperationID   string
	Method        string
	Path          string
	Summary       string
	Description   string
	Tags          []string
	Public        bool
	SuccessStatus int
}

// ModulePlugin is what a contributed module returns. RegisterRoutes is
// required; Compose is optional — supply it (typically yourModule.Compose,
// exactly like the built-ins) to join the DI/health composition graph, or
// leave it nil for a routes-only module that manages its own state.
type ModulePlugin struct {
	// ID is the module's stable identifier; it must not collide with a
	// built-in ("tenant", "user", "auth", "api_key", "audit", "content",
	// "notification", "admin", "health") or another contributed module.
	ID string
	// Compose, when non-nil, adds the module to the catalog so pk-core
	// validates its declared dependencies at compose time. It is the same
	// func(yourModule).Compose the built-ins register.
	Compose pkmodule.Constructor
	// RegisterRoutes mounts the module's AUTHENTICATED HTTP routes. They sit
	// behind the full perimeter: identity resolution, the anonymous-mutation
	// gate, and the request-body cap — exactly like the built-in modules.
	// Optional (a module may be public-only).
	RegisterRoutes func(mux *http.ServeMux)
	// RegisterPublicRoutes mounts routes that are reachable WITHOUT
	// authentication — public forms (a waitlist join), inbound webhooks, public
	// status pages, redirects. They still get identity resolution (so
	// RequestActor works when a credential IS presented) and the request-body
	// cap, but they bypass the anonymous-mutation gate at any path. Use this
	// only for surfaces you intend to be world-reachable. Optional.
	RegisterPublicRoutes func(mux *http.ServeMux)
	// OpenAPI declares the extension's supported HTTP operations. BuildApp
	// validates method/path/operation-ID uniqueness before accepting the
	// plugin, then exposes one aggregate OpenAPI 3.1 document for tooling.
	OpenAPI []OpenAPIOperation
}

// ExtraModule builds one contributed module from the shared environment. It
// runs during BuildApp, after the built-in stores and registrars exist, so it
// can build its store on the shared DB and register admin pages / health
// checks immediately.
type ExtraModule func(ModuleEnv) (ModulePlugin, error)

type options struct {
	extra []ExtraModule
}

// Option configures BuildApp and Run.
type Option func(*options)

// WithModules contributes custom modules to the batteries-included starter.
// Each is composed into the same catalog as the nine built-ins and its routes
// are mounted behind the same security middleware.
//
//	app, err := starterapp.BuildApp(ctx, cfg, starterapp.WithModules(
//	    func(env starterapp.ModuleEnv) (starterapp.ModulePlugin, error) {
//	        st, err := notesqlite.New(env.DB)
//	        if err != nil {
//	            return starterapp.ModulePlugin{}, err
//	        }
//	        m, err := note.NewModule(note.WithStore(st),
//	            note.WithAdminRegistrar(env.Admin), note.WithHealthRegistrar(env.Health))
//	        if err != nil {
//	            return starterapp.ModulePlugin{}, err
//	        }
//	        return starterapp.ModulePlugin{
//	            ID: note.ModuleID, Compose: m.Compose,
//	            RegisterRoutes: m.HTTPHandler().RegisterRoutes,
//	        }, nil
//	    },
//	))
func WithModules(mods ...ExtraModule) Option {
	return func(o *options) { o.extra = append(o.extra, mods...) }
}

func applyOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}
