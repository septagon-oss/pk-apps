// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	pkmodule "github.com/septagon-oss/pk-core/pkg/module"
	"github.com/septagon-oss/pk-core/pkg/observability/health"
	"github.com/septagon-oss/pk-modules/pkg/audit"
	"github.com/septagon-oss/pk-modules/pkg/portslib"
)

const (
	ModuleID          = "poll_management"
	ModuleName        = "Poll Management"
	ModuleDescription = "Lifecycle-managed polls with signed public voting."
	ModuleVersion     = "0.4.0"
	APIPath           = "/api/v1/polls"
	AdminPath         = "/admin/poll_management/Poll"
)

// The scopes this module enforces on its own routes. They are exported because
// starterapp needs the same strings to build the API-key allowlist: a module
// that enforces a scope it never declared produces keys that can never satisfy
// it, so declaration and enforcement must read from one place.
const (
	ScopeRead  = "polls:read"
	ScopeWrite = "polls:write"
	ScopeAdmin = "polls:admin"
)

// APIKeyScopes is the set an application may grant to a machine credential.
func APIKeyScopes() []string { return []string{ScopeRead, ScopeWrite, ScopeAdmin} }

type Option func(*config)

type config struct {
	store  Store
	db     *sql.DB
	admin  portslib.AdminRegistrar
	health portslib.HealthRegistrar
	audit  audit.AuditService
}

func WithStore(store Store) Option {
	return func(cfg *config) { cfg.store = store }
}

func WithDB(db *sql.DB) Option {
	return func(cfg *config) { cfg.db = db }
}

func WithAdminRegistrar(registrar portslib.AdminRegistrar) Option {
	return func(cfg *config) { cfg.admin = registrar }
}

func WithHealthRegistrar(registrar portslib.HealthRegistrar) Option {
	return func(cfg *config) { cfg.health = registrar }
}

func WithAuditService(service audit.AuditService) Option {
	return func(cfg *config) { cfg.audit = service }
}

type Module struct {
	metadata pkmodule.Metadata
	store    Store
	service  *Service
	handler  *Handler
}

func NewModule(opts ...Option) (*Module, error) {
	var cfg config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	store := cfg.store
	if store == nil {
		if cfg.db == nil {
			return nil, errors.New("poll: no store configured; use WithStore or WithDB")
		}
		var err error
		store, err = NewSQLiteStore(cfg.db)
		if err != nil {
			return nil, err
		}
	}
	voterSecret, err := store.VoterSecret(context.Background())
	if err != nil {
		return nil, err
	}
	service := NewService(store, cfg.audit)
	handler, err := NewHandler(service, voterSecret)
	if err != nil {
		return nil, err
	}
	module := &Module{
		metadata: pkmodule.Metadata{
			ID:          ModuleID,
			Name:        ModuleName,
			Description: ModuleDescription,
			Version:     ModuleVersion,
		},
		store:   store,
		service: service,
		handler: handler,
	}
	if err := registerAdmin(cfg.admin); err != nil {
		return nil, err
	}
	// The insights page needs the constructed module (it reads the service),
	// so it registers after the resource.
	if cfg.admin != nil {
		if err := cfg.admin.RegisterPage(portslib.AdminPage{
			ModuleID: ModuleID,
			Path:     InsightsPath,
			Title:    "Poll insights",
			Render:   module.insightsPage,
		}); err != nil {
			return nil, err
		}
	}
	if err := registerHealth(cfg.health, store); err != nil {
		return nil, err
	}
	service.flushAuditBestEffort(context.Background())
	return module, nil
}

func (m *Module) Compose() pkmodule.Composable {
	return pkmodule.Must(
		m.metadata,
		pkmodule.WithDependencies(
			pkmodule.RequiresPort[audit.AuditService](pkmodule.PortSpec{
				Version:           audit.ModuleVersion,
				Purpose:           "Deliver durable poll lifecycle audit events.",
				Category:          pkmodule.DependencyCategoryData,
				SubCategory:       "audit",
				PreferredProvider: "audit_management",
			}),
			pkmodule.OptionalPort[portslib.AdminRegistrar](pkmodule.PortSpec{
				Version:           portslib.AdminRegistrarContractVersion,
				Purpose:           "Mount poll management in the admin shell.",
				Category:          pkmodule.DependencyCategoryUI,
				SubCategory:       "admin",
				PreferredProvider: "admin_management",
			}),
			pkmodule.OptionalPort[portslib.HealthRegistrar](pkmodule.PortSpec{
				Version:           "0.0.0",
				Purpose:           "Report poll store reachability.",
				Category:          pkmodule.DependencyCategoryMonitoring,
				SubCategory:       "health",
				PreferredProvider: "health_management",
			}),
		),
	)
}

func (m *Module) HTTPHandler() *Handler { return m.handler }

func (m *Module) Service() *Service { return m.service }

func registerAdmin(registrar portslib.AdminRegistrar) error {
	if registrar == nil {
		return nil
	}
	if err := registrar.RegisterResource(portslib.AdminResource{
		ModuleID:      ModuleID,
		EntityName:    "Poll",
		SingularLabel: "poll",
		PluralLabel:   "polls",
		Description:   "Draft, publish, close, and archive tenant-owned public decisions.",
		APIPath:       APIPath,
		IDKey:         "id",
		Columns: []portslib.AdminColumn{
			{Key: "title", Label: "Question", Kind: portslib.AdminFieldText, Primary: true},
			{Key: "status", Label: "Status", Kind: portslib.AdminFieldStatus},
			{Key: "vote_count", Label: "Votes", Kind: portslib.AdminFieldCount},
			{Key: "closes_at", Label: "Closes", Kind: portslib.AdminFieldDateTime},
		},
		Fields: []portslib.AdminField{
			{
				Key: "slug", Label: "Public slug", Kind: portslib.AdminFieldSlug,
				Required: true, Placeholder: "quarterly-roadmap",
				Help: "Lowercase letters, numbers, and hyphens. Public slugs are globally unique.",
			},
			{Key: "title", Label: "Question", Kind: portslib.AdminFieldText, Required: true},
			{
				Key: "description", Label: "Context", Kind: portslib.AdminFieldTextarea,
				Placeholder: "Give voters enough context to make a useful choice.",
			},
			{
				Key: "options", Label: "Options", Kind: portslib.AdminFieldTags,
				Required: true, Min: 2, Max: maxOptions,
				Help: "Enter two to twenty unique choices.",
			},
			{
				Key: "closes_at", Label: "Scheduled close", Kind: portslib.AdminFieldDateTime,
				Help: "Optional. The public ballot stops accepting votes at this UTC time.",
			},
			{
				Key: "status", Label: "Status", Kind: portslib.AdminFieldStatus,
				ReadOnly: true, DefaultValue: StatusDraft,
			},
		},
		CanCreate: true,
		CanEdit:   true,
		EditWhen: &portslib.AdminRowCondition{
			Field: "status", Operator: portslib.AdminConditionEquals, Value: StatusDraft,
		},
		CanDelete: true,
		DeleteWhen: &portslib.AdminRowCondition{
			Field: "status", Operator: portslib.AdminConditionEquals, Value: StatusDraft,
		},
		Actions: []portslib.AdminAction{
			{
				Label: "Publish", Method: http.MethodPost, PathSuffix: "/publish",
				VisibleWhen: &portslib.AdminRowCondition{
					Field: "status", Operator: portslib.AdminConditionEquals, Value: StatusDraft,
				},
			},
			{
				Label: "Close", Method: http.MethodPost, PathSuffix: "/close",
				Variant: "warning", Confirm: "Close this poll? New votes will be rejected.",
				VisibleWhen: &portslib.AdminRowCondition{
					Field: "status", Operator: portslib.AdminConditionEquals, Value: StatusPublished,
				},
			},
			{
				Label: "Archive", Method: http.MethodPost, PathSuffix: "/archive",
				Variant: "danger", Confirm: "Archive this poll and remove its public page?",
				VisibleWhen: &portslib.AdminRowCondition{
					Field: "status", Operator: portslib.AdminConditionEquals, Value: StatusClosed,
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("poll: register admin resource: %w", err)
	}
	if err := registrar.RegisterSidebarSection(portslib.SidebarSection{
		ModuleID: ModuleID,
		Label:    "Decisions",
		Order:    45,
		Items: []portslib.SidebarItem{
			{Path: AdminPath, Label: "Polls"},
		},
	}); err != nil {
		return fmt.Errorf("poll: register admin sidebar: %w", err)
	}
	return nil
}

func registerHealth(registrar portslib.HealthRegistrar, store Store) error {
	if registrar == nil {
		return nil
	}
	checker := health.CheckerFunc(func(ctx context.Context) error {
		return store.Ping(ctx)
	})
	if err := registrar.Register(ModuleID+".store", checker); err != nil {
		return fmt.Errorf("poll: register health check: %w", err)
	}
	return nil
}
