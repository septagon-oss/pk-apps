// Implements: REQ-016.
// Per: ADR-0017, ADR-0031.
// Discipline: C-14.

package pollmodule

// adminpage.go is the modular-frontend reference: a module-owned admin page
// built entirely from pk-ui components and tw utility classes, with not one
// line of authored CSS. The admin shell already serves the whole design
// system (theme tokens, role variables, utility rules) in its stylesheet, so
// a module page links that one asset and composes components.
//
// This is the story an extension author copies: register a portslib.AdminPage,
// render pk-ui, done.

import (
	"net/http"

	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"

	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-ui/contracts/atoms"
	"github.com/septagon-oss/pk-ui/contracts/layouts"
	"github.com/septagon-oss/pk-ui/contracts/molecules"
	web "github.com/septagon-oss/pk-ui/render/web"
)

// InsightsPath is the shell path of the module-owned insights page.
const InsightsPath = "/admin/poll_management/insights"

// insightsPage renders a read-only overview of the tenant's polls. The whole
// document is pk-ui; the stylesheet is the shell's own.
func (m *Module) insightsPage(w http.ResponseWriter, r *http.Request) {
	principal := identity.PrincipalFromContext(r.Context())
	if principal.IsAnonymous() {
		http.Error(w, "unauthorized: authentication required", http.StatusUnauthorized)
		return
	}

	page, err := m.service.List(r.Context(), principal.TenantID, 50, 0)
	if err != nil {
		http.Error(w, "polls: list failed", http.StatusInternalServerError)
		return
	}

	var body g.Node
	if len(page.Items) == 0 {
		body = web.EmptyState(atoms.EmptyStateProps{
			Title:       "No polls yet",
			Description: "Create the first poll from the Polls resource and it will show up here.",
			Bordered:    true,
			Actions: []atoms.EmptyStateAction{
				{Label: "Go to polls", Href: "/admin/poll_management/Poll"},
			},
		})
	} else {
		rows := make([]molecules.TableRow, 0, len(page.Items))
		for _, p := range page.Items {
			rows = append(rows, molecules.TableRow{ID: p.ID, Cells: map[string]any{
				"title":  p.Title,
				"status": p.Status,
				"votes":  p.VoteCount,
				"slug":   p.Slug,
			}})
		}
		body = web.Table(molecules.TableProps{
			Columns: []molecules.TableColumn{
				{Key: "title", Label: "Question"},
				{Key: "status", Label: "Status"},
				{Key: "votes", Label: "Votes"},
				{Key: "slug", Label: "Public slug"},
			},
			Rows: rows,
		})
	}

	doc := h.Doctype(h.HTML(h.Lang("en"),
		h.Head(
			h.Meta(h.Charset("utf-8")),
			h.Meta(h.Name("viewport"), h.Content("width=device-width,initial-scale=1")),
			h.TitleEl(g.Text("Poll insights")),
			h.Link(h.Rel("stylesheet"), h.Href("/admin/static/_admin.css")),
		),
		h.Body(
			web.Container(layouts.ContainerProps{MaxWidth: "4xl"},
				web.Stack(layouts.StackProps{Gap: "6"},
					web.Breadcrumb(molecules.BreadcrumbProps{Items: []molecules.BreadcrumbItem{
						{Label: "Overview", Href: "/admin"},
						{Label: "Polls", Href: "/admin/poll_management/Poll"},
						{Label: "Insights"},
					}}),
					web.Heading(atoms.HeadingProps{Text: "Poll insights", Level: 1}),
					web.Text(atoms.TextProps{
						Content: "Every poll this tenant owns, with live vote counts. " +
							"This page is rendered by the module itself, entirely from pk-ui components.",
						Size: "sm", Color: "muted",
					}),
					body,
				),
			),
		),
	))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = doc.Render(w)
}
