// Implements: REQ-005.
// Per: ADR-0009, ADR-0022, ADR-0031.
// Discipline: C-14.

package starterapp

// admin_forbidden_view.go renders the 403 interstitial as a typed view,
// retiring the product's last html/template. Same containment as the login
// page — one inline <style>, no script, strict CSP — and the same line: the
// dark editorial voice reads its colors and type through generated --pk-*
// tokens, and the one component (the return-to-sign-in call to action) is a
// pk-ui Button-classed anchor re-colored by the page's .cta-signal role
// remap.

import (
	"bytes"

	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"

	"github.com/septagon-oss/pk-ui/render/web"
)

// forbiddenVoiceCSS is the interstitial's art direction on the generated
// custom properties; .cta-signal re-maps the brand roles to signal lime for
// the single scoped component, exactly as the login page does.
const forbiddenVoiceCSS = `
  * { box-sizing: border-box; }
  body {
    min-height: 100vh;
    margin: 0;
    display: grid;
    place-items: center;
    padding: 24px;
    color: #eff4e9;
    background: var(--pk-color-sidebar-bg);
    font-family: var(--pk-font-body);
  }
  main {
    width: min(100%, 620px);
    padding: clamp(28px, 7vw, 64px);
    border: 1px solid rgba(255, 255, 255, .22);
  }
  .eyebrow {
    margin: 0 0 18px;
    color: var(--pk-color-signal);
    font: 700 11px/1.3 var(--pk-font-mono);
    letter-spacing: .14em;
    text-transform: uppercase;
  }
  h1 {
    max-width: 9ch;
    margin: 0;
    font: 500 clamp(42px, 9vw, 76px)/.95 var(--pk-font-display);
    letter-spacing: -.04em;
  }
  p { max-width: 48ch; color: #b8c3bc; line-height: 1.6; }
  code { font-family: var(--pk-font-mono); }
  .cta-signal {
    --pk-role-surface-brand: var(--pk-color-signal);
    --pk-role-surface-brand-hover: #e5fa82;
    --pk-role-fg-on-brand: var(--pk-color-sidebar-bg);
    margin-top: 14px;
  }
  :focus-visible { outline: 3px solid #8ab4ff; outline-offset: 4px; }
`

func forbiddenView() g.Node {
	return h.Doctype(h.HTML(h.Lang("en"),
		h.Head(
			h.Meta(h.Charset("utf-8")),
			h.Meta(h.Name("viewport"), h.Content("width=device-width,initial-scale=1")),
			h.TitleEl(g.Text("Access required · PlatformKit")),
			h.StyleEl(g.Raw(inlineBaseCSS()+forbiddenVoiceCSS)),
		),
		h.Body(h.Main(
			h.P(h.Class("eyebrow"), g.Text("403 / insufficient scope")),
			h.H1(g.Text("This console needs an administrator.")),
			h.P(
				g.Text("You are signed in, but this account does not carry both "),
				h.Code(g.Text("admin")), g.Text(" and "), h.Code(g.Text("console:access")),
				g.Text(". Ask a workspace administrator to grant access or sign in with a different account."),
			),
			h.A(h.Class(web.ButtonClasses("primary", "medium").Compile()+" cta-signal"),
				h.Href(adminLoginPath), g.Text("Return to sign in")),
		)),
	))
}

// renderForbiddenView buffers the view; the render inputs are constants, so
// an error is a programmer error surfaced at test time.
func renderForbiddenView() ([]byte, error) {
	var buf bytes.Buffer
	if err := forbiddenView().Render(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
