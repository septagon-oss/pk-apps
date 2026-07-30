// Implements: REQ-005.
// Per: ADR-0009, ADR-0022, ADR-0031.
// Discipline: C-14.

package starterapp

// admin_login_view.go renders the sign-in page as a typed gomponents view
// composed ONLY of pk-ui components — Input, Alert, Button — plus the page's
// voice. It stays fully self-contained (one inline <style>, no external
// stylesheet, no script) because it serves anonymous visitors under a CSP of
// `default-src 'none'; style-src 'unsafe-inline'`, and that containment is
// the point. Inside that one stylesheet the console's line holds:
//
//   - Tokens are generated from themes.Default() via tokens.CSSVars.
//   - Component rules are emitted from pk-ui's own class registry
//     (emission.For(web.ClassLists()...)), so the controls here are the
//     same implementation the admin console renders.
//   - Voice — the dark story panel, brand mark, serif hero — is bespoke CSS
//     aliased onto --pk-* custom properties (ADR-0022). The signal-lime call
//     to action is a REAL pk-ui Button whose color roles are re-mapped in a
//     page-scoped rule (.cta-signal): the role indirection the design system
//     exists for, not a competing button implementation.

import (
	"bytes"
	"sync"

	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"

	"github.com/septagon-oss/pk-design/pkg/themes"
	"github.com/septagon-oss/pk-design/pkg/tokens"
	"github.com/septagon-oss/pk-ui/contracts"
	"github.com/septagon-oss/pk-ui/contracts/atoms"
	"github.com/septagon-oss/pk-ui/render/web"
	"github.com/septagon-oss/styleengine"
	"github.com/septagon-oss/tw/emission"
)

// loginVoiceCSS is the page's art direction, reading its colors and type
// through the generated --pk-* custom properties. The `min-width: 320px`
// floor and reduced-motion guard are part of the accessibility contract
// pinned by the security hardening tests. `.cta-signal` re-maps the brand
// color roles to the login's signal lime for the one component scoped
// inside it — retheming by role indirection, per ADR-0022.
const loginVoiceCSS = `
  :root {
    --ink: var(--pk-color-text-primary);
    --muted: var(--pk-color-text-muted);
    --paper: var(--pk-color-surface-canvas);
    --field: var(--pk-color-sidebar-bg);
    --signal: var(--pk-color-signal);
    --accent: var(--pk-color-accent-default);
    --display: var(--pk-font-display);
    --body: var(--pk-font-body);
    --mono: var(--pk-font-mono);
  }
  * { box-sizing: border-box; }
  html { min-width: 320px; background: var(--paper); }
  body {
    min-height: 100vh;
    margin: 0;
    color: var(--ink);
    background: var(--paper);
    font-family: var(--body);
    line-height: 1.5;
  }
  button, input { font: inherit; }
  :focus-visible { outline: 3px solid #326de6; outline-offset: 3px; }
  .cta-signal {
    --pk-role-surface-brand: var(--pk-color-signal);
    --pk-role-surface-brand-hover: #e5fa82;
    --pk-role-fg-on-brand: var(--pk-color-sidebar-bg);
    min-height: 50px;
    margin-top: 26px;
  }
  .skip {
    position: fixed;
    z-index: 10;
    inset: 8px auto auto 8px;
    padding: 10px 14px;
    color: white;
    background: var(--accent);
    transform: translateY(-160%);
  }
  .skip:focus { transform: translateY(0); }
  .shell {
    min-height: 100vh;
    display: grid;
    grid-template-columns: minmax(300px, .9fr) minmax(480px, 1.1fr);
  }
  .story {
    min-height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 48px;
    padding: clamp(28px, 6vw, 76px);
    color: #eff4e9;
    background: var(--field);
    border-right: 1px solid rgba(255, 255, 255, .12);
  }
  .brand {
    display: inline-flex;
    align-items: center;
    gap: 13px;
    color: inherit;
    font-size: 13px;
    font-weight: 750;
    letter-spacing: .04em;
  }
  .mark {
    width: 33px;
    height: 33px;
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 3px;
    padding: 5px;
    border: 1px solid rgba(255, 255, 255, .42);
  }
  .mark i { display: block; background: var(--signal); }
  .mark i:nth-child(2) { background: transparent; border: 1px solid rgba(255,255,255,.5); }
  .mark i:nth-child(3) { grid-column: 1 / -1; height: 4px; align-self: end; }
  .story-copy { max-width: 570px; }
  .eyebrow {
    margin: 0 0 20px;
    color: var(--signal);
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: .15em;
    text-transform: uppercase;
  }
  .story h1 {
    max-width: 8ch;
    margin: 0;
    font-family: var(--display);
    font-size: clamp(46px, 7vw, 92px);
    font-weight: 500;
    letter-spacing: -.045em;
    line-height: .92;
  }
  .story-copy > p:last-child {
    max-width: 42ch;
    margin: 28px 0 0;
    color: #b8c3bc;
    font-size: clamp(15px, 1.5vw, 18px);
  }
  .story-foot {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 22px;
    color: #9eada4;
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: .08em;
    text-transform: uppercase;
  }
  .signin {
    min-width: 0;
    display: grid;
    place-items: center;
    padding: clamp(24px, 7vw, 88px);
    background: var(--paper);
  }
  .panel { width: min(100%, 470px); }
  .panel-head { margin-bottom: 34px; }
  .kicker {
    margin: 0 0 10px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .13em;
    text-transform: uppercase;
  }
  .panel h2 {
    margin: 0;
    font-family: var(--display);
    font-size: clamp(38px, 5vw, 55px);
    font-weight: 500;
    letter-spacing: -.035em;
    line-height: 1;
  }
  .sub { margin: 13px 0 0; color: var(--muted); font-size: 14px; }
  .panel-gap { margin-bottom: 22px; }
  .field-gap { margin-top: 19px; }
  .secure { margin-top: 18px; text-align: center; }
  @media (max-width: 820px) {
    .shell { grid-template-columns: 1fr; }
    .story { min-height: auto; padding: 24px; gap: 34px; }
    .story h1 { max-width: 12ch; font-size: clamp(40px, 12vw, 65px); }
    .story-copy > p:last-child { margin-top: 18px; }
    .story-foot { display: none; }
    .signin { place-items: start center; padding: 42px 20px 64px; }
  }
  @media (max-width: 420px) {
    .story-copy > p:last-child { display: none; }
    .panel h2 { font-size: 39px; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
  }
`

// inlineBaseCSS assembles the shared self-contained core for anonymous
// pages: generated theme tokens, role variables, and the rules for pk-ui's
// entire class registry — so any pk-ui component composes correctly with no
// external stylesheet. Computed once; the inputs are compile-time constants,
// so on error the voice still ships and controls degrade to unstyled rather
// than failing the flow.
var inlineBaseCSS = sync.OnceValue(func() string {
	tokenCSS, err := tokens.CSSVars(themes.Default().Tokens)
	if err != nil {
		tokenCSS = ":root {}\n"
	}
	utilityCSS := ""
	if utility, err := emission.For(web.ClassLists()...); err == nil {
		if rendered, rerr := emission.RoleVars().Merge(utility).Render(styleengine.RenderOptions{Minify: true}); rerr == nil {
			utilityCSS = rendered
		}
	}
	return tokenCSS + utilityCSS
})

func loginStylesheet() string { return inlineBaseCSS() + loginVoiceCSS }

// loginView renders the full sign-in document. The DOM contract the tests
// and browsers rely on carries over: field ids and names, autocomplete
// hints, maxlength caps, the required/autofocus pair on the tenant field,
// the role=alert notice, and the skip link.
func loginView(v adminLoginView) g.Node {
	return h.Doctype(h.HTML(h.Lang("en"),
		h.Head(
			h.Meta(h.Charset("utf-8")),
			h.Meta(h.Name("viewport"), h.Content("width=device-width, initial-scale=1")),
			h.Meta(h.Name("color-scheme"), h.Content("light")),
			h.TitleEl(g.Text("Sign in · "+v.AppName)),
			h.StyleEl(g.Raw(loginStylesheet())),
		),
		h.Body(
			h.A(h.Class("skip"), h.Href("#signin"), g.Text("Skip to sign in")),
			h.Main(h.Class("shell"),
				h.Section(h.Class("story"), g.Attr("aria-labelledby", "product-title"),
					h.Div(h.Class("brand"),
						h.Span(h.Class("mark"), g.Attr("aria-hidden", "true"), h.I(), h.I(), h.I()),
						h.Span(g.Text("PLATFORMKIT / OPERATOR")),
					),
					h.Div(h.Class("story-copy"),
						h.P(h.Class("eyebrow"), g.Text("A composed system, in one place")),
						h.H1(h.ID("product-title"), g.Text("Run the work. Keep the context.")),
						h.P(g.Text("Inspect modules, manage tenant data, and follow operational changes from a console that stays close to the code.")),
					),
					h.Div(h.Class("story-foot"),
						h.Span(g.Text("Local-first")), h.Span(g.Text("Scope-aware")), h.Span(g.Text("Open source")),
					),
				),
				h.Section(h.Class("signin"), h.ID("signin"), g.Attr("aria-labelledby", "signin-title"),
					h.Div(h.Class("panel"),
						h.Header(h.Class("panel-head"),
							h.P(h.Class("kicker"), g.Text(v.Environment+" workspace")),
							h.H2(h.ID("signin-title"), g.Text("Welcome back.")),
							h.P(h.Class("sub"), g.Text("Sign in with an administrator account for this tenant.")),
						),
						g.If(v.Error != "",
							h.Div(h.Class("panel-gap"), web.Alert(atoms.AlertProps{
								Variant: "error",
								Message: v.Error,
							})),
						),
						g.If(v.Development,
							h.Div(h.Class("panel-gap"), web.Alert(atoms.AlertProps{
								Variant: "success",
								Title:   "Development workspace",
								Message: "Tenant " + v.BootstrapTenant + " and email " + v.BootstrapEmail +
									" are prefilled. Use the local password printed in the terminal.",
							})),
						),
						h.Form(h.Method("post"), h.Action(adminLoginPath),
							h.Div(h.Class("field-gap"), web.Input(atoms.InputProps{
								ComponentProps: contracts.ComponentProps{ID: "tenant_id",
									Attrs: map[string]string{"autocomplete": "organization", "maxlength": "128"}},
								Name: "tenant_id", Label: "Tenant ID",
								Value: v.TenantID, Required: true, AutoFocus: true,
							})),
							h.Div(h.Class("field-gap"), web.Input(atoms.InputProps{
								ComponentProps: contracts.ComponentProps{ID: "email",
									Attrs: map[string]string{"autocomplete": "username", "maxlength": "320"}},
								Name: "email", Type: "email", Label: "Email",
								Value: v.Email, Required: true,
							})),
							h.Div(h.Class("field-gap"), web.Input(atoms.InputProps{
								ComponentProps: contracts.ComponentProps{ID: "password",
									Attrs: map[string]string{"autocomplete": "current-password", "maxlength": "1024"}},
								Name: "password", Type: "password", Label: "Password",
								Required: true,
							})),
							web.Button(atoms.ButtonProps{
								ComponentProps: contracts.ComponentProps{Class: "cta-signal"},
								Text:           "Enter operator workspace",
								Variant:        "primary", Size: "large", Type: "submit", FullWidth: true,
							}),
						),
						h.P(h.Class(web.TextClasses("muted", "xs", "").Compile()+" secure"),
							g.Text("Session cookies are HttpOnly and tenant-scoped requests remain isolated.")),
					),
				),
			),
		),
	))
}

// renderLoginView buffers the view so a render failure can never emit a
// half-written document after the status line.
func renderLoginView(v adminLoginView) ([]byte, error) {
	var buf bytes.Buffer
	if err := loginView(v).Render(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
