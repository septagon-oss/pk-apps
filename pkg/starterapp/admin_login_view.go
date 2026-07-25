// Implements: REQ-005.
// Per: ADR-0009, ADR-0022, ADR-0031.
// Discipline: C-14.

package starterapp

// admin_login_view.go renders the sign-in page as a typed gomponents view on
// the design system, completing the console's template retirement. The page
// stays fully self-contained — one inline <style>, no external stylesheet,
// no script — because it is served to anonymous visitors under a CSP of
// `default-src 'none'; style-src 'unsafe-inline'`, and that property is the
// point. Inside that one stylesheet the console's line holds:
//
//   - Tokens are generated from themes.Default() via tokens.CSSVars — the
//     hand-copied hex palette this file used to carry is gone; retheming the
//     design system rethemes the login.
//   - Components — the labeled inputs, the error notice, the development
//     callout, the footnote — are tw class lists, with their rules emitted
//     by emission.For into the same inline sheet.
//   - Voice — the dark story panel, the brand mark, the serif hero, the
//     signal-lime call to action — is bespoke CSS aliased onto --pk-*
//     custom properties, product chrome per ADR-0022, not a component.

import (
	"bytes"
	"sync"

	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"

	"github.com/septagon-oss/pk-design/pkg/themes"
	"github.com/septagon-oss/pk-design/pkg/tokens"
	"github.com/septagon-oss/styleengine"
	"github.com/septagon-oss/tw"
	"github.com/septagon-oss/tw/emission"
)

// loginClasses are the component styles the sign-in panel composes. Their
// rules reach the inline stylesheet through loginUtilityCSS, so a class
// declared here is styled by construction.
var loginClasses = struct {
	Notice    tw.ClassList
	DevNote   tw.ClassList
	DevTitle  tw.ClassList
	Code      tw.ClassList
	Field     tw.ClassList
	LabelRow  tw.ClassList
	LabelHint tw.ClassList
	Input     tw.ClassList
	Secure    tw.ClassList
}{
	Notice: tw.New().MarginBottom(tw.S5).PaddingX(tw.S3_5).PaddingY(tw.S3).
		BorderLeft(tw.Border4).BorderLeftColor(tw.BorderDanger).
		Bg(tw.SurfaceDangerSoft).TextColor(tw.FgDanger).FontSize(tw.TextSM),
	DevNote: tw.New().MarginBottom(tw.S5).PaddingX(tw.S4).PaddingY(tw.S3).
		Border(tw.Border1).BorderColor(tw.BorderBrand).Rounded(tw.RadiusSM).
		Bg(tw.SurfaceBrandSoft).TextColor(tw.FgSecondary).FontSize(tw.TextXS),
	DevTitle: tw.New().Display(tw.DisplayBlock).MarginBottom(tw.S1).
		FontWeight(tw.FontSemibold).TextColor(tw.FgPrimary),
	Code:  tw.New().FontFamily(tw.FontMono),
	Field: tw.New().MarginTop(tw.S5),
	LabelRow: tw.New().Display(tw.DisplayFlex).Items(tw.ItemsBaseline).
		Justify(tw.JustifyBetween).Gap(tw.S3).MarginBottom(tw.S1_5).
		FontSize(tw.TextXS).FontWeight(tw.FontBold).TextColor(tw.FgPrimary),
	LabelHint: tw.New().TextColor(tw.FgMuted).FontFamily(tw.FontMono).
		FontWeight(tw.FontNormal),
	Input: tw.New().Display(tw.DisplayBlock).Width(tw.SFull).MinHeight(tw.S12).
		PaddingX(tw.S3).PaddingY(tw.S2_5).
		Rounded(tw.RadiusSM).Border(tw.Border1).BorderColor(tw.BorderPrimary).
		Bg(tw.SurfacePrimary).TextColor(tw.FgPrimary).
		On(tw.StateHover, func(c tw.ClassList) tw.ClassList { return c.BorderColor(tw.BorderSecondary) }).
		On(tw.StatePlaceholder, func(c tw.ClassList) tw.ClassList { return c.TextColor(tw.FgPlaceholder) }),
	Secure: tw.New().MarginTop(tw.S4).TextAlign(tw.TextCenter).
		FontSize(tw.TextXS).TextColor(tw.FgMuted),
}

// loginVoiceCSS is the page's art direction: the dark story panel, the brand
// mark, the editorial hero, and the signal-lime call to action. It reads its
// colors and type through the same --pk-* custom properties the generated
// token block defines, so it follows the theme without being a component.
// The `min-width: 320px` floor and reduced-motion guard are part of the
// accessibility contract pinned by the security hardening tests.
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
  .cta {
    width: 100%;
    min-height: 50px;
    margin-top: 26px;
    padding: 10px 18px;
    color: var(--field);
    background: var(--signal);
    border: 1px solid #aabe45;
    border-radius: 3px;
    font-weight: 800;
    cursor: pointer;
    transition: transform 160ms cubic-bezier(.22,1,.36,1), background-color 160ms ease;
  }
  .cta:hover { background: #e5fa82; transform: translateY(-1px); }
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

// loginStylesheet assembles the page's one inline <style>: generated theme
// tokens, then role vars plus the rules for exactly the class lists above,
// then the voice. Computed once; the inputs are compile-time constants, so
// on error the voice CSS still ships and the page degrades to unstyled
// components rather than failing the login flow.
var loginStylesheet = sync.OnceValue(func() string {
	tokenCSS, err := tokens.CSSVars(themes.Default().Tokens)
	if err != nil {
		tokenCSS = ":root {}\n"
	}
	utility, err := emission.For(
		loginClasses.Notice, loginClasses.DevNote, loginClasses.DevTitle,
		loginClasses.Code, loginClasses.Field, loginClasses.LabelRow,
		loginClasses.LabelHint, loginClasses.Input, loginClasses.Secure,
	)
	utilityCSS := ""
	if err == nil {
		if rendered, rerr := emission.RoleVars().Merge(utility).Render(styleengine.RenderOptions{Minify: true}); rerr == nil {
			utilityCSS = rendered
		}
	}
	return tokenCSS + utilityCSS + loginVoiceCSS
})

// loginView renders the full sign-in document. The DOM contract the tests
// and browsers rely on carries over from the retired template: field ids and
// names, autocomplete hints, the required/autofocus pair on the tenant
// field, the alert notice, and the skip link.
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
							h.Div(h.Class(loginClasses.Notice.Compile()), h.Role("alert"),
								g.Attr("aria-live", "assertive"), g.Text(v.Error)),
						),
						g.If(v.Development,
							h.Aside(h.Class(loginClasses.DevNote.Compile()),
								h.Strong(h.Class(loginClasses.DevTitle.Compile()), g.Text("Development workspace")),
								g.Text("Tenant "), h.Code(h.Class(loginClasses.Code.Compile()), g.Text(v.BootstrapTenant)),
								g.Text(" and email "), h.Code(h.Class(loginClasses.Code.Compile()), g.Text(v.BootstrapEmail)),
								g.Text(" are prefilled. Use the local password printed in the terminal."),
							),
						),
						h.Form(h.Method("post"), h.Action(adminLoginPath),
							loginField("tenant_id", "Tenant ID",
								h.Input(h.Class(loginClasses.Input.Compile()), h.ID("tenant_id"), h.Name("tenant_id"),
									h.Value(v.TenantID), h.AutoComplete("organization"), h.MaxLength("128"),
									h.Required(), h.AutoFocus()),
							),
							loginField("email", "Email",
								h.Input(h.Class(loginClasses.Input.Compile()), h.ID("email"), h.Name("email"),
									h.Value(v.Email), h.Type("email"), h.AutoComplete("username"), h.MaxLength("320"),
									h.Required()),
							),
							loginField("password", "Password",
								h.Input(h.Class(loginClasses.Input.Compile()), h.ID("password"), h.Name("password"),
									h.Type("password"), h.AutoComplete("current-password"), h.MaxLength("1024"),
									h.Required()),
							),
							h.Button(h.Class("cta"), h.Type("submit"), g.Text("Enter operator workspace")),
						),
						h.P(h.Class(loginClasses.Secure.Compile()),
							g.Text("Session cookies are HttpOnly and tenant-scoped requests remain isolated.")),
					),
				),
			),
		),
	))
}

// loginField wraps one labeled control in the shared field layout, keeping
// the visible "required" hint the retired template showed for every field.
func loginField(id, label string, control g.Node) g.Node {
	return h.Div(h.Class(loginClasses.Field.Compile()),
		h.Label(h.Class(loginClasses.LabelRow.Compile()), h.For(id),
			g.Text(label),
			h.Span(h.Class(loginClasses.LabelHint.Compile()), g.Text("required")),
		),
		control,
	)
}

// renderLoginView buffers the view so a render failure can never emit a
// half-written document after the status line (C-10 spirit for handlers).
func renderLoginView(v adminLoginView) ([]byte, error) {
	var buf bytes.Buffer
	if err := loginView(v).Render(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
