// Implements: REQ-005.
// Per: ADR-0009.
// Discipline: C-14.

// admin_auth.go owns the browser-facing login flow that closes the v0.1.0
// open-admin dashboard. guardAdmin requires an authenticated principal to view
// any admin route; anonymous visitors are redirected to a minimal login page
// that authenticates against the auth module, sets the HttpOnly session cookie,
// and redirects back into the shell. Logout revokes the session and clears the
// cookie.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/septagon-oss/pk-core/pkg/security/cookies"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-modules/pkg/auth"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

const (
	adminLoginPath  = "/admin/login"
	adminLogoutPath = "/admin/logout"
)

var adminLoginTemplate = template.Must(template.New("admin-login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Sign in · {{.AppName}}</title>
<style>
  :root {
    --ink: #15221f;
    --muted: #62706b;
    --paper: #f2efe7;
    --sheet: #fffdf7;
    --field: #12201d;
    --line: #d2cec2;
    --signal: #d8f35d;
    --accent: #0f5d4e;
    --danger: #a33131;
    --display: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
    --body: "IBM Plex Sans", Aptos, "Helvetica Neue", sans-serif;
    --mono: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
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
  .notice {
    margin: 0 0 22px;
    padding: 12px 14px;
    border-left: 4px solid var(--danger);
    color: #672121;
    background: #fff1ee;
    font-size: 13px;
  }
  .demo {
    margin: 0 0 22px;
    padding: 13px 15px;
    border: 1px solid #cad79c;
    background: #f6fadf;
    font-size: 12px;
  }
  .demo strong { display: block; margin-bottom: 3px; }
  .demo code { font-family: var(--mono); }
  .field { margin-top: 19px; }
  label {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 7px;
    font-size: 12px;
    font-weight: 750;
  }
  label span {
    color: var(--muted);
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 500;
  }
  input {
    width: 100%;
    min-height: 48px;
    padding: 10px 12px;
    color: var(--ink);
    background: var(--sheet);
    border: 1px solid #aaa89f;
    border-radius: 3px;
  }
  input:hover { border-color: #686d68; }
  button {
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
  button:hover { background: #e5fa82; transform: translateY(-1px); }
  .secure {
    margin: 18px 0 0;
    color: var(--muted);
    font-size: 11px;
    text-align: center;
  }
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
</style>
</head>
<body>
<a class="skip" href="#signin">Skip to sign in</a>
<main class="shell">
  <section class="story" aria-labelledby="product-title">
    <div class="brand">
      <span class="mark" aria-hidden="true"><i></i><i></i><i></i></span>
      <span>PLATFORMKIT / OPERATOR</span>
    </div>
    <div class="story-copy">
      <p class="eyebrow">A composed system, in one place</p>
      <h1 id="product-title">Run the work. Keep the context.</h1>
      <p>Inspect modules, manage tenant data, and follow operational changes from a console that stays close to the code.</p>
    </div>
    <div class="story-foot"><span>Local-first</span><span>Scope-aware</span><span>Open source</span></div>
  </section>
  <section class="signin" id="signin" aria-labelledby="signin-title">
    <div class="panel">
      <header class="panel-head">
        <p class="kicker">{{.Environment}} workspace</p>
        <h2 id="signin-title">Welcome back.</h2>
        <p class="sub">Sign in with an administrator account for this tenant.</p>
      </header>
      {{if .Error}}<div class="notice" role="alert" aria-live="assertive">{{.Error}}</div>{{end}}
      {{if .Development}}
      <aside class="demo">
        <strong>Development workspace</strong>
        Tenant <code>{{.DemoTenant}}</code> and email <code>{{.DemoEmail}}</code> are prefilled. Use the demo password printed in the terminal.
      </aside>
      {{end}}
      <form method="post" action="/admin/login">
        <div class="field">
          <label for="tenant_id">Tenant ID <span>required</span></label>
          <input id="tenant_id" name="tenant_id" value="{{.TenantID}}" autocomplete="organization" maxlength="128" required autofocus>
        </div>
        <div class="field">
          <label for="email">Email <span>required</span></label>
          <input id="email" name="email" value="{{.Email}}" type="email" autocomplete="username" maxlength="320" required>
        </div>
        <div class="field">
          <label for="password">Password <span>required</span></label>
          <input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required>
        </div>
        <button type="submit">Enter operator workspace</button>
      </form>
      <p class="secure">Session cookies are HttpOnly and tenant-scoped requests remain isolated.</p>
    </div>
  </section>
</main>
</body>
</html>`))

var adminForbiddenTemplate = template.Must(template.New("admin-forbidden").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access required · PlatformKit</title>
<style>
*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;color:#eff4e9;background:#12201d;font-family:"IBM Plex Sans",Aptos,sans-serif}
main{width:min(100%,620px);padding:clamp(28px,7vw,64px);border:1px solid rgba(255,255,255,.22)}
p:first-child{margin:0 0 18px;color:#d8f35d;font:700 11px/1.3 "IBM Plex Mono",monospace;letter-spacing:.14em;text-transform:uppercase}
h1{max-width:9ch;margin:0;font:500 clamp(42px,9vw,76px)/.95 "Iowan Old Style",Georgia,serif;letter-spacing:-.04em}
p{max-width:48ch;color:#b8c3bc;line-height:1.6}a{min-height:44px;display:inline-flex;align-items:center;margin-top:14px;padding:0 16px;color:#12201d;background:#d8f35d;font-weight:800;text-decoration:none}:focus-visible{outline:3px solid #8ab4ff;outline-offset:4px}
</style></head><body><main><p>403 / insufficient scope</p><h1>This console needs an administrator.</h1><p>You are signed in, but this account does not carry both <code>admin</code> and <code>console:access</code>. Ask a workspace administrator to grant access or sign in with a different account.</p><a href="/admin/login">Return to sign in</a></main></body></html>`))

// guardAdmin requires explicit interactive-console capabilities. Anonymous
// callers are redirected to sign in; authenticated callers without both
// capabilities receive a clear 403. Authorization depends on scopes rather
// than the informational AuthMethod label.
func guardAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := identity.PrincipalFromContext(r.Context())
		if principal.IsAnonymous() {
			http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
			return
		}
		if !principal.HasScope(scopeAdmin) || !principal.HasScope(scopeConsoleAccess) {
			renderAdminForbidden(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// registerAdminAuth wires the login and logout routes. They are registered
// directly on the mux (not behind guardAdmin) so an anonymous visitor can
// reach the login form.
func (a *App) registerAdminAuth(mux *http.ServeMux) {
	mux.HandleFunc(adminLoginPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			tenantID, email := "", ""
			if a.environment == "development" {
				tenantID, email = seed.TenantID, a.seedEmail
			}
			a.renderAdminLogin(w, tenantID, email, "", http.StatusOK)
		case http.MethodPost:
			a.handleAdminLogin(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc(adminLogoutPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if c, err := r.Cookie(sessionCookieName()); err == nil && c.Value != "" {
			_ = a.authMod.Service().Logout(r.Context(), c.Value)
		}
		_ = cookies.Clear(w, r, cookies.KindSession)
		http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
	})
}

type adminLoginView struct {
	Error       string
	TenantID    string
	Email       string
	AppName     string
	Environment string
	Development bool
	DemoTenant  string
	DemoEmail   string
}

func (a *App) renderAdminLogin(w http.ResponseWriter, tenantID, email, errMsg string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = adminLoginTemplate.Execute(w, adminLoginView{
		Error:       errMsg,
		TenantID:    tenantID,
		Email:       email,
		AppName:     a.appName,
		Environment: a.environment,
		Development: a.environment == "development",
		DemoTenant:  seed.TenantID,
		DemoEmail:   a.seedEmail,
	})
}

func renderAdminForbidden(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	_ = adminForbiddenTemplate.Execute(w, nil)
}

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderAdminLogin(w, "", "", "We could not read that form. Please try again.", http.StatusBadRequest)
		return
	}
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant_id"))
	email := strings.TrimSpace(r.PostForm.Get("email"))
	sess, err := a.authMod.Service().Login(r.Context(), tenantID, auth.Credentials{
		Email:    email,
		Password: r.PostForm.Get("password"),
	})
	if err != nil {
		// Uniform message: never disclose whether the tenant, user, or
		// password was the wrong part.
		a.renderAdminLogin(
			w,
			tenantID,
			email,
			"Sign in failed. Check your tenant, email, and password.",
			http.StatusUnauthorized,
		)
		return
	}
	if err := cookies.Write(w, r, cookies.KindSession, sess.ID); err != nil {
		http.Error(w, "could not set session cookie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, a.adminBasePath, http.StatusSeeOther)
}
