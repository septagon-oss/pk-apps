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

	"github.com/septagon-oss/pk-core/pkg/security/cookies"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-modules/pkg/auth"
)

const (
	adminLoginPath  = "/admin/login"
	adminLogoutPath = "/admin/logout"
)

// adminLoginTemplate is the pre-auth sign-in page. There is no stylesheet
// before authentication (the shell's CSS sits behind the admin surface), so
// the palette is inlined — and its literals are the pk token pipeline's
// default theme values, taken directly from
// pk-design/pkg/themes/default.tokens.json (color.surface.canvas/primary,
// color.text.primary/muted, color.border.default, color.accent.default/
// hover/on, color.status.danger/dangerbg, color.focus, font.body), so the
// login page matches the shell chrome it signs the operator into.
var adminLoginTemplate = template.Must(template.New("admin-login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in — {{.AppName}}</title>
<style>
  body { margin:0; background:#f2efe7; color:#15221f; font-family:"IBM Plex Sans", Aptos, "Helvetica Neue", sans-serif; display:flex; min-height:100vh; align-items:center; justify-content:center; }
  form { background:#fffdf7; border:1px solid #cbc5b8; border-radius:12px; padding:32px; width:340px; box-sizing:border-box; }
  h1 { font-size:20px; margin:0 0 4px; }
  p.sub { color:#5f6b65; font-size:13px; margin:0 0 20px; }
  label { display:block; font-size:12px; color:#5f6b65; margin:14px 0 4px; }
  input { width:100%; box-sizing:border-box; background:#fffdf7; border:1px solid #cbc5b8; border-radius:6px; color:#15221f; padding:9px 10px; font-size:14px; }
  input:focus { outline:2px solid #326de6; outline-offset:1px; }
  button { width:100%; margin-top:20px; background:#0f5d4e; color:#f9fff9; border:0; border-radius:6px; padding:10px; font-weight:700; font-size:14px; cursor:pointer; }
  button:hover { background:#0a493e; }
  .err { background:#fbe5e2; border:1px solid #9e3833; color:#9e3833; border-radius:6px; padding:8px 10px; font-size:13px; margin-bottom:8px; }
</style>
</head>
<body>
<form method="post" action="/admin/login">
  <h1>Sign in</h1>
  <p class="sub">{{.AppName}} admin</p>
  {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  <label for="tenant_id">Tenant ID</label>
  <input id="tenant_id" name="tenant_id" value="{{.TenantID}}" autocomplete="off">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="username">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
</body>
</html>`))

// guardAdmin requires an INTERACTIVE (session) principal to view the admin
// surface. Anonymous callers and non-interactive credentials (API keys) are
// redirected to the login page. Gating on the session auth method — not merely
// "not anonymous" — keeps machine credentials out of the human console; a
// programmatic client should use the tenant-scoped /api/v1 surface with its API
// key, not the admin UI. (OSS has only a coarse admin notion; per-role gating
// of the console is a downstream authorization concern.) This closes both the
// v0.1.0 open-admin dashboard and the v0.2.0 any-credential-is-admin gap.
func guardAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity.PrincipalFromContext(r.Context()).AuthMethod != "session" {
			http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
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
			renderAdminLogin(w, a.appName, "", "")
		case http.MethodPost:
			a.handleAdminLogin(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc(adminLogoutPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
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

// renderAdminLogin renders the sign-in page. appName comes from cfg.AppName
// via App.appName so a rebranded deployment's login page carries its own
// product name, not the starter's.
func renderAdminLogin(w http.ResponseWriter, appName, tenantID, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusUnauthorized
	}
	w.WriteHeader(status)
	_ = adminLoginTemplate.Execute(w, map[string]string{
		"AppName":  appName,
		"Error":    errMsg,
		"TenantID": tenantID,
	})
}

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderAdminLogin(w, a.appName, "", "invalid form submission")
		return
	}
	tenantID := r.PostForm.Get("tenant_id")
	sess, err := a.authMod.Service().Login(r.Context(), tenantID, auth.Credentials{
		Email:    r.PostForm.Get("email"),
		Password: r.PostForm.Get("password"),
	})
	if err != nil {
		// Uniform message: never disclose whether the tenant, user, or
		// password was the wrong part.
		renderAdminLogin(w, a.appName, tenantID, "Sign in failed. Check your tenant, email, and password.")
		return
	}
	if err := cookies.Write(w, r, cookies.KindSession, sess.ID); err != nil {
		http.Error(w, "could not set session cookie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, a.adminBasePath, http.StatusSeeOther)
}
