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

var adminLoginTemplate = template.Must(template.New("admin-login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in — PlatformKit</title>
<style>
  body { margin:0; background:#0F172A; color:#F8FAFC; font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; display:flex; min-height:100vh; align-items:center; justify-content:center; }
  form { background:#1E293B; border:1px solid #334155; border-radius:12px; padding:32px; width:340px; box-sizing:border-box; }
  h1 { font-size:20px; margin:0 0 4px; }
  p.sub { color:#94A3B8; font-size:13px; margin:0 0 20px; }
  label { display:block; font-size:12px; color:#94A3B8; margin:14px 0 4px; }
  input { width:100%; box-sizing:border-box; background:#0F172A; border:1px solid #334155; border-radius:6px; color:#F8FAFC; padding:9px 10px; font-size:14px; }
  button { width:100%; margin-top:20px; background:#2DD4BF; color:#0F172A; border:0; border-radius:6px; padding:10px; font-weight:700; font-size:14px; cursor:pointer; }
  .err { background:#7f1d1d33; border:1px solid #b91c1c; color:#fecaca; border-radius:6px; padding:8px 10px; font-size:13px; margin-bottom:8px; }
</style>
</head>
<body>
<form method="post" action="/admin/login">
  <h1>Sign in</h1>
  <p class="sub">PlatformKit admin</p>
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

// guardAdmin requires an authenticated principal to view the admin surface.
// Anonymous callers are redirected to the login page. This is what closes the
// v0.1.0 open-admin dashboard.
func guardAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity.PrincipalFromContext(r.Context()).IsAnonymous() {
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
			renderAdminLogin(w, "", "")
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

func renderAdminLogin(w http.ResponseWriter, tenantID, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusUnauthorized
	}
	w.WriteHeader(status)
	_ = adminLoginTemplate.Execute(w, map[string]string{"Error": errMsg, "TenantID": tenantID})
}

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderAdminLogin(w, "", "invalid form submission")
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
		renderAdminLogin(w, tenantID, "Sign in failed. Check your tenant, email, and password.")
		return
	}
	if err := cookies.Write(w, r, cookies.KindSession, sess.ID); err != nil {
		http.Error(w, "could not set session cookie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, a.adminBasePath, http.StatusSeeOther)
}
