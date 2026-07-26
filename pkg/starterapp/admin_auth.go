// Implements: REQ-005.
// Per: ADR-0009.
// Discipline: C-14.

// admin_auth.go owns the browser-facing login flow that closes the v0.1.0
// open-admin dashboard. guardAdmin requires an authenticated principal to view
// any admin route; anonymous visitors are redirected to a login page rendered
// by the typed view in admin_login_view.go, which authenticates against the
// auth module, sets the HttpOnly session cookie, and redirects back into the
// shell. Logout revokes the session and clears the cookie.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

import (
	"net/http"
	"strings"

	"github.com/septagon-oss/pk-core/pkg/security/cookies"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-modules/pkg/auth"
)

const (
	adminLoginPath  = "/admin/login"
	adminLogoutPath = "/admin/logout"
)

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
				tenantID, email = a.seedTenantID, a.seedEmail
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
	Error           string
	TenantID        string
	Email           string
	AppName         string
	Environment     string
	Development     bool
	BootstrapTenant string
	BootstrapEmail  string
}

func (a *App) renderAdminLogin(w http.ResponseWriter, tenantID, email, errMsg string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	page, err := renderLoginView(adminLoginView{
		Error:           errMsg,
		TenantID:        tenantID,
		Email:           email,
		AppName:         a.appName,
		Environment:     a.environment,
		Development:     a.environment == "development",
		BootstrapTenant: a.seedTenantID,
		BootstrapEmail:  a.seedEmail,
	})
	if err != nil {
		http.Error(w, "could not render sign-in page", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(page)
}

func renderAdminForbidden(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	page, err := renderForbiddenView()
	if err != nil {
		http.Error(w, "insufficient scope", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(page)
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
