// Implements: REQ-005.
// Per: ADR-0009.
// Discipline: C-14.

// identity.go owns the request-identity wiring for the starter app: the
// resolvers that turn a session cookie, a session bearer token, or an API-key
// bearer token into an identity.Principal, and the middleware that enforces
// authentication on the mutating API surface. Without this file the modules'
// per-request tenant scoping has no principal to read, so it is the piece that
// turns the composed modules into an actually-authenticated application.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

import (
	"net/http"
	"strings"

	"github.com/septagon-oss/pk-core/pkg/security/cookies"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-modules/pkg/apikey"
	"github.com/septagon-oss/pk-modules/pkg/auth"
)

// sessionCookieName is the name of the cookie the browser login flow sets and
// the session resolver reads. It comes from the pk-core cookies registry so
// the name and security profile (HttpOnly, SameSite, Secure-when-TLS) stay in
// one place.
func sessionCookieName() string {
	if name, err := cookies.Name(cookies.KindSession); err == nil {
		return name
	}
	return "pk_session"
}

// bearerToken returns the token from an "Authorization: Bearer <token>"
// header, or "" when the header is absent or malformed.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// newSessionResolver resolves identity from a session presented either as the
// session cookie or as an Authorization: Bearer <session-id> header. A missing
// or invalid/expired session yields an anonymous principal with a nil error,
// so public routes still serve and a stale cookie degrades to logged-out
// rather than hard-failing; protected handlers reject anonymous callers
// themselves via the tenant they require.
func newSessionResolver(svc auth.AuthService) identity.ResolverFunc {
	cookieName := sessionCookieName()
	return func(r *http.Request) (identity.Principal, error) {
		sid := ""
		if c, err := r.Cookie(cookieName); err == nil {
			sid = c.Value
		}
		if sid == "" {
			sid = bearerToken(r)
		}
		if sid == "" {
			return identity.Principal{}, nil
		}
		sess, err := svc.ValidateSession(r.Context(), sid)
		if err != nil || sess == nil {
			return identity.Principal{}, nil
		}
		return identity.Principal{
			Subject:    sess.UserID,
			TenantID:   sess.TenantID,
			AuthMethod: "session",
		}, nil
	}
}

// newAPIKeyResolver resolves identity from an Authorization: Bearer <api-key>
// header. A token that is not in API-key format, or that fails verification,
// yields an anonymous principal so the resolver chain falls through to the
// session resolver. The key carries its own tenant, which is why API-key
// lookup is (correctly) global: the credential itself selects the tenant.
func newAPIKeyResolver(svc apikey.APIKeyService) identity.ResolverFunc {
	return func(r *http.Request) (identity.Principal, error) {
		tok := bearerToken(r)
		if tok == "" {
			return identity.Principal{}, nil
		}
		key, err := svc.Verify(r.Context(), tok)
		if err != nil || key == nil {
			return identity.Principal{}, nil
		}
		return identity.Principal{
			Subject:    key.UserID,
			TenantID:   key.TenantID,
			AuthMethod: "api_key",
		}, nil
	}
}

// isMutation reports whether an HTTP method changes state.
func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// isLoginRequest reports whether r is the one endpoint that MUST accept an
// anonymous mutation: POST to the auth sessions collection (login). It is an
// exact method+path match — NOT a prefix over the whole /api/v1/auth/ subtree —
// so anonymous logout (DELETE /api/v1/auth/sessions/{id}) and any other auth
// mutation are NOT exempt and fail closed at the gate.
func isLoginRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	return strings.TrimSuffix(r.URL.Path, "/") == "/api/v1/auth/sessions"
}

// requireAuthenticated wraps a handler so only an authenticated (non-anonymous)
// principal reaches it. Used for operator surfaces like /metrics that would
// otherwise leak process internals (expvar exposes cmdline and memstats) to any
// unauthenticated caller.
func requireAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity.PrincipalFromContext(r.Context()).IsAnonymous() {
			http.Error(w, "unauthorized: authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuthenticatedMutations blocks anonymous state-changing requests to the
// /api/v1 surface as defense in depth: even if a handler forgets to scope by
// tenant, an unauthenticated mutation fails closed here with 401. Only the
// login endpoint is exempt, because a caller cannot hold a session before it
// authenticates.
func requireAuthenticatedMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutation(r.Method) &&
			strings.HasPrefix(r.URL.Path, "/api/v1/") &&
			!isLoginRequest(r) &&
			identity.PrincipalFromContext(r.Context()).IsAnonymous() {
			http.Error(w, "unauthorized: authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
