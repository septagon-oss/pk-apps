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
	"slices"
	"strings"

	"github.com/septagon-oss/pk-core/pkg/security/cookies"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-modules/pkg/apikey"
	"github.com/septagon-oss/pk-modules/pkg/auth"
)

const (
	scopeAuthenticated = "authenticated"
	scopeAdmin         = "admin"
	scopeConsoleAccess = "console:access"
	scopeUsersWrite    = "users:write"
)

var reservedInteractiveScopes = []string{scopeAdmin, scopeConsoleAccess}

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
func newSessionResolver(svc auth.AuthService, adminSubject string) identity.ResolverFunc {
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
		scopes := []string{scopeAuthenticated}
		if sess.UserID == adminSubject {
			scopes = append(scopes, scopeAdmin, scopeConsoleAccess, scopeUsersWrite)
		}
		return identity.Principal{
			Subject:    sess.UserID,
			TenantID:   sess.TenantID,
			AuthMethod: "session",
			Scopes:     scopes,
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
		scopes := make([]string, 0, len(key.Scopes))
		for _, scope := range key.Scopes {
			// Interactive privileges have never belonged on machine
			// credentials. New keys cannot request these scopes; filtering here
			// also makes legacy rows fail closed.
			if slices.Contains(reservedInteractiveScopes, scope) {
				continue
			}
			scopes = append(scopes, scope)
		}
		return identity.Principal{
			Subject:    key.UserID,
			TenantID:   key.TenantID,
			AuthMethod: "api_key",
			Scopes:     scopes,
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

// maxRequestBodyBytes caps every inbound request body. JSON API requests are
// small; 1 MiB is generous and turns an unbounded-body memory-exhaustion DoS
// into a 413.
const maxRequestBodyBytes int64 = 1 << 20

// limitRequestBody caps every request body. Applied once, outermost, so it
// covers every route — including the pre-auth login endpoint and any
// contributed module route. A client that declares an over-cap Content-Length
// gets a clear 413 up front; otherwise http.MaxBytesReader is the hard cap so
// the process never buffers an arbitrarily large body.
func limitRequestBody(max int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fast path: an over-cap Content-Length answers 413 with a clear
		// message. Without this, a handler reading a MaxBytesReader-truncated
		// body surfaces a misleading "invalid JSON" 400 (an evaluator's exact
		// complaint). Covers the common case — curl/fetch/most clients send
		// Content-Length; the MaxBytesReader below still bounds chunked or
		// unknown-length bodies.
		if r.ContentLength > max {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		next.ServeHTTP(w, r)
	})
}

// requireMetricsAccess protects process internals with an explicit capability.
// Administrators inherit access; machine credentials must request metrics:read.
func requireMetricsAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := identity.PrincipalFromContext(r.Context())
		if principal.IsAnonymous() {
			http.Error(w, "unauthorized: authentication required", http.StatusUnauthorized)
			return
		}
		if !principal.HasScope(scopeAdmin) && !principal.HasScope("metrics:read") {
			http.Error(w, "forbidden: metrics:read scope required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiScopeRule struct {
	path     string
	resource string
}

var builtinAPIScopeRules = []apiScopeRule{
	{path: "/api/v1/tenants", resource: "tenants"},
	{path: "/api/v1/users", resource: "users"},
	{path: "/api/v1/audit-events", resource: "audit"},
	{path: "/api/v1/api-keys", resource: "api-keys"},
	{path: "/api/v1/content", resource: "content"},
	{path: "/api/v1/notifications", resource: "notifications"},
}

// authorizeBuiltinAPI gives the starter's built-in data APIs explicit
// read/write capabilities. The seeded administrator bypasses resource scopes;
// API keys and ordinary sessions must carry <resource>:read or
// <resource>:write. Contributed routes remain responsible for their own domain
// authorization because only the extension knows its capability vocabulary.
func authorizeBuiltinAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resource string
		for _, rule := range builtinAPIScopeRules {
			if r.URL.Path == rule.path || strings.HasPrefix(r.URL.Path, rule.path+"/") {
				resource = rule.resource
				break
			}
		}
		if resource == "" {
			next.ServeHTTP(w, r)
			return
		}
		principal := identity.PrincipalFromContext(r.Context())
		if principal.IsAnonymous() {
			http.Error(w, "unauthorized: authentication required", http.StatusUnauthorized)
			return
		}
		scope := resource + ":read"
		if isMutation(r.Method) {
			scope = resource + ":write"
		}
		if !principal.HasScope(scopeAdmin) && !principal.HasScope(scope) {
			http.Error(w, "forbidden: "+scope+" scope required", http.StatusForbidden)
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
