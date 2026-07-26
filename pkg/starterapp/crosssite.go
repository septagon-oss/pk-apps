// Implements: REQ-005.
// Per: ADR-0009, ADR-0029.
// Discipline: C-14.

package starterapp

// crosssite.go rejects cross-site state-changing requests that rely on an
// ambient browser credential — the CSRF layer.
//
// Why this exists when the session cookie is already SameSite=Lax: Lax stops a
// cross-SITE POST, and that is the common attack, but "site" is registrable
// domain (eTLD+1), not origin. Any sibling subdomain is same-site, so a
// deployment that serves customer content, a preview host, or anything
// attacker-influenceable next to the console can still forge authenticated
// mutations. Lax was also the ONLY barrier: nothing failed if a later route
// accepted a mutation on GET, or if the cookie profile ever changed. One
// browser attribute should not be the whole defense for a multi-tenant SaaS.
//
// The check is deliberately narrow, because breadth here breaks real clients:
//
//   - Safe methods pass. GET/HEAD/OPTIONS must not change state; the built-in
//     handlers enforce that with explicit method switches.
//   - Requests carrying an Authorization header pass. A bearer token is not an
//     ambient credential — a cross-site page cannot attach one — so
//     token-authenticated clients (SPAs on another host, mobile apps, CI,
//     curl) are unaffected by origin policy.
//   - Everything else is a browser relying on cookies. It must be same-origin.
//
// Fetch metadata is preferred (Sec-Fetch-Site states the relationship
// directly); Origin is the fallback for browsers that do not send it. A
// request with neither header is not a browser carrying ambient credentials,
// so it passes — this middleware is not an authentication check, and the
// mutation gate behind it still refuses anonymous writes.

import (
	"net/http"
	"strings"
)

// safeHTTPMethod reports whether the method is read-only by contract.
func safeHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// rejectCrossSiteMutations blocks unsafe cross-origin requests that depend on
// cookies. See the file comment for the exemptions and why each one is safe.
func rejectCrossSiteMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeHTTPMethod(r.Method) || r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}

		switch r.Header.Get("Sec-Fetch-Site") {
		case "same-origin":
			next.ServeHTTP(w, r)
			return
		case "none":
			// User-initiated: typed address, bookmark, or a restored session.
			// There is no attacker-controlled initiator.
			next.ServeHTTP(w, r)
			return
		case "same-site", "cross-site":
			// same-site is rejected on purpose: it is exactly the sibling-subdomain
			// case SameSite=Lax permits.
			http.Error(w, "forbidden: cross-site state-changing request", http.StatusForbidden)
			return
		}

		// No fetch metadata. Fall back to Origin when the browser sent one.
		if origin := r.Header.Get("Origin"); origin != "" && !originMatchesRequest(origin, r) {
			http.Error(w, "forbidden: cross-origin state-changing request", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originMatchesRequest reports whether an Origin header names the host this
// request was addressed to. Scheme is not compared: a TLS-terminating proxy
// commonly forwards an https origin over a plaintext hop, and rejecting that
// would break every standard deployment.
func originMatchesRequest(origin string, r *http.Request) bool {
	host := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	if host == origin {
		// Not an http(s) origin — "null" (sandboxed iframe, file://) or a custom
		// scheme. Never treat it as our own host.
		return false
	}
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	return strings.EqualFold(host, r.Host)
}
