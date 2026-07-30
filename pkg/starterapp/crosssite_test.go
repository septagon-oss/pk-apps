// Validates: REQ-005.
// Per: ADR-0009.
// Discipline: C-14.

package starterapp

// crosssite_test.go pins the CSRF layer, including the case the session
// cookie's SameSite=Lax does NOT cover: a sibling subdomain is same-site, so
// without this check an attacker-influenceable host next to the console could
// forge authenticated mutations.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRejectCrossSiteMutations(t *testing.T) {
	t.Parallel()

	reached := false
	handler := rejectCrossSiteMutations(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		// Safe methods are never state-changing; the handlers enforce that with
		// explicit method switches.
		{"GET cross-site passes", http.MethodGet,
			map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusOK},

		// The console's own fetch: same-origin, cookie-authenticated.
		{"same-origin POST passes", http.MethodPost,
			map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},

		// Typed address / bookmark / restored session — no attacker initiator.
		{"user-initiated POST passes", http.MethodPost,
			map[string]string{"Sec-Fetch-Site": "none"}, http.StatusOK},

		// The classic forgery.
		{"cross-site POST rejected", http.MethodPost,
			map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},

		// The gap SameSite=Lax leaves open: a sibling subdomain is same-site.
		{"same-site POST rejected", http.MethodPost,
			map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"same-site DELETE rejected", http.MethodDelete,
			map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},

		// A bearer token cannot be attached by a cross-site page, so token
		// clients keep working from any origin.
		{"bearer token exempt from origin policy", http.MethodPost,
			map[string]string{"Sec-Fetch-Site": "cross-site", "Authorization": "Bearer abc"}, http.StatusOK},

		// Browsers without fetch metadata: fall back to Origin.
		{"matching Origin passes", http.MethodPost,
			map[string]string{"Origin": "https://console.example.test"}, http.StatusOK},
		{"foreign Origin rejected", http.MethodPost,
			map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"opaque Origin rejected", http.MethodPost,
			map[string]string{"Origin": "null"}, http.StatusForbidden},

		// Neither header: not a browser carrying ambient credentials. The
		// mutation gate behind this middleware still refuses anonymous writes.
		{"no browser headers passes", http.MethodPost, nil, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(tc.method, "/api/v1/content", strings.NewReader("{}"))
			req.Host = "console.example.test"
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if allowed := tc.want == http.StatusOK; reached != allowed {
				t.Fatalf("handler reached = %t, want %t", reached, allowed)
			}
		})
	}
}

// TestOriginMatchesRequestIgnoresScheme documents the deliberate exception: a
// TLS-terminating proxy forwards an https Origin over a plaintext hop, so
// comparing schemes would reject every standard deployment.
func TestOriginMatchesRequestIgnoresScheme(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Host = "console.example.test"

	for _, origin := range []string{
		"https://console.example.test",
		"http://console.example.test",
		"https://CONSOLE.example.test",
	} {
		if !originMatchesRequest(origin, req) {
			t.Errorf("origin %q should match host %q", origin, req.Host)
		}
	}
	for _, origin := range []string{
		"https://console.example.test.evil.example",
		"https://other.example.test",
		"null",
		"",
	} {
		if originMatchesRequest(origin, req) {
			t.Errorf("origin %q must not match host %q", origin, req.Host)
		}
	}
}
