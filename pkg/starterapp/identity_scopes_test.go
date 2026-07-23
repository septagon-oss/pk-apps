// Validates: REQ-005.
// Per: ADR-0009.
// Discipline: C-14.
package starterapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/septagon-oss/pk-modules/pkg/apikey"
	"github.com/septagon-oss/pk-modules/pkg/auth"
)

type resolverAuthService struct {
	session *auth.Session
}

func (s resolverAuthService) Login(
	context.Context,
	string,
	auth.Credentials,
) (*auth.Session, error) {
	return nil, errors.New("not implemented")
}

func (s resolverAuthService) Logout(context.Context, string) error { return nil }

func (s resolverAuthService) ValidateSession(context.Context, string) (*auth.Session, error) {
	return s.session, nil
}

func (s resolverAuthService) InvalidateAllSessions(context.Context, string) error {
	return nil
}

type resolverAPIKeyService struct {
	key *apikey.APIKey
}

func (s resolverAPIKeyService) Issue(
	context.Context,
	string,
	string,
	string,
	[]string,
	time.Duration,
) (string, *apikey.APIKey, error) {
	return "", nil, errors.New("not implemented")
}

func (s resolverAPIKeyService) Verify(context.Context, string) (*apikey.APIKey, error) {
	return s.key, nil
}

func (s resolverAPIKeyService) Revoke(context.Context, string, string) error { return nil }

func (s resolverAPIKeyService) List(context.Context, string) ([]*apikey.APIKey, error) {
	return nil, nil
}

func TestSessionResolverGrantsConsoleOnlyToSeededAdministrator(t *testing.T) {
	t.Parallel()

	resolve := func(subject, adminSubject string) []string {
		t.Helper()
		resolver := newSessionResolver(resolverAuthService{session: &auth.Session{
			ID: "session", UserID: subject, TenantID: "tenant",
		}}, adminSubject)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer session")
		principal, err := resolver(req)
		if err != nil {
			t.Fatalf("resolve session: %v", err)
		}
		return principal.Scopes
	}

	ordinary := resolve("ordinary", "admin")
	if containsScope(ordinary, scopeAdmin) || containsScope(ordinary, scopeConsoleAccess) {
		t.Fatalf("ordinary session received console scopes: %v", ordinary)
	}
	if !containsScope(ordinary, scopeAuthenticated) {
		t.Fatalf("ordinary session missing authenticated scope: %v", ordinary)
	}

	adminScopes := resolve("admin", "admin")
	for _, scope := range []string{scopeAuthenticated, scopeAdmin, scopeConsoleAccess, scopeUsersWrite} {
		if !containsScope(adminScopes, scope) {
			t.Fatalf("admin session missing %q: %v", scope, adminScopes)
		}
	}
}

func TestAPIKeyResolverPropagatesModuleScopesAndFiltersInteractiveScopes(t *testing.T) {
	t.Parallel()
	resolver := newAPIKeyResolver(resolverAPIKeyService{key: &apikey.APIKey{
		UserID:   "service",
		TenantID: "tenant",
		Scopes:   []string{"extension:read", scopeAdmin, scopeConsoleAccess},
	}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer pk_example")
	principal, err := resolver(req)
	if err != nil {
		t.Fatalf("resolve API key: %v", err)
	}
	if !principal.HasScope("extension:read") {
		t.Fatalf("module scope was dropped: %v", principal.Scopes)
	}
	if principal.HasScope(scopeAdmin) || principal.HasScope(scopeConsoleAccess) {
		t.Fatalf("machine credential retained interactive scope: %v", principal.Scopes)
	}
}

func containsScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}
