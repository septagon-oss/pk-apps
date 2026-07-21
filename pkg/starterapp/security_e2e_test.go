// Package starterapp — security_e2e_test.go owns the end-to-end authorization
// regression: it drives the fully composed mux over HTTP and proves the two
// properties the v0.1.0 audit found missing at the HTTP boundary — (1) an
// unauthenticated mutation is rejected, and (2) an authenticated caller cannot
// read another tenant's row by ID even though it knows the exact ID. These are
// the exploit-shaped cases that the store-level tests confirm at the data layer
// and this test confirms travel correctly through the real handler + identity
// middleware stack.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

// Validates: REQ-001.
// Per: ADR-0009.
// Discipline: C-14.
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
	"github.com/septagon-oss/pk-modules/pkg/content"
)

func TestCrossTenantAndAnonymousAPIAccessDenied(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"

	ctx := context.Background()
	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	defer app.Close()

	// Plant a content row owned by a DIFFERENT tenant than the seeded admin
	// (whose tenant is seed.TenantID). We write it straight through the service
	// so the HTTP layer is the only thing under test.
	const victimID = "victim-content-1"
	if err := app.contentMod.Service().Create(ctx, &content.Content{
		ID:         victimID,
		TenantID:   "tenant_victim",
		Kind:       "post",
		Slug:       "victim-secret",
		Title:      "victim secret",
		Body:       "confidential",
		BodyFormat: "markdown",
		AuthorID:   "victim-admin",
	}); err != nil {
		t.Fatalf("seed cross-tenant content: %v", err)
	}

	mux, err := app.Mux()
	if err != nil {
		t.Fatalf("Mux: %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// (1) Anonymous mutation is rejected with 401 (defense-in-depth gate).
	anonPost, err := http.Post(srv.URL+"/api/v1/content", "application/json",
		strings.NewReader(`{"kind":"post","slug":"x","title":"x","body":"x"}`))
	if err != nil {
		t.Fatalf("anonymous POST: %v", err)
	}
	anonPost.Body.Close()
	if anonPost.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous POST /api/v1/content = %d, want 401", anonPost.StatusCode)
	}

	// Authenticate as the seeded admin (belongs to seed.TenantID).
	loginBody := fmt.Sprintf(`{"tenant_id":%q,"email":%q,"password":%q}`,
		seed.TenantID, seed.UserEmail, seed.UserPass)
	loginResp, err := http.Post(srv.URL+"/api/v1/auth/sessions", "application/json",
		strings.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	lBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusCreated {
		t.Fatalf("login status = %d, want 201; body=%s", loginResp.StatusCode, string(lBody))
	}
	var session struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(lBody, &session); err != nil || session.ID == "" {
		t.Fatalf("no session id: err=%v body=%s", err, string(lBody))
	}

	authGet := func(path string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+session.ID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// (2) The IDOR: the authenticated admin knows the victim row's exact ID but
	// belongs to a different tenant. The read must be 404 — never the row.
	if code, body := authGet("/api/v1/content/" + victimID); code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET /api/v1/content/%s = %d, want 404; body=%s", victimID, code, body)
	}

	// Sanity: the same authenticated caller CAN reach its own tenant's content
	// surface (200 with an empty list, not 401/404), proving the deny above is
	// tenant scoping and not a blanket failure.
	if code, body := authGet("/api/v1/content"); code != http.StatusOK {
		t.Fatalf("authenticated GET /api/v1/content (own tenant) = %d, want 200; body=%s", code, body)
	}
}
