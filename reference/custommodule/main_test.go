// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/septagon-oss/pk-apps/pkg/starterapp"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
)

func TestWidgetReferenceDeclaresScopesOpenAPIAndAppendOnlyMigration(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "widgets.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	plugin, err := widgetModule(starterapp.ModuleEnv{DB: db})
	if err != nil {
		t.Fatalf("widgetModule: %v", err)
	}
	if len(plugin.APIKeyScopes) != 2 ||
		plugin.APIKeyScopes[0] != widgetReadScope ||
		plugin.APIKeyScopes[1] != widgetWriteScope {
		t.Fatalf("APIKeyScopes = %v", plugin.APIKeyScopes)
	}
	if len(plugin.OpenAPI) != 3 {
		t.Fatalf("OpenAPI operations = %d, want 3", len(plugin.OpenAPI))
	}
	if _, err := newWidgetStore(db); err != nil {
		t.Fatalf("second migration pass: %v", err)
	}
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM widget_schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("read migration ledger: %v", err)
	}
	if applied != 1 {
		t.Fatalf("applied migrations = %d, want 1", applied)
	}
}

func TestWidgetReferenceEnforcesScopesAndServerOwnedIdentity(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "widgets.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	plugin, err := widgetModule(starterapp.ModuleEnv{DB: db})
	if err != nil {
		t.Fatalf("widgetModule: %v", err)
	}
	mux := http.NewServeMux()
	plugin.RegisterRoutes(mux)

	request := func(method, path, body string, scopes ...string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(identity.ContextWithPrincipal(req.Context(), identity.Principal{
			Subject: "user_1", TenantID: "tenant_1", AuthMethod: "api_key", Scopes: scopes,
		}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := request(http.MethodGet, "/api/v1/widgets", "", "content:read"); rec.Code != http.StatusForbidden {
		t.Fatalf("unrelated scope read = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	createdRec := request(
		http.MethodPost,
		"/api/v1/widgets",
		`{"id":"chosen","tenant_id":"other","owner_id":"other","name":"secure"}`,
		widgetWriteScope,
	)
	if createdRec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201; body=%s", createdRec.Code, createdRec.Body.String())
	}
	var created widget
	if err := json.Unmarshal(createdRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created widget: %v", err)
	}
	if created.ID == "" || created.ID == "chosen" ||
		created.TenantID != "tenant_1" ||
		created.OwnerID != "user_1" {
		t.Fatalf("server-owned widget = %+v", created)
	}
	if rec := request(
		http.MethodPost,
		"/api/v1/widgets",
		`{"name":"typo","unknown":true}`,
		widgetWriteScope,
	); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field create = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if rec := request(
		http.MethodGet,
		"/api/v1/widgets/"+created.ID,
		"",
		widgetReadScope,
	); rec.Code != http.StatusOK {
		t.Fatalf("scoped read = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}
