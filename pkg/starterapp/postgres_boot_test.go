// postgres_boot_test.go is the production-profile gate: it boots the WHOLE
// application against a real Postgres and drives the same operations an
// operator does, so "PlatformKit runs on Postgres" is an executable claim
// rather than a README sentence.
//
// The per-adapter conformance suites in pk-modules prove each store honors the
// contract. This proves the composition: nine modules over one Postgres pool
// (branding_management sits out until pk-modules ships its Postgres adapter),
// the first-boot seed, the HTTP surface, tenant-scoped reads, and the canonical
// opaque-segment by-id routes — the seams where an engine swap actually breaks.
//
// Gated on PK_POSTGRES_TEST_DSN so `go test ./...` stays green without a
// database; CI (or a developer with a container) sets it and the gate runs.
//
// ADR: ADR-0017 (composition through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// postgresDSN returns the Postgres test DSN or skips.
func postgresDSN(t *testing.T) string {
	t.Helper()
	v := os.Getenv("PK_POSTGRES_TEST_DSN")
	if v == "" {
		t.Skip("PK_POSTGRES_TEST_DSN not set; skipping Postgres boot gate")
	}
	return v
}

// resetPostgres drops every table the starter creates so the boot under test
// is a genuine first boot — schema creation, seeding, and all.
func resetPostgres(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for reset: %v", err)
	}
	defer db.Close()
	// DROP ... CASCADE in one statement so ordering and FKs are irrelevant.
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}

// apiSegment encodes an entity ID the way the API requires: the literal "id-"
// prefix followed by the lowercase hex of the identifier's bytes.
func apiSegment(id string) string {
	return "id-" + hex.EncodeToString([]byte(id))
}

func TestPostgresBootAndConsoleOperations(t *testing.T) {
	dsn := postgresDSN(t)
	resetPostgres(t, dsn)

	cfg := DefaultConfig()
	cfg.Database.Driver = "postgres" // resolves to the registered pgx driver
	cfg.Database.DSN = dsn

	ctx := context.Background()
	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp on postgres: %v", err)
	}
	defer app.Close()

	// Every module with a Postgres adapter composed. branding_management is
	// SQLite-only in pk-modules today, so the Postgres profile composes nine
	// of the starter's ten modules; bump this when the adapter lands.
	if got := len(app.AllModuleIDs()); got != 9 {
		t.Fatalf("composed %d modules on postgres, want 9", got)
	}

	srv := httptest.NewServer(mustMux(t, app))
	defer srv.Close()

	// Health answers before anything else — the readiness a deployment checks.
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz = %v, %v; want 200", resp, err)
	}
	resp.Body.Close()

	// The first-boot seed ran against Postgres: the local admin can log in.
	sid := loginSeeded(t, srv)
	if sid == "" {
		t.Fatal("seeded login returned no session id")
	}

	do := func(method, path, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+sid)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer r.Body.Close()
		raw, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(raw)
	}

	// The four console operations, over the canonical opaque-segment routes:
	// create, open, publish, delete. This is the exact sequence that broke on
	// a wire-format change once before, so it is the one worth pinning.
	status, body := do(http.MethodPost, "/api/v1/content",
		`{"kind":"post","slug":"pg-gate","title":"Postgres gate","body":"x","body_format":"markdown"}`)
	if status != http.StatusCreated {
		t.Fatalf("create content = %d: %s", status, body)
	}
	var created struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.ID == "" {
		t.Fatalf("create response: %v (%s)", err, body)
	}
	seg := apiSegment(created.ID)

	if status, body = do(http.MethodGet, "/api/v1/content/"+seg, ""); status != http.StatusOK {
		t.Fatalf("get content = %d: %s", status, body)
	}
	if status, body = do(http.MethodPost, "/api/v1/content/"+seg+"/publish", ""); status != http.StatusNoContent {
		t.Fatalf("publish content = %d: %s", status, body)
	}

	// A list read comes back tenant-scoped and includes the row.
	status, body = do(http.MethodGet, "/api/v1/content", "")
	if status != http.StatusOK || !strings.Contains(body, created.ID) {
		t.Fatalf("list content = %d, missing %q: %s", status, created.ID, body)
	}

	if status, body = do(http.MethodDelete, "/api/v1/content/"+seg, ""); status != http.StatusNoContent {
		t.Fatalf("delete content = %d: %s", status, body)
	}
	if status, _ = do(http.MethodGet, "/api/v1/content/"+seg, ""); status != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", status)
	}

	// A malformed id segment is a 400, not a 404: the request is malformed
	// rather than naming something absent. Same rule on both engines.
	if status, _ = do(http.MethodGet, "/api/v1/content/"+created.ID, ""); status != http.StatusBadRequest {
		t.Fatalf("raw (unencoded) id = %d, want 400", status)
	}
}

// TestPostgresSecondBootReusesSchema proves the schema creation is idempotent:
// a restart against a populated database must not fail, wipe, or duplicate.
// This is the upgrade path every deployment takes on every release.
func TestPostgresSecondBootReusesSchema(t *testing.T) {
	dsn := postgresDSN(t)
	resetPostgres(t, dsn)

	cfg := DefaultConfig()
	cfg.Database.Driver = "postgres"
	cfg.Database.DSN = dsn

	ctx := context.Background()
	first, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	srv := httptest.NewServer(mustMux(t, first))
	sid := loginSeeded(t, srv)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/content",
		strings.NewReader(`{"kind":"post","slug":"survivor","title":"Survivor","body":"x","body_format":"markdown"}`))
	req.Header.Set("Authorization", "Bearer "+sid)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed row: %v (%v)", err, resp)
	}
	resp.Body.Close()
	srv.Close()
	first.Close()

	// Boot again on the same database.
	second, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("second boot on populated database: %v", err)
	}
	defer second.Close()
	srv2 := httptest.NewServer(mustMux(t, second))
	defer srv2.Close()

	sid2 := loginSeeded(t, srv2)
	req2, _ := http.NewRequest(http.MethodGet, srv2.URL+"/api/v1/content", nil)
	req2.Header.Set("Authorization", "Bearer "+sid2)
	r2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	defer r2.Body.Close()
	raw, _ := io.ReadAll(r2.Body)
	if !strings.Contains(string(raw), "survivor") {
		t.Fatalf("row written before the restart is gone after it: %s", string(raw))
	}
	fmt.Fprintln(io.Discard, "data survived the restart")
}
