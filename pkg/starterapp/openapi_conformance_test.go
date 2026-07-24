// Package starterapp — openapi_conformance_test.go binds api/openapi.yaml to
// the running app. It walks every path+method the spec declares against a
// booted starter and asserts the observed status is one the spec documents,
// then asserts the walk covered every spec operation — so the spec cannot
// drift from the implementation in either direction: a route added without
// spec coverage fails the coverage check, and a spec entry the app does not
// honor fails the status check.
//
// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
package starterapp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// specOps parses api/openapi.yaml just deeply enough to know, for every
// path+method, which response codes are declared. A hand-rolled line scan
// keeps the module free of a YAML dependency; the spec is authored in this
// repo, so its formatting is under our control.
func specOps(t *testing.T) map[string]map[string]bool {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("open spec: %v", err)
	}
	defer f.Close()

	ops := map[string]map[string]bool{}
	var curPath, curOp string
	pathRe := regexp.MustCompile(`^  (/[^:]*):\s*$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|delete|patch):\s*$`)
	codeRe := regexp.MustCompile(`^        '([0-9]{3})':`)
	inPaths := false

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && len(line) > 0 && line[0] != ' ' && line[0] != '#':
			inPaths = false // left the paths: block (e.g. components:)
		}
		if !inPaths {
			continue
		}
		if m := pathRe.FindStringSubmatch(line); m != nil {
			curPath, curOp = m[1], ""
			continue
		}
		if m := methodRe.FindStringSubmatch(line); m != nil {
			curOp = strings.ToUpper(m[1]) + " " + curPath
			ops[curOp] = map[string]bool{}
			continue
		}
		if curOp != "" {
			if m := codeRe.FindStringSubmatch(line); m != nil {
				ops[curOp][m[1]] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan spec: %v", err)
	}
	if len(ops) == 0 {
		t.Fatal("parsed zero operations from api/openapi.yaml")
	}
	return ops
}

func TestOpenAPISpecVersionMatchesDefaultConfig(t *testing.T) {
	t.Parallel()

	spec, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	match := regexp.MustCompile(`(?m)^  version: (\S+)\s*$`).FindSubmatch(spec)
	if len(match) != 2 {
		t.Fatal("api/openapi.yaml is missing info.version")
	}
	if got, want := string(match[1]), DefaultConfig().AppVersion; got != want {
		t.Fatalf("api/openapi.yaml info.version = %q, want runtime version %q", got, want)
	}
}

func TestOpenAPIPasswordLimitUsesUTF8Bytes(t *testing.T) {
	t.Parallel()

	spec, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	if !strings.Contains(string(spec), "x-max-utf8-bytes: 72") {
		t.Fatal("UserInput.password is missing its 72-byte UTF-8 limit")
	}
	if strings.Contains(string(spec), "maxLength: 72") {
		t.Fatal("password byte limit is incorrectly documented as a character-count maxLength")
	}
}

func TestOpenAPIPasswordMutationDocumentsAdminCapability(t *testing.T) {
	t.Parallel()

	spec, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	if !strings.Contains(
		string(spec),
		"restricted to callers with the reserved `admin` scope",
	) {
		t.Fatal("UserInput.password does not document its administrator-only capability")
	}
	ops := specOps(t)
	for _, operation := range []string{
		"POST /api/v1/users",
		"PUT /api/v1/users/{id}",
	} {
		if !ops[operation]["403"] {
			t.Errorf("%s does not declare the password-capability 403 response", operation)
		}
	}
}

func TestOpenAPIProtectedOperationsDocumentForbidden(t *testing.T) {
	t.Parallel()

	for operation, responses := range specOps(t) {
		parts := strings.SplitN(operation, " ", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed parsed operation %q", operation)
		}
		path := parts[1]
		protected := false
		for _, rule := range builtinAPIScopeRules {
			if path == rule.path || strings.HasPrefix(path, rule.path+"/") {
				protected = true
				break
			}
		}
		if protected && !responses["403"] {
			t.Errorf("%s is scope-protected but does not declare 403", operation)
		}
	}
}

func TestOpenAPISpecMatchesApp(t *testing.T) {
	t.Parallel()
	ops := specOps(t)

	dbPath := filepath.Join(t.TempDir(), "pk.db")
	cfg := DefaultConfig()
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dbPath)
	cfg.HTTP.Addr = ":0"
	app, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	defer app.Close()
	srv := httptest.NewServer(mustMux(t, app))
	defer srv.Close()

	sid := loginSeeded(t, srv)
	covered := map[string]bool{}

	// call sends a request, asserts the spec declares the operation and the
	// observed status, marks the operation covered, and returns the decoded
	// JSON body (nil for non-JSON/no-content responses).
	call := func(method, specPath, realPath, body string, auth bool, want int) map[string]any {
		t.Helper()
		op := method + " " + specPath
		declared, ok := ops[op]
		if !ok {
			t.Fatalf("app exercises %s but the spec does not declare it", op)
		}
		if !declared[fmt.Sprintf("%d", want)] {
			t.Fatalf("%s: test expects %d but the spec does not declare that status (declares %v)", op, want, declared)
		}
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		} else {
			rdr = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, srv.URL+realPath, rdr)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if auth {
			req.Header.Set("Authorization", "Bearer "+sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, realPath, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %d, want %d (spec op %s)", method, realPath, resp.StatusCode, want, op)
		}
		covered[op] = true
		var decoded map[string]any
		if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			_ = json.NewDecoder(resp.Body).Decode(&decoded)
		}
		return decoded
	}
	id := func(m map[string]any, key string) string {
		v, _ := m[key].(string)
		if v == "" {
			t.Fatalf("fixture response missing %q: %v", key, m)
		}
		return v
	}

	// --- health (open) ---
	call("GET", "/healthz", "/healthz", "", false, 200)
	call("GET", "/live", "/live", "", false, 204)
	call("GET", "/ready", "/ready", "", false, 200)

	// --- auth ---
	login := fmt.Sprintf(`{"tenant_id":%q,"email":%q,"password":%q}`, seed.TenantID, seed.UserEmail, seed.UserPass)
	sess2 := call("POST", "/api/v1/auth/sessions", "/api/v1/auth/sessions", login, false, 201)
	call("GET", "/api/v1/auth/sessions/{id}", "/api/v1/auth/sessions/"+sid, "", true, 200)
	call("DELETE", "/api/v1/auth/sessions/{id}", "/api/v1/auth/sessions/"+id(sess2, "id"), "", true, 204)

	// --- tenants (provisioning is a platform op: POST is always 403; a
	// caller may only touch its own tenant, so DELETE runs last) ---
	call("GET", "/api/v1/tenants", "/api/v1/tenants", "", true, 200)
	call("GET", "/api/v1/tenants/{id}", "/api/v1/tenants/"+seed.TenantID, "", true, 200)
	call("POST", "/api/v1/tenants", "/api/v1/tenants", `{"slug":"conf-t","name":"Conformance"}`, true, 403)
	call("PUT", "/api/v1/tenants/{id}", "/api/v1/tenants/"+seed.TenantID, fmt.Sprintf(`{"slug":%q,"name":%q}`, seed.TenantSlug, seed.TenantName), true, 200)

	// --- users ---
	call("GET", "/api/v1/users", "/api/v1/users", "", true, 200)
	u := call("POST", "/api/v1/users", "/api/v1/users", `{"email":"conf@example.test","username":"conf"}`, true, 201)
	call("GET", "/api/v1/users/{id}", "/api/v1/users/"+id(u, "id"), "", true, 200)
	call("PUT", "/api/v1/users/{id}", "/api/v1/users/"+id(u, "id"), `{"email":"conf@example.test","username":"conf","display_name":"Conf"}`, true, 200)
	call("DELETE", "/api/v1/users/{id}", "/api/v1/users/"+id(u, "id"), "", true, 204)

	// --- api keys ---
	k := call("POST", "/api/v1/api-keys", "/api/v1/api-keys", `{"name":"conf-key","scopes":["content:read"]}`, true, 201)
	call("GET", "/api/v1/api-keys", "/api/v1/api-keys", "", true, 200)
	key, _ := k["key"].(map[string]any)
	if key == nil {
		t.Fatal("issue response missing key object")
	}
	call("DELETE", "/api/v1/api-keys/{id}", "/api/v1/api-keys/"+id(key, "id"), "", true, 204)

	// --- audit (read-only) ---
	call("GET", "/api/v1/audit-events", "/api/v1/audit-events?limit=5", "", true, 200)

	// --- content ---
	c := call("POST", "/api/v1/content", "/api/v1/content", `{"kind":"post","slug":"conf","title":"Conf","body":"x"}`, true, 201)
	call("GET", "/api/v1/content", "/api/v1/content?kind=post", "", true, 200)
	call("GET", "/api/v1/content/{id}", "/api/v1/content/"+id(c, "id"), "", true, 200)
	call("PUT", "/api/v1/content/{id}", "/api/v1/content/"+id(c, "id"), `{"kind":"post","slug":"conf","title":"Conf 2","body":"y"}`, true, 200)
	call("POST", "/api/v1/content/{id}/publish", "/api/v1/content/"+id(c, "id")+"/publish", "", true, 204)
	call("POST", "/api/v1/content/{id}/unpublish", "/api/v1/content/"+id(c, "id")+"/unpublish", "", true, 204)
	call("DELETE", "/api/v1/content/{id}", "/api/v1/content/"+id(c, "id"), "", true, 204)

	// --- notifications (snake_case JSON, consistent with the rest of the API) ---
	n := call("POST", "/api/v1/notifications", "/api/v1/notifications", `{"title":"Conf","body":"hello"}`, true, 201)
	call("GET", "/api/v1/notifications", "/api/v1/notifications", "", true, 200)
	call("POST", "/api/v1/notifications/{id}/read", "/api/v1/notifications/"+id(n, "id")+"/read", "", true, 204)
	s := call("POST", "/api/v1/notification-subscriptions", "/api/v1/notification-subscriptions", `{"channel":"in_app","category":"system"}`, true, 201)
	call("DELETE", "/api/v1/notification-subscriptions/{id}", "/api/v1/notification-subscriptions/"+id(s, "id"), "", true, 204)

	// --- tenant delete last: a caller may only delete its own tenant, and
	// after that the walk is over ---
	call("DELETE", "/api/v1/tenants/{id}", "/api/v1/tenants/"+seed.TenantID, "", true, 204)

	// --- coverage: every spec operation must have been exercised ---
	for op := range ops {
		if !covered[op] {
			t.Errorf("spec declares %s but the conformance walk never exercised it", op)
		}
	}
}
