// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/septagon-oss/pk-modules/pkg/portslib"

	"github.com/septagon-oss/pk-apps/pkg/starterapp"
)

func TestPollExtensionReleaseJourney(t *testing.T) {
	t.Parallel()
	cfg := starterapp.DefaultConfig()
	cfg.HTTP.Addr = "127.0.0.1:0"
	cfg.Database.DSN = "file:" + filepath.Join(t.TempDir(), "platformkit.db") +
		"?_pragma=busy_timeout(5000)&cache=shared&mode=rwc"
	app, err := starterapp.BuildApp(
		context.Background(),
		cfg,
		starterapp.WithModules(buildPollModule),
	)
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	t.Cleanup(func() {
		if err := app.Close(); err != nil {
			t.Errorf("app.Close: %v", err)
		}
	})
	handler, err := app.Mux()
	if err != nil {
		t.Fatalf("Mux: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	sessionID := login(t, server.Client(), server.URL)
	apiKey := issueAPIKey(t, server.Client(), server.URL, sessionID)

	ready := doRequest(t, server.Client(), http.MethodGet, server.URL+"/ready", "", nil)
	assertStatus(t, ready, http.StatusOK)
	if !bytes.Contains(ready.body, []byte(`"modules":"11"`)) {
		t.Fatalf("/ready does not include extension module: %s", ready.body)
	}

	created := doRequest(
		t,
		server.Client(),
		http.MethodPost,
		server.URL+"/api/v1/polls",
		apiKey,
		map[string]any{
			"slug":        "release-decision",
			"title":       "What should ship next?",
			"description": "Choose the next public investment.",
			"options":     []string{"Documentation", "SDK", "Dashboard"},
		},
	)
	assertStatus(t, created, http.StatusCreated)
	var poll struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	decodeResponse(t, created.body, &poll)
	if poll.ID == "" || poll.Status != "draft" {
		t.Fatalf("created poll = %+v", poll)
	}

	draftPage := doRequest(
		t, server.Client(), http.MethodGet,
		server.URL+"/polls/release-decision", "", nil,
	)
	assertStatus(t, draftPage, http.StatusNotFound)

	published := doRequest(
		t,
		server.Client(),
		http.MethodPost,
		server.URL+"/api/v1/polls/"+encodeID(t, poll.ID)+"/publish",
		apiKey,
		nil,
	)
	assertStatus(t, published, http.StatusOK)

	page := doRequest(
		t, server.Client(), http.MethodGet,
		server.URL+"/polls/release-decision", "", nil,
	)
	assertStatus(t, page, http.StatusOK)
	if !strings.Contains(page.contentType, "text/html") ||
		!bytes.Contains(page.body, []byte("What should ship next?")) ||
		!bytes.Contains(page.body, []byte(`name="option_index"`)) {
		t.Fatalf("public voting page is incomplete: type=%q body=%s", page.contentType, page.body)
	}

	publicJSON := doRequest(
		t, server.Client(), http.MethodGet,
		server.URL+"/api/v1/public/polls/release-decision", "", nil,
	)
	assertStatus(t, publicJSON, http.StatusOK)
	var publicResult struct {
		Poll map[string]any `json:"poll"`
	}
	decodeResponse(t, publicJSON.body, &publicResult)
	for _, privateField := range []string{"id", "tenant_id", "author_id"} {
		if _, leaked := publicResult.Poll[privateField]; leaked {
			t.Fatalf("public API leaks %q: %s", privateField, publicJSON.body)
		}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	voter := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	formRequest, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/polls/release-decision/vote",
		strings.NewReader("option_index=0&company="),
	)
	if err != nil {
		t.Fatal(err)
	}
	formRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formResponse, err := voter.Do(formRequest)
	if err != nil {
		t.Fatalf("form vote: %v", err)
	}
	formResponse.Body.Close()
	if formResponse.StatusCode != http.StatusSeeOther ||
		formResponse.Header.Get("Location") != "/polls/release-decision?voted=1" {
		t.Fatalf(
			"form vote = %d location %q, want 303 success redirect",
			formResponse.StatusCode,
			formResponse.Header.Get("Location"),
		)
	}
	voter.CheckRedirect = nil
	confirmation := doRequest(
		t,
		voter,
		http.MethodGet,
		server.URL+"/polls/release-decision?voted=1",
		"",
		nil,
	)
	assertStatus(t, confirmation, http.StatusOK)
	if !bytes.Contains(confirmation.body, []byte("Your ballot was recorded")) {
		t.Fatalf("form confirmation is missing: %s", confirmation.body)
	}
	changed := doRequest(
		t,
		voter,
		http.MethodPost,
		server.URL+"/api/v1/public/polls/release-decision/votes",
		"",
		map[string]any{"option_index": 1},
	)
	assertVote(t, changed, 1, "1")
	changedAgain := doRequest(
		t,
		voter,
		http.MethodPost,
		server.URL+"/api/v1/public/polls/release-decision/votes",
		"",
		map[string]any{"option_index": 2},
	)
	assertVote(t, changedAgain, 1, "2")

	closed := doRequest(
		t,
		server.Client(),
		http.MethodPost,
		server.URL+"/api/v1/polls/"+encodeID(t, poll.ID)+"/close",
		apiKey,
		nil,
	)
	assertStatus(t, closed, http.StatusOK)
	afterClose := doRequest(
		t,
		voter,
		http.MethodPost,
		server.URL+"/api/v1/public/polls/release-decision/votes",
		"",
		map[string]any{"option_index": 2},
	)
	assertStatus(t, afterClose, http.StatusConflict)

	spec := doRequest(
		t, server.Client(), http.MethodGet,
		server.URL+"/openapi/extensions.json", "", nil,
	)
	assertStatus(t, spec, http.StatusOK)
	if !bytes.Contains(spec.body, []byte(`"/api/v1/public/polls/{slug}/votes"`)) ||
		!bytes.Contains(spec.body, []byte(`"operationId":"polls.publicVote"`)) {
		t.Fatalf("extension OpenAPI is missing public voting: %s", spec.body)
	}

	auditLog := doRequest(
		t,
		server.Client(),
		http.MethodGet,
		server.URL+"/api/v1/audit-events?limit=100",
		sessionID,
		nil,
	)
	assertStatus(t, auditLog, http.StatusOK)
	for _, action := range []string{"poll.created", "poll.published", "poll.closed"} {
		if !bytes.Contains(auditLog.body, []byte(action)) {
			t.Errorf("audit log missing %q: %s", action, auditLog.body)
		}
	}
}

type response struct {
	status      int
	contentType string
	body        []byte
}

func login(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	result := doRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/api/v1/auth/sessions",
		"",
		map[string]any{
			"tenant_id": "tenant_local",
			"email":     "operator@local.test",
			"password":  "local-development-only",
		},
	)
	assertStatus(t, result, http.StatusCreated)
	var session struct {
		ID string `json:"id"`
	}
	decodeResponse(t, result.body, &session)
	if session.ID == "" {
		t.Fatal("login returned an empty session id")
	}
	return session.ID
}

func issueAPIKey(t *testing.T, client *http.Client, baseURL, sessionID string) string {
	t.Helper()
	result := doRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/api/v1/api-keys",
		sessionID,
		map[string]any{
			"name":   "poll-release-test",
			"scopes": []string{"polls:read", "polls:write"},
		},
	)
	assertStatus(t, result, http.StatusCreated)
	var issued struct {
		Plaintext string `json:"plaintext"`
	}
	decodeResponse(t, result.body, &issued)
	if issued.Plaintext == "" {
		t.Fatal("API key issue returned an empty plaintext")
	}
	return issued.Plaintext
}

func doRequest(
	t *testing.T,
	client *http.Client,
	method,
	url,
	bearer string,
	body any,
) response {
	t.Helper()
	var reader io.Reader
	switch value := body.(type) {
	case nil:
	case io.Reader:
		reader = value
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	result, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer result.Body.Close()
	payload, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, url, err)
	}
	return response{
		status:      result.StatusCode,
		contentType: result.Header.Get("Content-Type"),
		body:        payload,
	}
}

func assertStatus(t *testing.T, got response, want int) {
	t.Helper()
	if got.status != want {
		t.Fatalf("status = %d, want %d; body=%s", got.status, want, got.body)
	}
}

func assertVote(t *testing.T, got response, wantTotal int, wantOption string) {
	t.Helper()
	assertStatus(t, got, http.StatusOK)
	var result struct {
		Total int            `json:"total"`
		Votes map[string]int `json:"votes"`
	}
	decodeResponse(t, got.body, &result)
	if result.Total != wantTotal || result.Votes[wantOption] != 1 {
		t.Fatalf("vote result=%s, want total=%d option %s=1", got.body, wantTotal, wantOption)
	}
}

func decodeResponse(t *testing.T, payload []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatalf("decode %s: %v", payload, err)
	}
}

// encodeID renders an entity id as the canonical opaque path segment the API
// requires, which is the form a client puts on the wire.
func encodeID(t *testing.T, id string) string {
	t.Helper()
	segment, ok := portslib.EncodeEntityID(id)
	if !ok {
		t.Fatalf("encode entity id %q", id)
	}
	return segment
}
