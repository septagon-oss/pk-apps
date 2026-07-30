// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkmodule "github.com/septagon-oss/pk-core/pkg/module"
	"github.com/septagon-oss/pk-core/pkg/security/identity"
	"github.com/septagon-oss/pk-modules/pkg/audit"
	"github.com/septagon-oss/pk-modules/pkg/portslib"

	_ "modernc.org/sqlite"
)

var fixedNow = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

func TestComposeUsesPublishedPortContractVersions(t *testing.T) {
	t.Parallel()

	_, store := newTestStore(t)
	module, err := NewModule(WithStore(store))
	if err != nil {
		t.Fatalf("NewModule: %v", err)
	}
	composed := module.Compose()
	if got := composed.Metadata().Version; got != ModuleVersion {
		t.Fatalf("module version = %q, want %q", got, ModuleVersion)
	}
	wantVersions := map[string]string{
		pkmodule.PortOf[audit.AuditService]("").Name:       audit.ModuleVersion,
		pkmodule.PortOf[portslib.AdminRegistrar]("").Name:  portslib.AdminRegistrarContractVersion,
		pkmodule.PortOf[portslib.HealthRegistrar]("").Name: "0.0.0",
	}
	dependencies := composed.Dependencies()
	if len(dependencies) != len(wantVersions) {
		t.Fatalf("dependency count = %d, want %d", len(dependencies), len(wantVersions))
	}
	for _, dependency := range dependencies {
		want, ok := wantVersions[dependency.Port.Name]
		if !ok {
			t.Errorf("unexpected dependency %s", dependency.Port.Name)
			continue
		}
		if dependency.Port.Version != want {
			t.Errorf(
				"%s contract version = %q, want %q",
				dependency.Port.Name,
				dependency.Port.Version,
				want,
			)
		}
	}
}

func TestPollValidationRejectsUnusablePolls(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		poll Poll
	}{
		{name: "missing slug", poll: Poll{Title: "Question", Options: []string{"A", "B"}}},
		{name: "invalid slug", poll: Poll{Slug: "Not A Slug", Title: "Question", Options: []string{"A", "B"}}},
		{name: "missing title", poll: Poll{Slug: "question", Options: []string{"A", "B"}}},
		{name: "one option", poll: Poll{Slug: "question", Title: "Question", Options: []string{"A"}}},
		{name: "duplicate options", poll: Poll{Slug: "question", Title: "Question", Options: []string{"Same", "same"}}},
		{name: "long description", poll: Poll{Slug: "question", Title: "Question", Description: strings.Repeat("x", maxDescriptionRunes+1), Options: []string{"A", "B"}}},
		{name: "past close", poll: Poll{Slug: "question", Title: "Question", Options: []string{"A", "B"}, ClosesAt: timePointer(time.Now().Add(-time.Hour))}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.poll.normalizeAndValidate(); err == nil {
				t.Fatal("normalizeAndValidate() error = nil")
			}
		})
	}
}

func TestFreshSchemaAppliesEveryAppendOnlyMigration(t *testing.T) {
	t.Parallel()
	db, store := newTestStore(t)
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM poll_schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != 3 {
		t.Fatalf("applied migrations = %d, want 3", count)
	}
	first, err := store.VoterSecret(context.Background())
	if err != nil {
		t.Fatalf("first VoterSecret: %v", err)
	}
	second, err := store.VoterSecret(context.Background())
	if err != nil {
		t.Fatalf("second VoterSecret: %v", err)
	}
	if !bytes.Equal(first, second) || len(first) != 32 {
		t.Fatal("voter secret was not persisted stably")
	}
}

func TestLegacyRuntimeSchemaUpgradesWithoutLosingPolls(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	_, err := db.Exec(`
		CREATE TABLE poll_polls (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL, options TEXT NOT NULL, author_id TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE TABLE poll_votes (
			poll_id TEXT NOT NULL, option_index INTEGER NOT NULL, voter_id TEXT NOT NULL,
			PRIMARY KEY (poll_id, voter_id)
		);
		INSERT INTO poll_polls
			(id, tenant_id, slug, title, options, author_id, created_at)
		VALUES
			('legacy', 'tenant', 'legacy-poll', 'Legacy?', '["Yes","No"]', 'author',
			 '2026-01-01T00:00:00Z');
	`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("upgrade legacy schema: %v", err)
	}
	poll, err := store.Get(context.Background(), "tenant", "legacy")
	if err != nil {
		t.Fatalf("get migrated poll: %v", err)
	}
	if poll.Status != StatusPublished || poll.UpdatedAt.IsZero() {
		t.Fatalf("legacy poll was not upgraded as published: %+v", poll)
	}
}

func TestLegacyDuplicatePublicSlugsBlockMigrationActionably(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	_, err := db.Exec(`
		CREATE TABLE poll_polls (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, slug TEXT NOT NULL,
			title TEXT NOT NULL, options TEXT NOT NULL, author_id TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		INSERT INTO poll_polls VALUES
			('one', 'tenant-a', 'same', 'One?', '["A","B"]', 'author-a', '2026-01-01T00:00:00Z'),
			('two', 'tenant-b', 'same', 'Two?', '["A","B"]', 'author-b', '2026-01-01T00:00:00Z');
	`)
	if err != nil {
		t.Fatalf("create duplicate legacy schema: %v", err)
	}
	_, err = NewSQLiteStore(db)
	if err == nil || !strings.Contains(err.Error(), `public slug "same" appears 2 times`) ||
		!strings.Contains(err.Error(), "rename duplicate slugs") {
		t.Fatalf("migration error = %v, want actionable duplicate-slug guidance", err)
	}
}

func TestLifecycleAuditPaginationAndPublicBoundary(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	recorder := &auditRecorder{}
	service := NewService(store, recorder)
	service.now = func() time.Time { return fixedNow }
	ctx := context.Background()

	for index := 0; index < 3; index++ {
		poll := &Poll{
			TenantID:    "tenant",
			AuthorID:    "author",
			Slug:        fmt.Sprintf("poll-%d", index),
			Title:       fmt.Sprintf("Question %d?", index),
			Description: "A useful decision.",
			Options:     []string{"Yes", "No"},
		}
		if err := service.Create(ctx, poll); err != nil {
			t.Fatalf("Create(%d): %v", index, err)
		}
	}
	page, err := service.List(ctx, "tenant", 2, 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Items) != 2 || page.Total != 3 || page.Offset != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}

	poll := page.Items[0]
	if _, err := service.GetPublicBySlug(ctx, poll.Slug); !errors.Is(err, ErrNotFound) {
		t.Fatalf("draft public lookup error = %v, want not found", err)
	}
	published, err := service.Transition(
		ctx, "tenant", "author", false, poll.ID, StatusPublished,
	)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := service.GetPublicBySlug(ctx, published.Slug); err != nil {
		t.Fatalf("published public lookup: %v", err)
	}
	if _, _, err := service.Vote(ctx, published.Slug, 0, "browser:voter"); err != nil {
		t.Fatalf("Vote: %v", err)
	}
	if _, err := service.Transition(
		ctx, "tenant", "author", false, poll.ID, StatusClosed,
	); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, _, err := service.Vote(ctx, published.Slug, 1, "browser:voter"); !errors.Is(err, ErrClosed) {
		t.Fatalf("vote after close error = %v, want closed", err)
	}
	if _, err := service.Transition(
		ctx, "tenant", "moderator", true, poll.ID, StatusArchived,
	); err != nil {
		t.Fatalf("moderator archive: %v", err)
	}
	if _, err := service.GetPublicBySlug(ctx, published.Slug); !errors.Is(err, ErrNotFound) {
		t.Fatalf("archived public lookup error = %v, want not found", err)
	}

	actions := recorder.actions()
	for _, want := range []string{"poll.created", "poll.published", "poll.closed", "poll.archived"} {
		if !containsString(actions, want) {
			t.Errorf("audit actions %v missing %q", actions, want)
		}
	}
}

func TestAuditOutboxSurvivesDeliveryFailure(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	recorder := &auditRecorder{fail: true}
	service := NewService(store, recorder)
	service.now = func() time.Time { return fixedNow }
	poll := testPoll("durable-audit")
	if err := service.Create(context.Background(), poll); err != nil {
		t.Fatalf("Create must succeed after durable enqueue: %v", err)
	}
	pending, err := store.PendingAudit(context.Background(), 10)
	if err != nil {
		t.Fatalf("PendingAudit: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending audit entries = %d, want 1", len(pending))
	}
	recorder.setFail(false)
	if err := service.FlushAudit(context.Background()); err != nil {
		t.Fatalf("FlushAudit retry: %v", err)
	}
	pending, err = store.PendingAudit(context.Background(), 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after retry = %d, err=%v", len(pending), err)
	}
}

func TestOnlyAuthorOrModeratorCanMutate(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	service := NewService(store, &auditRecorder{})
	service.now = func() time.Time { return fixedNow }
	poll := testPoll("ownership")
	if err := service.Create(context.Background(), poll); err != nil {
		t.Fatal(err)
	}
	input := PollUpdate{
		Slug: "ownership", Title: "Changed?", Options: []string{"Yes", "No"},
	}
	if _, err := service.Update(
		context.Background(), "tenant", "other", false, poll.ID, input,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-author update error = %v, want forbidden", err)
	}
	if _, err := service.Update(
		context.Background(), "tenant", "moderator", true, poll.ID, input,
	); err != nil {
		t.Fatalf("moderator update: %v", err)
	}
}

func TestConcurrentBallotChangesRemainOneVote(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	service := NewService(store, &auditRecorder{})
	service.now = func() time.Time { return fixedNow }
	poll := testPoll("concurrent")
	if err := service.Create(context.Background(), poll); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transition(
		context.Background(), "tenant", "author", false, poll.ID, StatusPublished,
	); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for index := 0; index < 24; index++ {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := service.Vote(
				context.Background(), poll.Slug, index%2, "browser:one-voter",
			)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent vote: %v", err)
		}
	}
	counts, err := service.Results(context.Background(), poll)
	if err != nil {
		t.Fatal(err)
	}
	if got := sumCounts(counts); got != 1 {
		t.Fatalf("concurrent total = %d, want one current ballot", got)
	}
}

func TestManagementHandlerEnforcesPollScopesAndStrictJSON(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	service := NewService(store, &auditRecorder{})
	service.now = func() time.Time { return fixedNow }
	secret, err := store.VoterSecret(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, secret)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"slug":"scoped","title":"Scoped?","options":["Yes","No"]}`

	readOnly := identity.Principal{
		Subject: "reader", TenantID: "tenant", Scopes: []string{"polls:read"},
	}
	rec := serveWithPrincipal(handler, http.MethodPost, APIPath, body, readOnly)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read-only create = %d, want 403", rec.Code)
	}

	writer := identity.Principal{
		Subject: "writer", TenantID: "tenant", Scopes: []string{"polls:write"},
	}
	rec = serveWithPrincipal(handler, http.MethodPost, APIPath, body, writer)
	if rec.Code != http.StatusCreated {
		t.Fatalf("write-scoped create = %d: %s", rec.Code, rec.Body.String())
	}
	rec = serveWithPrincipal(handler, http.MethodGet, APIPath, "", writer)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("write-only list = %d, want 403", rec.Code)
	}
	rec = serveWithPrincipal(
		handler,
		http.MethodPost,
		APIPath,
		`{"slug":"bad","title":"Bad?","options":["A","B"],"unknown":true}`,
		writer,
	)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown field") {
		t.Fatalf("unknown JSON field response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestSignedVoterCookieRejectsTampering(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	service := NewService(store, nil)
	secret, err := store.VoterSecret(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, secret)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/polls/example/vote", nil)
	rec := httptest.NewRecorder()
	voterID, err := handler.voterIdentity(rec, req)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !strings.HasPrefix(voterID, "browser:") {
		t.Fatalf("voter identity=%q cookies=%v", voterID, cookies)
	}
	valid := httptest.NewRequest(http.MethodGet, "/polls/example", nil)
	valid.AddCookie(cookies[0])
	if got := handler.existingVoterIdentity(valid); got != voterID {
		t.Fatalf("signed cookie resolved to %q, want %q", got, voterID)
	}
	tampered := *cookies[0]
	tampered.Value += "tampered"
	bad := httptest.NewRequest(http.MethodGet, "/polls/example", nil)
	bad.AddCookie(&tampered)
	if got := handler.existingVoterIdentity(bad); got != "" {
		t.Fatalf("tampered cookie resolved to %q", got)
	}
}

func TestVoteLimiterBoundsBurstAndReturnsRetryWindow(t *testing.T) {
	t.Parallel()
	limiter := newVoteLimiter()
	for attempt := 0; attempt < voteLimitPerWindow; attempt++ {
		if allowed, _ := limiter.allow("network", fixedNow); !allowed {
			t.Fatalf("attempt %d was rejected before limit", attempt)
		}
	}
	allowed, retry := limiter.allow("network", fixedNow)
	if allowed || retry != voteLimitWindow {
		t.Fatalf("over-limit result = allowed:%v retry:%v", allowed, retry)
	}
	if allowed, _ := limiter.allow("network", fixedNow.Add(voteLimitWindow)); !allowed {
		t.Fatal("new rate-limit window did not reset")
	}
}

func TestPublicPageIsResponsiveAccessibleAndRedacted(t *testing.T) {
	t.Parallel()
	poll := testPoll("public-page")
	poll.Status = StatusPublished
	poll.ID = "private-id"
	poll.TenantID = "private-tenant"
	poll.Description = "Context for the choice."
	view := buildPublicPageView(poll, map[int]int{0: 3, 1: 1}, 0, true, fixedNow)
	rec := httptest.NewRecorder()
	writePublicPage(rec, http.StatusOK, view)
	body := rec.Body.String()
	for _, marker := range []string{
		`name="viewport"`,
		`<fieldset>`,
		`required`,
		`prefers-reduced-motion`,
		`<progress`,
		`your vote`,
		`.choice input{position:absolute;z-index:1;inset:0;width:100%;height:100%`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("public page missing %q", marker)
		}
	}
	for _, private := range []string{"private-id", "private-tenant", "author"} {
		if strings.Contains(body, private) {
			t.Errorf("public page leaked %q", private)
		}
	}
}

func TestAdminContributionDeclaresTypedLifecycleResource(t *testing.T) {
	t.Parallel()
	recorder := &adminRecorder{}
	if err := registerAdmin(recorder); err != nil {
		t.Fatalf("registerAdmin: %v", err)
	}
	resource := recorder.resource
	if resource.APIPath != APIPath || !resource.CanCreate || !resource.CanEdit {
		t.Fatalf("unexpected admin resource: %+v", resource)
	}
	if len(resource.Columns) < 4 || len(resource.Actions) != 3 {
		t.Fatalf("admin resource lacks useful columns/actions: %+v", resource)
	}
	kinds := make(map[string]portslib.AdminFieldKind)
	for _, field := range resource.Fields {
		kinds[field.Key] = field.Kind
	}
	if kinds["options"] != portslib.AdminFieldTags ||
		kinds["description"] != portslib.AdminFieldTextarea ||
		kinds["closes_at"] != portslib.AdminFieldDateTime {
		t.Fatalf("admin fields are not schema-aware: %v", kinds)
	}
	if resource.EditWhen == nil || resource.EditWhen.Value != StatusDraft ||
		resource.DeleteWhen == nil || resource.DeleteWhen.Value != StatusDraft {
		t.Fatal("admin edit/delete controls are not restricted to draft polls")
	}
	wantActionStatus := []string{StatusDraft, StatusPublished, StatusClosed}
	for index, action := range resource.Actions {
		if action.VisibleWhen == nil || action.VisibleWhen.Value != wantActionStatus[index] {
			t.Errorf(
				"admin action %q condition = %+v, want status %q",
				action.Label,
				action.VisibleWhen,
				wantActionStatus[index],
			)
		}
	}
}

func newTestStore(t *testing.T) (*sql.DB, Store) {
	t.Helper()
	db := openTestDB(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return db, store
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "poll.db") +
		"?_pragma=busy_timeout(5000)&cache=shared&mode=rwc"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("db.Ping: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	})
	return db
}

func testPoll(slug string) *Poll {
	return &Poll{
		TenantID:    "tenant",
		AuthorID:    "author",
		Slug:        slug,
		Title:       "What should we do?",
		Description: "Choose the next step.",
		Options:     []string{"Yes", "No"},
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func serveWithPrincipal(
	handler http.Handler,
	method,
	path,
	body string,
	principal identity.Principal,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request = request.WithContext(identity.ContextWithPrincipal(request.Context(), principal))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

type auditRecorder struct {
	mu     sync.Mutex
	events []*audit.Event
	fail   bool
}

type adminRecorder struct {
	resource portslib.AdminResource
	section  portslib.SidebarSection
}

func (r *adminRecorder) RegisterResource(resource portslib.AdminResource) error {
	r.resource = resource
	return nil
}

func (*adminRecorder) RegisterPage(portslib.AdminPage) error { return nil }

func (r *adminRecorder) RegisterSidebarSection(section portslib.SidebarSection) error {
	r.section = section
	return nil
}

func (r *auditRecorder) Record(_ context.Context, event *audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("audit unavailable")
	}
	cloned := *event
	r.events = append(r.events, &cloned)
	return nil
}

func (r *auditRecorder) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	actions := make([]string, len(r.events))
	for index, event := range r.events {
		actions[index] = event.Action
	}
	return actions
}

func (r *auditRecorder) setFail(value bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = value
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
