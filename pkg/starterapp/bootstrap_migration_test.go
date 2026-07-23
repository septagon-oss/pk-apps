// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package starterapp

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/septagon-oss/pk-core/pkg/security/passhash"
	apikeysqlite "github.com/septagon-oss/pk-modules/pkg/apikey/store/sqlite"
	auditsqlite "github.com/septagon-oss/pk-modules/pkg/audit/store/sqlite"
	"github.com/septagon-oss/pk-modules/pkg/auth"
	authsqlite "github.com/septagon-oss/pk-modules/pkg/auth/store/sqlite"
	contentsqlite "github.com/septagon-oss/pk-modules/pkg/content/store/sqlite"
	notificationsqlite "github.com/septagon-oss/pk-modules/pkg/notification/store/sqlite"
	tenantsqlite "github.com/septagon-oss/pk-modules/pkg/tenant/store/sqlite"
	usersqlite "github.com/septagon-oss/pk-modules/pkg/user/store/sqlite"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

func TestBuildAppMigratesLegacyBootstrapIdentityAndOwnedData(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() migration error = %v", err)
	}

	adminUser, err := app.user.Service().Get(ctx, seed.TenantID, seed.UserID)
	if err != nil {
		t.Fatalf("migrated administrator lookup: %v", err)
	}
	if adminUser.Email != seed.UserEmail {
		t.Fatalf("migrated administrator email = %q, want %q", adminUser.Email, seed.UserEmail)
	}
	if app.adminSubject != seed.UserID {
		t.Fatalf("adminSubject = %q, want %q", app.adminSubject, seed.UserID)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		seed.TenantID,
		seed.UserID,
		seed.UserPass,
	); err != nil {
		t.Fatalf("current bootstrap password does not verify: %v", err)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		seed.TenantID,
		seed.UserID,
		legacyBootstrapUserPassword,
	); err == nil {
		t.Fatal("historical bootstrap password still verifies after migration")
	}

	if _, err := app.authMod.Service().Login(ctx, legacyBootstrapTenantID, auth.Credentials{
		Email:    legacyBootstrapUserEmail,
		Password: legacyBootstrapUserPassword,
	}); err == nil {
		t.Fatal("historical bootstrap login still succeeds after migration")
	}
	session, err := app.authMod.Service().Login(ctx, seed.TenantID, auth.Credentials{
		Email:    seed.UserEmail,
		Password: seed.UserPass,
	})
	if err != nil {
		t.Fatalf("current bootstrap login: %v", err)
	}

	mux, err := app.Mux()
	if err != nil {
		t.Fatalf("Mux(): %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+session.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("migrated administrator GET /admin status = %d, want 200", rec.Code)
	}

	assertNoLegacyBootstrapReferences(t, app.db, 2)

	var (
		contentTenant string
		contentAuthor string
		contentBody   string
	)
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT tenant_id, author_id, body FROM content WHERE id = 'content_existing'`,
	).Scan(&contentTenant, &contentAuthor, &contentBody); err != nil {
		t.Fatalf("read migrated content: %v", err)
	}
	if contentTenant != seed.TenantID || contentAuthor != seed.UserID || contentBody != "preserve me" {
		t.Fatalf(
			"migrated content = tenant %q author %q body %q",
			contentTenant,
			contentAuthor,
			contentBody,
		)
	}

	var historicalSessionRevokedAt sql.NullTime
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT revoked_at FROM auth_sessions WHERE id = 'session_existing'`,
	).Scan(&historicalSessionRevokedAt); err != nil {
		t.Fatalf("read migrated historical session: %v", err)
	}
	if !historicalSessionRevokedAt.Valid {
		t.Fatal("session issued under the historical default password was not revoked")
	}

	var markerCount int
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM starterapp_migrations WHERE id = ?`,
		bootstrapIdentityMigrationID,
	).Scan(&markerCount); err != nil {
		t.Fatalf("read migration marker: %v", err)
	}
	if markerCount != 1 {
		t.Fatalf("migration marker count = %d, want 1", markerCount)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("first app Close(): %v", err)
	}

	second, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("second BuildApp() after migration = %v", err)
	}
	defer second.Close()

	var tenantCount, userCount int
	if err := second.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM tenants WHERE id = ?`,
		seed.TenantID,
	).Scan(&tenantCount); err != nil {
		t.Fatalf("count current tenants: %v", err)
	}
	if err := second.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE id = ? AND tenant_id = ?`,
		seed.UserID,
		seed.TenantID,
	).Scan(&userCount); err != nil {
		t.Fatalf("count current administrators: %v", err)
	}
	if tenantCount != 1 || userCount != 1 {
		t.Fatalf("second boot duplicated identity: tenants=%d users=%d", tenantCount, userCount)
	}
}

func TestBootstrapMigrationPreservesCustomizedProductionIdentity(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create customized password hasher: %v", err)
	}
	customPassword := "operator-rotated-password"
	customHash, err := hasher.Hash(customPassword)
	if err != nil {
		t.Fatalf("hash customized password: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open customized fixture: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE tenants SET slug = 'customer-workspace', name = 'Customer Workspace'
		 WHERE id = ?`,
		legacyBootstrapTenantID,
	); err != nil {
		t.Fatalf("customize fixture tenant: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE users
		 SET email = 'owner@customer.test',
		     username = 'owner',
		     display_name = 'Workspace Owner',
		     pass_hash = ?
		 WHERE id = ? AND tenant_id = ?`,
		customHash,
		legacyBootstrapUserID,
		legacyBootstrapTenantID,
	); err != nil {
		t.Fatalf("customize fixture administrator: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close customized fixture: %v", err)
	}

	cfg.Environment = "production"
	cfg.Seed.AdminEmail = "configured-bootstrap@customer.test"
	cfg.Seed.AdminPassword = "configuration-only-password"
	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() customized migration error = %v", err)
	}
	defer app.Close()

	migratedTenant, err := app.tenant.Service().Get(ctx, seed.TenantID)
	if err != nil {
		t.Fatalf("migrated customized tenant lookup: %v", err)
	}
	if migratedTenant.Slug != "customer-workspace" || migratedTenant.Name != "Customer Workspace" {
		t.Fatalf(
			"customized tenant changed to slug=%q name=%q",
			migratedTenant.Slug,
			migratedTenant.Name,
		)
	}

	migratedUser, err := app.user.Service().Get(ctx, seed.TenantID, seed.UserID)
	if err != nil {
		t.Fatalf("migrated customized administrator lookup: %v", err)
	}
	if migratedUser.Email != "owner@customer.test" ||
		migratedUser.Username != "owner" ||
		migratedUser.DisplayName != "Workspace Owner" {
		t.Fatalf(
			"customized administrator changed to email=%q username=%q display=%q",
			migratedUser.Email,
			migratedUser.Username,
			migratedUser.DisplayName,
		)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		seed.TenantID,
		seed.UserID,
		customPassword,
	); err != nil {
		t.Fatalf("customized password was not preserved: %v", err)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		seed.TenantID,
		seed.UserID,
		cfg.Seed.AdminPassword,
	); err == nil {
		t.Fatal("production migration replaced the operator-rotated password")
	}

	var historicalSessionRevokedAt sql.NullTime
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT revoked_at FROM auth_sessions WHERE id = 'session_existing'`,
	).Scan(&historicalSessionRevokedAt); err != nil {
		t.Fatalf("read customized historical session: %v", err)
	}
	if historicalSessionRevokedAt.Valid {
		t.Fatal("migration revoked a session after the bootstrap password had been rotated")
	}

	assertNoLegacyBootstrapReferences(t, app.db, 1)
}

func createLegacyBootstrapFixture(t *testing.T, dsn string) {
	t.Helper()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open legacy fixture: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	storeInitializers := []struct {
		name string
		run  func(*sql.DB) error
	}{
		{"tenant", func(db *sql.DB) error { _, err := tenantsqlite.New(db); return err }},
		{"user", func(db *sql.DB) error { _, err := usersqlite.New(db); return err }},
		{"audit", func(db *sql.DB) error { _, err := auditsqlite.New(db); return err }},
		{"auth", func(db *sql.DB) error { _, err := authsqlite.New(db); return err }},
		{"API key", func(db *sql.DB) error { _, err := apikeysqlite.New(db); return err }},
		{"content", func(db *sql.DB) error { _, err := contentsqlite.New(db); return err }},
		{"notification", func(db *sql.DB) error { _, err := notificationsqlite.New(db); return err }},
	}
	for _, initializer := range storeInitializers {
		if err := initializer.run(db); err != nil {
			t.Fatalf("initialize %s store: %v", initializer.name, err)
		}
	}

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create fixture password hasher: %v", err)
	}
	legacyHash, err := hasher.Hash(legacyBootstrapUserPassword)
	if err != nil {
		t.Fatalf("hash fixture password: %v", err)
	}

	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	inserts := []struct {
		name  string
		query string
		args  []any
	}{
		{
			"tenant",
			`INSERT INTO tenants (id, slug, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			[]any{legacyBootstrapTenantID, legacyBootstrapTenantSlug, legacyBootstrapTenantName, now, now},
		},
		{
			"user",
			`INSERT INTO users
			 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			[]any{
				legacyBootstrapUserID,
				legacyBootstrapTenantID,
				legacyBootstrapUserEmail,
				legacyBootstrapUserName,
				legacyHash,
				legacyBootstrapUserDisplay,
				now,
				now,
			},
		},
		{
			"session",
			`INSERT INTO auth_sessions
			 (id, user_id, tenant_id, issued_at, expires_at, revoked_at)
			 VALUES ('session_existing', ?, ?, ?, ?, NULL)`,
			[]any{legacyBootstrapUserID, legacyBootstrapTenantID, now, expires},
		},
		{
			"API key",
			`INSERT INTO api_keys
			 (id, tenant_id, user_id, name, prefix, hash, scopes, last_used_at, revoked_at, expires_at, created_at)
			 VALUES ('key_existing', ?, ?, 'existing', 'pk_existing', 'hash', 'content:read', NULL, NULL, NULL, ?)`,
			[]any{legacyBootstrapTenantID, legacyBootstrapUserID, now},
		},
		{
			"audit event",
			`INSERT INTO audit_events
			 (id, tenant_id, actor, action, resource, severity, details, emitted_at)
			 VALUES ('audit_existing', ?, ?, 'created', 'content', 'info', 'preserve me', ?)`,
			[]any{legacyBootstrapTenantID, legacyBootstrapUserID, now},
		},
		{
			"content",
			`INSERT INTO content
			 (id, tenant_id, kind, slug, title, body, body_format, author_id, published_at, created_at, updated_at)
			 VALUES ('content_existing', ?, 'post', 'existing', 'Existing', 'preserve me', 'markdown', ?, NULL, ?, ?)`,
			[]any{legacyBootstrapTenantID, legacyBootstrapUserID, now, now},
		},
		{
			"notification",
			`INSERT INTO notifications
			 (id, tenant_id, user_id, title, body, category, severity, data, read_at, emitted_at)
			 VALUES ('notification_existing', ?, ?, 'Existing', 'preserve me', 'system', 'info', '{}', NULL, ?)`,
			[]any{legacyBootstrapTenantID, legacyBootstrapUserID, now},
		},
		{
			"notification subscription",
			`INSERT INTO notification_subscriptions
			 (id, tenant_id, user_id, category, channel, created_at)
			 VALUES ('subscription_existing', ?, ?, 'system', 'in_app', ?)`,
			[]any{legacyBootstrapTenantID, legacyBootstrapUserID, now},
		},
	}
	for _, insert := range inserts {
		if _, err := db.Exec(insert.query, insert.args...); err != nil {
			t.Fatalf("insert legacy %s: %v", insert.name, err)
		}
	}
}

func assertNoLegacyBootstrapReferences(t *testing.T, db *sql.DB, expectedSessions int) {
	t.Helper()

	checks := []struct {
		name  string
		query string
		args  []any
	}{
		{"tenant ID", `SELECT COUNT(*) FROM tenants WHERE id = ?`, []any{legacyBootstrapTenantID}},
		{"tenant slug", `SELECT COUNT(*) FROM tenants WHERE slug = ?`, []any{legacyBootstrapTenantSlug}},
		{"user ID", `SELECT COUNT(*) FROM users WHERE id = ?`, []any{legacyBootstrapUserID}},
		{"user tenant", `SELECT COUNT(*) FROM users WHERE tenant_id = ?`, []any{legacyBootstrapTenantID}},
		{"session identity", `SELECT COUNT(*) FROM auth_sessions WHERE tenant_id = ? OR user_id = ?`, []any{legacyBootstrapTenantID, legacyBootstrapUserID}},
		{"API key identity", `SELECT COUNT(*) FROM api_keys WHERE tenant_id = ? OR user_id = ?`, []any{legacyBootstrapTenantID, legacyBootstrapUserID}},
		{"audit identity", `SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? OR actor = ?`, []any{legacyBootstrapTenantID, legacyBootstrapUserID}},
		{"content identity", `SELECT COUNT(*) FROM content WHERE tenant_id = ? OR author_id = ?`, []any{legacyBootstrapTenantID, legacyBootstrapUserID}},
		{"notification identity", `SELECT COUNT(*) FROM notifications WHERE tenant_id = ? OR user_id = ?`, []any{legacyBootstrapTenantID, legacyBootstrapUserID}},
		{"subscription identity", `SELECT COUNT(*) FROM notification_subscriptions WHERE tenant_id = ? OR user_id = ?`, []any{legacyBootstrapTenantID, legacyBootstrapUserID}},
	}
	for _, check := range checks {
		var count int
		if err := db.QueryRow(check.query, check.args...).Scan(&count); err != nil {
			t.Fatalf("count legacy %s: %v", check.name, err)
		}
		if count != 0 {
			t.Errorf("legacy %s references = %d, want 0", check.name, count)
		}
	}

	var migratedCounts string
	if err := db.QueryRow(`
		SELECT printf(
			'tenant=%d user=%d session=%d key=%d audit=%d content=%d notification=%d subscription=%d',
			(SELECT COUNT(*) FROM tenants WHERE id = ?),
			(SELECT COUNT(*) FROM users WHERE tenant_id = ? AND id = ?),
			(SELECT COUNT(*) FROM auth_sessions WHERE tenant_id = ? AND user_id = ?),
			(SELECT COUNT(*) FROM api_keys WHERE tenant_id = ? AND user_id = ?),
			(SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND actor = ?),
			(SELECT COUNT(*) FROM content WHERE tenant_id = ? AND author_id = ?),
			(SELECT COUNT(*) FROM notifications WHERE tenant_id = ? AND user_id = ?),
			(SELECT COUNT(*) FROM notification_subscriptions WHERE tenant_id = ? AND user_id = ?)
		)`,
		seed.TenantID,
		seed.TenantID, seed.UserID,
		seed.TenantID, seed.UserID,
		seed.TenantID, seed.UserID,
		seed.TenantID, seed.UserID,
		seed.TenantID, seed.UserID,
		seed.TenantID, seed.UserID,
		seed.TenantID, seed.UserID,
	).Scan(&migratedCounts); err != nil {
		t.Fatalf("read migrated reference counts: %v", err)
	}
	want := fmt.Sprintf(
		"tenant=1 user=1 session=%d key=1 audit=1 content=1 notification=1 subscription=1",
		expectedSessions,
	)
	if migratedCounts != want {
		t.Fatalf("migrated reference counts = %q, want %q", migratedCounts, want)
	}
}
