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
	"strings"
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

// Keep this fixture independent from bootstrap_migration.go. These are the
// exact values published by v0.1.0 through v0.3.1; deriving the fixture from
// migration constants would let an incorrect migration test itself green.
const (
	releasedBootstrapTenantID     = "tenant_acme"
	releasedBootstrapTenantSlug   = "acme"
	releasedBootstrapTenantName   = "Acme Inc"
	releasedBootstrapUserID       = "user_admin"
	releasedBootstrapUserEmail    = "admin@local.test"
	releasedBootstrapUserName     = "admin"
	releasedBootstrapUserDisplay  = "Demo Admin"
	releasedBootstrapUserPassword = "changeme"
)

func TestBuildAppNeutralizesLegacyBootstrapLabelsAndPreservesDurableIDs(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() migration error = %v", err)
	}

	migratedTenant, err := app.tenant.Service().Get(ctx, releasedBootstrapTenantID)
	if err != nil {
		t.Fatalf("migrated tenant lookup: %v", err)
	}
	if migratedTenant.Slug != seed.TenantSlug || migratedTenant.Name != seed.TenantName {
		t.Fatalf(
			"migrated tenant = slug %q name %q, want slug %q name %q",
			migratedTenant.Slug,
			migratedTenant.Name,
			seed.TenantSlug,
			seed.TenantName,
		)
	}

	adminUser, err := app.user.Service().Get(
		ctx,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
	)
	if err != nil {
		t.Fatalf("migrated administrator lookup: %v", err)
	}
	if adminUser.Email != seed.UserEmail {
		t.Fatalf("migrated administrator email = %q, want %q", adminUser.Email, seed.UserEmail)
	}
	if adminUser.Username != seed.UserName || adminUser.DisplayName != seed.UserDisplay {
		t.Fatalf(
			"migrated administrator = username %q display %q, want username %q display %q",
			adminUser.Username,
			adminUser.DisplayName,
			seed.UserName,
			seed.UserDisplay,
		)
	}
	if app.adminSubject != releasedBootstrapUserID {
		t.Fatalf("adminSubject = %q, want %q", app.adminSubject, releasedBootstrapUserID)
	}
	if app.seedTenantID != releasedBootstrapTenantID {
		t.Fatalf("seedTenantID = %q, want %q", app.seedTenantID, releasedBootstrapTenantID)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
		seed.UserPass,
	); err != nil {
		t.Fatalf("current bootstrap password does not verify: %v", err)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
		releasedBootstrapUserPassword,
	); err == nil {
		t.Fatal("historical bootstrap password still verifies after migration")
	}

	if _, err := app.authMod.Service().Login(ctx, releasedBootstrapTenantID, auth.Credentials{
		Email:    releasedBootstrapUserEmail,
		Password: releasedBootstrapUserPassword,
	}); err == nil {
		t.Fatal("historical bootstrap login still succeeds after migration")
	}
	session, err := app.authMod.Service().Login(ctx, releasedBootstrapTenantID, auth.Credentials{
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

	loginReq := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	loginRec := httptest.NewRecorder()
	mux.ServeHTTP(loginRec, loginReq)
	if !strings.Contains(loginRec.Body.String(), `value="`+releasedBootstrapTenantID+`"`) {
		t.Fatalf("development login does not prefill preserved tenant ID: %s", loginRec.Body.String())
	}

	assertDurableBootstrapReferencesPreserved(t, app.db, 2)

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
	if contentTenant != releasedBootstrapTenantID ||
		contentAuthor != releasedBootstrapUserID ||
		contentBody != "preserve me" {
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
	var historicalAPIKeyRevokedAt sql.NullTime
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT revoked_at FROM api_keys WHERE id = 'key_existing'`,
	).Scan(&historicalAPIKeyRevokedAt); err != nil {
		t.Fatalf("read migrated historical API key: %v", err)
	}
	if !historicalAPIKeyRevokedAt.Valid {
		t.Fatal("API key minted through the historical default password was not revoked")
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
		releasedBootstrapTenantID,
	).Scan(&tenantCount); err != nil {
		t.Fatalf("count current tenants: %v", err)
	}
	if err := second.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE id = ? AND tenant_id = ?`,
		releasedBootstrapUserID,
		releasedBootstrapTenantID,
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
		releasedBootstrapTenantID,
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
		releasedBootstrapUserID,
		releasedBootstrapTenantID,
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

	migratedTenant, err := app.tenant.Service().Get(ctx, releasedBootstrapTenantID)
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

	migratedUser, err := app.user.Service().Get(
		ctx,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
	)
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
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
		customPassword,
	); err != nil {
		t.Fatalf("customized password was not preserved: %v", err)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
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
	var historicalAPIKeyRevokedAt sql.NullTime
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT revoked_at FROM api_keys WHERE id = 'key_existing'`,
	).Scan(&historicalAPIKeyRevokedAt); err != nil {
		t.Fatalf("read customized historical API key: %v", err)
	}
	if historicalAPIKeyRevokedAt.Valid {
		t.Fatal("migration revoked an API key after the bootstrap password had been rotated")
	}

	assertDurableBootstrapReferencesPreserved(t, app.db, 1)
}

func TestBootstrapMigrationFindsPriorEmailKeyedReplacementAdministrator(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	const replacementUserID = "replacement_owner"
	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open replacement-administrator fixture: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE users SET id = ? WHERE tenant_id = ? AND id = ?`,
		replacementUserID,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
	); err != nil {
		t.Fatalf("replace prior email-keyed administrator: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close replacement-administrator fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() with replacement administrator: %v", err)
	}
	replacement, err := app.user.Service().Get(
		ctx,
		releasedBootstrapTenantID,
		replacementUserID,
	)
	if err != nil {
		t.Fatalf("resolve replacement administrator: %v", err)
	}
	if replacement.Email != seed.UserEmail ||
		replacement.Username != seed.UserName ||
		replacement.DisplayName != seed.UserDisplay {
		t.Fatalf(
			"replacement administrator labels = email %q username %q display %q",
			replacement.Email,
			replacement.Username,
			replacement.DisplayName,
		)
	}
	if app.adminSubject != replacementUserID {
		t.Fatalf("adminSubject = %q, want replacement ID %q", app.adminSubject, replacementUserID)
	}
	if _, err := app.authMod.Service().Login(ctx, releasedBootstrapTenantID, auth.Credentials{
		Email:    seed.UserEmail,
		Password: seed.UserPass,
	}); err != nil {
		t.Fatalf("replacement administrator current login: %v", err)
	}
	var recordedTenantID, recordedUserID string
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT tenant_id, user_id
		 FROM starterapp_bootstrap_identity
		 WHERE id = 'active'`,
	).Scan(&recordedTenantID, &recordedUserID); err != nil {
		t.Fatalf("read recorded replacement identity: %v", err)
	}
	if recordedTenantID != releasedBootstrapTenantID || recordedUserID != replacementUserID {
		t.Fatalf(
			"recorded identity = tenant %q user %q, want tenant %q user %q",
			recordedTenantID,
			recordedUserID,
			releasedBootstrapTenantID,
			replacementUserID,
		)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("close replacement-administrator app: %v", err)
	}

	// A later configuration change must not make identity discovery fall back
	// to email and create a second administrator. The durable ledger remains
	// authoritative after the one-time migration.
	cfg.Environment = "production"
	cfg.Seed.AdminEmail = "new-config-value@customer.test"
	cfg.Seed.AdminPassword = "new-configuration-only-password"
	second, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("second BuildApp() with changed configuration: %v", err)
	}
	defer second.Close()
	if second.adminSubject != replacementUserID {
		t.Fatalf("second adminSubject = %q, want %q", second.adminSubject, replacementUserID)
	}
	var currentIDCount int
	if err := second.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE id = ?`,
		seed.UserID,
	).Scan(&currentIDCount); err != nil {
		t.Fatalf("count duplicate current administrator: %v", err)
	}
	if currentIDCount != 0 {
		t.Fatalf("current administrator duplicates = %d, want 0", currentIDCount)
	}
}

func TestBootstrapMigrationFindsReplacementAdministratorWhenTenantRowIsMissing(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	const replacementUserID = "replacement_owner"
	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open missing-tenant replacement fixture: %v", err)
	}
	updates := []string{
		`UPDATE users SET id = '` + replacementUserID + `' WHERE id = '` + releasedBootstrapUserID + `'`,
		`UPDATE auth_sessions SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE api_keys SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE audit_events SET actor = '` + replacementUserID + `' WHERE actor = '` + releasedBootstrapUserID + `'`,
		`UPDATE content SET author_id = '` + replacementUserID + `' WHERE author_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE notifications SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE notification_subscriptions SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE extension_assets SET owner_id = '` + replacementUserID + `' WHERE owner_id = '` + releasedBootstrapUserID + `'`,
	}
	for _, update := range updates {
		if _, err := db.ExecContext(ctx, update); err != nil {
			t.Fatalf("replace bootstrap administrator reference: %v", err)
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM tenants WHERE id = ?`,
		releasedBootstrapTenantID,
	); err != nil {
		t.Fatalf("delete released tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close missing-tenant replacement fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() missing tenant with replacement administrator: %v", err)
	}
	defer app.Close()

	if app.seedTenantID != releasedBootstrapTenantID ||
		app.adminSubject != replacementUserID {
		t.Fatalf(
			"resolved identity = tenant %q user %q, want tenant %q user %q",
			app.seedTenantID,
			app.adminSubject,
			releasedBootstrapTenantID,
			replacementUserID,
		)
	}
	var releasedUserCount int
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE id = ?`,
		releasedBootstrapUserID,
	).Scan(&releasedUserCount); err != nil {
		t.Fatalf("count duplicate released administrator: %v", err)
	}
	if releasedUserCount != 0 {
		t.Fatalf("duplicate released administrators = %d, want 0", releasedUserCount)
	}
	var extensionOwner string
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT owner_id FROM extension_assets WHERE id = 'asset_existing'`,
	).Scan(&extensionOwner); err != nil {
		t.Fatalf("read contributed-module owner: %v", err)
	}
	if extensionOwner != replacementUserID {
		t.Fatalf("contributed-module owner = %q, want %q", extensionOwner, replacementUserID)
	}
	for _, check := range []struct {
		name  string
		query string
	}{
		{"session", `SELECT COUNT(*) FROM auth_sessions WHERE id = 'session_existing' AND revoked_at IS NOT NULL`},
		{"API key", `SELECT COUNT(*) FROM api_keys WHERE id = 'key_existing' AND revoked_at IS NOT NULL`},
	} {
		var revoked int
		if err := app.db.QueryRowContext(ctx, check.query).Scan(&revoked); err != nil {
			t.Fatalf("inspect replacement administrator %s revocation: %v", check.name, err)
		}
		if revoked != 1 {
			t.Fatalf("replacement administrator %s revoked rows = %d, want 1", check.name, revoked)
		}
	}
}

func TestBootstrapMigrationRejectsReusedReleasedAdministratorID(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create collision password hasher: %v", err)
	}
	ordinaryHash, err := hasher.Hash("ordinary-user-password")
	if err != nil {
		t.Fatalf("hash colliding user password: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open released-ID collision fixture: %v", err)
	}
	const replacementUserID = "replacement_owner"
	if _, err := db.ExecContext(
		ctx,
		`UPDATE users SET id = ? WHERE id = ?`,
		replacementUserID,
		releasedBootstrapUserID,
	); err != nil {
		t.Fatalf("re-key released administrator: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO users
		 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
		 VALUES (?, ?, 'ordinary@customer.test', 'ordinary', ?, 'Ordinary User', 1, ?, ?)`,
		releasedBootstrapUserID,
		releasedBootstrapTenantID,
		ordinaryHash,
		now,
		now,
	); err != nil {
		t.Fatalf("reuse released administrator ID: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close released-ID collision fixture: %v", err)
	}

	if _, err := BuildApp(ctx, cfg); err == nil {
		t.Fatal("BuildApp() granted bootstrap authority across an ambiguous released-ID collision")
	} else if !strings.Contains(err.Error(), "conflicting released bootstrap administrator") {
		t.Fatalf("BuildApp() collision error = %v", err)
	}
}

func TestBootstrapMigrationRevokesReleasedCredentialsWhenIDIsForeign(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create foreign-ID password hasher: %v", err)
	}
	ordinaryHash, err := hasher.Hash("ordinary-user-password")
	if err != nil {
		t.Fatalf("hash foreign-ID user password: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open foreign-ID fixture: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM users WHERE id = ?`,
		releasedBootstrapUserID,
	); err != nil {
		t.Fatalf("delete released administrator: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO tenants (id, slug, name, created_at, updated_at)
		 VALUES ('tenant_other', 'other', 'Other Tenant', ?, ?)`,
		now,
		now,
	); err != nil {
		t.Fatalf("insert foreign tenant: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO users
		 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
		 VALUES (?, 'tenant_other', 'ordinary@customer.test', 'ordinary', ?, 'Ordinary User', 1, ?, ?)`,
		releasedBootstrapUserID,
		ordinaryHash,
		now,
		now,
	); err != nil {
		t.Fatalf("reuse released ID in foreign tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close foreign-ID fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() with foreign released ID: %v", err)
	}
	defer app.Close()

	if app.adminSubject == releasedBootstrapUserID {
		t.Fatalf("foreign user %q received bootstrap authority", releasedBootstrapUserID)
	}
	if _, err := app.authMod.Service().ValidateSession(ctx, "session_existing"); err == nil {
		t.Fatal("session for superseded released identity remained usable")
	}
	var revokedAPIKey int
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM api_keys
		 WHERE id = 'key_existing' AND revoked_at IS NOT NULL`,
	).Scan(&revokedAPIKey); err != nil {
		t.Fatalf("inspect superseded released API key: %v", err)
	}
	if revokedAPIKey != 1 {
		t.Fatalf("superseded released API key revoked rows = %d, want 1", revokedAPIKey)
	}
	foreignUser, err := app.user.Service().Get(
		ctx,
		"tenant_other",
		releasedBootstrapUserID,
	)
	if err != nil {
		t.Fatalf("lookup foreign colliding user: %v", err)
	}
	if foreignUser.Email != "ordinary@customer.test" {
		t.Fatalf("foreign colliding user was mutated to %q", foreignUser.Email)
	}
}

func TestBootstrapMigrationDoesNotGrantAdminToNewIDCollision(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create collision password hasher: %v", err)
	}
	ordinaryPassword := "ordinary-user-password"
	ordinaryHash, err := hasher.Hash(ordinaryPassword)
	if err != nil {
		t.Fatalf("hash ordinary password: %v", err)
	}

	const replacementUserID = "customer_owner"
	cfg.Environment = "production"
	cfg.Seed.AdminEmail = "owner@customer.test"
	cfg.Seed.AdminPassword = "replacement-owner-password"

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open user-ID collision fixture: %v", err)
	}
	now := time.Now().UTC()
	updates := []string{
		`UPDATE users SET id = '` + replacementUserID + `', email = '` + cfg.Seed.AdminEmail + `' WHERE id = '` + releasedBootstrapUserID + `'`,
		`UPDATE auth_sessions SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE api_keys SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE audit_events SET actor = '` + replacementUserID + `' WHERE actor = '` + releasedBootstrapUserID + `'`,
		`UPDATE content SET author_id = '` + replacementUserID + `' WHERE author_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE notifications SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE notification_subscriptions SET user_id = '` + replacementUserID + `' WHERE user_id = '` + releasedBootstrapUserID + `'`,
		`UPDATE extension_assets SET owner_id = '` + replacementUserID + `' WHERE owner_id = '` + releasedBootstrapUserID + `'`,
	}
	for _, update := range updates {
		if _, err := db.ExecContext(ctx, update); err != nil {
			t.Fatalf("replace bootstrap administrator references: %v", err)
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO users
		 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
		 VALUES (?, ?, 'ordinary@customer.test', 'ordinary', ?, 'Ordinary User', 1, ?, ?)`,
		seed.UserID,
		releasedBootstrapTenantID,
		ordinaryHash,
		now,
		now,
	); err != nil {
		t.Fatalf("insert colliding ordinary user: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close user-ID collision fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() with user-ID collision: %v", err)
	}
	defer app.Close()

	if app.adminSubject != replacementUserID {
		t.Fatalf("adminSubject = %q, want email-keyed owner %q", app.adminSubject, replacementUserID)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		releasedBootstrapTenantID,
		seed.UserID,
		ordinaryPassword,
	); err != nil {
		t.Fatalf("ordinary account password changed: %v", err)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		releasedBootstrapTenantID,
		seed.UserID,
		cfg.Seed.AdminPassword,
	); err == nil {
		t.Fatal("ordinary account received the bootstrap administrator password")
	}
	if _, err := app.authMod.Service().Login(ctx, releasedBootstrapTenantID, auth.Credentials{
		Email:    cfg.Seed.AdminEmail,
		Password: cfg.Seed.AdminPassword,
	}); err != nil {
		t.Fatalf("email-keyed owner login: %v", err)
	}
}

func TestBootstrapMigrationPrefersReleasedTenantOverNewIDCollision(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open tenant-ID collision fixture: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO tenants (id, slug, name, created_at, updated_at)
		 VALUES (?, 'customer-local', 'Existing Customer Tenant', ?, ?)`,
		seed.TenantID,
		now,
		now,
	); err != nil {
		t.Fatalf("insert colliding tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close tenant-ID collision fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() with tenant-ID collision: %v", err)
	}
	defer app.Close()

	if app.seedTenantID != releasedBootstrapTenantID {
		t.Fatalf("seedTenantID = %q, want released tenant %q", app.seedTenantID, releasedBootstrapTenantID)
	}
	collidingTenant, err := app.tenant.Service().Get(ctx, seed.TenantID)
	if err != nil {
		t.Fatalf("lookup colliding tenant: %v", err)
	}
	if collidingTenant.Slug != "customer-local" || collidingTenant.Name != "Existing Customer Tenant" {
		t.Fatalf(
			"colliding tenant changed to slug=%q name=%q",
			collidingTenant.Slug,
			collidingTenant.Name,
		)
	}
}

func TestBootstrapMigrationChoosesNonconflictingNeutralLabels(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)
	cfg.Environment = "production"
	cfg.Seed.AdminEmail = seed.UserEmail
	cfg.Seed.AdminPassword = "production-bootstrap-password"

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create label-collision password hasher: %v", err)
	}
	ordinaryHash, err := hasher.Hash("ordinary-user-password")
	if err != nil {
		t.Fatalf("hash label-collision password: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open label-collision fixture: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO tenants (id, slug, name, created_at, updated_at)
		 VALUES ('tenant_existing_local', ?, 'Existing Local Tenant', ?, ?)`,
		seed.TenantSlug,
		now,
		now,
	); err != nil {
		t.Fatalf("insert colliding tenant slug: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO users
		 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
		 VALUES ('existing_operator', ?, ?, ?, ?, 'Existing Operator', 1, ?, ?)`,
		releasedBootstrapTenantID,
		seed.UserEmail,
		seed.UserName,
		ordinaryHash,
		now,
		now,
	); err != nil {
		t.Fatalf("insert colliding user labels: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close label-collision fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() with label collisions: %v", err)
	}
	defer app.Close()

	migratedTenant, err := app.tenant.Service().Get(ctx, releasedBootstrapTenantID)
	if err != nil {
		t.Fatalf("lookup migrated tenant: %v", err)
	}
	if migratedTenant.Slug != "platformkit-local" {
		t.Fatalf("migrated tenant slug = %q, want collision-safe neutral slug", migratedTenant.Slug)
	}
	migratedAdmin, err := app.user.Service().Get(
		ctx,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
	)
	if err != nil {
		t.Fatalf("lookup migrated administrator: %v", err)
	}
	if migratedAdmin.Email != "operator+platformkit@local.test" {
		t.Fatalf("migrated administrator email = %q, want collision-safe neutral email", migratedAdmin.Email)
	}
	if migratedAdmin.Username != "platformkit-operator" {
		t.Fatalf("migrated administrator username = %q, want collision-safe neutral username", migratedAdmin.Username)
	}
	if _, err := app.authMod.Service().Login(ctx, releasedBootstrapTenantID, auth.Credentials{
		Email:    migratedAdmin.Email,
		Password: cfg.Seed.AdminPassword,
	}); err != nil {
		t.Fatalf("collision-safe administrator login: %v", err)
	}
	if app.seedEmail != migratedAdmin.Email {
		t.Fatalf("operator-facing banner email = %q, want %q", app.seedEmail, migratedAdmin.Email)
	}

	ordinary, err := app.user.Service().Get(ctx, releasedBootstrapTenantID, "existing_operator")
	if err != nil {
		t.Fatalf("lookup existing operator: %v", err)
	}
	if ordinary.Email != seed.UserEmail || ordinary.Username != seed.UserName {
		t.Fatalf("existing operator labels changed to email=%q username=%q", ordinary.Email, ordinary.Username)
	}
}

func TestBootstrapMigrationRepairsMissingReleasedAdministrator(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create missing-administrator password hasher: %v", err)
	}
	ordinaryPassword := "ordinary-user-password"
	ordinaryHash, err := hasher.Hash(ordinaryPassword)
	if err != nil {
		t.Fatalf("hash missing-administrator collision password: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open missing-administrator fixture: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM users WHERE id = ? AND tenant_id = ?`,
		releasedBootstrapUserID,
		releasedBootstrapTenantID,
	); err != nil {
		t.Fatalf("delete released administrator: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO users
		 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
		 VALUES ('ordinary_operator', ?, ?, ?, ?, 'Ordinary Operator', 1, ?, ?)`,
		releasedBootstrapTenantID,
		seed.UserEmail,
		seed.UserName,
		ordinaryHash,
		now,
		now,
	); err != nil {
		t.Fatalf("insert ordinary label owner: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close missing-administrator fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() missing released administrator: %v", err)
	}
	defer app.Close()

	if app.adminSubject != releasedBootstrapUserID {
		t.Fatalf("adminSubject = %q, want repaired released ID %q", app.adminSubject, releasedBootstrapUserID)
	}
	repaired, err := app.user.Service().Get(
		ctx,
		releasedBootstrapTenantID,
		releasedBootstrapUserID,
	)
	if err != nil {
		t.Fatalf("lookup repaired released administrator: %v", err)
	}
	if repaired.Email != "operator+platformkit@local.test" ||
		repaired.Username != "platformkit-operator" {
		t.Fatalf(
			"repaired administrator labels = email %q username %q",
			repaired.Email,
			repaired.Username,
		)
	}
	if _, err := app.authMod.Service().Login(ctx, releasedBootstrapTenantID, auth.Credentials{
		Email:    repaired.Email,
		Password: seed.UserPass,
	}); err != nil {
		t.Fatalf("repaired released administrator login: %v", err)
	}
	if err := app.user.Service().VerifyPassword(
		ctx,
		releasedBootstrapTenantID,
		"ordinary_operator",
		ordinaryPassword,
	); err != nil {
		t.Fatalf("ordinary label owner password changed: %v", err)
	}
	if app.seedEmail != repaired.Email {
		t.Fatalf("development banner email = %q, want repaired email %q", app.seedEmail, repaired.Email)
	}

	var extensionOwner string
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT owner_id FROM extension_assets WHERE id = 'asset_existing'`,
	).Scan(&extensionOwner); err != nil {
		t.Fatalf("read contributed-module owner: %v", err)
	}
	if extensionOwner != releasedBootstrapUserID {
		t.Fatalf("contributed-module owner = %q, want repaired ID %q", extensionOwner, releasedBootstrapUserID)
	}

	for _, check := range []struct {
		name  string
		query string
	}{
		{"session", `SELECT COUNT(*) FROM auth_sessions WHERE id = 'session_existing' AND revoked_at IS NOT NULL`},
		{"API key", `SELECT COUNT(*) FROM api_keys WHERE id = 'key_existing' AND revoked_at IS NOT NULL`},
	} {
		var revoked int
		if err := app.db.QueryRowContext(ctx, check.query).Scan(&revoked); err != nil {
			t.Fatalf("inspect repaired administrator %s revocation: %v", check.name, err)
		}
		if revoked != 1 {
			t.Fatalf("repaired administrator %s revoked rows = %d, want 1", check.name, revoked)
		}
	}
}

func TestBootstrapMigrationRepairsMissingReleasedTenant(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open missing-tenant fixture: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM tenants WHERE id = ?`,
		releasedBootstrapTenantID,
	); err != nil {
		t.Fatalf("delete released tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close missing-tenant fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() missing released tenant: %v", err)
	}
	defer app.Close()

	repaired, err := app.tenant.Service().Get(ctx, releasedBootstrapTenantID)
	if err != nil {
		t.Fatalf("lookup repaired released tenant: %v", err)
	}
	if repaired.Slug != seed.TenantSlug || repaired.Name != seed.TenantName {
		t.Fatalf("repaired tenant = slug %q name %q", repaired.Slug, repaired.Name)
	}
	if app.seedTenantID != releasedBootstrapTenantID ||
		app.adminSubject != releasedBootstrapUserID {
		t.Fatalf(
			"repaired identity = tenant %q user %q",
			app.seedTenantID,
			app.adminSubject,
		)
	}
	assertDurableBootstrapReferencesPreserved(t, app.db, 1)
}

func TestBootstrapMigrationRepairsBothMissingReleasedIdentityRows(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open missing-identity fixture: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM users WHERE id = ? AND tenant_id = ?`,
		releasedBootstrapUserID,
		releasedBootstrapTenantID,
	); err != nil {
		t.Fatalf("delete released administrator: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM tenants WHERE id = ?`,
		releasedBootstrapTenantID,
	); err != nil {
		t.Fatalf("delete released tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close missing-identity fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() missing both released identity rows: %v", err)
	}
	defer app.Close()

	if app.seedTenantID != releasedBootstrapTenantID ||
		app.adminSubject != releasedBootstrapUserID {
		t.Fatalf(
			"repaired identity = tenant %q user %q, want tenant %q user %q",
			app.seedTenantID,
			app.adminSubject,
			releasedBootstrapTenantID,
			releasedBootstrapUserID,
		)
	}
	if _, err := app.authMod.Service().Login(ctx, releasedBootstrapTenantID, auth.Credentials{
		Email:    seed.UserEmail,
		Password: seed.UserPass,
	}); err != nil {
		t.Fatalf("recreated released administrator login: %v", err)
	}
	assertDurableBootstrapReferencesPreserved(t, app.db, 2)

	for _, check := range []struct {
		name  string
		query string
	}{
		{"session", `SELECT COUNT(*) FROM auth_sessions WHERE id = 'session_existing' AND revoked_at IS NOT NULL`},
		{"API key", `SELECT COUNT(*) FROM api_keys WHERE id = 'key_existing' AND revoked_at IS NOT NULL`},
	} {
		var revoked int
		if err := app.db.QueryRowContext(ctx, check.query).Scan(&revoked); err != nil {
			t.Fatalf("inspect recreated identity %s revocation: %v", check.name, err)
		}
		if revoked != 1 {
			t.Fatalf("recreated identity %s revoked rows = %d, want 1", check.name, revoked)
		}
	}
}

func TestBootstrapMigrationFindsReleasedIDsInUnknownExtensionTable(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	createLegacyBootstrapFixture(t, cfg.Database.DSN)

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open extension-only fixture: %v", err)
	}
	for _, statement := range []string{
		`DELETE FROM users`,
		`DELETE FROM tenants`,
		`DELETE FROM auth_sessions`,
		`DELETE FROM api_keys`,
		`DELETE FROM audit_events`,
		`DELETE FROM content`,
		`DELETE FROM notifications`,
		`DELETE FROM notification_subscriptions`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("remove built-in identity evidence with %q: %v", statement, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close extension-only fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() with extension-only released IDs: %v", err)
	}
	defer app.Close()
	if app.seedTenantID != releasedBootstrapTenantID ||
		app.adminSubject != releasedBootstrapUserID {
		t.Fatalf(
			"extension-only identity = tenant %q user %q, want tenant %q user %q",
			app.seedTenantID,
			app.adminSubject,
			releasedBootstrapTenantID,
			releasedBootstrapUserID,
		)
	}
	var extensionTenant, extensionOwner string
	if err := app.db.QueryRowContext(
		ctx,
		`SELECT tenant_id, owner_id FROM extension_assets WHERE id = 'asset_existing'`,
	).Scan(&extensionTenant, &extensionOwner); err != nil {
		t.Fatalf("read extension-only durable references: %v", err)
	}
	if extensionTenant != releasedBootstrapTenantID ||
		extensionOwner != releasedBootstrapUserID {
		t.Fatalf(
			"extension-only durable references = tenant %q owner %q",
			extensionTenant,
			extensionOwner,
		)
	}
}

func TestBootstrapIdentityLedgerRevokesCredentialsBeforeRecreatingDeletedIdentity(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	first, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("first BuildApp(): %v", err)
	}
	session, err := first.authMod.Service().Login(ctx, seed.TenantID, auth.Credentials{
		Email:    seed.UserEmail,
		Password: seed.UserPass,
	})
	if err != nil {
		t.Fatalf("create pre-deletion session: %v", err)
	}
	_, key, err := first.apiKey.Service().Issue(
		ctx,
		seed.TenantID,
		seed.UserID,
		"pre-deletion",
		[]string{"content:read"},
		0,
	)
	if err != nil {
		t.Fatalf("create pre-deletion API key: %v", err)
	}
	if _, err := first.db.ExecContext(
		ctx,
		`DELETE FROM users WHERE id = ? AND tenant_id = ?`,
		seed.UserID,
		seed.TenantID,
	); err != nil {
		t.Fatalf("delete recorded administrator: %v", err)
	}
	if _, err := first.db.ExecContext(
		ctx,
		`DELETE FROM tenants WHERE id = ?`,
		seed.TenantID,
	); err != nil {
		t.Fatalf("delete recorded tenant: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first app: %v", err)
	}

	second, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("BuildApp() after recorded identity deletion: %v", err)
	}
	defer second.Close()

	if _, err := second.authMod.Service().ValidateSession(ctx, session.ID); err == nil {
		t.Fatal("session for deleted bootstrap identity remained valid after recreation")
	}
	for _, check := range []struct {
		name  string
		id    string
		query string
	}{
		{
			name:  "session",
			id:    session.ID,
			query: `SELECT COUNT(*) FROM auth_sessions WHERE id = ? AND revoked_at IS NOT NULL`,
		},
		{
			name:  "API key",
			id:    key.ID,
			query: `SELECT COUNT(*) FROM api_keys WHERE id = ? AND revoked_at IS NOT NULL`,
		},
	} {
		var revoked int
		if err := second.db.QueryRowContext(ctx, check.query, check.id).Scan(&revoked); err != nil {
			t.Fatalf("inspect recreated recorded identity %s: %v", check.name, err)
		}
		if revoked != 1 {
			t.Fatalf("recreated recorded identity %s revoked rows = %d, want 1", check.name, revoked)
		}
	}
	if _, err := second.authMod.Service().Login(ctx, seed.TenantID, auth.Credentials{
		Email:    seed.UserEmail,
		Password: seed.UserPass,
	}); err != nil {
		t.Fatalf("recreated recorded administrator login: %v", err)
	}
}

func TestBootstrapSeedRepairsMissingPasswordHashInProduction(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)
	cfg.Environment = "production"
	cfg.Seed.AdminPassword = "production-bootstrap-password"

	first, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("first production BuildApp(): %v", err)
	}
	if _, err := first.db.ExecContext(
		ctx,
		`UPDATE users SET pass_hash = '' WHERE id = ? AND tenant_id = ?`,
		seed.UserID,
		seed.TenantID,
	); err != nil {
		t.Fatalf("clear bootstrap password hash: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first production app: %v", err)
	}

	second, err := BuildApp(ctx, cfg)
	if err != nil {
		t.Fatalf("second production BuildApp(): %v", err)
	}
	defer second.Close()
	if _, err := second.authMod.Service().Login(ctx, seed.TenantID, auth.Credentials{
		Email:    seed.UserEmail,
		Password: cfg.Seed.AdminPassword,
	}); err != nil {
		t.Fatalf("production bootstrap with missing hash was not repaired: %v", err)
	}
}

func TestBootstrapMigrationRejectsUnrecordedNeutralIDCollision(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t)

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create neutral-ID collision password hasher: %v", err)
	}
	privatePassword := "customer-private-password"
	privateHash, err := hasher.Hash(privatePassword)
	if err != nil {
		t.Fatalf("hash neutral-ID collision password: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("open neutral-ID collision fixture: %v", err)
	}
	if _, err := tenantsqlite.New(db); err != nil {
		t.Fatalf("initialize neutral-ID tenant store: %v", err)
	}
	if _, err := usersqlite.New(db); err != nil {
		t.Fatalf("initialize neutral-ID user store: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO tenants (id, slug, name, created_at, updated_at)
		 VALUES (?, 'customer-local', 'Customer Tenant', ?, ?)`,
		seed.TenantID,
		now,
		now,
	); err != nil {
		t.Fatalf("insert neutral-ID tenant collision: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO users
		 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
		 VALUES (?, ?, 'victim@customer.test', 'victim', ?, 'Victim User', 1, ?, ?)`,
		seed.UserID,
		seed.TenantID,
		privateHash,
		now,
		now,
	); err != nil {
		t.Fatalf("insert neutral-ID user collision: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close neutral-ID collision fixture: %v", err)
	}

	app, err := BuildApp(ctx, cfg)
	if app != nil {
		_ = app.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unrecorded bootstrap ID collision") {
		t.Fatalf("BuildApp() neutral-ID collision error = %v", err)
	}

	db, err = sql.Open("sqlite", cfg.Database.DSN)
	if err != nil {
		t.Fatalf("reopen neutral-ID collision fixture: %v", err)
	}
	defer db.Close()
	var storedHash string
	if err := db.QueryRowContext(
		ctx,
		`SELECT pass_hash FROM users WHERE id = ? AND tenant_id = ?`,
		seed.UserID,
		seed.TenantID,
	).Scan(&storedHash); err != nil {
		t.Fatalf("read colliding user's password: %v", err)
	}
	if err := hasher.Verify(privatePassword, storedHash); err != nil {
		t.Fatalf("colliding user's private password changed: %v", err)
	}
	if err := hasher.Verify(seed.UserPass, storedHash); err == nil {
		t.Fatal("colliding user adopted the public local bootstrap password")
	}

	var ledgerCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM sqlite_master
		 WHERE type = 'table' AND name = 'starterapp_bootstrap_identity'`,
	).Scan(&ledgerCount); err != nil {
		t.Fatalf("inspect collision migration ledger: %v", err)
	}
	if ledgerCount != 0 {
		t.Fatal("failed collision resolution committed a bootstrap identity ledger")
	}
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
	if _, err := db.Exec(`
		CREATE TABLE extension_assets (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			name TEXT NOT NULL
		)`); err != nil {
		t.Fatalf("initialize contributed-module fixture: %v", err)
	}

	hasher, err := passhash.NewBcrypt(passhash.MinCost)
	if err != nil {
		t.Fatalf("create fixture password hasher: %v", err)
	}
	legacyHash, err := hasher.Hash(releasedBootstrapUserPassword)
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
			[]any{releasedBootstrapTenantID, releasedBootstrapTenantSlug, releasedBootstrapTenantName, now, now},
		},
		{
			"user",
			`INSERT INTO users
			 (id, tenant_id, email, username, pass_hash, display_name, active, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			[]any{
				releasedBootstrapUserID,
				releasedBootstrapTenantID,
				releasedBootstrapUserEmail,
				releasedBootstrapUserName,
				legacyHash,
				releasedBootstrapUserDisplay,
				now,
				now,
			},
		},
		{
			"session",
			`INSERT INTO auth_sessions
			 (id, user_id, tenant_id, issued_at, expires_at, revoked_at)
			 VALUES ('session_existing', ?, ?, ?, ?, NULL)`,
			[]any{releasedBootstrapUserID, releasedBootstrapTenantID, now, expires},
		},
		{
			"API key",
			`INSERT INTO api_keys
			 (id, tenant_id, user_id, name, prefix, hash, scopes, last_used_at, revoked_at, expires_at, created_at)
			 VALUES ('key_existing', ?, ?, 'existing', 'pk_existing', 'hash', 'content:read', NULL, NULL, NULL, ?)`,
			[]any{releasedBootstrapTenantID, releasedBootstrapUserID, now},
		},
		{
			"audit event",
			`INSERT INTO audit_events
			 (id, tenant_id, actor, action, resource, severity, details, emitted_at)
			 VALUES ('audit_existing', ?, ?, 'created', 'content', 'info', 'preserve me', ?)`,
			[]any{releasedBootstrapTenantID, releasedBootstrapUserID, now},
		},
		{
			"content",
			`INSERT INTO content
			 (id, tenant_id, kind, slug, title, body, body_format, author_id, published_at, created_at, updated_at)
			 VALUES ('content_existing', ?, 'post', 'existing', 'Existing', 'preserve me', 'markdown', ?, NULL, ?, ?)`,
			[]any{releasedBootstrapTenantID, releasedBootstrapUserID, now, now},
		},
		{
			"notification",
			`INSERT INTO notifications
			 (id, tenant_id, user_id, title, body, category, severity, data, read_at, emitted_at)
			 VALUES ('notification_existing', ?, ?, 'Existing', 'preserve me', 'system', 'info', '{}', NULL, ?)`,
			[]any{releasedBootstrapTenantID, releasedBootstrapUserID, now},
		},
		{
			"notification subscription",
			`INSERT INTO notification_subscriptions
			 (id, tenant_id, user_id, category, channel, created_at)
			 VALUES ('subscription_existing', ?, ?, 'system', 'in_app', ?)`,
			[]any{releasedBootstrapTenantID, releasedBootstrapUserID, now},
		},
		{
			"contributed-module row",
			`INSERT INTO extension_assets (id, tenant_id, owner_id, name)
			 VALUES ('asset_existing', ?, ?, 'preserve me')`,
			[]any{releasedBootstrapTenantID, releasedBootstrapUserID},
		},
	}
	for _, insert := range inserts {
		if _, err := db.Exec(insert.query, insert.args...); err != nil {
			t.Fatalf("insert legacy %s: %v", insert.name, err)
		}
	}
}

func assertDurableBootstrapReferencesPreserved(t *testing.T, db *sql.DB, expectedSessions int) {
	t.Helper()

	checks := []struct {
		name  string
		query string
		args  []any
	}{
		{
			"released tenant slug",
			`SELECT COUNT(*) FROM tenants WHERE slug = ?`,
			[]any{releasedBootstrapTenantSlug},
		},
		{
			"released administrator email",
			`SELECT COUNT(*) FROM users WHERE email = ?`,
			[]any{releasedBootstrapUserEmail},
		},
		{
			"fresh-install tenant ID",
			`SELECT COUNT(*) FROM tenants WHERE id = ?`,
			[]any{seed.TenantID},
		},
		{
			"fresh-install administrator ID",
			`SELECT COUNT(*) FROM users WHERE id = ?`,
			[]any{seed.UserID},
		},
		{
			"fresh-install session identity",
			`SELECT COUNT(*) FROM auth_sessions WHERE tenant_id = ? OR user_id = ?`,
			[]any{seed.TenantID, seed.UserID},
		},
		{
			"fresh-install API-key identity",
			`SELECT COUNT(*) FROM api_keys WHERE tenant_id = ? OR user_id = ?`,
			[]any{seed.TenantID, seed.UserID},
		},
		{
			"fresh-install audit identity",
			`SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? OR actor = ?`,
			[]any{seed.TenantID, seed.UserID},
		},
		{
			"fresh-install content identity",
			`SELECT COUNT(*) FROM content WHERE tenant_id = ? OR author_id = ?`,
			[]any{seed.TenantID, seed.UserID},
		},
		{
			"fresh-install notification identity",
			`SELECT COUNT(*) FROM notifications WHERE tenant_id = ? OR user_id = ?`,
			[]any{seed.TenantID, seed.UserID},
		},
		{
			"fresh-install subscription identity",
			`SELECT COUNT(*) FROM notification_subscriptions WHERE tenant_id = ? OR user_id = ?`,
			[]any{seed.TenantID, seed.UserID},
		},
		{
			"fresh-install contributed identity",
			`SELECT COUNT(*) FROM extension_assets WHERE tenant_id = ? OR owner_id = ?`,
			[]any{seed.TenantID, seed.UserID},
		},
	}
	for _, check := range checks {
		var count int
		if err := db.QueryRow(check.query, check.args...).Scan(&count); err != nil {
			t.Fatalf("count stale %s: %v", check.name, err)
		}
		if count != 0 {
			t.Errorf("stale %s rows = %d, want 0", check.name, count)
		}
	}

	var preservedCounts string
	if err := db.QueryRow(`
		SELECT printf(
			'tenant=%d user=%d session=%d key=%d audit=%d content=%d notification=%d subscription=%d extension=%d',
			(SELECT COUNT(*) FROM tenants WHERE id = ?),
			(SELECT COUNT(*) FROM users WHERE tenant_id = ? AND id = ?),
			(SELECT COUNT(*) FROM auth_sessions WHERE tenant_id = ? AND user_id = ?),
			(SELECT COUNT(*) FROM api_keys WHERE tenant_id = ? AND user_id = ?),
			(SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND actor = ?),
			(SELECT COUNT(*) FROM content WHERE tenant_id = ? AND author_id = ?),
			(SELECT COUNT(*) FROM notifications WHERE tenant_id = ? AND user_id = ?),
			(SELECT COUNT(*) FROM notification_subscriptions WHERE tenant_id = ? AND user_id = ?),
			(SELECT COUNT(*) FROM extension_assets WHERE tenant_id = ? AND owner_id = ?)
		)`,
		releasedBootstrapTenantID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
		releasedBootstrapTenantID, releasedBootstrapUserID,
	).Scan(&preservedCounts); err != nil {
		t.Fatalf("read preserved reference counts: %v", err)
	}
	want := fmt.Sprintf(
		"tenant=1 user=1 session=%d key=1 audit=1 content=1 notification=1 subscription=1 extension=1",
		expectedSessions,
	)
	if preservedCounts != want {
		t.Fatalf("preserved reference counts = %q, want %q", preservedCounts, want)
	}
}
