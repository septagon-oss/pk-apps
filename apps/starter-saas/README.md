# starter-saas

The runnable PlatformKit OSS monolith. One Go binary, one SQLite file, and
nine composed modules: `tenant_management`, `user_management`,
`audit_management`, `health_management`, `auth_management`,
`api_key_management`, `content_management`, `notification_management`, and
`admin_management`.

## Quickstart

```bash
git clone https://github.com/septagon-oss/septagon-oss-workspace
cd septagon-oss-workspace/pk-apps/apps/starter-saas
go run .
```

The binary boots on `:8080` and prints a banner with the admin URL plus
default credentials. On first boot it creates one tenant (`Acme Inc`) and one
admin user (`admin@local.test` / `changeme`).

| Endpoint | Purpose |
|----------|---------|
| `http://localhost:8080/` | HTML landing page |
| `http://localhost:8080/admin` | Admin UI (entity CRUD + custom pages) |
| `http://localhost:8080/healthz` | Aggregated health checks (JSON) |
| `http://localhost:8080/metrics` | `expvar` runtime metrics (JSON) |
| `http://localhost:8080/live` | Liveness probe (`204 No Content`) |
| `http://localhost:8080/ready` | Readiness probe (JSON) |
| `http://localhost:8080/api/v1/tenants` | Tenant CRUD |
| `http://localhost:8080/api/v1/users` | User CRUD (requires `?tenant_id=...`) |
| `http://localhost:8080/api/v1/audit-events` | Audit log (read) |
| `http://localhost:8080/api/v1/auth/sessions` | Login + session lifecycle |
| `http://localhost:8080/api/v1/api-keys` | API key CRUD |
| `http://localhost:8080/api/v1/content` | Content CRUD |
| `http://localhost:8080/api/v1/notifications` | Notification CRUD |

## Configuration

`config.yaml` is read from the working directory at startup. Every key has a
sensible default if the file is missing.

To swap the database driver, register a different `database/sql` driver in
`main.go` and update `database.dsn` in `config.yaml`. The OSS reference
driver is `modernc.org/sqlite`, pinned via the `pk-modules` go.mod.

## Adding a module

1. Construct it in `app.go` with `WithSQLiteDSN(cfg.Database.DSN)` and the
   shared admin/health registrars.
2. Append `m.Compose` to the `pkmodule.NewBundle` entries and the module ID
   to the `modules` slice.
3. Call `m.HTTPHandler().RegisterRoutes(mux)` in `App.mux()`.

## Tests

```bash
go test ./...
```

`main_test.go` runs three smoke tests: catalog composition, first-boot
seeding, and HTTP route registration. They all use a per-test SQLite file
under `t.TempDir()` and never touch the network.
