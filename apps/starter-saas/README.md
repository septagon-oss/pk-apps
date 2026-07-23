# starter-saas

The runnable PlatformKit OSS monolith. One Go binary, one SQLite file, and
nine composed modules: `tenant_management`, `user_management`,
`audit_management`, `health_management`, `auth_management`,
`api_key_management`, `content_management`, `notification_management`, and
`admin_management`.

## Quickstart

```bash
git clone https://github.com/septagon-oss/pk-apps
cd pk-apps/apps/starter-saas
go run .
```

The binary binds to loopback at `127.0.0.1:8080` and prints the admin URL plus
development credentials in the terminal. On first boot it creates one tenant
and one administrator. The public landing and login pages never expose the
password.

| Endpoint | Purpose |
|----------|---------|
| `http://localhost:8080/` | HTML landing page |
| `http://localhost:8080/admin` | Scope-protected, schema-aware operator console |
| `http://localhost:8080/healthz` | Aggregated health checks (JSON) |
| `http://localhost:8080/metrics` | Authenticated `expvar` runtime metrics (JSON) |
| `http://localhost:8080/openapi/extensions.json` | Extension OpenAPI 3.1 document |
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

`config.yaml` is read from the working directory at startup. The checked-in
development config is immediately runnable and loopback-only. Calling
`starterapp.DefaultConfig()` directly gives the same safe local default.

A missing expected config file fails closed as production and requires
`seed.admin_password`. To listen beyond loopback, explicitly set the address
and use production mode:

```yaml
environment: "production"
http:
  addr: "0.0.0.0:8080"
seed:
  admin_email: "operator@example.com"
  admin_password: "load-this-from-your-secret-store"
```

To swap the database driver, register a different `database/sql` driver in
`main.go` and update `database.dsn` in `config.yaml`. The OSS reference
driver is `modernc.org/sqlite`, pinned via the `pk-modules` go.mod.

## Where the code lives

`main.go` here is a thin (~25-line) wrapper: it loads `config.yaml`, registers
the SQLite driver, and hands a signal context to `starterapp.Run`. All of the
application logic — the module composition graph, the shared `*sql.DB`, the
HTTP mux, the first-boot seed, and the serve loop — lives in the importable
package `github.com/septagon-oss/pk-apps/pkg/starterapp`. The public front-door
repo (`github.com/septagon-oss/platformkit`) is the same wrapper over the same
package, so the runnable app has exactly one source of truth.

## Adding a module

The app opens **one** shared `*sql.DB` in `starterapp.BuildApp` and every data
module is built on that single connection pool. Do not give a new module its
own handle. Contribute it through the supported `WithModules` seam; its
`ModuleEnv` supplies the shared database plus admin, health, and audit ports:

```go
cfg := starterapp.DefaultConfig()
err := starterapp.Run(ctx, cfg, starterapp.WithModules(
    func(env starterapp.ModuleEnv) (starterapp.ModulePlugin, error) {
        store, err := mysqlite.New(env.DB)
        if err != nil {
            return starterapp.ModulePlugin{}, err
        }
        module, err := mymodule.New(
            mymodule.WithStore(store),
            mymodule.WithAudit(env.Audit),
        )
        if err != nil {
            return starterapp.ModulePlugin{}, err
        }
        return starterapp.ModulePlugin{
            ID:             "my_module",
            RegisterRoutes: module.RegisterRoutes,
            OpenAPI: []starterapp.OpenAPIOperation{{
                OperationID: "things.list",
                Method:      "GET",
                Path:        "/api/v1/things",
                Summary:     "List things",
            }},
        }, nil
    },
))
```

Authenticated routes inherit identity resolution, the anonymous mutation gate,
and the 1 MiB request-body cap. Declare intentionally anonymous surfaces with
`RegisterPublicRoutes`; those routes remain body-capped and appear as public in
the contributed OpenAPI document.

## Tests

```bash
go test ./pkg/starterapp/...
```

The `starterapp` package tests run the smoke suite (catalog composition,
first-boot seeding, HTTP route registration) plus the fresh-database
first-run regression and single-shared-pool guards. They all use a per-test
SQLite file under `t.TempDir()` and never touch the network.
