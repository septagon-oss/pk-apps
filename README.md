# pk-apps

Minimal OSS app examples for PlatformKit.

This repo proves that the public core and public module pack can compose into a
real module plan. Apps are where modules become product workflows: they choose
module sets, provider options, runtime hosts, and integration policies without
changing the modules underneath. This repo should not contain Pro/private
modules, client overlays, staging state, or hosted deployment automation.

## Run me first: `apps/starter-saas`

The canonical "first-run" path for PlatformKit OSS v0.0.0 is the
**Starter SaaS** monolith at `apps/starter-saas`. One Go binary, one
SQLite file, and all nine OSS modules — `tenant_management`,
`user_management`, `auth_management`, `api_key_management`,
`content_management`, `notification_management`, `audit_management`,
`health_management`, and `admin_management` — composed end-to-end.

### Quickstart

```bash
git clone https://github.com/septagon-oss/septagon-oss-workspace
cd septagon-oss-workspace/pk-apps/apps/starter-saas
go run .
```

The binary boots on `:8080` and prints a banner with the admin URL plus
default credentials. On first boot it creates one tenant (`Acme Inc`)
and one admin user (`admin@local.test` / `changeme`).

### What you get on `:8080`

| Endpoint | Purpose |
|----------|---------|
| `/` | HTML landing page |
| `/admin` | Admin UI (entity CRUD + custom pages) |
| `/healthz` | Aggregated health checks (JSON) |
| `/metrics` | `expvar` runtime metrics (JSON) |
| `/live` | Liveness probe (`204 No Content`) |
| `/ready` | Readiness probe (JSON) |
| `/api/v1/tenants` | Tenant CRUD |
| `/api/v1/users` | User CRUD (requires `?tenant_id=...`) |
| `/api/v1/audit-events` | Audit log (read) |
| `/api/v1/auth/sessions` | Login + session lifecycle |
| `/api/v1/api-keys` | API key CRUD |
| `/api/v1/content` | Content CRUD |
| `/api/v1/notifications` | Notification CRUD |

See `apps/starter-saas/README.md` for the full reference, including
config, adding modules, and tests.

For a deeper walkthrough — what to read first, what to change first,
and how to swap a provider — see the
[Starter SaaS tutorial in pk-docs](https://github.com/septagon-oss/pk-docs/blob/main/docs/v0.0.0/starter-saas-tutorial.md).

## Other examples

- `examples/minimal` — composes the core OSS module pack with no
  runtime; useful as a unit-test fixture for module wiring.
- `examples/runtime` — composes the module pack into `pk-runtime` and
  verifies `/ready` through `pk-testkit`.

## Verify

```bash
make verify
make staticcheck
make example
make runtime-example
```
