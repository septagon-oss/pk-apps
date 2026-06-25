# pk-apps Charter

## Purpose

Runnable PlatformKit OSS app compositions and examples. Demonstrates how modules, runtime, and core contracts compose into working applications.

## In Scope

- `starter-saas`: a complete, runnable SaaS application with 9 composed modules, SQLite persistence, admin UI, health checks, and Prometheus metrics
- `cmd/`: individual application binaries and entry points
- `examples/`: focused code samples showing specific composition patterns
- `minimal/`: the smallest possible PlatformKit application

## Out of Scope

- Production deployment configurations (Docker Compose, Kubernetes manifests)
- Staging or demo infrastructure
- Benchmarking or load-testing harnesses
- Commercial product compositions with Pro modules

## Dependencies

- `github.com/septagon-oss/pk-core` — core contracts
- `github.com/septagon-oss/pk-modules` — reference module implementations
- `github.com/septagon-oss/pk-runtime` — runtime host and HTTP contracts
- `github.com/septagon-oss/pk-shared` — shared vocabulary
- `github.com/septagon-oss/pk-testkit` — test helpers
- `modernc.org/sqlite` — embeddable database
