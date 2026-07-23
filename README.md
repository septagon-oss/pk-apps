# pk-apps

> Part of [PlatformKit](https://github.com/septagon-oss/platformkit) — the
> open-source Go backend for multi-tenant SaaS.

[![Go Reference](https://pkg.go.dev/badge/github.com/septagon-oss/pk-apps.svg)](https://pkg.go.dev/github.com/septagon-oss/pk-apps)
[![CI](https://github.com/septagon-oss/pk-apps/actions/workflows/go.yml/badge.svg)](https://github.com/septagon-oss/pk-apps/actions/workflows/go.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

`pk-apps` owns PlatformKit's canonical application composition package. It
connects `pk-core`, `pk-modules`, and `pk-runtime` into one importable starter
without introducing a product domain or a second runnable application.

## Choose one entry point

To run PlatformKit, clone the public front door:

```bash
git clone https://github.com/septagon-oss/platformkit
cd platformkit
go run .
```

To build a downstream product, import
`github.com/septagon-oss/pk-apps/pkg/starterapp` and contribute
application-owned modules through `starterapp.WithModules`:

```go
err := starterapp.Run(
    ctx,
    starterapp.DefaultConfig(),
    starterapp.WithModules(yourModule),
)
```

`reference/custommodule` is the sole reference implementation of that
extension seam. It is intentionally outside `pkg/`: it is not installed by the
starter, not a product template, and not another supported composition.

## What `starterapp` composes

The package assembles nine reusable OSS modules against one shared SQLite
connection:

- tenant, user, authentication, and API-key management;
- content, notifications, and append-only audit;
- admin and health surfaces;
- authenticated request identity, explicit API scopes, request limits, and
  extension OpenAPI discovery.

The canonical front door binds to loopback and installs local development
bootstrap data. Configured and non-development environments fail closed without
an explicit administrator password.

Product workflows, client modules, hosted deployment state, and commercial
capabilities belong outside this repository.

## Verify

```bash
make verify
```

For architecture, configuration, security, and extension guides, use the
[PlatformKit documentation hub](https://github.com/septagon-oss/pk-docs).

## License

Apache-2.0. See [LICENSE](LICENSE).
