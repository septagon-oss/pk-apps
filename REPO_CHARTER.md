# pk-apps Charter

## Purpose

Own the single importable PlatformKit OSS starter composition used by the
public `platformkit` front door and downstream applications.

## In scope

- `pkg/starterapp`: the canonical nine-module composition, HTTP perimeter,
  local bootstrap, configuration, and lifecycle.
- `reference/custommodule`: one non-shipped downstream extension reference.
- Conformance, security, and end-to-end tests for the composition.

## Out of scope

- Runnable application binaries or alternate starters.
- Teaching-only module bundles.
- Sample products, client domains, showcase applications, or hosted-service
  assumptions.
- Production deployment manifests and staging state.

## Dependencies

- `github.com/septagon-oss/pk-core` — core contracts.
- `github.com/septagon-oss/pk-modules` — reusable module implementations.
- `github.com/septagon-oss/pk-runtime` — runtime host and HTTP contracts.
- `github.com/septagon-oss/pk-shared` — shared vocabulary.
- `github.com/septagon-oss/pk-testkit` — test helpers.
- `modernc.org/sqlite` — embeddable database.
