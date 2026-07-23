# Agent orientation

`pk-apps` owns one canonical composition package:
`pkg/starterapp`. It is a library repository. The only supported runnable
front door is [septagon-oss/platformkit](https://github.com/septagon-oss/platformkit).

## Canonical paths

- Build or embed the standard composition with `pkg/starterapp`.
- Extend it with `starterapp.WithModules`.
- Consult `reference/custommodule` only for the downstream extension contract.
  It is not a shipped module, product domain, second starter, or alternate
  architecture.
- `pkg/starterapp/bootstrap_migration.go` contains historical bootstrap
  literals solely to migrate durable state. They are not current defaults or
  alternate product examples.

Do not create app binaries, teaching bundles, sample products, client modules,
or alternate composition paths in this repository. Product-specific code
belongs in the downstream product repository.

Local development bootstrap data exists only to make the canonical front door
bootable on loopback. It is not production configuration and must never be
copied into deployed environments.

Before submitting changes, run `make verify`.
