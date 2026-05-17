# pk-apps

Minimal OSS app examples for PlatformKit.

This repo proves that the public core and public module pack can compose into a
real module plan. Apps are where modules become product workflows: they choose
module sets, provider options, runtime hosts, and integration policies without
changing the modules underneath. This repo should not contain Pro/private
modules, client overlays, staging state, or hosted deployment automation.

## Current Surface

- `examples/minimal`: composes the core OSS module pack
- `examples/runtime`: composes the module pack into `pk-runtime` and verifies
  `/ready` through `pk-testkit`

## Verify

```bash
make verify
make staticcheck
make example
make runtime-example
```
