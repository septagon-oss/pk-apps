# pk-apps

Minimal OSS app examples for PlatformKit.

This repo proves that the public core and public module pack can compose into a
real module plan. It should not contain Pro modules, client overlays, staging
state, or private deployment automation.

## Current Surface

- `examples/minimal`: composes the core OSS module pack

## Verify

```bash
go test ./...
go run ./examples/minimal
```
