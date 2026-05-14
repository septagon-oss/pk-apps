# Contributing

This repository is the small OSS upstream for PlatformKit.

Early contributions should preserve the minimal surface:

- keep core framework packages provider-neutral
- do not add private `septagon-dev` imports
- do not add client, demo, staging, or hosted-cloud assumptions
- add tests for contract behavior before expanding APIs

Run before opening a pull request:

```bash
go test ./...
```

