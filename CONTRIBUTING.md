# Contributing

This repository is part of the small OSS upstream for PlatformKit.

Early contributions should preserve the minimal surface:

- keep packages provider-neutral
- do not add private or internal imports
- do not add client, demo, staging, or hosted-cloud assumptions
- add tests for contract behavior before expanding APIs

Run before opening a pull request:

```bash
make verify
```
