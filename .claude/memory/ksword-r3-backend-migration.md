# Light R3 shared backend migration

- Target: `shared/usermode/backend/`, namespace `ks::r3`; no Qt or reverse Light includes.
- Keep existing Qt-free `ksword` and ArkDriverClient unchanged; no new CLI commands.
- One secondary feature per commit, after Light Release/x64 linking and complete LightTests/suite-manifest PASS.
- Preserve texts, raw endpoint tuples, partial results, order, identity checks, thread ownership and resource lifetime.
- Baseline Light build and 41 expected suites passed; logs in `.codex-build-logs/r3-migration/baseline-*`.
- First migration: TCP/UDP enumeration and TCP close. GUI connection/firewall models stay in Light; public endpoint types, WinSock/address helpers and close policy live in shared.
- Use the 64-bit MSBuild/v143 HostX64 toolchain with all three architecture properties; reuse existing driver, disable driver build/sign for Light standalone builds.
- Exact per-feature build/test records and commit IDs: `.codex-build-logs/r3-migration/progress.jsonl`.
