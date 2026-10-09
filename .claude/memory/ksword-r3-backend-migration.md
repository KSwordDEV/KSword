# Light R3 shared backend migration

- Target: `shared/usermode/backend/`, namespace `ks::r3`; no Qt or reverse Light includes.
- Keep existing Qt-free `ksword` and ArkDriverClient unchanged; no new CLI commands.
- One secondary feature per commit, after Light Release/x64 linking and complete LightTests/suite-manifest PASS.
- Preserve texts, raw endpoint tuples, partial results, order, identity checks, thread ownership and resource lifetime.
- Baseline Light build and 41 expected suites passed; logs in `.codex-build-logs/r3-migration/baseline-*`.
- First migration: TCP/UDP enumeration and TCP close. GUI connection/firewall models stay in Light; public endpoint types, WinSock/address helpers and close policy live in shared.
- Use the 64-bit MSBuild/v143 HostX64 toolchain with all three architecture properties; reuse existing driver, disable driver build/sign for Light standalone builds.
- Exact per-feature build/test records and commit IDs: `.codex-build-logs/r3-migration/progress.jsonl`.

## Completed migration and verification

- Completed 66 independent feature commits on `main`, followed by documentation of final validation. Durable full-SHA/build/regression ledger: `shared/usermode/backend/MIGRATION.jsonl`; entry-point overview: `shared/usermode/backend/README.md`.
- The planned groups cover network, service/registry, startup/privilege, files, processes/details, drivers, hardware, windows, ETW, system tools, native object/NtQuery queries and security evidence. Final source review also extracted window-list capture protection, clipboard clearing/live owner queries and remaining native process identity/name adapters.
- File mapped-process scanning in this checkout is pure R0, so it remains in Light. Core application startup/elevation, R0 workflow guards, navigation-cache selection, UI clipboard copy/export/paste and rendering remain frontend/application responsibilities.
- Final Light Release/x64 clean rebuild and complete regression passed (42 suites; 68 shared-backend assertions). All 98 backend `.cpp` files compile/link in the standalone `/W4 /WX` test project. Both consumer projects and filters register every backend source/header.
- `tools/Test-KSwordR3BackendBoundary.ps1` compiles each backend header in its own TU and checks actual compiler include traces. Final 109-header check passed, and the standalone test executable has no Qt DLL dependency.
- R3 token fallback and object-type R0 evidence use synchronous callback/adapter boundaries at the original call locations; mixed collectors retain the caller-owned verified process lease until R0 completes. Preserve thread/COM/ETW/clipboard/PDH lifetime semantics when adding CLI consumers.
- MSBuild uses the source basename for object outputs by default: splitting two same-named samplers across directories collides. Use distinct implementation basenames (`SystemPerformanceSampler.cpp`, `DiskActivitySampler.cpp`) and invalidate the affected original TU after resolving a collision.
- Make byte-container zero-fill types explicit (`BYTE{0}`) for `/W4 /WX`; retain the same behavior. Task Scheduler code needs Taskschd/UUID link dependencies when compiling outside the Light project.
- All original Light C++ string literals were retained. Source/code-scope audits and automated regressions do not replace manual acceptance of every live GUI operation.
- No migration commit changed the main application, CLI, existing shared implementation, driver/client/protocol sources. Reused the existing driver binary and disabled driver rebuild/sign during standalone Light validation.
