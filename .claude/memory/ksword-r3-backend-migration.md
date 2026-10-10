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

## CLI 消费共享 R3 后端

- 66 项 CLI 对应关系保存在 `docs/cli/coverage.json`，业务文档位于 `docs/cli/`；`CommandRegistry` 同时定义命令路径、参数校验与逐层帮助，R3 适配器按业务源文件注册。已有 R0 入口保留默认行为，显式 R3 不自动调用驱动。
- 后端 UI 状态文本只作显示；CLI 使用结构化 API 状态、实际回读与资源关闭字段，不能从“完成”文本推导成功。未知数据用 null；地址/句柄用十六进制字符串，64 位计数/FILETIME 用十进制字符串。
- 安全证据 helper 使用系统 Windows PowerShell、UTF-8 JSON 与已有 lossless evidence JSON 解析器；超时/取消回收自己启动的 helper，逐来源区分不可用、部分和格式错误。Bugcheck 迁移的 R3 能力只有计算机环境元数据；BAM/ahcache 只包含原后端摘要，不推导执行历史。
- 进程身份查询在全部导航、详情、名称和事件路径采样期间保留经过创建时间验证且带 SYNCHRONIZE 的进程句柄。PID 显示回退不是可执行文件名称证据，采样后还需检查退出状态。
- NPFS 原生目录枚举路径必须带末尾反斜杠，否则可能出现 open 成功而目录 query 返回 C000000D。剪贴板的 NULL opener 不能证明剪贴板未被占用；OpenClipboard(NULL) 的重复打开行为与显式 HWND 不同。
