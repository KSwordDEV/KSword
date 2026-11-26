# 私有内存指针导出绑定 · 本机实测回执

- 日期：2026-11-26
- 范围：ActionAnalyze 11 项验收清单第 5 项，正式 CLI 单目标 AMD64 私有内存指针导出，以及 `OwnedDataWatchSession` 同一启动语义。
- 测试主机：Windows 10 Pro for Workstations，AMD64；只使用自有子进程和本机调试 API，不加载驱动，不附加系统进程或用户其它进程。
- 测试对象：`Ksword5.1/x64/Release/KswordCLI.exe`，SHA-256 `375d4c19a8db526f8ac864d70db00a84b7f615a791a766f37b3987a5d0ddeb9f`。整批运行前后散列一致，没有并发重建。测试后同树仍有其它作者的并发构建，但不再改变本次证据的实际产物身份。
- 夹具：`tools/action_analyze_validation/private_pointer_watch/`，GCC 16.1.0（MSYS2 UCRT64）构建，SHA-256 `118ebe7568a7b0198b98f2a70bfa56fe278ae0c7cbd43c599a6dca4f974939c6`。
- 原始会话：`.codex-build-logs/behavior-planning/action-analyze-private-pointer-watch-20261126-080516-378909-40060.log`，229 行，`PRIVATE_POINTER_WATCH=PASS`。

## 一、产品入口与本次改动

| 入口 | 改动 |
| --- | --- |
| `KswordCLI/ActionAnalyze/Control/CooperativeBreakpointGate.{h,cpp}` | 新模块。复用双目标 Ready 事件与 Gate 管道参数；目标只继承置位事件副本和管道读端，宿主独占写端；只有真实 `Armed` 才写入 `'1'`，EOF 取消启动。 |
| `KswordCLI/ActionAnalyze/Control/NativeBreakpointImage.{h,cpp}` | 新增 `ResolveNativePointerDataSite`、`VerifyNativePointerDataSite`；只读取 AMD64 PE 的指针数据导出，冻结当前 `MEM_PRIVATE` 可写区间，停止期间回读选择器和区域属性。 |
| `KswordCLI/ActionAnalyze/Control/NativeDebugOwner.{h,cpp}` | `NativeBreakpointRequest::writeWatchPointerExport` 与 `NativeBreakpointBinding` 的 `pointerExportAddress/allocationBase/regionBase/regionBytes/regionProtection`；只在 `ArmBreakpoint` 准入、`InstallBreakpoint`、`ReadWatchedData`、`PrepareBreakpointResume` 接入。 |
| `KswordCLI/ActionAnalyze/Control/OwnedDataWatchSession.{h,cpp}` | `Start` 的 `indirect` 参数默认 `false`，沿用原直接绑定语义；间接模式创建 Gate、等待 Ready、在 `Query` 中观察实际 `Armed` 后放行；`Close` 关闭写端取消未放行的业务。并发作者后来在参数末尾追加 `sampleId`，本批未改其步进／取消逻辑。 |
| `KswordCLI/ActionAnalyze/Cli/BreakpointCommand.cpp` | 正式 CLI `--watch-pointer-export`，必须与 `--watch-write-bytes` 和 `--export` 同时使用；回执列 `siteKind=private-pointer-export`、实际 `address` 和区域元数据。 |
| `KswordCLI/CommandRegistry.cpp` | 修复 `--watch-pointer-export` 被当作有值选项的缺陷，改为无值开关；本次修复构建 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，产物 SHA-256 `49321FA545F5AC82153C9D7BBC7FD33EEE3096D236485FB27F836A198E95487A`，随后同树并发构建 `375d4c…` 完成实测。 |
| Qt | 「监控 → 行为分析 → 写入停点」增加绑定方式选择，回执增加指针导出地址、私有分配基址、区域基址、区域字节数和区域保护。只做源码与语言包，未构建、未启动窗口。 |
| Light | 「监控 → ActionAnalyze → 写入停点」增加同一绑定方式选择和区域回执。只做源码，未构建、未启动窗口。 |

正式命令（夹具对每条用例逐条启动）：

```text
KswordCLI.exe analyze breakpoint session --exe <ActionAnalyzePrivatePointerWatch.exe> \
  --export WatchedPointer --watch-write-bytes 1|2|4|8 --watch-pointer-export \
  --confirm --disposition resume-detach --input jsonl
```

目标协议：解析继承的 `--ksword-breakpoint-ready`、`--ksword-breakpoint-gate`；初始化私有区域和 8 字节对齐指针后 `SetEvent(ready)`；阻塞读取 Gate；只有收到字节 `'1'` 才进入业务，EOF 正常退出。夹具不使用 sleep 猜测就绪。

## 二、夹具与固定输出

| 项目 | 路径／值 |
| --- | --- |
| 源码 | `tools/action_analyze_validation/private_pointer_watch/PrivatePointerWatchChild.c` |
| MSVC 工程 | `PrivatePointerWatchChild.vcxproj`、`.filters`；固定 `IntDir=<工具目录>/x64/Release`，统一 `OutDir=Ksword5.1/x64/Release` |
| 本机实际编译 | `D:\Software\msys64\ucrt64\bin\gcc.EXE -O2 -Wall -Wextra -Wno-unused-parameter …`，`BelowNormal`，退出 `0` |
| 夹具产物 | `Ksword5.1/x64/Release/ActionAnalyzePrivatePointerWatch.exe`，运行时 SHA-256 `118ebe…` |
| 互斥 | `Local\KSword.ActionAnalyze.CliValidation`，同一线程 `try/finally` 持有；本批为等待方，未与其它 CLI 验收并发运行。正式 CLI 构建经仓库 `tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI`，构建前等待既有 CLI 产物锁释放；构建后整批运行由 Python 同线程持有该互斥。 |
| 回执文件 | 目标在 Ready 前写出实际 `pointer/allocationBase/regionBase/regionBytes/regionProtection/type`；测试逐项对照 CLI 输出后删除 |

夹具初始化 `VirtualAlloc` 私有区域（64 KiB）和指针；`rw` 为 `PAGE_READWRITE`，`rwx` 为 `PAGE_EXECUTE_READWRITE`。`KSwordActionAnalyzeDataWatchV1` 标记和 `WatchedPointer` 均在 PE 导出中，后者位于可写数据节。

## 三、通过结果

### 1. 真实变化、同值、范围外、新线程、旧令牌、Continue、Close

| 宽度／保护 | 实际关注地址 | 指针导出地址 | 私有分配基址 | 区域字节 | 区域保护 | 结果 |
| --- | --- | --- | --- | ---: | ---: | --- |
| 1／RW | `0x278A6F50100` | `0x00007ff60dd18030` | `0x278A6F50000` | 65,536 | `4` | 通过 |
| 2／RW | `0x17215CD0100` | `0x00007ff60dd18030` | `0x17215CD0000` | 65,536 | `4` | 通过 |
| 4／RW | `0x1752A160100` | `0x00007ff60dd18030` | `0x1752A160000` | 65,536 | `4` | 通过 |
| 8／RW | `0x1A4959B0100` | `0x00007ff60dd18030` | `0x1A4959B0000` | 65,536 | `4` | 通过 |
| 8／RWX | `0x1B4525A0100` | `0x00007ff60dd18030` | `0x1B4525A0000` | 65,536 | `64` | 通过 |

每个宽度均满足：

- `breakpoint.siteKind=private-pointer-export`，`address` 等于目标回执的实际指针，`pointerExportAddress` 指向映像选择器且与 `address` 不同。
- 范围外写和同值写不产生停点，业务完成事件自然出现。
- 首次真实变化掩码为 `1`；`enrolledAfterStop=0`，命中线程创建 FILETIME 与独立 `GetThreadTimes` 一致。
- 继续后由首次停点后新建的线程写关注范围末字节再次命中：宽度 1/2/4/8 的掩码分别为 `1/2/8/128`，`enrolledAfterStop=1`，TID 和 `threadId` 均与首停点不同。
- 用第一代停点令牌提交 `continue/2` 返回 `stale-stop`，当前停点仍持有。
- 关闭回执 `clean=true`、`attached=false`、`breakpoint.state=retired`、`enrolledThreads=0`；CLI 和目标均退出 `0`；脱离后目标仍能写同一区间并正常退出。

### 2. 空指针与不可绑定区间

| 用例 | CLI 原生结果 | 目标取消 |
| --- | --- | --- |
| 指针为 0 | `breakpoint.state=rejected`，`stage=resolve-requested-image-site`，Win32 `487` | Gate EOF，退出 `0` |
| 8 字节宽度下未对齐 | 同上 | 同上 |
| 区域为 `PAGE_READONLY` | 同上 | 同上 |
| 指针指向 `MEM_IMAGE` 数据节 | 同上 | 同上 |
| 指针在提交页末端、宽度越界 | 同上 | 同上 |

`487` 为 `ERROR_INVALID_ADDRESS`。五种拒绝均未发布停点，也未把选择器内容当作可写私有区间。

### 3. 区间失效后不重绑

| 失效方式 | CLI 结果 | 重绑 |
| --- | --- | --- |
| 首次停点后选择器改指另一私有分配 | `breakpoint.state=retired`，`stage=write-watch-private-region-changed` | `false` |
| 首次停点后区域保护改为 `PAGE_EXECUTE_READWRITE` | 同上 | `false` |
| 释放后在同一地址映射文件视图（`MEM_MAPPED`） | 同上 | `false` |

三种情况都继续使用原关注地址完成写入，下一次硬件停点回读时清退旧绑定，`pointerExportAddress`、`address` 和区域元数据仍保留旧值，没有发布第二个绑定。目标随后正常退出 `0`。

> 设计修正：最初使用 `PAGE_READWRITE|PAGE_NOCACHE` 作为保护变化，实测该标志在目标区域被忽略，CLI 仍正常持有停点。改为同样可写的 `PAGE_EXECUTE_READWRITE` 后，冻结的保护属性差异被 `VerifyNativePointerDataSite` 检出。失败原始日志见 `.codex-build-logs/behavior-planning/action-analyze-private-pointer-watch-20261126-080328-281161-12556.log`。

### 4. 启动取消

| 场景 | 结果 | 耗时 | CLI 退出 |
| --- | --- | ---: | ---: |
| 目标不置位 Ready | `private-data-target-not-ready`，Win32 `1460`（`ERROR_TIMEOUT`） | 5.031 s | `3` |
| 目标在 Ready 前退出 | `private-data-target-not-ready`，Win32 `1067`（`ERROR_PROCESS_ABORTED`） | 0.016 s | `3` |
| 武装前取消／EOF | 五种拒绝用例均在 Gate 关闭后由 EOF 正常退出 | — | 目标 `0` |

产品 Ready 上限为 5 秒；夹具不缩短产品等待，测试允许范围 4.5–7.5 秒。

## 四、失败原始记录与修复

| 日志 | 实际失败 | 处理 |
| --- | --- | --- |
| `…-20261126-075943-319317-2388.log` | 测试把 CLI 帧当成 `result`，读取 `hello['targetPid']` 抛 `KeyError` | 修正测试会话返回值为 `frame['result']` |
| `…-20261126-080024-606477-41924.log` | `CheckRemoteDebuggerPresent` 以 `PROCESS_QUERY_LIMITED_INFORMATION` 打开目标，返回 Win32 `5` | 改为 `PROCESS_QUERY_INFORMATION`，与既有夹具一致 |
| `…-20261126-080328-281161-12556.log` | `PAGE_NOCACHE` 未被目标区域保留，保护变化用例仍正常持有停点 | 改用 `PAGE_EXECUTE_READWRITE`，写入仍可完成且保护属性不同 |

这三份日志保留在 `.codex-build-logs/behavior-planning/`，作为失败原始证据，不纳入通过结论。

## 五、清理与边界

- 夹具 EXE、工具目录 `x64/Release`、临时回执文件均已删除；无残留 `ActionAnalyzePrivatePointerWatch.exe` 或 `KswordCLI.exe` 进程。
- 统一 Release 中没有新增随机目录或运行副本；证据日志是唯一保留的文本产物。
- Windows 区域查询不提供分配代次；`allocationGenerationVerified=false`。同地址释放后由另一个私有分配原样重用的情况无法由当前 API 证明，回执不作该承诺。
- 对齐宽度为 1/2/4/8，页粒度区域边界与宽度对齐的组合使“对齐且跨区”的请求不可能成立；越界用例实际由对齐检查先拒绝。任意私有页、任意长度、跨区范围和后续新分配自动传播仍为无。
- 异常终止恢复、所有者死亡后继续控制、多目标私有指针绑定不在本批范围。
- Qt／Light 只完成源码、工程和语言包检查；未构建桌面端、未启动 GUI。Light 低高度窗口的既有纵向布局缺口未在本批修复，不能宣称视觉验收通过。
- 语言包定点新增「绑定区域基址」「绑定区域保护」中英文条目；`python tools/i18n_language_pack.py audit` 退出 `0`，审计 32,034 条源字符串。桌面工程和新增源文件均已登记，未做桌面编译。
- 步进底层与 `NativeStepRuntime` 由另一位作者修复，本批未修改其逻辑，也未覆盖其工作树改动。

## 六、11 项第 5 项定点登记

| 判据 | 实际证据 |
| --- | --- |
| 正式 CLI 绑定方式 | `--watch-pointer-export` 无值开关，`--watch-write-bytes` 1/2/4/8；`siteKind=private-pointer-export` |
| 真实地址 | 每轮 CLI `address` 与目标 `VirtualAlloc` 返回值逐字节相等；选择器地址、分配基址、区域基址、字节数和保护均独立对照 |
| 私有类型 | `MEM_PRIVATE`（类型 `0x20000`）；RW 保护 `4`，RWX 保护 `0x40` |
| 真实变化 | 四宽度首字节变化掩码 `1`；后建线程末字节掩码 `1/2/8/128`；同值、范围外均放行 |
| 新线程 | 首停点后创建，TID、`threadId`、创建 FILETIME 均独立核验，`enrolledAfterStop=1` |
| 旧令牌 | 第一代令牌在第二代停点上返回 `stale-stop`，当前停点未释放 |
| Continue／Close | 继续返回 `continued`；关闭 `clean=true`、`attached=false`、登记归零，目标脱离后继续写入并退出 `0` |
| 拒绝 | 空指针、未对齐、只读、`MEM_IMAGE`、越界均为 `rejected`／Win32 `487` |
| 不重绑 | 指针变更、保护变更、释放后同址映射替换均为 `write-watch-private-region-changed`，无第二个绑定 |
| Ready／退出／EOF | 无 Ready 5.031 s 后 `1460`；提前退出 0.016 s 后 `1067`；武装前关闭 Gate 由 EOF 正常退出 |
| 桌面 | 绑定方式和区域回执已接入 Qt／Light 源码，双语文审 32,034 条通过；桌面构建、GUI 和低高度布局未验 |
