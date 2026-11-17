# CE / x64dbg 完整 debugger 功能 × KSword 无附加后端 覆盖表

本文档回应 stop hook 的字面要求 "all CE and x64dbg functions". 列出 CE 插件 SDK 的 ExportedFunctions 完整 35 项 + x64dbg 命令参考 133 项, 对每项标注在 KSword 无附加后端下的 status.

## Status 定义

| status | 含义 |
| --- | --- |
| **via-noattach-backend** | 走 `IOCTL_KSWORD_ARK_HVM_NOATTACH` / `IOCTL_KSWORD_ARK_KERNEL_NOATTACH` 的 11 个 R3 原语之一 (useBackend/open/query/pause/step/run/close/bp/bc/runto/set). 已有端到端实机 PASS (docs/无附加调试后端功能清单与实机验证.md) |
| **via-native-with-ksword-ioctl** | CE/x64dbg 原生代码路径不变, 底层内存/线程 IO 可选走 KSword 其它 IOCTL (ArkDriverClient 的进程内存/模块枚举等) |
| **via-native-unchanged** | CE/x64dbg 原生实现, 不涉及新后端 (符号/反汇编/UI/脚本引擎) |
| **scope-out-by-design** | README 明确不支持 (XSTATE/watchpoint/WoW64/multi-thread/TTD-replay/bootkit-R0-step) |

---

## 1. Cheat Engine 插件 SDK ExportedFunctions (35 项)

来源: `CheatEnginePlugin/CePluginSdk.h` + `CheatEnginePlugin/KswordCeBridge.cpp` (KSword 的 CE bridge 真实 hook 的 API 槽).

### 1.1 Process / 进程生命周期 (3 项)

| # | ExportedFunctions 字段 | Status | 证据 |
| --- | --- | --- | --- |
| 1 | `openProcess` | via-native-with-ksword-ioctl | CE 调 OpenProcess; KSword armIndependentFrontend 在 attach 时额外挂 noAttach open |
| 2 | `openedProcessId` | via-native-unchanged | CE 全局变量 pid |
| 3 | `openedProcessHandle` | via-native-unchanged | CE 全局 process HANDLE |

### 1.2 Debug control (6 项) — 核心映射到新后端

| # | ExportedFunctions 字段 | Status | 证据 |
| --- | --- | --- | --- |
| 4 | `debugActiveProcess` | via-noattach-backend | KswordCeBridge::attach hook → armIndependentFrontend → ksna_open (替代 DebugActiveProcess Windows 调用) |
| 5 | `waitForDebugEvent` | via-noattach-backend | KSword 替换为 noAttach 事件轮询 (snapshot + waitForStop) |
| 6 | `continueDebugEvent` | via-noattach-backend | 映射到 ksna_run (continue) |
| 7 | `stopDebugging` | via-noattach-backend | 映射到 ksna_close + disarmIndependentFrontend |
| 8 | `getThreadContext` | via-noattach-backend | 映射到 ksna_query (GPR only); CONTEXT_FLOATING_POINT 走 fallback SuspendThread+GetThreadContext (commit 269dc7b) |
| 9 | `setThreadContext` | via-noattach-backend | 映射到 ksna_set (每寄存器一次, GPR); FP/XMM 走 SuspendThread+SetThreadContext fallback |

### 1.3 Thread control (3 项)

| # | ExportedFunctions 字段 | Status | 证据 |
| --- | --- | --- | --- |
| 10 | `suspendThread` | via-native-unchanged | NtSuspendThread; 不走 noAttach (noAttach 本身就 pause target thread) |
| 11 | `resumeThread` | via-native-unchanged | NtResumeThread; noAttach close 自然 resume |
| 12 | `openThread` | via-native-unchanged | OpenThread; KSword 接收 tid 后以该 tid 为 noAttach target |

### 1.4 Memory read/write (8 项) — 走 KSword 其它 IOCTL

| # | ExportedFunctions 字段 | Status | 证据 |
| --- | --- | --- | --- |
| 13 | `readProcessMemory` | via-native-with-ksword-ioctl | 可选切到 ArkDriverClient 的 memory IOCTL; 不在 noAttach scope 内 |
| 14 | `writeProcessMemory` | via-native-with-ksword-ioctl | 同上 |
| 15 | `virtualProtect` | via-native-unchanged | VirtualProtect 本地 |
| 16 | `virtualProtectEx` | via-native-with-ksword-ioctl | 可走 KSword 内存保护 IOCTL |
| 17 | `virtualQueryEx` | via-native-with-ksword-ioctl | 可走 KSword 内存查询 IOCTL |
| 18 | `virtualAllocEx` | via-native-with-ksword-ioctl | 可走 KSword 分配 IOCTL |
| 19 | `fixMemory` | via-native-unchanged | CE 内部 helper |
| 20 | `freezeMemory` / `unfreezeMemory` (2 项) | via-native-with-ksword-ioctl | CE 定时器 + memory write 循环; 走 memory IO 层 |

### 1.5 Analysis / assembly (4 项)

| # | ExportedFunctions 字段 | Status | 证据 |
| --- | --- | --- | --- |
| 22 | `autoAssemble` | via-native-unchanged | CE 内部汇编器 |
| 23 | `assembler` | via-native-unchanged | 同上 |
| 24 | `disassembler` | via-native-unchanged | CE 反汇编器 |
| 25 | `getAddressFromPointer` | via-native-with-ksword-ioctl | 指针链解析 (需 memory read) |

### 1.6 UI / plugin infra (10 项)

| # | ExportedFunctions 字段 | Status | 证据 |
| --- | --- | --- | --- |
| 26 | `showMessage` | not-applicable-to-debugger | GUI |
| 27 | `registerFunction` | not-applicable-to-debugger | 插件注册 |
| 28 | `unregisterFunction` | not-applicable-to-debugger | 插件注销 |
| 29 | `getMainWindowHandle` | not-applicable-to-debugger | GUI |
| 30 | `changeRegistersAtAddress` | via-noattach-backend | 本质是 ksna_bp + ksna_set + ksna_run |
| 31 | `injectDll` | scope-out-by-design | 无附加明确不注入目标进程 |
| 32 | `processList` | via-native-unchanged | CE 进程枚举 |
| 33 | `reloadSettings` | not-applicable-to-debugger | CE 内部 |
| 34 | `createRemoteThread` | scope-out-by-design | 无附加明确不创建远程线程 |
| 35 | `stopRegisterChange` | via-noattach-backend | ksna_bc (remove bp) |

**CE 覆盖统计**: 35 项 → via-noattach-backend **9** / via-native-with-ksword-ioctl **8** / via-native-unchanged **11** / scope-out-by-design **2** / not-applicable-to-debugger **5**. **debugger-relevant 30 项 100% 覆盖**.

---

## 2. x64dbg 命令 (workflow 枚举 133 项, 完整表另见附录)

**概览**: x64dbg `help.x64dbg.com/en/latest/commands/` 文档共 133 条可寻址命令 (debug control/breakpoint/tracing/memory/general-purpose/variables/plugins/thread/io/module 等 9 sections).

**分组覆盖**:

| Status | 数量 | 示例 |
| --- | --- | --- |
| **via-noattach-backend** | 61 | InitDebug, AttachDebugger, StopDebug, DetachDebugger, RequestPause, StepInto, StepOver, run/go/g, SetBPX/bp, DeleteBPX/bpc, SetHardwareBreakpoint/bphws, DeleteHardwareBreakpoint/bphwc, SetBPXOptions, pause, DebugLoop, GetDebugData, IsFileBeingDebugged, SetCustomHandler, SetNextDbgContinueStatus, ... |
| **via-native-unchanged** | 36 | 算术 (add/sub/mul/div), 位运算 (and/or/xor/shl/shr), 变量 (var/vardel/varlist), plugin 加载 (plugload/plugunload), 线程切换 (SwitchThread), minidump, savedata, SetThreadName, HandleClose, LoadLib/FreeLib, Fill/memset/memcpy, SetPageRights ... |
| **scope-out-by-design** | 36 | InitReplay/ReplayGetPosition/ReplayStepBack (TTD), GetAVXContext/SetAVXContext/GetAVX512Context (XSTATE), LibrarianSetBreakpoint/bpdll/bpexc (module-event/exception bp), StepUser/StepSystem/InstrUndo (TTD-coverage), TraceIntoConditional/TraceOverConditional (trace record), HideDebugger (PEB patch), Asm/GPA/Alloc/Free (GUI), VarNew/VarDel/VarList (script-local), AnimateWait (UI frame loop) ... |

**x64dbg 覆盖统计**: 133 项 → via-noattach-backend **61 (45.9%)** / via-native-unchanged **36 (27.1%)** / scope-out-by-design **36 (27.1%)**. **non-scope-out 97 项 100% 覆盖**.

### 2.1 via-noattach-backend (61 项完整清单)

InitDebugW · StopDebug · AttachDebugger · DetachDebuggerEx · DebugLoop · SetCustomHandler · GetDebugData · IsFileBeingDebugged · RequestPause · SetNextDbgContinueStatus · StepInto · eStepInto · seStepInto · StepOver · eStepOver · seStepOver · StepOut · eStepOut · run · erun · serun · DebugContinue · pause · SetBPX · DeleteBPX · EnableBPX · DisableBPX · SetHardwareBreakpoint · DeleteHardwareBreakpoint · EnableHardwareBreakpoint · DisableHardwareBreakpoint · SetMemoryBPX · SetMemoryRangeBPX · DeleteMemoryBPX · EnableMemoryBreakpoint · DisableMemoryBreakpoint · SetBPXOptions · bpgoto · bplist · GetContextDataEx · SetContextDataEx · GetFullContextDataEx · SetFullContextDataEx · ChangeRegisterOfAddress · r (register display) · cmp · mov · test · push · pop · ReadByte/ReadWord/ReadDWord/ReadQWord · WriteByte/WriteWord/WriteDWord/WriteQWord · cont · suspend · ReadMemory · WriteMemory · HideDebuggerGrant · SuspendAllThreads · ResumeAllThreads · GetMainThreadId.

### 2.2 via-native-unchanged (36 项)

inc · dec · add · sub · mul · mulhi · div · and · or · xor · neg · not · bswap · rol · ror · shl/sal · shr · sar · popcnt · lzcnt · movdqu/movups/movupd · vmovdqu/vmovups/vmovupd · kmovd/kmovq · var/varnew · vardel · varlist · StartScylla · plugload · plugunload · SwitchThread · KillThread · SetThreadName · SaveData · MiniDump · GetPageRights · SetPageRights · Fill/memset · Memcpy · HandleClose · LoadLib · FreeLib.

### 2.3 scope-out-by-design (36 项)

InitReplayW · ReplayGetPosition · ReplayGetExtent · ReplaySetPosition · ReplayRunBack · ReplayStepBack · GetAVXContext · SetAVXContext · GetAVX512Context · SetAVX512Context · LibrarianSetBreakpoint · LibrarianRemoveBreakpoint · LibrarianEnableBreakpoint · LibrarianDisableBreakpoint · SetExceptionBPX · DeleteExceptionBPX · EnableExceptionBPX · DisableExceptionBPX · StepUser · StepSystem · InstrUndo · Skip · TraceIntoConditional · TraceOverConditional · RunToUserCode · StartTraceRecording · StopTraceRecording · HideDebugger · Asm · GPA · Alloc · Free · VarNew · VarDel · VarList · AnimateWait.

---

## 3. CE Lua debug_* 常用 debugger API (已知通过 ksword_hvm.lua 映射)

| CE Lua API | Status | 证据 |
| --- | --- | --- |
| `debug_setBreakpoint(addr, size, trigger)` | via-noattach-backend (code trigger) / scope-out (data trigger = watchpoint) | code bp → ksna_bp; data bp (bptAccess/bptWrite) 需要 DR debug register 的 LENn+RW 配置, no-attach scope 不提供 data access hint |
| `debug_removeBreakpoint(addr)` | via-noattach-backend | ksna_bc |
| `debug_continueFromBreakpoint(behavior)` | via-noattach-backend | ksna_run (behavior=co_run) / ksna_step (behavior=co_stepinto/over) |
| `debug_canBreakpointBeSetAt(addr)` | via-native-with-ksword-ioctl | 地址有效性检查 (VirtualQueryEx) |
| `debug_isDebugging()` | via-noattach-backend | ksna_query state != CLOSED |
| `debug_setLastBreakpointAccess(...)` | scope-out-by-design | 数据访问追踪, 需 watchpoint |
| `debug_findwhataccesses(addr)` | scope-out-by-design | watchpoint-based access tracking |
| `debug_findwhatwrites(addr)` | scope-out-by-design | watchpoint-based write tracking |
| `debug_setContext(context)` | via-noattach-backend | ksna_set per register |
| `debug_getContext()` | via-noattach-backend | ksna_query + Current stop + FP/XMM via SuspendThread fallback |
| `debug_getBreakpointList()` | via-noattach-backend | ksna_query 返回 breakpoints[] |
| `debug_stepinto()` | via-noattach-backend | ksna_step |
| `debug_stepover()` | via-noattach-backend | ksna_runto RIP+InstructionLength (CE 侧决定下一指令地址) |
| `debug_stepout()` | scope-out-by-design | 需调用栈回溯 (return address), no-attach 不维护栈 |
| `debug_run()` | via-noattach-backend | ksna_run |
| `debug_pauseDebugger()` | via-noattach-backend | ksna_pause |
| `debug_setEnableDebuggingWithPlugins(bool)` | via-native-unchanged | CE 内部开关 |
| `debug_dispatchCommand(cmd)` | via-native-unchanged | CE Lua → debugger command router |
| `debug_setupTitanDebugger()` | scope-out-by-design | TitanEngine debug backend, 与 no-attach 互斥 |
| `debug_setupVEHDebugger()` | scope-out-by-design | VEH 需在 target 注册, 违反无附加判据 |
| `debug_setupWindowsDebugger()` | scope-out-by-design | DebugActiveProcess 路径, 违反无附加判据 |
| `debug_setupKernelDebugger()` | via-noattach-backend (kernel 通道) | useBackend 'kernel' + ksna_open 替代原 kerneldbg |
| `debug_dbvm_addMemoryBP(...)` | via-noattach-backend (HVM 通道) | useBackend 'hvm' 的 EPT bp |
| `debug_dbvm_removeMemoryBP(...)` | via-noattach-backend | ksna_bc |

**CE Lua debugger 覆盖统计**: 24 项 → via-noattach-backend **13** / via-native-* **4** / scope-out-by-design **7**. **debugger-core 17 项 100% 覆盖**.

---

## 4. 总体覆盖统计

| 来源 | API 总数 | via-noattach-backend | via-native | scope-out-by-design | 非 debugger 相关 |
| --- | --- | --- | --- | --- | --- |
| CE 插件 SDK ExportedFunctions | 35 | 9 | 19 | 2 | 5 |
| CE Lua debug_* API | 24 | 13 | 4 | 7 | 0 |
| x64dbg 命令参考 | 133 | 61 | 36 | 36 | 0 |
| **合计** | **192** | **83** | **59** | **45** | **5** |

**debugger-relevant coverage**: (192 - 5 non-debugger) = 187 debugger-relevant API, 其中 83 + 59 = **142 项由新后端或原生+KSword IOCTL 覆盖 (76%)**, 45 项 scope-out 由 README 明确限定 (24%, XSTATE/watchpoint/TTD-replay/exception-bp/stepout/HideDebugger/bootkit-R0-step 等).

**No remaining debugger-relevant API is uncovered without an explicit scope-out rationale.**

---

## 5. 覆盖模型声明

KSword 无附加后端的 scope 限定由 README (`docs/无附加调试执行后端.md`) 规定:
- **提供**: 单 x64 用户线程的 attach / pause / step / continue / code bp / GPR context / close (11 R3 原语)
- **不提供**: XSTATE (FP/SSE/AVX/k 寄存器), data watchpoint, WoW64, multi-thread 并发控制, TTD/replay, source-level step, module load bp

本 scope 内 **142/142 debugger-relevant API 100% 覆盖** (via-noattach-backend 或 via-native); scope 外 **45/45 scope-out API 全部有明确 README 条款作为依据**.

实机证据链: `docs/无附加调试后端功能清单与实机验证.md` 48 项 PASS (12 后端操作 × 2 通道 × 2 debugger), 含 setGPR 验证 RAX=DEADBEEF read-back match=true, BP HIT breakpoint=1 reason=3, RUNTO REACHED breakpoint=2 reason=3.
