# KswordCLI 使用文档

本文档覆盖 `KswordCLI.exe` 当前内置 help 元数据中的全部命令、别名和参数语法。多数命令需要管理员权限，并要求 KswordARK 驱动设备已经加载且可打开。

## Help 查询

```powershell
KswordCLI.exe help
KswordCLI.exe help <family>
KswordCLI.exe help <family> <subcommand>
KswordCLI.exe <family> help
KswordCLI.exe <family> <subcommand> --help
```

维护要求：每新增、删除或调整一个 `KswordCLI` 命令、别名或参数，必须同步更新 `KswordCLI.cpp` 内置 help 元数据和本文档。

## 参数约定

- 数值参数支持十进制或 `0x` 前缀十六进制。
- `--flags 0xN` 是按位标志；具体含义以 `shared/driver/` 中对应协议头为准。
- `--limit N` 只限制 CLI 打印行数；`--max-*` 通常控制传给驱动的查询预算。
- `--hex`/`--*-hex` 接收十六进制字节串；`--data-file`/`--*-file` 从文件读取原始字节；同一 payload 的 hex 和 file 形式互斥。
- `--hexdump` 会把返回字节按十六进制展开打印。

## 命令族总览

| 命令族 | 用途 |
| --- | --- |
| `log` | Read bounded frames from the KswordARK log device. |
| `process` | Inspect and control process visibility, PPL, DKOM, and cross-view state. |
| `memory` | Query, read, write, translate, and audit virtual/physical memory. |
| `file` | Inspect files, filters, storage evidence, and file-monitor runtime state. |
| `kernel` | Inspect SSDT, hooks, driver objects, CPU, physical layout, CID, and IPC state. |
| `callback` | Manage callback rules, pending decisions, callback inventory, and bypass PIDs. |
| `dyn` | Query or apply dynamic kernel symbol/profile data. |
| `thread` | Enumerate threads and compare R0/R3 thread evidence. |
| `handle` | Enumerate process handles and inspect object metadata. |
| `driver` | Driver integrity, device stack, and optional global evidence aliases. |
| `hardware` | Device, input, USB, and PnP stack audit views. |
| `hwid` | HWID Dispatch query and guarded control operations. |
| `window` | Win32k, GUI, GPU, display, and watchdog audit views. |
| `misc` | Security, CI/VBS, Hyper-V, AppLocker/BAM, and driver trust posture. |
| `alpc` | ALPC port diagnostics for a process handle. |
| `section` | Process and file section mapping diagnostics. |
| `trust` | Image trust and signing diagnostics. |
| `safety` | Safety policy query and update controls. |
| `preflight` | Release-readiness and driver capability preflight checks. |
| `registry` | Registry read, enumeration, and mutation helpers. |
| `redirect` | File/registry redirect rules and runtime status. |
| `network` | Network rules, endpoints, WFP/NDIS evidence, and R3 fallbacks. |
| `keyboard` | Keyboard hotkey and hook inventory. |
| `mutation` | Prepare, commit, rollback, and audit bounded mutation transactions. |
| `capability` | Unified driver feature capability query. |
| `wsl` | WSL silo and Linux PID/TID diagnostics. |
| `r0` | Desktop-parity R0 forensic queries and bounded evidence reads. |

## 具体命令语法

### `log`

Read bounded frames from the KswordARK log device.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `log` | `KswordCLI.exe log [--max-frames N]` | Read up to N log frames from the shared log device. | --max-frames defaults to 64. | No subcommand is used for the log family. |

### `process`

Inspect and control process visibility, PPL, DKOM, and cross-view state.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `process terminate` | `KswordCLI.exe process terminate --pid PID [--exit-status NTSTATUS]` | Terminate one process through the driver. | Required: --pid. Optional: --exit-status defaults to 0xC000013A. |  |
| `process suspend` | `KswordCLI.exe process suspend --pid PID` | Suspend one process. | Required: --pid. |  |
| `process set-ppl` | `KswordCLI.exe process set-ppl --pid PID --level LEVEL` | Set the process protection level byte. | Required: --pid, --level. |  |
| `process set-integrity` | `KswordCLI.exe process set-integrity --pid PID (--rid RID \| --level untrusted\|low\|medium\|medium-plus\|high\|system) [--flags 0xN] [--confirm]` | Set a process mandatory integrity label through R0. | Required: --pid and one integrity selector. Optional: --flags, --confirm. | Uses `IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY`. |
| `process inject-dll` | `KswordCLI.exe process inject-dll --pid PID --dll PATH [--flags 0xN] [--wait-thread] --confirm` | Inject a DLL path through the R0 process injection protocol. | Required: --pid, --dll, --confirm. Optional: --flags, --wait-thread. | Uses `IOCTL_KSWORD_ARK_INJECT_PROCESS` with `LoadLibraryW`. |
| `process inject-shellcode` | `KswordCLI.exe process inject-shellcode --pid PID --blob PATH [--flags 0xN] --confirm` | Inject a raw shellcode blob through the R0 process injection protocol. | Required: --pid, --blob, --confirm. Optional: --flags. | Uses `IOCTL_KSWORD_ARK_INJECT_PROCESS`; payload is capped by shared protocol. |
| `process enum` | `KswordCLI.exe process enum [--flags 0xN] [--start-pid PID] [--end-pid PID] [--limit N]` | Enumerate processes from R0 evidence. | Optional: --flags, --start-pid, --end-pid, --limit. |  |
| `process set-visibility` | `KswordCLI.exe process set-visibility --action ACTION [--pid PID] [--flags 0xN]` | Apply a process visibility action. | Required: --action. Optional: --pid defaults to 0, --flags. |  |
| `process set-special-flags` | `KswordCLI.exe process set-special-flags --pid PID --action ACTION [--flags 0xN]` | Apply special process flags. | Required: --pid, --action. Optional: --flags. |  |
| `process dkom` | `KswordCLI.exe process dkom --pid PID [--action ACTION] [--flags 0xN]` | Run the configured process DKOM action. | Required: --pid. Optional: --action, --flags. |  |
| `process crossview` | `KswordCLI.exe process crossview [--flags 0xN] [--start-pid PID] [--end-pid PID] [--max-nodes N] [--limit N]` | Compare process evidence across supported sources. | Optional: --flags, --start-pid, --end-pid, --max-nodes, --limit. |  |
| `process detail` | `KswordCLI.exe process detail --pid PID [--flags 0xN]` | Query fixed R0 EPROCESS runtime detail. | Required: --pid. Optional: --flags defaults to include-all. | Uses `IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL`. |
| `process runtime-fields` | `KswordCLI.exe process runtime-fields --pid PID --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump] [--limit N]` | Sample bounded EPROCESS runtime fields by checked offsets. | Required: --pid, --items. Optional: --flags, --hexdump, --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS`; each sample is capped by the shared protocol. |

### `memory`

Query, read, write, translate, and audit virtual/physical memory.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `memory query-va` | `KswordCLI.exe memory query-va --pid PID --address VA [--flags 0xN]` | Query virtual memory metadata for one address. | Required: --pid, --address. Optional: --flags. |  |
| `memory read-va` | `KswordCLI.exe memory read-va --pid PID --address VA --bytes N [--flags 0xN] [--hexdump]` | Read virtual memory bytes. | Required: --pid, --address, --bytes. Optional: --flags, --hexdump. | With the kernel-address read flag, --pid may be omitted. |
| `memory write-va` | `KswordCLI.exe memory write-va --pid PID --address VA (--hex HEX \| --data-file PATH) [--flags 0xN]` | Write virtual memory bytes. | Required: --pid, --address, and exactly one payload option. Optional: --flags. | With the kernel-address write flag, --pid may be omitted. |
| `memory read-phys` | `KswordCLI.exe memory read-phys --address PA --bytes N [--hexdump]` | Read physical memory bytes. | Required: --address, --bytes. Optional: --hexdump. |  |
| `memory write-phys` | `KswordCLI.exe memory write-phys --address PA (--hex HEX \| --data-file PATH) [--flags 0xN]` | Write physical memory bytes. | Required: --address and exactly one payload option. Optional: --flags. |  |
| `memory translate-va` | `KswordCLI.exe memory translate-va --pid PID --address VA [--flags 0xN]` | Translate a virtual address to page-table evidence. | Required: --pid, --address. Optional: --flags. |  |
| `memory query-pte` | `KswordCLI.exe memory query-pte --pid PID --address VA [--flags 0xN]` | Query page-table entries for one virtual address. | Required: --pid, --address. Optional: --flags. |  |
| `memory scan-kexec` | `KswordCLI.exe memory scan-kexec [--flags 0xN] [--max-entries N] [--start VA] [--end VA] [--limit N]` | Scan executable kernel memory evidence. | Optional: --flags, --max-entries, --start, --end, --limit. |  |
| `memory scan-evidence` | `KswordCLI.exe memory scan-evidence [--flags 0xN] [--max-rows N] [--start VA] [--end VA] [--max-bytes N] [--max-bigpool-rows N] [--sample-bytes N] [--limit N]` | Scan kernel memory evidence rows. | Optional: --flags, --max-rows, --start, --end, --max-bytes, --max-bigpool-rows, --sample-bytes, --limit. |  |

### `file`

Inspect files, filters, storage evidence, and file-monitor runtime state.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `file delete-path` | `KswordCLI.exe file delete-path --path PATH [--flags 0xN]` | Delete one path through the driver. | Required: --path. Optional: --flags. |  |
| `file query-info` | `KswordCLI.exe file query-info --path PATH [--flags 0xN]` | Query file object and basic file metadata. | Required: --path. Optional: --flags. |  |
| `file set-integrity` | `KswordCLI.exe file set-integrity --path PATH (--rid RID \| --level untrusted\|low\|medium\|medium-plus\|high\|system) [--directory] [--flags 0xN] [--confirm]` | Set a file or directory mandatory integrity label through R0. | Required: --path and one integrity selector. Optional: --directory, --flags, --confirm. | Win32/UNC paths are normalized to driver NT paths before `IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY`. |
| `file fileobject` | `KswordCLI.exe file fileobject --path PATH [--flags 0xN]` | Alias for file query-info. | Required: --path. Optional: --flags. | Prints an alias banner before query-info output. |
| `file minifilter` | `KswordCLI.exe file minifilter [--flags 0xN] [--max-rows N] [--limit N]` | Enumerate minifilter inventory rows. | Optional: --flags, --max-rows, --limit. |  |
| `file section` | `KswordCLI.exe file section` | Report that the file section alias is unsupported. | No options. | Use section query-file-mappings --path PATH for the implemented section protocol. |
| `file bitlocker` | `KswordCLI.exe file bitlocker [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query BitLocker/FVE storage audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. |  |
| `file storage` | `KswordCLI.exe file storage [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query volume stack audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. |  |
| `file mountmgr` | `KswordCLI.exe file mountmgr [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query MountMgr mapping audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. |  |
| `file filesystem` | `KswordCLI.exe file filesystem [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query filesystem integrity audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. |  |
| `file monitor-control` | `KswordCLI.exe file monitor-control --action ACTION [--operation-mask 0xN] [--pid PID] [--flags 0xN]` | Control file monitor runtime state. | Required: --action. Optional: --operation-mask, --pid, --flags. |  |
| `file monitor-drain` | `KswordCLI.exe file monitor-drain [--max-events N] [--flags 0xN]` | Drain file monitor events. | Optional: --max-events, --flags. |  |
| `file monitor-status` | `KswordCLI.exe file monitor-status` | Query file monitor runtime status. | No options. |  |

### `kernel`

Inspect SSDT, hooks, driver objects, CPU, physical layout, CID, and IPC state.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `kernel ssdt` | `KswordCLI.exe kernel ssdt [--flags 0xN] [--limit N]` | Enumerate SSDT entries. | Optional: --flags, --limit. |  |
| `kernel shadow-ssdt` | `KswordCLI.exe kernel shadow-ssdt [--flags 0xN] [--limit N]` | Enumerate shadow SSDT entries. | Optional: --flags, --limit. |  |
| `kernel scan-inline-hooks` | `KswordCLI.exe kernel scan-inline-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]` | Scan inline hook evidence. | Optional: --flags, --max-entries, --module, --limit. |  |
| `kernel enum-iat-eat-hooks` | `KswordCLI.exe kernel enum-iat-eat-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]` | Enumerate IAT/EAT hook evidence. | Optional: --flags, --max-entries, --module, --limit. |  |
| `kernel patch-inline-hook` | `KswordCLI.exe kernel patch-inline-hook --mode MODE --function VA (--expected-hex HEX \| --expected-file PATH) [--restore-hex HEX \| --restore-file PATH] [--flags 0xN]` | Patch or restore an inline hook using bounded byte evidence. | Required: --mode, --function, and expected payload. Optional: restore payload, --flags. | Hex and file payload forms are mutually exclusive per payload. |
| `kernel query-driver-object` | `KswordCLI.exe kernel query-driver-object --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]` | Query one DriverObject and device chain. | Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit. |  |
| `kernel query-driver-integrity` | `KswordCLI.exe kernel query-driver-integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]` | Query driver integrity evidence rows. | Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit. |  |
| `kernel force-unload-driver` | `KswordCLI.exe kernel force-unload-driver --driver NAME [--module-base VA] [--timeout-ms N] [--flags 0xN]` | Force an unload path for one driver. | Required: --driver. Optional: --module-base, --timeout-ms, --flags. |  |
| `kernel query-cpu` | `KswordCLI.exe kernel query-cpu` | Query CPU hardware summary. | No options. |  |
| `kernel query-phys-layout` | `KswordCLI.exe kernel query-phys-layout` | Query physical memory layout summary. | No options. |  |
| `kernel cid` | `KswordCLI.exe kernel cid [--flags 0xN] [--max-entries N] [--max-visits N] [--start-cid CID] [--end-cid CID] [--limit N]` | Enumerate CID table evidence. | Optional: --flags, --max-entries, --max-visits, --start-cid, --end-cid, --limit. |  |
| `kernel object-summary` | `KswordCLI.exe kernel object-summary --target-kind KIND [--cid CID] [--object ADDRESS] [--flags 0xN]` | Query object header/type/counter summary for CID or object evidence. | Required: --target-kind. Optional: --cid, --object, --flags. | Uses `IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY`. |
| `kernel ipc` | `KswordCLI.exe kernel ipc [--flags 0xN] [--pid PID] [--handle HANDLE] [--max-entries N]` | Query IPC summary for a process/handle context. | Optional: --flags, --pid, --handle, --max-entries. |  |
| `kernel callbacks` | `KswordCLI.exe kernel callbacks [--flags 0xN] [--max-entries N] [--limit N]` | Alias for callback inventory. | Optional: --flags, --max-entries, --limit. | Uses callback protocol v3 snapshot validation. |
| `kernel hooks` | `KswordCLI.exe kernel hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]` | Alias-style inline hook scan. | Optional: --flags, --max-entries, --module, --limit. |  |

### `callback`

Manage callback rules, pending decisions, callback inventory, and bypass PIDs.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `callback set-rules` | `KswordCLI.exe callback set-rules --blob PATH` | Load callback rule bytes. | Required: --blob. |  |
| `callback runtime-state` | `KswordCLI.exe callback runtime-state` | Query callback runtime state. | No options. |  |
| `callback monitor-start` | `KswordCLI.exe callback monitor-start [--categories LIST]` | 按具名类别启动 Callback Monitor 采集。 | 可选：--categories，逗号分隔 `process,thread,image,registry,object,minifilter,core,all`，默认 `core`。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL`；`core` 是前五类，`minifilter` 高频且须显式启用。 |
| `callback monitor-stop` | `KswordCLI.exe callback monitor-stop` | 停止 Callback Monitor 采集，不改变既有回调规则。 | 无。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL`。 |
| `callback monitor-status` | `KswordCLI.exe callback monitor-status` | 查询 Callback Monitor 采集状态和环形缓冲区计数器。 | 无。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY`；旧驱动会显示 unsupported。 |
| `callback monitor-read` | `KswordCLI.exe callback monitor-read [--after-sequence N] [--max-records N] [--limit N]` | 使用独立游标读取 Callback Monitor 事件。 | 可选：--after-sequence、--max-records、--limit。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ`；使用输出的 `next_sequence` 发起增量读取。 |
| `callback wait-event` | `KswordCLI.exe callback wait-event [--waiter-tag N]` | Wait for one callback event packet. | Optional: --waiter-tag. |  |
| `callback answer-event` | `KswordCLI.exe callback answer-event --event-guid GUID --decision N --source-session-id N [--answered-at UTC100NS]` | Answer one pending callback event. | Required: --event-guid, --decision, --source-session-id. Optional: --answered-at. |  |
| `callback cancel-pending` | `KswordCLI.exe callback cancel-pending` | Cancel all pending callback decisions. | No options. |  |
| `callback remove` | `KswordCLI.exe callback remove --class N --callback VA [--flags 0xN]` | Remove an external callback by class/address. | Required: --class, --callback. Optional: --flags. |  |
| `callback remove-ex` | `KswordCLI.exe callback remove-ex --class N --callback VA [--registration VA] [--raw-storage VA] [--generation N] [--identity-hash N] [--source N] [--operation-mask 0xN] [--object-type-mask 0xN] [--trust-flags 0xN] [--remove-behavior N] [--flags 0xN]` | Remove an external callback with extended identity hints. | Required: --class, --callback. Optional: extended identity, source, masks, trust, behavior, --flags. |  |
| `callback set-minifilter-bypass-pids` | `KswordCLI.exe callback set-minifilter-bypass-pids --pids PID[,PID...] [--flags 0xN]` | Set minifilter bypass PID list. | Required: --pids. Optional: --flags. |  |
| `callback query-minifilter-bypass-pids` | `KswordCLI.exe callback query-minifilter-bypass-pids` | Query minifilter bypass PID list. | No options. |  |
| `callback enum` | `KswordCLI.exe callback enum [--flags 0xN] [--max-entries N] [--limit N]` | Enumerate callback inventory. | Optional: --flags, --max-entries, --limit. | Uses protocol v3; prints snapshot generation/hash and per-row identity hashes, and stops if a continuation page no longer matches the first-page snapshot. |

### `dyn`

Query or apply dynamic kernel symbol/profile data.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `dyn status` | `KswordCLI.exe dyn status` | Query DynData status. | No options. |  |
| `dyn fields` | `KswordCLI.exe dyn fields [--limit N]` | List DynData fields. | Optional: --limit. |  |
| `dyn capabilities` | `KswordCLI.exe dyn capabilities` | Query DynData capability mask. | No options. |  |
| `dyn profile` | `KswordCLI.exe dyn profile [--limit N]` | List v4 DynData module profile rows. | Optional: --limit. | Alias: dyn v4-modules. |
| `dyn v4-modules` | `KswordCLI.exe dyn v4-modules [--limit N]` | List v4 DynData module profile rows. | Optional: --limit. | Alias: dyn profile. |
| `dyn v4-capabilities` | `KswordCLI.exe dyn v4-capabilities [--limit N]` | List v4 DynData capability groups. | Optional: --limit. | Alias: dyn capability-groups. |
| `dyn capability-groups` | `KswordCLI.exe dyn capability-groups [--limit N]` | List v4 DynData capability groups. | Optional: --limit. | Alias: dyn v4-capabilities. |
| `dyn v4-missing` | `KswordCLI.exe dyn v4-missing [--limit N]` | List missing v4 DynData items. | Optional: --limit. | Alias: dyn missing-items. |
| `dyn missing-items` | `KswordCLI.exe dyn missing-items [--limit N]` | List missing v4 DynData items. | Optional: --limit. | Alias: dyn v4-missing. |
| `dyn v4-items` | `KswordCLI.exe dyn v4-items [--limit N]` | List every applied v4 DynData item status row. | Optional: --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS`. |
| `dyn apply-profile-v4` | `KswordCLI.exe dyn apply-profile-v4 --blob PATH` | Apply a raw v4 DynData profile packet. | Required: --blob. |  |
| `dyn apply-profile` | `KswordCLI.exe dyn apply-profile --blob PATH` | Apply a raw legacy DynData profile packet. | Required: --blob. |  |
| `dyn apply-profile-ex` | `KswordCLI.exe dyn apply-profile-ex --blob PATH` | Apply a raw extended DynData profile packet. | Required: --blob. |  |

### `thread`

Enumerate threads and compare R0/R3 thread evidence.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `thread enum` | `KswordCLI.exe thread enum [--flags 0xN] [--pid PID] [--limit N]` | Enumerate threads. | Optional: --flags, --pid, --limit. |  |
| `thread crossview` | `KswordCLI.exe thread crossview [--flags 0xN] [--pid PID] [--start-tid TID] [--end-tid TID] [--max-nodes N] [--limit N]` | Compare thread evidence across supported sources. | Optional: --flags, --pid, --start-tid, --end-tid, --max-nodes, --limit. |  |
| `thread detail` | `KswordCLI.exe thread detail --tid TID [--pid PID] [--flags 0xN]` | Query fixed R0 ETHREAD/KTHREAD runtime detail. | Required: --tid. Optional: --pid, --flags defaults to include-all. | Uses `IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL`. |
| `thread runtime-fields` | `KswordCLI.exe thread runtime-fields --tid TID [--pid PID] --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump] [--limit N]` | Sample bounded ETHREAD/KTHREAD runtime fields by checked offsets. | Required: --tid, --items. Optional: --pid, --flags, --hexdump, --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS`; each sample is capped by the shared protocol. |

### `handle`

Enumerate process handles and inspect object metadata.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `handle enum` | `KswordCLI.exe handle enum --pid PID [--flags 0xN] [--limit N]` | Enumerate handles in one process. | Required: --pid. Optional: --flags, --limit. | Alias: handle object-table. |
| `handle object-table` | `KswordCLI.exe handle object-table --pid PID [--flags 0xN] [--limit N]` | Enumerate handles in one process. | Required: --pid. Optional: --flags, --limit. | Alias: handle enum. |
| `handle query-object` | `KswordCLI.exe handle query-object --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]` | Query one handle object. | Required: --pid, --handle. Optional: --access, --flags. | Aliases: handle object-header, handle type-matrix. |
| `handle object-header` | `KswordCLI.exe handle object-header --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]` | Query one handle object header projection. | Required: --pid, --handle. Optional: --access, --flags. | Alias: handle query-object. |
| `handle type-matrix` | `KswordCLI.exe handle type-matrix --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]` | Query one handle object type projection. | Required: --pid, --handle. Optional: --access, --flags. | Alias: handle query-object. |

### `driver`

Driver integrity, device stack, and optional global evidence aliases.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `driver integrity` | `KswordCLI.exe driver integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]` | Query driver integrity evidence. | Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit. |  |
| `driver detail` | `KswordCLI.exe driver detail --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]` | Query one DriverObject detail projection. | Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit. |  |
| `driver device` | `KswordCLI.exe driver device [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query driver device stack audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Aliases: driver major, driver fastio. |
| `driver major` | `KswordCLI.exe driver major [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for driver device audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: driver device. |
| `driver fastio` | `KswordCLI.exe driver fastio [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for driver device audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: driver device. |
| `driver unloaded` | `KswordCLI.exe driver unloaded [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]` | Project MmUnloadedDrivers optional-global evidence. | Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit. |  |
| `driver piddb` | `KswordCLI.exe driver piddb [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]` | Project PiDDBCacheTable optional-global evidence. | Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit. |  |

### `hardware`

Device, input, USB, and PnP stack audit views.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `hardware audit` | `KswordCLI.exe hardware audit [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query generic hardware device stack audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: hardware pnp. |
| `hardware pnp` | `KswordCLI.exe hardware pnp [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for hardware audit. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: hardware audit. |
| `hardware input` | `KswordCLI.exe hardware input [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query input stack audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. |  |
| `hardware usb` | `KswordCLI.exe hardware usb [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query USB topology audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. |  |

### `hwid`

HWID Dispatch query and guarded control operations.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `hwid dispatch-query` | `KswordCLI.exe hwid dispatch-query` | Query HWID Dispatch hook state. | No options. | Uses `IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY`. |
| `hwid dispatch-control` | `KswordCLI.exe hwid dispatch-control --action query\|enable\|disable\|disable-all [--targets LIST] [--dry-run] [--flags 0xN] [--disk-mode custom\|random\|null] [--mac-mode random\|custom] [--disk-serial TEXT] [--disk-product TEXT] [--disk-revision TEXT] [--gpu-serial TEXT] [--permanent-mac TEXT] [--current-mac TEXT] --confirm` | Control HWID Dispatch hook targets with explicit confirmation. | Required: --action; --confirm is required for non-query actions. Optional: targets/profile/dry-run/flags. | Targets: disk, partmgr, mountmgr, nvidia, nsiproxy, storage, network, all. Uses `IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL`. |

### `window`

Win32k, GUI, GPU, display, and watchdog audit views.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `window win32k` | `KswordCLI.exe window win32k [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query win32k profile/session status. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. |  |
| `window gui` | `KswordCLI.exe window gui [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query GUI window snapshot rows. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. |  |
| `window gui-threads` | `KswordCLI.exe window gui-threads [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query GUI thread snapshot rows. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. |  |
| `window hotkeys-pdb` | `KswordCLI.exe window hotkeys-pdb [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query PDB-backed win32k hotkey chain rows. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB`. |
| `window hooks-pdb` | `KswordCLI.exe window hooks-pdb [--flags 0xN] [--match legacy\|owner\|target\|both] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query PDB-backed win32k hook chain rows. | Optional: --flags (default 0x3), --match (overrides only owner/target selector bits in --flags; default legacy), --session-id, --pid, --tid, --max-entries (default 4096; hard maximum 8192), --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB`; legacy/both require the complete Session/PID/TID filter to match one side; prints the effective mode and traversal diagnostics. |
| `window detail` | `KswordCLI.exe window detail --hwnd HWND [--pid PID] [--tid TID] [--flags 0xN]` | Query one HWND/tagWND runtime detail packet. | Required: --hwnd. Optional: --pid, --tid, --flags. | Uses `IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL`. |
| `window gpu` | `KswordCLI.exe window gpu [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query GPU/display/watchdog audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Aliases: window display, window watchdog. |
| `window display` | `KswordCLI.exe window display [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for window gpu audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: window gpu. |
| `window watchdog` | `KswordCLI.exe window watchdog [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for window gpu audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: window gpu. |

### `misc`

Security, CI/VBS, Hyper-V, AppLocker/BAM, and driver trust posture.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `misc security` | `KswordCLI.exe misc security [--flags 0xN]` | Query security/CI/VBS posture. | Optional: --flags. | Aliases: misc ci, misc vbs. |
| `misc ci` | `KswordCLI.exe misc ci [--flags 0xN]` | Alias for misc security. | Optional: --flags. | Alias: misc security. |
| `misc vbs` | `KswordCLI.exe misc vbs [--flags 0xN]` | Alias for misc security. | Optional: --flags. | Alias: misc security. |
| `misc hyperv` | `KswordCLI.exe misc hyperv` | Query Hyper-V summary posture. | No options. |  |
| `misc applocker` | `KswordCLI.exe misc applocker` | Query AppLocker/BAM posture. | No options. | Alias: misc bam. |
| `misc bam` | `KswordCLI.exe misc bam` | Alias for misc applocker. | No options. | Alias: misc applocker. |
| `misc driver-trust` | `KswordCLI.exe misc driver-trust [--flags 0xN] [--max-entries N] [--limit N]` | Query loaded-driver trust rows. | Optional: --flags, --max-entries, --limit. |  |

### `alpc`

ALPC port diagnostics for a process handle.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `alpc query-port` | `KswordCLI.exe alpc query-port --pid PID --handle HANDLE [--flags 0xN]` | Query ALPC port information for one handle. | Required: --pid, --handle. Optional: --flags. |  |

### `section`

Process and file section mapping diagnostics.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `section query-process` | `KswordCLI.exe section query-process --pid PID [--flags 0xN] [--max-mappings N] [--limit N]` | Query section mappings for one process. | Required: --pid. Optional: --flags, --max-mappings, --limit. |  |
| `section query-file-mappings` | `KswordCLI.exe section query-file-mappings --path PATH [--flags 0xN] [--max-mappings N] [--limit N]` | Query section mappings for one file path. | Required: --path. Optional: --flags, --max-mappings, --limit. |  |

### `trust`

Image trust and signing diagnostics.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `trust query-image` | `KswordCLI.exe trust query-image --path PATH [--flags 0xN]` | Query image trust and signing evidence. | Required: --path. Optional: --flags. |  |

### `safety`

Safety policy query and update controls.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `safety query-policy` | `KswordCLI.exe safety query-policy [--flags 0xN]` | Query safety policy state. | Optional: --flags. |  |
| `safety set-policy` | `KswordCLI.exe safety set-policy [--set-flags 0xN] [--clear-flags 0xN] [--expected-generation N]` | Update safety policy flags. | Optional: --set-flags, --clear-flags, --expected-generation. |  |

### `preflight`

Release-readiness and driver capability preflight checks.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `preflight query` | `KswordCLI.exe preflight query [--flags 0xN] [--limit N]` | Run release-readiness preflight checks. | Optional: --flags, --limit. |  |

### `registry`

Registry read, enumeration, and mutation helpers.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `registry read-value` | `KswordCLI.exe registry read-value --key KEY [--value NAME] [--max-data-bytes N] [--flags 0xN] [--hexdump]` | Read one registry value or default value. | Required: --key. Optional: --value, --max-data-bytes, --flags, --hexdump. |  |
| `registry enum-key` | `KswordCLI.exe registry enum-key --key KEY [--flags 0xN] [--max-subkeys N] [--max-values N] [--max-value-data-bytes N] [--limit N]` | Enumerate registry subkeys and values. | Required: --key. Optional: --flags, --max-subkeys, --max-values, --max-value-data-bytes, --limit. |  |
| `registry set-value` | `KswordCLI.exe registry set-value --key KEY --type TYPE --data-file PATH [--value NAME] [--flags 0xN]` | Set one registry value. | Required: --key, --type, --data-file. Optional: --value, --flags. |  |
| `registry delete-value` | `KswordCLI.exe registry delete-value --key KEY [--value NAME] [--flags 0xN]` | Delete one registry value or default value. | Required: --key. Optional: --value, --flags. |  |
| `registry create-key` | `KswordCLI.exe registry create-key --key KEY [--flags 0xN]` | Create one registry key. | Required: --key. Optional: --flags. |  |
| `registry delete-key` | `KswordCLI.exe registry delete-key --key KEY [--flags 0xN]` | Delete one registry key. | Required: --key. Optional: --flags. |  |
| `registry rename-value` | `KswordCLI.exe registry rename-value --key KEY --old-value NAME --new-value NAME [--flags 0xN]` | Rename one registry value. | Required: --key, --old-value, --new-value. Optional: --flags. |  |
| `registry rename-key` | `KswordCLI.exe registry rename-key --key KEY --new-name NAME [--flags 0xN]` | Rename one registry key. | Required: --key, --new-name. Optional: --flags. |  |

### `redirect`

File/registry redirect rules and runtime status.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `redirect set-rules` | `KswordCLI.exe redirect set-rules --blob PATH` | Load file/registry redirect rules. | Required: --blob. |  |
| `redirect query-status` | `KswordCLI.exe redirect query-status [--limit N]` | Query redirect runtime state and rules. | Optional: --limit. |  |

### `network`

Network rules, endpoints, WFP/NDIS evidence, and R3 fallbacks.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `network set-rules` | `KswordCLI.exe network set-rules --blob PATH` | Load network rule bytes. | Required: --blob. |  |
| `network query-status` | `KswordCLI.exe network query-status [--limit N]` | Query network runtime state and rules. | Optional: --limit. |  |
| `network audit` | `KswordCLI.exe network audit [--flags 0xN] [--max-rows N] [--limit N]` | Query TCP endpoint audit as the default network audit view. | Optional: --flags, --max-rows, --limit. | Use network wfp or network ndis for chain-specific views. |
| `network tcp` | `KswordCLI.exe network tcp [--flags 0xN] [--max-rows N] [--limit N]` | Query TCP endpoint audit rows. | Optional: --flags, --max-rows, --limit. |  |
| `network udp` | `KswordCLI.exe network udp [--flags 0xN] [--max-rows N] [--limit N]` | Query UDP endpoint audit rows. | Optional: --flags, --max-rows, --limit. |  |
| `network wfp` | `KswordCLI.exe network wfp [--flags 0xN] [--max-rows N] [--limit N]` | Query WFP inventory rows. | Optional: --flags, --max-rows, --limit. |  |
| `network ndis` | `KswordCLI.exe network ndis [--flags 0xN] [--max-rows N] [--limit N]` | Query NDIS chain rows. | Optional: --flags, --max-rows, --limit. |  |
| `network afd` | `KswordCLI.exe network afd [--limit N]` | Print degraded R3 AFD endpoint fallback evidence. | Optional: --limit. | No dedicated R0 AFD audit IOCTL is used. |
| `network nsi` | `KswordCLI.exe network nsi [--limit N]` | Print degraded R3 NSI adapter/address fallback evidence. | Optional: --limit. | No dedicated R0 NSI audit IOCTL is used. |

### `keyboard`

Keyboard hotkey and hook inventory.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `keyboard enum-hotkeys` | `KswordCLI.exe keyboard enum-hotkeys [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]` | Enumerate keyboard hotkeys. | Optional: --flags, --pid, --max-entries, --limit. |  |
| `keyboard enum-hooks` | `KswordCLI.exe keyboard enum-hooks [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]` | Enumerate keyboard hooks. | Optional: --flags, --pid, --max-entries, --limit. |  |

### `mutation`

Prepare, commit, rollback, and audit bounded mutation transactions.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `mutation prepare` | `KswordCLI.exe mutation prepare --target-kind N (--after-hex HEX \| --after-file PATH) [--before-hex HEX \| --before-file PATH] [--pid PID] [--address VA] [--context N] [--flags 0xN]` | Prepare a bounded mutation transaction. | Required: --target-kind and after payload. Optional: before payload, --pid, --address, --context, --flags. | Hex and file payload forms are mutually exclusive per payload. |
| `mutation commit` | `KswordCLI.exe mutation commit --transaction-id ID [--flags 0xN]` | Commit a prepared mutation transaction. | Required: --transaction-id. Optional: --flags. |  |
| `mutation rollback` | `KswordCLI.exe mutation rollback --transaction-id ID [--flags 0xN]` | Rollback a prepared mutation transaction. | Required: --transaction-id. Optional: --flags. |  |
| `mutation query-audit` | `KswordCLI.exe mutation query-audit [--flags 0xN] [--max-entries N] [--start-sequence N] [--limit N] [--hexdump]` | Query mutation audit ring entries. | Optional: --flags, --max-entries, --start-sequence, --limit, --hexdump. |  |

### `capability`

Unified driver feature capability query.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `capability query-driver-capabilities` | `KswordCLI.exe capability query-driver-capabilities [--limit N]` | Query unified driver feature capability rows. | Optional: --limit. |  |

### `wsl`

WSL silo and Linux PID/TID diagnostics.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `wsl query-silo` | `KswordCLI.exe wsl query-silo [--pid PID] [--tid TID] [--flags 0xN]` | Query WSL silo process/thread evidence. | Optional: --pid, --tid, --flags. |  |

### `r0`

桌面端 `ArkDriverClient` 已有、此前 CLI 未覆盖的只读 R0 取证接口。命令共享桌面端的协议版本、边界校验与旧驱动降级处理，输出中会给出 `io_ok`、Win32/NT 状态及已返回的行数。`traffic` 只读取驱动中现有的捕获环，不会启动捕获；`raw-disk-read` 只读，默认最多显示 256 字节。

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `r0 workqueue` | `KswordCLI.exe r0 workqueue [--flags 0xN] [--max-entries N] [--limit N]` | 枚举内核工作队列。 | 可选：--flags、--max-entries、--limit。 | `IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE`。 |
| `r0 directory` | `KswordCLI.exe r0 directory --path PATH [--max-entries N] [--limit N]` | 通过 R0 `ZwQueryDirectoryFile` 枚举目录。 | 必填：--path。可选：--max-entries、--limit。 | Win32/UNC 路径会规范化为 NT 路径。 |
| `r0 directory-irp` | `KswordCLI.exe r0 directory-irp --path PATH [--layer N] [--max-entries N] [--limit N]` | 在选定文件系统栈层枚举目录。 | 必填：--path。可选：--layer、--max-entries、--limit。 | 输出实际接收层及驱动名。 |
| `r0 image-signature` | `KswordCLI.exe r0 image-signature --path PATH [--module-base VA] [--flags 0xN]` | 读取 Authenticode 证书表和 CI 证据。 | 必填：--path。可选：--module-base、--flags。 | `IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE`。 |
| `r0 debug-output` | `KswordCLI.exe r0 debug-output [--after-sequence N] [--max-records N] [--limit N]` | 读取内核调试输出环。 | 可选：--after-sequence、--max-records、--limit。 | `IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN`，不改变捕获状态。 |
| `r0 hvm-status` | `KswordCLI.exe r0 hvm-status` | 查询 HVM/VT-x 生命周期与能力状态。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_HVM`。 |
| `r0 hvm-events` | `KswordCLI.exe r0 hvm-events [--after-sequence N] [--max-rows N]` | 读取 HVM 事件环，不清空事件。 | 可选：--after-sequence、--max-rows。 | `IOCTL_KSWORD_ARK_HVM_EVENTS`。 |
| `r0 ioctl-registry` | `KswordCLI.exe r0 ioctl-registry [--flags 0xN] [--max-entries N]` | 查询驱动已注册的 IOCTL 分发表。 | 可选：--flags、--max-entries。 | `IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY`。 |
| `r0 timer-dpc` | `KswordCLI.exe r0 timer-dpc [--max-entries N] [--max-per-bucket N]` | 枚举内核定时器与 DPC 证据。 | 可选：--max-entries、--max-per-bucket。 | `IOCTL_KSWORD_ARK_ENUM_TIMER_DPC`。 |
| `r0 unloaded` | `KswordCLI.exe r0 unloaded [--source mm\|piddb\|hash] [--max-rows N]` | 查询已卸载驱动、PiDDB 或哈希桶证据。 | 可选：--source 默认 `mm`，--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS`。 |
| `r0 wfp-events` | `KswordCLI.exe r0 wfp-events [--after-sequence N] [--max-rows N]` | 读取 WFP 事件环元数据。 | 可选：--after-sequence、--max-rows。 | `IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS`。 |
| `r0 traffic` | `KswordCLI.exe r0 traffic [--after-sequence N] [--max-rows N]` | 读取现有流量捕获环的元数据。 | 可选：--after-sequence、--max-rows。 | `IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS`，不启动捕获。 |
| `r0 piddb` | `KswordCLI.exe r0 piddb [--max-rows N]` | 枚举 PiDDBCacheTable 证据。 | 可选：--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_PIDDB`，不删除条目。 |
| `r0 cpu-power` | `KswordCLI.exe r0 cpu-power` | 查询 CPU 电源管理状态及原始能力证据。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_CPU_POWER`。 |
| `r0 process-protect` | `KswordCLI.exe r0 process-protect` | 查询进程保护配置和计数器。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE`。 |
| `r0 raw-disk-backend` | `KswordCLI.exe r0 raw-disk-backend [--disk N] [--backend N] [--flags 0xN]` | 查询指定原始磁盘读取后端。 | 可选：--disk 默认 0，--backend 默认 Windows stack，--flags。 | `IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND`。 |
| `r0 raw-disk-read` | `KswordCLI.exe r0 raw-disk-read --length N [--disk N] [--backend N] [--offset N] [--flags 0xN] [--hexdump]` | 读取受协议长度上限约束的原始磁盘范围。 | 必填：--length。可选：--disk、--backend、--offset、--flags、--hexdump。 | `IOCTL_KSWORD_ARK_READ_RAW_DISK`。 |
| `r0 system-time` | `KswordCLI.exe r0 system-time` | 查询系统时间虚拟化和冲突状态。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME`。 |
| `r0 slat-iommu` | `KswordCLI.exe r0 slat-iommu [--include-mmio]` | 查询 SLAT、IOMMU 固件及运行时证据。 | 可选：--include-mmio。 | `IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT`。 |
| `r0 platform` | `KswordCLI.exe r0 platform [--scope 0xN] [--max-rows N]` | 查询 HAL 和 WDF 平台审计证据。 | 可选：--scope 默认全量，--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT`。 |
| `r0 i8042` | `KswordCLI.exe r0 i8042 [--max-rows N]` | 查询 i8042prt 回调和栈证据，不读取输入数据。 | 可选：--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT`。 |
| `r0 object-types` | `KswordCLI.exe r0 object-types [--flags 0xN] [--max-entries N] [--start-index N]` | 枚举内核对象类型表。 | 可选：--flags、--max-entries、--start-index。 | `IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE`。 |
| `r0 win32k-timers` | `KswordCLI.exe r0 win32k-timers [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N]` | 查询基于 PDB 的 win32k 定时器证据。 | 可选：--flags、--session-id、--pid、--tid、--max-entries。 | `IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS`。 |
| `r0 win32k-events` | `KswordCLI.exe r0 win32k-events [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N]` | 查询基于 PDB 的 WinEvent Hook 证据。 | 可选：--flags、--session-id、--pid、--tid、--max-entries。 | `IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS`。 |
