# 内核对象与证据 R3 命令

## 命名通信端点（迁移项 52）

```powershell
KswordCLI.exe kernel endpoints help
KswordCLI.exe help kernel endpoints enum
KswordCLI.exe kernel endpoints enum --root '\BaseNamedObjects' --max-depth 1 --json
```

`kernel endpoints enum` 使用共享后端通信类型筛选：ALPC Port、Port、WaitCompletionPacket、TpWorkerFactory、Event、Section、Mutant、Semaphore、IoCompletion、Timer、Job、Keyed Event。这些是命名 IPC／同步对象注册证据，不能推断所有者、服务端／客户端、消息内容或内核地址；不打开这些对象或发送消息。

参数与 `kernel directory enum` 相同，默认深度 3，默认起点是共享后端的常见根和发现的会话根；指定 `--root` 时只遍历该根。跨根共享保留行／扫描条目／时间预算，Directory 仅用于遍历，不输出，SymbolicLink 不跟随。筛选不剪去父目录。data 增加 roots、sessionDiscovery/currentSessionKnown；其余深度、计数、条目、来源、预算和完整性格式同目录递归。数量为观察前缀，自动根发现失败为部分结果。完整有效空为 0；读取／发现／元数据／关闭受限、实际预算或输出截断为 6；所有根读取失败为 3，API 缺失为 5，格式错误为 4。help 无原生调用，不依赖 KswordARK 或回退 R0。

测试用自建父子目录和两层事件核对筛选／深度，确认目录不输出、链接不跟随、筛选不剪枝；独立原生查询核对 KnownDlls 中 Section 对象，区分实际保留预算与仅输出截断。

## 命名对象（迁移项 51）

```powershell
KswordCLI.exe kernel base-named-objects help
KswordCLI.exe help kernel base-named-objects enum
KswordCLI.exe kernel base-named-objects enum --scope global --json
KswordCLI.exe kernel base-named-objects enum --scope session --session-id 0 --json
```

`kernel base-named-objects enum`：`--scope all|global|session`（all）；session 必须带 `--session-id uint32`（0 有效），其他 scope 不接受它。global 读取原生 `\BaseNamedObjects`，session 读取 `\Sessions\SID\BaseNamedObjects`，all 使用共享后端的全局和发现的会话根。`--filter` 是名称／类型／路径／目标大小写不敏感子串；`--max-entries 1..100000` 每目录实际预算（100000）；`--duration-ms 100..30000` 整体预算（8000）；`--limit 1..100000` 输出上限（1000）；支持 `--backend r3` 和 `--json`。

data 提供 scope/sessionId/filter/roots、sessionDiscovery/currentSessionKnown/currentSessionWin32Error、sources、scannedRootCount/enumeratedCount/matchedCount/returnedCount、truncated/limited/cancelled/malformed 和 objects。条目与目录证据格式见命名空间一节；数量用十进制字符串，原生状态用十六进制，未知字段为 null。会话发现失败仍保留会话 0／当前会话候选，并标记不完整。全局路径不代表所有应用私有命名空间，不根据名称推断所有者 PID、内核地址或对象可操作性。

完整有效空／筛选空为 0；会话发现、部分目录／元数据、关闭、预算／取消或输出截断为 6；选择根／全部根读取失败为 3；目录 API 缺失为 5；格式错误为 4。不创建、控制或修改对象，不自动回退 R0。help 不做会话发现。VM 自建命名目录并独立核对其出现和关闭后的消失，同时验证全局／会话路径、缺失会话和实际读取预算。

## Device／Driver 对象注册（迁移项 50）

```powershell
KswordCLI.exe kernel objects help
KswordCLI.exe help kernel objects enum
KswordCLI.exe kernel objects enum --scope driver --kind driver --json
```

`kernel objects enum` 支持 `--scope all|device|driver|filesystem|filters`（all）、`--kind all|device|driver`（all）、`--filter`（不区分大小写子串）、`--max-entries 1..100000`（每目录，100000）、`--duration-ms 100..30000`（整个 sweep API 调用间预算，8000）、`--limit 1..100000`（输出，1000）、`--backend r3`、`--json`。按共享后端固定的 `\Device`、`\Driver`、`\FileSystem`、`\FileSystem\Filters` 读取注册名称与类型；不直接打开设备发 IOCTL、不加载／卸载驱动、不调用 R0。

data 提供 scope/kindFilter/filter/roots/sources、scannedRootCount/enumeratedCount/matchedCount/returnedCount、truncated/limited/cancelled/malformed、objects。源与条目沿用上述命名空间结构；Device／Driver 没有已实现的安全 R3 opener，所以 opened、句柄／指针计数为 null，不能据名称猜测 DRIVER_OBJECT／DEVICE_OBJECT 地址、派遣函数、加载模块或 IOCTL 支持。Directory／SymbolicLink 的补充元数据仍按已有后端读取。R0 对象查询及 `driver modules` 的 R3 映像元数据保持原含义。

完整有效空／筛选空可成功为 0；部分根、字段／关闭失败、预算／取消／截断为 6；选择根或全部根失败为 3，目录 API 不可用为 5，格式错误为 4。帮助不读取目录。测试通过独立 NtQueryDirectoryObject 核对 Device／Driver 名称和类型，并确认未实现的对象打开／计数从未冒充成功。

## 符号链接（迁移项 49）

```powershell
KswordCLI.exe kernel symlink help
KswordCLI.exe help kernel symlink query
KswordCLI.exe kernel symlink query --path '\KnownDlls\KnownDllPath' --json
KswordCLI.exe kernel symlink enum --root '\KnownDlls' --target-filter System32 --json
```

`query` 要求 `--path` 为原生对象绝对路径，支持 `--backend r3`、`--json`；`enum` 支持 `--root`（省略使用共享常见根及会话发现）、`--filter`（名称／路径／类型／目标子串）、`--target-filter`（目标子串）、`--max-entries 1..100000`（每目录，100000）、`--duration-ms 100..30000`（整个 sweep API 调用间预算，8000）、`--limit 1..100000`（显示链接，1000）、`--backend r3`、`--json`。筛选不区分大小写，只读直接目录条目，不递归或跟随目标。

query data 保留 requestedPath、nameDerivedFromRequest=true、link（上一节的打开／basic／symlinkTarget／关闭结构）。名称／路径来自请求，不冒充已查询的规范对象名称。enum data 保留根和会话发现、sources、symbolicLinkCount/matchedCount/returnedCount/unknownTargetFilterCount、truncated/limited/cancelled/malformed、links。此视图只对符号链接查询额外元数据，不为目录打开多余计数句柄。未知目标不能证明筛选排除，保留 unknownTargetFilterCount 并返回部分结果，不能让读取失败冒充精确空匹配。

目标使用原始计长 UTF-16，成功的空目标为 `""`，未取得为 null；验证长度／缓冲范围并在 65534 字节内增长。只说明实际存储目标，不保证目标存在、可打开或对应可靠 DOS 路径。basic 计数包含查询的临时引用；所有句柄关闭后输出。完整可得证据为 0；打开／目标查询失败为 3（明确 API／状态未支持为 5），格式错误为 4；元数据、缓冲预算、关闭、筛选证据／根不完整或显示截断为 6。没有链接创建／删除／修改、目标打开或 R0 fallback，help 不访问对象。VM 独立 NtQuerySymbolicLinkObject 核对自建链接，测试错误类型、缺失链接、目标筛选、读取预算与释放。

## 对象目录递归（迁移项 48）

```powershell
KswordCLI.exe kernel directory help
KswordCLI.exe help kernel directory enum
KswordCLI.exe kernel directory enum --root '\BaseNamedObjects' --max-depth 1 --json
KswordCLI.exe kernel directory enum --root '\KnownDlls' --max-depth 0 --json
```

`kernel directory enum` 使用共享后端的广度优先遍历，支持 `--root`（原生绝对路径，默认 `\`）、`--max-depth 0..32`（4）、`--filter`（路径／名称／类型／链接目标子串，不区分大小写）、`--max-rows 1..2500`（2500，后端保留匹配行）、`--max-scanned-entries 1..10000`（10000，读取／遍历条目）、`--max-entries 1..100000`（每目录条目预算）、`--duration-ms 100..30000`（整个 sweep 的 API 调用间预算，8000）、`--limit 1..2500`（输出上限，1000）、`--backend r3`、`--json`。

深度 0 是起点目录的直接子项；扫描下一层目录时 depth 加一。只把 Directory 放入队列，SymbolicLink 只显示不递归。筛选只选择显示行，不剪去父目录或后代读取。深度上限定义请求视图范围，达到该深度可正常完整成功，同时显示 depthBoundaryDirectoryCount；读取／保留行／时间预算与输出截断则明确为部分结果。共享 Light 视图也复用该收集器，限制保留 2500 行，修复原循环在单个大目录内越过显示上限的问题。

data 提供 root/filter/maxDepth、completeWithinDepth/metadataComplete、limited/cancelled/malformed、scannedDirectoryCount/scannedEntryCount、matchedObservedCount/storedCount/returnedCount、depthBoundaryDirectoryCount/deduplicatedPathCount、truncated、sources、entries。中断时 matchedObservedCount 只是已遍历前缀的匹配数量，不能冒充总数。每个 source 带实际目录 depth 及上一节的打开／枚举／关闭证据；每个条目带实际深度、原生名称／类型／路径及可得的目录／链接元数据，未知为 null。

完整请求视图可成功为 0（包含有效空或筛选空）；实际预算、取消、后端字段／目录受限、关闭失败或输出截断为 6，起点／所有目录失败且无可读结果为 3，API 不可用为 5，响应格式错误为 4。不能推断未遍历深层对象不存在，不暴露猜测的内核地址、不修改对象、不回退 R0。help 不读取命名空间。测试独立核对自建父目录／子目录／孙事件的 BFS 深度和名称，覆盖深度边界、筛选不剪枝、实际读取预算、保留行预算与仅显示截断的差异。

## 对象命名空间（迁移项 47）

```powershell
KswordCLI.exe help kernel
KswordCLI.exe kernel namespace help
KswordCLI.exe help kernel namespace enum
KswordCLI.exe kernel namespace enum --root '\KnownDlls' --json
KswordCLI.exe kernel namespace enum --json
```

`kernel namespace enum` 支持 `--root`（可选，原生对象绝对路径，首字符反斜杠，最多 32766 个 UTF-16 单元）、`--filter`（路径／名称／类型／链接目标大小写不敏感子串）、`--max-entries 1..100000`（每目录实际条目上限，100000）、`--duration-ms 100..30000`（整个读取 sweep 的 API 调用间预算，8000）、`--limit 1..100000`（输出上限，1000）、`--backend r3`、`--json`。指定 root 只枚举直接子项；不指定时使用共享后端的常见根及会话相关根，不做递归。所有操作纯 R3，没有设备打开、R0 fallback、对象修改或 UI 导航。

data 提供 requestedRoot/filter/roots、sessionDiscovery、currentSessionKnown/currentSessionWin32Error、sources、requestedRootCount/scannedRootCount/openedRootCount/enumeratedCount/matchedCount/returnedCount、truncated/limited/cancelled/malformed、entries。sources 记录每个目录 apiAvailable、openAttempted/opened/openNtStatus、queryAttempted/lastQueryNtStatus/lastReturnedBytes、enumeratedCount、complete/limited/cancelled/cycle/malformed、closeAttempted/closed/closeWin32Error。目录成功读尽与打不开分开，最后实际 NTSTATUS 保留；常见根可能在当前系统不存在或访问受限。会话发现保留 `\Sessions` 的独立枚举和当前会话查询状态，不能把其失败当作完整根清单。

条目提供 root/depth/parentPath/name/type/fullPath、metadataProbeSupported/metadataProbeRequested、openAttempted/opened/openNtStatus、basic、symlinkTarget、closeAttempted/closed/closeWin32Error、statusDisplay。只对 Directory／SymbolicLink 做已实现的安全只读打开，其他类型 opened 和计数为 null，不能据名字推断内核地址或对象可打开。basic 提供 attempted/available/ntStatus/returnedBytes/malformed、handleCount/pointerCount、attributes/grantedAccess、pagedPoolBytes/nonPagedPoolBytes；数量为十进制字符串、标志／状态为十六进制。计数包含查询时的临时引用。symlinkTarget 提供 attempted/available/ntStatus/requiredBytes/malformed/limited/value；有效空目标与未取得分开，不解析 UI 状态文字。

目录缓冲最多 4 MiB，检查实际长度和内嵌 UNICODE_STRING 指针／偶数字节／范围，基本信息检查固定响应长度；符号链接缓冲最多 65534 字节，重复条目检测防止无限循环。正常和失败路径保留句柄所有权并关闭。预算在原生调用间检查，不能硬中断内核调用；对象名称／关联可能在采样期间变化，结果不是所有隐藏内核对象的完整清单。完整有效空／筛选空为 0；常见根／元数据缺失、截断、预算／取消／关闭失败为 6；选择根或全部根打不开为 3，目录 API 不可用为 5，响应格式错误为 4。help 不解析 ntdll 或枚举目录。原生契约见 [NtOpenDirectoryObject](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopendirectoryobject)、[NtQueryDirectoryObject](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntquerydirectoryobject)。VM 使用自建目录／子目录／符号链接／事件独立核对名称、类型、目标与关闭后的消失，驱动保持停止。
