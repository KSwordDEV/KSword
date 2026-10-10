# 内核对象与证据 R3 命令

## Atom／注册剪贴板格式名称（迁移项 55）

```powershell
KswordCLI.exe kernel atoms help
KswordCLI.exe help kernel atoms enum
KswordCLI.exe kernel atoms enum --scope global --filter Ksword --json
KswordCLI.exe kernel atoms enum --scope clipboard --start-id 0xc000 --end-id 0xffff --json
```

`kernel atoms enum` 复用 GlobalGetAtomNameW／GetClipboardFormatNameW，支持 `--scope all|global|clipboard`（all）、`--start-id`／`--end-id`（0xc000..0xffff，默认全范围，起点不能大于终点）、`--filter` 名称／十六进制 ID 子串、`--duration-ms 100..30000`（8000）、`--limit 1..16384`（16384，仅输出上限）、`--backend r3`、`--json`。

data 提供 source/scope/filter/startId/endId、completeRange/evidenceComplete、limited/cancelled/malformed、scannedIdCount/globalNameCount/clipboardNameCount/failedQueryCount/matchedCount/returnedCount/truncated 和 atoms。每个 ID 有 id/hexId、独立 global/clipboard 的 attempted/available/absent/win32Error/malformed/name、sameName（只有两个来源都取得名称时有布尔值）。两个表的同一数值可以对应不同名称，不合并成假定统一的表。

已查询的未分配 ID 返回 invalid-handle／invalid-parameter／not-found 时是有效空洞；未查询或不适用字段为 null；其他错误、无错误码的失败保留为不可用，不冒充空。完整有效空为 0；无名称且有意外查询失败为 5；混合失败、预算／取消或输出截断为 6；不合法 API 长度为 4。仅覆盖公共字符串 ID 范围，不读取进程本地 Atom 表、整数 Atom、预定义剪贴板格式、引用数或所有者；不创建／删除 Atom、不打开或读取／修改剪贴板，不回退 R0。help 不扫描 ID。

VM 测试注册自建 Unicode Global Atom 和剪贴板格式，并独立查询核对名称／来源；Global Atom 删除后验证有效空洞，剪贴板格式登记由隔离快照恢复清理。宿主只执行读取。

## 命名管道（迁移项 54）

```powershell
KswordCLI.exe kernel pipes help
KswordCLI.exe help kernel pipes enum
KswordCLI.exe kernel pipes enum --directory device --filter Ksword --json
KswordCLI.exe kernel pipes probe --path '\Device\NamedPipe\OwnPipe' --confirm --json
```

`enum` 支持 `--directory all|device|dos`（all，读取原生 `\Device\NamedPipe`／`\??\PIPE`）、`--filter` 名称／原生路径子串、`--max-entries 1..100000` 每目录实际上限（100000）、`--duration-ms 100..30000` 整体预算（8000）、`--limit 1..100000` 输出上限（1000）。两根可能是同一对象的别名，保留各来源行，不冒充独立连接数量。枚举不打开管道实例，不读取或写入消息。共享读取会补齐目录路径末尾反斜杠；缺少它时 NPFS 的打开可成功，但枚举返回 C000000D，不能据打开成功判断枚举成功。

data 提供 source/directory/filter/sources、ioResults（各来源的最后 IO NTSTATUS／Information）、enumeratedCount/matchedCount/returnedCount、truncated/limited/malformed、pipes；每条为 name/directory/ntPath/win32Path、attributes、sizeBytes/allocationBytes、creationTime/lastAccessTime/lastWriteTime/changeTime。计数与原生时间／大小是十进制字符串，属性和原生状态是十六进制。原生缓冲使用实际 IO_STATUS_BLOCK.Information，校验链式偏移、对齐和名称字节范围；区分 NoMoreFiles／NoMoreEntries 正常终点与正值非成功状态。完整有效空为 0，原生失败为 3，格式错误为 4，API 缺失为 5，部分来源／关闭失败／预算／取消／截断为 6。

`probe` 必须带完整管道原生 `--path` 和 `--confirm`，只请求 FILE_READ_ATTRIBUTES|SYNCHRONIZE，打开验证可能影响实例可用性／连接状态。data 提供 target/action、source 的实际打开／关闭证据、requestSucceeded、ioNtStatus/information、basic 查询状态、计数和访问掩码；临时引用在输出前关闭。完整打开／查询／关闭为 0；打开失败为 3，格式错误为 4，API 缺失为 5，IO／基本信息／关闭证据不完整为 6。不能推断所有者 PID、实例数量或消息内容，不做消息读写或模拟，不回退 R0。两命令支持 `--backend r3` 和 `--json`，help 不执行原生调用。

VM 仅对自建管道执行 probe，独立 Win32 目录核对登记。Win10 实测即使只请求读属性，打开／关闭也会使服务端实例进入连接已关闭状态；夹具用 DisconnectNamedPipe 重置自己的实例，并通过 GetNamedPipeInfo 独立确认服务端仍有效，随后销毁并验证打开失败。不能向用户承诺 probe 对实例状态无影响。宿主测试不打开第三方实例。

## 对象类型矩阵（迁移项 53）

```powershell
KswordCLI.exe kernel object-types help
KswordCLI.exe help kernel object-types enum
KswordCLI.exe kernel object-types enum --filter event --json
```

`kernel object-types enum`：`--filter` 为类型名称大小写不敏感子串；`--limit 1..256`（256）仅限制输出；支持 `--backend r3`、`--json`。共享后端直接读取 NtQueryObject(ObjectTypesInformation)，不给 R0 补充回调。原有 `r0 object-types` 保持原语法和行为。

data 提供 source/apiAvailable/attempted/ntStatus/returnedBytes/bufferBytes、complete/limited/malformed、reportedCount/parsedCount/matchedCount/returnedCount/truncated、types。每种类型提供 type/typeIndex、当前与高水位 objects/handles/pagedPoolBytes/nonPagedPoolBytes/namePoolBytes/handleTableBytes、invalidAttributes/validAccessMask/genericRead/genericWrite/genericExecute/genericAll、securityRequired/maintainHandleCount/poolType/defaultPagedPoolCharge/defaultNonPagedPoolCharge。计数为十进制字符串，标志为十六进制。计数随采样时刻变化，不能拿两个调用的瞬时计数要求一致。

原生缓冲最多 16 MiB／8 次增长，矩阵最多保留 256 种类型，校验实际返回长度、每个记录和计数字符串的指针／长度／步进，不把格式错误当作成功的短矩阵。完整有效空为 0；原生失败为 3；格式错误为 4；API／信息类不可用为 5；读取／输出预算为 6。R3 不提供内核 ObjectType 地址、回调列表、过程指针等 R0 专属证据，不打开驱动、不自动回退。help 不发起查询。

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
