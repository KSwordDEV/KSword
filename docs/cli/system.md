# 系统工具 R3 命令

## 系统时间（迁移项 45）

```powershell
KswordCLI.exe system time help
KswordCLI.exe help system time query
KswordCLI.exe system time query --json
KswordCLI.exe system time query --max-data-bytes 65536 --json
```

`system time query` 支持 `--max-data-bytes 1..65536`（256，注册表值的原始字节预览）、`--backend r3`、`--json`。只读取现有共享后端的本地／UTC 时钟、时区、运行时长和 `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters` 全部直接值，不设置时间／时区／NTP、不请求重同步、不调用驱动。

data.clock 保留 utcFileTime、calendarKnown、calendarValidationWin32Error、utcRaw/localRaw 及验证后的 utc/local 的 year/month/day/dayOfWeek/hour/minute/second/millisecond，atomicSnapshot=false；多次 API 读取不是同一瞬间。zone 保留 available/stateId/win32Error/malformed、standardName/daylightName、baseBiasMinutes/standardBiasMinutes/daylightBiasMinutes/effectiveBiasMinutes、standardTransitionRaw/daylightTransitionRaw；Bias 是“本地时间加该分钟数得到 UTC”，方向与 UTC 偏移相反。转换规则中的 year=0 是相对日期、month=0 可以表示无 DST，不把规则字段当绝对时间。dynamicZone 提供 available/stateId/win32Error、registryKeyName、dynamicDaylightTimeDisabled；查询失败返回 null，不显示假的 UTC+00／未禁用。

uptime 提供 tickCountMs、estimateAvailable、estimatedBootFileTime、authoritativeBootTimestamp=false。原始 Tick 是系统启动以来的毫秒，开机时间只是当前 UTC FILETIME 减去 Tick 的估计，时钟调整会影响推算，溢出／下溢时估计为 null。API 定义见 [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)。w32time 保留 path/opened/absent/complete/limited、open/enum/closeWin32Error、valueCount、values（原始 name/registryType/byteCount/dataHex/dataTruncated/dataMalformed/numericValue）；REG_EXPAND_SZ 仍是原始未展开字节，DWORD 数值为 JSON 数字，QWORD／FILETIME／Tick／计数为十进制字符串。其他类型通过原始字节查看，不解析显示文字推导状态。displaySections 保留原 Light 分组与显示文本，每项预览 256 字符并标明截断。

完整证据为 0，时区／W32Time 不可用、枚举／关闭失败、预算或字节预览截断、开机估计不可用为 6，格式错误为 4。有效空的 W32Time 键可以成功；键缺失或被拒绝要保留原始状态。注册表遍历最多 100000 项／8 秒（API 调用间），单值缓冲 16 MiB，名称遵循 SDK 16383 字符上限；短／未终止字符串、错误 DWORD/QWORD 大小及实际返回长度／容量错误不当作正常值。空 MULTI_SZ 的单个 NUL 也接受，参见 [Registry value types](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)。此结果不证明 W32Time 服务在运行、NTP 服务器可达或时钟已同步。help 不查询时间或注册表。测试独立核对当前 FILETIME／Tick、时区偏移符号与原始 W32Time 字节，包含不可用、空值、截断、格式／资源错误夹具。

## Shell 右键菜单注册（迁移项 44）

```powershell
KswordCLI.exe system context-menu help
KswordCLI.exe help system context-menu enum
KswordCLI.exe system context-menu enum --scope file --kind verb --json
KswordCLI.exe system context-menu enum --state disabled --json
KswordCLI.exe system context-menu disable --registration '*\shell\MyVerb' --confirm --json
KswordCLI.exe system context-menu enable --registration '*\shell\MyVerb' --confirm --json
```

`enum` 支持 `--scope all|file|directory|folder`（all）、`--kind all|handler|verb`（all）、`--state all|enabled|disabled`（all）、`--registration`（精确注册路径）、`--limit 1..100000`（1000）、`--backend r3`、`--json`。共享后端只扫描 HKCR 的 `*\shellex\ContextMenuHandlers`、`Directory\shellex\ContextMenuHandlers`、`Folder\shellex\ContextMenuHandlers`、`*\shell`、`Directory\shell` 五个入口及 HKLM 备份，不遍历任意扩展名、桌面背景或动态 Explorer 菜单，不执行 COM／命令。每项是注册证据，不等于已激活的菜单或已加载模块。

data 提供来源、elevatedDisplay、backupRoot、sources（hive/path/opened/absent/complete/limited、open/enum/closeWin32Error、count）、snapshotCount/matchedCount/returnedCount/truncated、entries。条目提供 registrationPath、kind、scopeDisplay、name/displayText、enabledRegistration、backupKeyName、clsidOrProgId、modulePathOrCommand、moduleFileCandidate、candidateFileExists/candidateAttributes/candidateWin32Error、fields、diagnosticDisplay。fields 区分 available/absent/malformed/limited、registryType、win32Error、value；REG_EXPAND_SZ 的文本经过原 SDK 展开，备份 Kind 是 DWORD 0=handler／1=verb。可选值缺失可成功，权限／预算／关键备份元数据缺失／输出截断为 6，畸形值为 4，所有来源不可读为 3；有效空集合为 0。禁用项保留原始备份信息，不假造实时模块查询。moduleFileCandidate 是后端从命令首项提取的候选，不保证无引号空格、相对路径、间接命令的真实可执行文件；candidateFileExists 只证明该候选的属性查询。

`disable`／`enable` 要求 `--registration`（上述入口的直接子项）和 `--confirm`，支持 `--backend r3`、`--json`。CLI 仅发布无 HKCU 覆盖的明确机器注册：HKCR 合并用户与机器视图，原备份格式无法保证逐用户还原，所以存在用户项或物理归属不可确认时在写入前返回 5。读取仍显示合并视图。规则见 [HKCR 合并与写入规则](https://learn.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key)。备份位于 `HKLM\SOFTWARE\KswordARKLight\ShellExtensionBackup`，键名沿用后端将路径反斜杠换成 `!` 的规则，完整子树在 Data 下。

禁用先复制完整注册子树，再逐项检查 SourcePath／BackupTime／Scope／Name／Kind 的写入，全部成功才删除活项；复制／元数据失败不删除活项。启用验证备份 SourcePath 与请求路径精确匹配，复制到新目标后才清理备份。活项与备份同时出现、现有备份／还原目标冲突均拒绝覆盖；缺少／非法 SourcePath 或 Kind 为 4。原生复制行为见 [RegCopyTreeW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcopytreew)。不会单独清除备份、转移用户项或调用 R0。

动作 data 包含 action/registrationPath/attempted、backendSucceeded、stage/win32Error、backupPath、backupCreated/dataCreated/copySucceeded/metadataSucceeded/sourceDeleted/destinationCreated/backupDeleted/backupRetained、cleanupWin32Error、calls（step/win32Error）、afterMachineRegistration/afterUserRegistration/afterBackup、verified/display。verified 根据原生复制／元数据／删除回执及独立物理键存在回读，不能证明与并发注册表写入的原子性或 Explorer 刷新；未完成时备份保留。仅预期操作和关闭均验证成功为 0，无副作用失败为 3，已发生部分步骤／回读或清理不完整为 6。要求现有注册表权限，不自动提权。每个来源遍历限制 100000 项／8 秒（API 调用间检查），字符串 1 MiB，帮助不读取／修改注册表。VM 使用自建机器注册子树核对 DWORD／二进制／多字符串／嵌套键备份与还原，并测试冲突、缺少元数据和用户覆盖拒绝。

## 事件日志（迁移项 43）

```powershell
KswordCLI.exe system event-log help
KswordCLI.exe help system event-log query
KswordCLI.exe system event-log query --channel system --limit 100 --json
KswordCLI.exe system event-log query --channel application --level information --messages on --json
```

`system event-log query` 使用已有共享 wevtapi 后端，支持 `--channel system|application`（system）、`--level all|critical|error|warning|information`（all）、`--messages off|on`（off）、`--limit 1..5000`（100）、`--duration-ms 100..30000`（10000）、`--backend r3`、`--json`。级别条件直接用于原后端 XPath；information 包含原始 level 0 和 4，不把 level 0 数值改成 4。只读最新一页，按通道反向顺序读取；不发布尚未实现的 Security／自定义通道、任意 XPath、载荷／XML解析、清空／删除能力。

data 提供 channel/levelFilter/messages、requestedCount/returnedCount/examinedCount、pageComplete（请求页完整）、channelExhausted（实际 NO_MORE_ITEMS）、limited/cancelled/malformed/elapsedMs、queryAttempted/queryWin32Error、contextAttempted/contextWin32Error、nextWin32Error、renderFailedCount/lastRenderWin32Error、unresolvedMessageCount、closeAttemptedCount/closeFailedCount/closeWin32ErrorsFirst32、events。达到所请求行数可正常成功，不等于通道导出完整；短批次不直接冒充通道已读尽。

事件提供 providerName、eventId、recordId、timestampFileTime/localTimeDisplay、level/levelDisplay、headerPid、computer、fields（available/absent/malformed/variantType）、messageRequested/messageAvailable/messagePartial/messageMalformed/messageLimited、metadataWin32Error/messageWin32Error、message。recordId、FILETIME 和计数为十进制字符串，未取得的属性为 null，不以 0 冒充未知。headerPid 仅是事件头记录上下文。默认不打开 Publisher 元数据或格式化消息；on 保留未压缩的多行文本，后端给 Light 的原列表文本仍按原方式压缩空白。缺少本地资源与部分插入解析均保留错误、部分状态和可取得的文本。

查询／context／Publisher／批次事件句柄在同一专用线程打开、渲染和关闭，输出之前已完成释放，关闭失败计数不会被最终“刷新完成”掩盖。最多 16 MiB 渲染缓冲、65536 消息字符和 5000 个检查记录；时间预算在原生调用之间检查，EvtNext 单次可等 5 秒，其他原生操作也不强制中断。类型／长度／内嵌指针／终止符错误为 4；无结果的调用失败为 3（明确未支持为 5）；读取中断、属性／消息缺失、部分消息、预算／取消、关闭失败为 6；完整有效空页为 0。帮助不读取日志。原生缓冲契约见 [EvtRender](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender)、[EvtFormatMessage](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtformatmessage)。

## 文件句柄占用（迁移项 42）

```powershell
KswordCLI.exe system file-holders help
KswordCLI.exe help system file-holders query
KswordCLI.exe system file-holders query --path C:\Temp\fixture.bin --json
KswordCLI.exe system file-holders query --path C:\Temp --recursive on --pid 1234 --creation-time 133000000000000000 --json
```

`system file-holders query` 要求 `--path`（非空，不包含字面包裹引号或末尾空格；shell 参数引号正常使用），支持 DOS／UNC／原生 `\Device\`／`\??\` 路径，Win32 相对路径先解析为绝对路径。可选 `--recursive off|on`（off）、`--pid`（正数）、`--creation-time`（正数，要求 pid）、`--duration-ms 250..30000`（10000）、`--max-handles 1..1000000`（1000000）、`--limit 1..100000`（1000）、`--backend r3`、`--json`。PID 筛选保留查询进程租约，校验创建时间和存活，扫描时按该创建时间检查；不匹配／已退出为 3。

读取 SystemExtendedHandleInformation，按当前进程探针句柄定位 File 类型；复制外部句柄到本调用方，专用 helper 上排除 pipe／char 后执行 NtQueryObject 名称查询。已有 Win32 路径尝试用 GetLongPathName 展开 8.3 短名（例如 TEMP 的 ADMINI~1）；不能解析的路径保留映射尝试，不保证所有别名。Nt 快照最多 8 次增长／128 MiB，验证实际返回长度和句柄数量，不把截短表当完整结果。每个名称查询等待最多 250 ms；最多四次超时或等待失败，之后停止扫描。正常 helper 停止后 join；卡住的 helper 不强杀，独占复制句柄直到内核返回后自行释放或 CLI 退出。时间／条目预算在系统调用间检查，不能强制中断底层内核查询。`--limit` 只限制显示，max-handles 限制实际系统表扫描。

data 提供 requestedPath/absolutePath/targetNtPath、recursive、pidFilter/creationTimeFilter、targetIdentity/targetIdentityStable、snapshotAttempted/snapshotNtStatus/snapshotBytes、totalHandleCount/examinedHandleCount/fileHandleCount/inspectedCount/skippedCount、protectedSkippedCount/openFailedCount/duplicateFailedCount/nonDiskCount/nameFailedCount/timeoutCount/waitFailedCount/waitWin32Error/identityMismatchCount、elapsedMs、complete/limited/cancelled/malformed、matchedCount/returnedCount/truncated、holders。计数／FILETIME 为十进制字符串，原始 NTSTATUS、句柄和权限为十六进制字符串，未知为 null。fileHandleCount 是遍历到的系统 File 类型数量（可包含 PID 筛选之外的条目），其他失败计数限定在筛选后的候选。

holder 提供 pid、processCreationTime/processAlive/identityWin32Error、processName/processPath/pathWin32Error、handle/grantedAccess、accessDisplay、objectName/win32Name。创建时间是打开的进程身份，系统句柄表没有原始创建代次，远程句柄或 PID 在快照之后可能变化；返回句柄只是远程数值，CLI 已释放自己的复制句柄，不承诺后续动作仍有效。只执行路径的大小写不敏感精确／目录边界比较，不按文件 ID 检索所有硬链接、重解析或重定向器别名，不涵盖只剩 section／模块映射而无文件句柄的占用。此项不关闭句柄、解锁、终止或转入 R0；已有 `file locks query` 的 Restart Manager 视图仍保留。

完整有效空结果为 0；受保护、进程打开／复制／名称／身份失败、超时、预算、取消、行截断、匹配行身份／路径不可用为 6，不能从空的部分结果得出“没有占用”。格式错误为 4、API 不可用为 5、快照或 File 类型定位失败为 3。没有自动启用 SeDebugPrivilege，权限不足如实保留计数。帮助不枚举系统句柄或打开目标。VM 测试持有两个自建文件句柄，独立核对数值、进程创建时间和路径；验证递归、限额、身份错误、查询保留句柄、释放后不再匹配。
