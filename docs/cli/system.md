# 系统工具 R3 命令

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
