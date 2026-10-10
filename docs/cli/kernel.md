# 内核对象与证据 R3 命令

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
