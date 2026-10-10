# 进程命令（R3）

使用 `help process` 逐层查找。已有命令不指定后端时继续使用原 R0 行为；显式选择 R3 不会自动切换到 R0。

## 原生枚举（迁移项 19）

```powershell
KswordCLI.exe process enum --backend r3 [--pid PID] [--name NAME] [--limit N] [--json]
KswordCLI.exe process enum --backend r3 --name notepad.exe --json
```

来自 NtQuerySystemInformation/SystemProcessInformation 的一次快照，保留原顺序。
pid 精确匹配（0 可显式选择 Idle）；name 按映像名称不区分大小写精确匹配；limit 只限制显示行数。
省略后端或使用 `--backend r0` 的原参数与原输出保持兼容，不接受 R3 专属筛选参数混用。

输出 source、complete、malformed、ntStatus、totalCount、matchedCount、returnedCount、missingPathCount、processes。
每项包含 pid、parentPid、creationTime（FILETIME，未知为 null）、name、nameSource、path、pathWin32Error、
sessionId、threadCount、handleCount、basePriority、kernelTime100ns、userTime100ns、cycleTime、
workingSetBytes、peakWorkingSetBytes、privatePageBytes、privateWorkingSetBytes、virtualSizeBytes、commitBytes、
pagedPoolBytes、nonPagedPoolBytes、pageFaultCount、I/O 三类操作次数与字节总数。
64 位时间／大小／计数为十进制字符串；basePriority 为有符号 JSON 整数。CPU 与 I/O 字段为累计值，不伪造采样速率。

映像路径通过保留的进程句柄读取；已知创建时间必须与快照一致，否则不把复用 PID 的新映像路径附到旧记录。
路径无法取得时为 null，保留原始错误码；nameSource 区分原生名称与原后端的显示占位名称。
匹配行中缺少路径返回 6，但原生身份和计数仍可用；有效空筛选返回 0。原生调用失败返回 3，
入口或信息类不可用返回 5；结构边界／字符串范围无效返回 4，不能把解析提前中止当成完整枚举。
