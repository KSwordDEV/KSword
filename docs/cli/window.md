# 窗口 R3 命令

## 枚举与管理（迁移项 36）

```powershell
KswordCLI.exe help window
KswordCLI.exe window detail help
KswordCLI.exe help window detail query
KswordCLI.exe window manage help
KswordCLI.exe help window manage minimize
KswordCLI.exe window enum --pid 1234 --json
KswordCLI.exe window detail query --hwnd 0x123456 --json
KswordCLI.exe window detail --hwnd 0x123456 --backend r3 --json
KswordCLI.exe window manage minimize --hwnd 0x123456 --pid 1234 --tid 5678 --creation-time 133000000000000000 --thread-creation-time 133000000010000000 --json
```

`window enum` 为纯 R3，支持 `--pid`、`--visible all|yes|no`（all）、`--sort stacking|process`（stacking）、`--limit 1..100000`（1000）、`--backend r3`、`--json`。只枚举调用方桌面的顶层窗口，按共享后端原有规则过滤 Progman／WorkerW／Shell_TrayWnd，不列出子控件、所有桌面或内核隐藏窗口。process 排序按 PID 稳定排序。旧 `window gui`、`win32k` 等 R0 命令保持兼容。

`window detail query` 默认 R3；现有 `window detail` 必须显式 `--backend r3` 才使用 R3，省略后端和显式 r0 仍走原来的 tagWND 协议。二者要求 `--hwnd`；R3 可选 `--pid`、`--tid`、`--creation-time`（正数且要求 pid）、`--thread-creation-time`（正数且要求 tid）、`--json`。R0 的 `--flags` 不用于 R3。detail 中间帮助仅展示已有调用入口及 query 子节点；query 叶子显示完整参数和限制。无效 HWND 或身份不匹配返回 3。

枚举 data 包含 source、complete（EnumWindows 遍历完整性）、limited、win32Error、examinedCount、skippedCount、shellFilteredCount、matchedCount、returnedCount、truncated、windows。query 提供 source、hwnd、found、identityMatched、win32Error、window。窗口提供 hwnd、pid、tid、processCreationTime、threadCreationTime、title、class、processImagePath、visible/enabled/minimized/maximized/unicode、style/exStyle、windowRect/clientRect、clientRectCoordinates 和 evidence。地址为十六进制字符串，FILETIME 为十进制字符串；每项 evidence 区分 available、empty、truncated 和 win32Error。有效无标题窗口的 title 是空字符串，读取失败是 null。优先 WINDOWINFO 的 clientRect 为屏幕坐标，GetClientRect 回退为客户区坐标，明确标注；不混用坐标含义。

按原后端提供 `window manage minimize|maximize|restore|foreground|close`，每个是独立叶子，要求非零 hwnd、pid、tid 及正数 creation-time、thread-creation-time，可选 `--wait-ms 0..10000`（2000）、`--backend r3`、`--json`。从 enum/query 的当前结果取得身份值。操作期间保留进程和线程句柄，检查线程归属／创建时间、对象存活与 HWND 的 PID/TID；请求前和回读时重新检查。HWND 没有 Win32 创建代次，同一存活线程重用 HWND 仍是限制，不能把快照当作持久窗口租约。

动作 data 包含 target、action、alreadySatisfied、attempted、requestAccepted、nativeReturn、win32Error、restoreAttempted/restoreAccepted/restoreWin32Error、verified、ownerStillMatches、ownersAlive、windowExists、foregroundWindow、before、after、requestDisplay。显示动作只有窗口可见且目标状态已满足时，才成功而不再写入；隐藏的正常窗口仍需要 restore 请求以显示。CLI 使用 ShowWindowAsync，后端默认同步行为与 Light 原有显示文字保留；API 接受异步请求不等于目标已执行。关闭只投递 WM_CLOSE，不结束进程；目标可以拒绝关闭。前台切换尊重 Windows 焦点权限和 UIPI，不附加输入队列或切换桌面。API 未提供错误码时保留 null，不编造访问拒绝。

请求失败为 3；已投递而效果未确认、或前台切换中的还原已投递但切换失败为 6；实际状态／原窗口消失确认后为 0。只有请求接受（或无需请求）且验证效果才会标记 verified。未完成请求可能在 CLI 退出后完成。枚举／读取字段缺失、窗口退出／归属变化、截断为 6；完整有效空枚举／筛选无匹配可成功。枚举预算为 100000 候选窗口／8 秒，在原生调用间检查；标题 32767 字符、类名 511 字符。帮助不创建目标句柄、打开驱动或提交操作。
