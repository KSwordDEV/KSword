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

## 剪贴板读取（迁移项 37）

```powershell
KswordCLI.exe help window clipboard
KswordCLI.exe window clipboard formats help
KswordCLI.exe help window clipboard formats enum
KswordCLI.exe window clipboard formats enum --json
KswordCLI.exe window clipboard formats enum --materialize on --json
KswordCLI.exe window clipboard text query --format auto --max-units 4096 --json
```

`clipboard formats enum`／`clipboard text query` 是相同层级结构的便捷别名，默认行为、参数和输出与 `window clipboard` 完全一致。

`window clipboard formats enum` 支持 `--materialize off|on`（默认 off）、`--limit 1..65536`（1000）、`--backend r3`、`--json`。默认只枚举格式、名称和身份，不调用 GetClipboardData；on 获取适用 HGLOBAL 的容量，可能同步触发延迟渲染和系统格式合成。GDI／显示对象不是 GlobalSize 内存对象，容量保留 null；私有／保留格式没有注册名称可以正常成功。

`window clipboard text query` 支持 `--format auto|unicode|ansi`（auto 优先 CF_UNICODETEXT，否则 CF_TEXT）、`--max-units 1..65536`（65536）、`--backend r3`、`--json`。Unicode 的限额按 UTF-16 代码单元计，ANSI 按转换前的输入字节计；CF_TEXT 按调用方当前系统 ACP 转换，不按 CF_LOCALE 推断原始编码，未新增 OEM／HTML／二进制解码。复制的内容在关闭剪贴板后输出，HGLOBAL 属于系统，不 GlobalFree。

两条命令的 data.clipboard 提供 source、opened、openWin32Error、closed、closeAttempted、closeWin32Error、sequenceStart/sequenceEnd、changedDuringCapture、ownerWindow/ownerPid/ownerTid/ownerWin32Error、openerWindowBeforeOpen、viewerChainHead、advertisedFormatCount/countWin32Error、enumComplete/enumWin32Error、limited。opener 是打开前的窗口，NULL 不能证明剪贴板未被占用（其他调用方也可能 OpenClipboard(NULL)）；viewerChainHead 仅是旧版查看器链的首项，不代表所有现代监听器。

格式查询还提供 materialize、enumeratedCount、returnedCount、truncated、formats。每项提供 id、name/nameWin32Error、category、handleBacked、globalMemorySizeSupported、dataRequested/dataAvailable/dataWin32Error、byteSize/sizeWin32Error。未请求的容量或不适用容量为 null；容量是十进制字符串，不解析 Light 的单位文字。

文本查询提供 requestedFormat、selectedFormat、formatAvailable、textAvailable、attempted、text、empty、returnedUtf16Units、previewUnits/previewUnit、allocatedByteSize、malformed、truncated、terminated、ansiCodePage、readWin32Error、unlockAttempted/unlocked/unlockWin32Error。有效空的终止文本为 `""` 并成功；格式不存在为 5，读取／锁定失败为 3，短／奇数字节 UTF-16、缺失终止符或不配对代理项为 4。截断不会切开有效代理对；未扫描到整个分配区时 terminated 可为 null，不冒充完整文本。unlocked 反映本调用的锁引用是否释放，不保证其他调用方没有锁引用。

OpenClipboard 最多 4 次、间隔 12 ms；枚举最多 65536 格式、8 秒（原生调用间检查），预览扫描最多限额加一个单位。注册名称／请求容量／枚举失败、序列变化、释放失败或输出截断为 6；有效完整空格式列表为 0。GetClipboardData 的延迟渲染调用不强制中断，挂起的所有者可能阻塞它；不把元数据模式当作渲染成功。所有打开／读取／GlobalUnlock／CloseClipboard 均保持原线程和所有权约束，CloseClipboard 的实际结果保留。纯 R3、当前窗口站，不要求驱动；帮助不访问剪贴板。本项不提供写入／清空，清空与额外所有者查询按迁移项 65 接入。

## 显示亲和性／捕获策略（迁移项 38）

```powershell
KswordCLI.exe window capture help
KswordCLI.exe help window capture query
KswordCLI.exe window capture query --hwnd 0x123456 --json
KswordCLI.exe window capture set --help
```

`window capture query` 要求 `--hwnd`，可选 `--pid`、`--tid`、`--creation-time`（正数且要求 pid）、`--thread-creation-time`（正数且要求 tid）、`--backend r3`、`--json`。跨进程读取 GetWindowDisplayAffinity，前后检查窗口归属和可获得的创建时间。data 提供 source、hwnd、pid、tid、identityMatched、layered、callerPid、callerOwnsWindow、affinity（attempted/available/value/mode/win32Error）。窗口变化／身份不匹配为 3，属性不可读取为 5，实际读出为 0；未知不等于 WDA_NONE。API 的 layered／DWM 合成条件见 [GetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowdisplayaffinity)。

`window capture set` 接入现有后端的自身窗口设置：要求 hwnd、pid、tid、creation-time、thread-creation-time 及 `--mode none|monitor|exclude`，可选 `--backend r3`、`--json`。**SetWindowDisplayAffinity 必须在窗口所属进程中调用，且目标必须是顶层窗口。** 独立 CLI 不拥有其他应用程序的 HWND，跨进程目标会在写入前返回 5，不新增注入／R0 写入能力。相同进程的适配器消费者／测试夹具可设置并回读；此成功测试不代表独立 KswordCLI.exe 能更改其他进程的窗口。

设置 data 保留 target、platform（RtlGetVersion 原始状态和版本）、requestedMode/requestedValue、callerOwnsWindow、topLevel、attempted、accepted、win32Error、before/after、ownerStillMatches、verified、display；后端添加结构化状态并保持 Light 原有显示文字。请求接受、实际回读值匹配且身份稳定才返回 0；API 失败为 3（明确未支持为 5），回读失败／降级／身份变化为 6。none=0、monitor=1、exclude=0x11；exclude 从 Windows 10 2004 起支持，旧系统可能按 monitor 处理，不能把降级当作请求完整成功；旧于 build 19041 或无法可靠查询版本时，exclude 在写入前返回 5。规则和拥有进程约束见 [SetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity)。输出仅证明策略属性和回读，未进行像素捕获验证。全部 help 查询都不调用设置／查询 API。
