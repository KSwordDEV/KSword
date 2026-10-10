# 窗口 R3 命令

## 剪贴板清空与实时所有者（迁移项 65）

```powershell
KswordCLI.exe window clipboard help
KswordCLI.exe help clipboard owner query
KswordCLI.exe clipboard owner query --json
KswordCLI.exe clipboard opener query --json
KswordCLI.exe help clipboard clear
KswordCLI.exe clipboard clear --confirm --expect-sequence 123 --json
```

`window clipboard owner query`／`opener query` 和 `clipboard` 别名只读 GetClipboardOwner／GetOpenClipboardWindow 与实际窗口 PID/TID，支持 `--backend r3`／`--json`。data 提供 source/window/windowAfter/windowPresent/stable/identityKnown、pid/tid/win32Error/clipboardSequence；句柄为十六进制，未知 PID/TID／零序号为 null。稳定的无窗口可成功为 0，身份查询错误或窗口变化为 6。这是双采样标识，不是保留的进程身份租约，不提供创建时间或授权依据。NULL opener HWND 不证明剪贴板没有被占用（OpenClipboard(NULL) 也可持有它），不打开剪贴板或读取内容。

`window clipboard clear`／`clipboard clear` 必须带 `--confirm`，可选 `--expect-sequence` 正 uint32、`--backend r3`／`--json`。清空当前调用者窗口站的所有格式，不读取、备份或恢复内容；序号 guard 在成功打开剪贴板后、EmptyClipboard 前比较，不匹配为 3 且不写入。data 提供 target/action/opened/attempted/requestSucceeded/verified/malformed/win32Error、期望／前后序号、sequenceMatched、前后格式计数／错误、实际关闭状态。零序号不可用，不当作空剪贴板。

同一线程按顺序执行打开／清空／计数回读／关闭，复用 4 次、间隔 12 ms 的打开重试。有效 EmptyClipboard 且零格式／关闭证据为成功 0；打开／guard／清空失败为 3，明确不支持为 5；原生计数格式错误为 4；缺失回读／序号／原计数／关闭证据为 6。系统可能通知原所有者，原生通知调用无法硬中断。不存在跨窗口站目标、保护策略修改、窗口注入或 R0 fallback；help 不执行读取／清空。

宿主测试不清空用户剪贴板。VM 使用自建发布窗口与格式验证所有者／占用者、序号不匹配不写入、真实清空与独立零格式回读；最后销毁自己的夹具。原有只读 formats/text 语法与默认行为保留。

## 窗口列表捕获保护适配（迁移项 64）

本项复用已有 `window capture query`／`window capture set`，不增加重复操作入口。set 调用共享 WindowListCapture::ApplyWindowListCaptureAffinity 的结构化结果，query／回读使用其 CaptureAffinityText 显示说明；显示文字不用于判定成功。参数、None／Monitor／Exclude 模式、进程／线程创建时间与当前进程顶层窗口限制、19041 Exclude 平台门禁均保持原有语义（见迁移项 38）。

set data 新增 source=`shared WindowListCapture; SetWindowDisplayAffinity + readback`，affinity 的 before/after 与 query data 增加 display；实际 accepted/error/after.value/ownerStillMatches/verified 决定结果。回读失败、降级或身份变化仍是部分证据 6，API 失败 3／不支持 5；独立 CLI 不拥有其他应用的窗口，拒绝该写入为 5。属性设置不等于捕获像素实证。help 不读写窗口。

每项测试复用原有所有权／平台／回读失败／降级／目标变化夹具，并在 VMware 中用同进程原生消费者执行生产 CLI 适配层设置三种策略，再通过 SDK 回读核对。该测试不代表独立 CLI 可以跨进程设置属性；跨进程拒绝及状态未改变另行验证。

## 全局热键探测（迁移项 40）

```powershell
KswordCLI.exe window hotkeys help
KswordCLI.exe help window hotkeys probe
KswordCLI.exe window hotkeys probe --key F23 --modifiers ctrl+alt+shift --json
KswordCLI.exe window hotkeys scan --limit 1320 --json
```

`window hotkeys probe` 要求 `--key`（A-Z、0-9、F1-F24、后端命名键或十进制／十六进制 VK 1..254）和 `--modifiers`（none 或小写 ctrl/alt/shift/win 以 + 连接，不重复）。命名键包括 Esc、Tab、Space、Enter、Backspace、Insert、Delete、Home、End、PageUp、PageDown、Left、Up、Right、Down、PrintScreen、Pause 及美式键名的标点（按 VK 解释，不按当前键盘布局字符推导）。`scan` 按共享后端原顺序探测 88 个键 × 15 个非空修饰组合，`--limit 1..1320`（1320）限制实际操作次数。两者均支持 `--backend r3` 和 `--json`。

这不是只读枚举：在新建专用线程上临时调用 RegisterHotKey(NULL)，成功后立即在原线程 UnregisterHotKey，线程退出并 join 后才输出；探测期间可能短暂拦截组合，一些系统默认热键可被成功注册临时覆盖。F12 为调试器保留，CLI 不尝试注册。其他注册失败的 1409 只说明“已占用或系统保留”，不推断所有者；Win 修饰组合标注系统保留候选。不会持久注册、发送键盘输入或调用 R0。API 规则见 [RegisterHotKey](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerhotkey)、[UnregisterHotKey](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unregisterhotkey)。

data 提供 source、transientRegistration、workerThreadId/workerExited、complete/limited/cancelled/cleanupFailed、requestedCount/returnedCount/availableCount/occupiedOrReservedCount/reservedCount/unknownCount、entries；计数为十进制字符串。每项提供 combination、modifiers/virtualKey（十六进制）、classification（available/occupied-or-reserved/reserved/unknown）、attempted/registered、registrationPossible（无法判断为 null）、registerWin32Error、unregisterAttempted/unregistered/unregisterWin32Error、ownerPid/ownerWindow（始终 null）、systemReservedCandidate/reservedReason。可注册是当时的注册证据，不是持续空闲保证；释放失败仍保留 registered=true、unregistered=false，不冒充已完成。

完整可判定结果为 0，即使组合不能注册；单项 F12 保留或全为无法判定为 5；未知与已知混合、释放失败、取消或限额为 6。最多 8 秒（原生调用间检查），释放失败停止探测，避免复用尚未释放的 ID；专用线程退出的生命周期与实际释放回执分开报告。help 不注册热键。进程热键候选见 `process hotkeys`，不等同于这里的实际全局注册探测。真实修改测试仅在克隆 VM 中完成：由独立 SDK 线程持有组合，验证探测不能注册；释放后验证 CLI 可注册且 SDK 再次注册成功，以及全矩阵每个成功注册的释放状态。

## 窗口层级与属性（迁移项 39）

```powershell
KswordCLI.exe window hierarchy help
KswordCLI.exe help window hierarchy query
KswordCLI.exe window hierarchy query --hwnd 0x123456 --json
```

`window hierarchy query` 要求非零 `--hwnd`，可选 `--pid`、`--tid`、`--creation-time`（正数，要求 pid）、`--thread-creation-time`（正数，要求 tid）、`--backend r3`、`--json`。使用共享 Win32 后端读取当前调用方桌面的父／根／根所有者／所有者关系、相邻顶层窗口、样式及解码位、类原子／过程／额外字节、几何、DPI 上下文、DWM 遮蔽／扩展边框、显示亲和性和 layered 属性，不遍历 UIA、切换桌面或转入 R0。

data 保留 hwnd、pid/tid、identityMatched、remoteProcedureValuesOpaque、fieldCount/unavailableFieldCount、parentChain、parentChainComplete/Cycle/Limited/Win32Error、topLevelZIndexZeroBased/topLevelZCount、zComplete/Cycle/Limited/Win32Error、fields。字段提供 name、available、notApplicable、value、errorDomain、error；不可用与不适用均为 null，原始 HWND／地址／标志为十六进制字符串，数量为十进制字符串，矩形／点保留有符号坐标。祖先链最多 32 项，顶层 Z 序最多 100000 项／8 秒（原生调用间检查），均检测循环；Z 序索引从零开始，仅是读取时的快照。GetParent 对顶层 popup 可返回所有者，GetAncestor(GA_PARENT) 的父链、GA_ROOT 与 GA_ROOTOWNER 分别输出，不混用。

窗口／客户区矩形遵循调用方 DPI 上下文；clientRect 使用客户区坐标，clientOriginScreen 提供客户区原点的屏幕坐标，DWM 扩展边框使用物理屏幕像素。缺少 DPI／DWM API 不猜测 DPI=96 或 cloak=0；非固定上下文的 contextDpi=0 记为不适用。callerClassRegistration 是调用方模块／系统类可见的查询，不代表远程类注册所有权；跨进程过程地址可能是系统代理，不能据此推断 subclass 或 Hook。亲和性／DWM 对子窗口等目标不可读时保留原始错误。

有效完整读取为 0；字段缺失、循环／预算、Z 序未找到根窗口为 6；目标消失、身份不匹配或读取期间归属变化为 3。前后复核 PID/TID 与可获取的创建时间；同一线程重用 HWND 无 Win32 创建代次，仍是限制。帮助不查询窗口或打开驱动。测试自建主窗口、子控件和 owned popup，通过独立 SDK 核对关系／样式／几何／DPI，并验证不可用字段、错误身份、退出目标与故障夹具的预算／循环。原生定义见 [GetAncestor](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getancestor)、[GetClassLongPtrW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclasslongptrw)、[GetDpiFromDpiAwarenessContext](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdpifromdpiawarenesscontext)。

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
