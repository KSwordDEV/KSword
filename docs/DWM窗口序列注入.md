# DWM 窗口序列注入

需要独立使用或分发兼容性测试时，使用 [DWM Order Tool](../DwmZOrderStandalone/README.md)。它复用下述代理和客户端，以原生 Win32 界面提供窗口选择、四种排序、持续保持、测试窗口及可选系统 DLL 附件的兼容性报告。源码导出包含完整核心实现，可以作为单独项目构建，无需 KSword 主程序、Qt 或驱动。

代理加载入口位于 **杂项 → DWM / Win32k 注入 → 加载 DWM 代理**。管理员运行主程序后，该按钮根据同目录的 `KswordDwmZOrder.dll` 准备一份 DWM 可读取的副本，再加载到当前会话的 `dwm.exe`。加载请求只初始化并校验代理，不修改窗口顺序。

目标窗口设置位于 **窗口 → 选中窗口 → 窗口输入与顺序**，也可从窗口右键菜单或属性对话框进入。窗口页的读取、应用不会自动加载代理；未加载时提示前往杂项页。停止全部保持与恢复全部输入设置也在杂项页。停止回调后 DLL 仍驻留，更新 EXE/DLL 后需注销登录以替换旧代理。本次控制协议为 v3，新增无目标窗口的 `Connect` 请求。

支持移到合成最前、合成最后、指定窗口之前或之后。勾选持续保持后，每次 DWM 更新排序或场景时重新应用；一次保持一个目标，切换目标先恢复上一个窗口。恢复操作按 Windows **当前**的窗口顺序重排，随后撤掉不再需要的回调。目标或参照关闭后解除保持；参照关闭时尝试恢复仍存在的目标。

这改变 DWM 合成窗口链表和对应的视觉节点顺序，可以越过原本位于其他 Band 的窗口。窗口的原始 Band、鼠标命中和键盘焦点仍由 Windows 管理。最小化、隐藏、独占呈现及安全桌面等场景不因列表排序自动变成可见或可交互状态。

窗口页新增的禁用、鼠标穿透与原 Band 内遮挡点击是单独的输入设置，具体语义与 Win32k 后端进展见 [窗口输入控制](窗口输入控制.md)。它们没有实现跨 UIAccess 的真实输入重排。

## 特征模型适配范围

代理不再把单个构建号、时间戳、映像大小或 PDB 身份当作运行时放行条件。它在 DWM 已加载的 `uDWM.dll` 内按函数边界扫描特征，解析 RIP 相对引用和调用目标，并同时校验 `CWindowData` 字段、`CWindowList` 虚表槽、CFG 元数据以及链表到视觉树的排序方向。任一依赖无法唯一解析就返回不支持，不会用旧版本地址继续执行。

以下版本均指 `uDWM.dll` 文件版本（省略 `10.0.`），不是 `winver` 显示的系统构建号。支持范围按完整模型划分；表中每个样本均已核对精确 PE/PDB 并通过离线回归。

| 系统 / 架构 | 已审查组件版本 | 状态 |
| --- | --- | --- |
| Windows 10，19041 组件系列，x64 | `19041.546`、`19041.6157`、`19041.6456` | **实验性**：3 个样本离线通过，尚未在 Win10 实际注入验收 |
| Windows 11 24H2，x64 | `26100.1`、`26100.1591`、`26100.2454`、`26100.3037`、`26100.4061`、`26100.4343`、`26100.5074`、`26100.7705`、`26100.7920`、`26100.9022`、`26100.9278` | 11 个样本离线通过；此前用户已确认本机置顶生效，各样本仍不等于逐一实机验收 |
| Windows 10 更早的组件系列、其它 Windows 11 组件系列、x86 / ARM64 | 未建立完整模型 | 暂不支持 |

Windows 10 2004、20H2、21H1、21H2、22H2 共用系统文件基础，参见 [Microsoft KB5015684](https://support.microsoft.com/en-us/servicing/os/windows-10/2022/06/kb5015684-featured-update-to-windows-10-version-22h2-by-using-an-enablement-package)。因此适配按 DLL 的 19041 组件系列判断，不能仅因系统显示 19044 / 19045 就拒绝，也不能据此宣称所有更新版本均已支持。未列出的组件即使具有相同 ABI，也必须通过运行时完整特征校验；列入正式验证范围前仍需补充精确样本。

Windows 11 模型含 15 个依赖函数；Windows 10 模型含 11 个依赖函数，每个已审查映像共 33 个热 / 冷代码片段。两个模型分别解析，不能混用函数或结构偏移。每个模型均要求全部依赖、3 个虚表槽、锁 / 管理器全局、WindowList 字段及 CFG 校验通过；只有唯一一个完整模型成功才发布运行时绑定。

Win10 的部分函数拆分到相距较远的冷代码块。代理按 `.pdata` / `.xdata` 的 chained unwind 归属逐块校验，跨块跳转必须落到该函数已匹配片段的指定位置；归属损坏、遗漏片段或跳转错位均拒绝。不能把首尾之间的无关代码当成同一个函数，也不能只匹配入口热代码。元数据格式见 [Microsoft x64 异常处理文档](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)。

`tools/dwm_zorder/generate_signature_model.py` 及其 Win10 生成模块只在离线生成阶段使用精确 Microsoft PDB 标注函数和调用关系；生成的代理只携带特征字节和校验规则，不读取或下载 PDB。工具核对样本 SHA256 和 PE 文件版本，拒绝不唯一的符号、缺少异常函数边界、排序调用图变化和布局字段变化，并对等价特征去重。新增系统构建必须重新审查完整模型，不能只添加一个入口通配字节。原先标成 `26100.8875` 的基准 DLL 已按其 PE 版本资源更正为 `26100.9022`。

## 执行链路

1. `OtherDock/DwmZOrderClient.cpp` 校验目标 HWND、PID、TID 和进程创建时间，选取当前会话且映像路径确认为系统 `dwm.exe` 的进程。Debug 权限只在操作线程的临时令牌中启用，结束时恢复之前的线程令牌。
2. 查询 DWM 主令牌的用户 SID，将代理复制到程序目录下的 `dwm-agent/<SHA256>/KswordDwmZOrder.dll`，只在这两个受管理目录和副本上为该 SID 增加读取、执行权限；原 DLL 及其父目录 ACL 不变。验证副本与原文件逐字节相同，拒绝受管理目录的重解析点及代理文件的重解析点、多重硬链接，并通过打开的句柄阻止加载期间替换副本或目录。
3. 通过目标进程实际加载模块的基址解析 `LoadLibraryExW` 等入口，并核对系统模块身份。远程加载线程和请求线程都使用 DWM 原本的进程身份，不设置用户模拟令牌。小型加载回执例程在同一远程线程取得真实 `GetLastError`、完整 64 位模块地址和线程退出码，再核对远端模块。代码页与数据页分开，执行前注册 x64 栈展开信息，返回前撤销。请求通过独立缓冲区交给 DLL 导出函数 `KswordDwmZOrderRequest`。超时后，缓冲区、文件租约和进程查询句柄均保留到对应线程退出；仍注册的展开信息及代码不释放。后台回收任务不能排队时也保留这些资源，不终止远程线程。
4. 协议版本 2 附带目标及参照的 `PROCESS_QUERY_LIMITED_INFORMATION` 句柄，客户端将其复制到 DWM，直到请求线程结束才关闭。代理通过这些只读句柄核对 PID、创建时间和存活状态，不需要以 DWM 账户重新打开用户进程，持续保持也不保留这些句柄。代理获取 DWM 自身的 `CDesktopManager::s_csDwmInstance` 锁，用 `FindWindowDataByHwnd` 查找已有窗口数据，验证整个桌面链表和目标身份后调用 `CWindowList::ZOrder`。该函数负责更新链表、自动父子关系、视觉树和阴影通知；随后调用 DWM 的 `UpdateScene`。两个查询 helper 使用 `NativeQueries.h` 中的专用调用封装，入口地址从通过完整校验的运行时绑定后封存在只读页中；该页保留至 DWM 进程退出。
5. 持续保持以原子替换方式接入 `CWindowList` 的 `ZOrder`、`UpdateScene`、`DestroyWindow` 三个虚表项。回调先后顺序和递归保护避免在一次原生更新尚未完成时重复重排。
6. 每次返回包含 DWM PID、合成位置、Band 和上方/下方 HWND 的执行回执。内部位置从视觉最前方以 0 开始计数，界面显示为 1；原生链表从后往前排列，因此回执必须反向计数并交换邻居方向。只有内部调用成功且链表回读一致时才标为已验证。读取失败或部分执行失败均保留错误状态。

修改直接发生在 DWM 内，不使用 Explorer 代理或 IAM 授权截获。停止保持会恢复顺序并撤掉回调；已安装过回调的 DLL 保留至该 DWM 进程退出，避免其他线程返回到已卸载代码。更换已注入的 DLL 版本后，需要注销再登录来使用新版本。

## 合成方向与恢复

原生桌面链表沿 `Flink` 从视觉最后方走向最前方。`CWindowList::ZOrder` 将目标插到第三个参数之后，因此第三个参数代表目标**下方**的窗口；传空代表链表哨兵，会把目标放到最下面。

此方向已在上述 11 个 Win11 样本的实际调用链中核对：`ZOrder` 写入新的前后链，`InsertIntoVisualTree` 使用 `FindPrecedingVisibleWindowVisual` 沿 `Blink` 查找参照，然后通过 `InsertChildAfter` 和 `CContainerVisualProxy::InsertChild` 调用 `IDCompositionVisual::AddVisual`，其中 `insertAbove=TRUE`。参照非空时这表示绘制在参照上方；参照为空时则表示位于所有兄弟节点下方，见 [Microsoft AddVisual 文档](https://learn.microsoft.com/en-us/windows/win32/api/dcomp/nf-dcomp-idcompositionvisual-addvisual)。

三个 Win10 样本也沿 `Flink` 从后往前排列，目标插到下方参照之后；视觉更新使用 `VisualCollection::InsertRelative(after=true, send=true)`，按“参照索引 + 1”插入或移动节点，再向合成通道提交相同索引。该链路独立校验 `CVisualProxy::InsertChildAt` 及通道的插入 / 重排虚表槽，不套用 Win11 的 AddVisual 特征。

| 界面操作 | 传给原生 ZOrder 的下方参照 |
| --- | --- |
| 移到合成最前 | 除目标外，原生链表的最后一个窗口 |
| 移到合成最后 | 空，即链表哨兵 |
| 紧邻参照窗口之前 | 参照窗口本身，目标绘制在其上方 |
| 紧邻参照窗口之后 | 参照窗口的原生前驱，跳过目标自身 |

恢复 Windows 当前顺序时，以 `GetWindow(GW_HWNDNEXT)` 寻找目标下方仍参与合成的窗口，再把目标插到其上方；`GW_HWNDPREV` 给出的是上方窗口，不能直接作为这里的下方参照。相邻窗口的 Win32 语义见 [GetWindow 文档](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindow)。

先前实现把原生链表头误认为视觉最前方，排序测试也沿用了同一假设，因此“移到合成最前”实际会置底。现已同时修正四种操作、恢复方向和回执索引；链表、Blink 遍历和对应系统模型的视觉插入方向均纳入特征校验。

## 维护所需的内部位置

以下是 `10.0.26100.9022` 基准样本的 RVA，仅用于解释和离线回归，其 PDB GUID 为 `0B64C1D1-F204-8615-FC50-D28401BCBB93`、Age 为 `1`。代理运行时使用 `DwmZOrderAgent/RuntimeResolver.cpp` 解析出的地址，不读取这些固定值。

| 项目 | RVA / 布局 |
| --- | --- |
| `CDesktopManager::s_pDesktopManagerInstance` | `0x120B68` |
| `CDesktopManager::s_csDwmInstance` | `0x120AF0` |
| DesktopManager 的 WindowList | 对象偏移 `0x1A8` |
| `CWindowList` 虚表 | `0xF9250`；销毁、排序、场景更新槽为 `1 / 6 / 47` |
| `FindWindowDataByHwnd` | `0x30290`；返回已有 `CWindowData*` |
| `GetWindowListForDesktopCanFail` | `0x57660`；返回桌面链表头 |
| `ZOrder` / `UpdateScene` / `DestroyWindow` | `0xEE380 / 0x21A80 / 0x8DC80` |
| WindowData 的 IDwmWindow / HWND / Band / Desktop / Visual | `0x18 / 0x28 / 0x80 / 0x88 / 0x1B8` |

两个模型的布局差异如下，字段由对应函数的实际访问校验，管理器字段和虚表槽从匹配后的引用解析：

| 项目 | Win10 19041 系列 | Win11 24H2 系列 |
| --- | --- | --- |
| WindowData 的 IDwmWindow / HWND / Band / Desktop / Visual | `0x18 / 0x28 / 0x70 / 0x78 / 0x180` | `0x18 / 0x28 / 0x80 / 0x88 / 0x1B8` |
| DesktopManager 的 WindowList | `0x1E8` | `0x1A8` |
| 销毁 / 排序 / 场景更新虚表槽 | `1 / 6 / 44` | `1 / 6 / 47` |
| 桌面链表查询 | `GetWindowListForDesktop` | `GetWindowListForDesktopCanFail` |

原型来自匹配的 Microsoft PDB，调用约定、字段访问及排序到视觉树的链路使用每个样本二进制反汇编核对。研究时还参考了 [DWMBlurGlass 的结构声明](https://github.com/Maplespe/DWMBlurGlass/blob/master/DWMBlurGlassExt/Common/DWMStruct.h)；本实现未引入其代码或依赖。每次支持新的系统组件版本，必须重新检查这些原型、布局和调用路径。

## 验证

部署入口将源 DLL 路径按调用进程的当前目录一次性解析为绝对路径，文件读取、副本目录和返回路径均使用该结果。`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` 要求完整路径，见 [LoadLibraryExW 文档](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)；此前相对路径输入会使副本加载返回 87，模块回执比对也随之失败。回归覆盖绝对路径、裸文件名及两种斜杠的相对路径复用同一副本，并在不同工作目录的子进程中验证正式加载与回执。

```powershell
python tools/dwm_zorder/verify_profile.py --self-test
& $msbuild DwmZOrderAgent/tests/OrderTests.vcxproj /p:Configuration=Release /p:Platform=x64 /m:1
& DwmZOrderAgent/tests/x64/Release/DwmZOrderTests.exe (Join-Path $PWD 'Ksword5.1/x64/Release/KswordDwmZOrder.dll')
& DwmZOrderAgent/tests/x64/Release/DwmZOrderTests.exe --runtime `
  .deps/dwm-zorder-corpus/19041.546/uDWM.dll `
  .deps/dwm-zorder-corpus/19041.6157/uDWM.dll `
  .deps/dwm-zorder-corpus/19041.6456/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.1/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.1591/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.2454/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.3037/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.4061/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.4343/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.5074/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.7705/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.7920/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.9022/uDWM.dll `
  .deps/dwm-zorder-corpus/26100.9278/uDWM.dll
```

离线检查验证旧样本的精确回归表，并拒绝损坏的身份、函数、虚表、CFG 及排序方向样本。运行时特征回归把 3 个 Win10 和 11 个 Win11 映像映射到内存，验证模型选择、地址重定位、调用图、字段布局、虚表和 CFG，并拒绝损坏的 Win10 冷代码块、归属元数据及跨块跳转；它不加载这些系统 DLL，也不注入 CI 的 DWM。本次 14 个映像共 506 项检查通过。原生测试覆盖排序边界、相邻位置、重复应用、非目标窗口顺序、无效句柄模型、新旧协议拒绝和拒绝在普通测试进程内修改运行时。排序模型另按 DirectComposition 从后往前绘制的顺序计算重叠像素所属窗口，检查置顶后的目标覆盖其他节点、相对前后关系、恢复时的下方参照，以及最前位置和上方/下方邻居回执；该模型不等同于实际桌面截图验收。加载回归测试在独立测试子进程中运行正式传输代码：验证文件不存在返回 126、真实 DLL 初始化拒绝返回 1114、Identification 级模拟复现 1346、加载线程没有模拟令牌、正式代理副本加载成功及 64 位模块回执一致。同时检查原文件权限不变、副本仅增加指定 SID 的读执行权限、文件租约阻止写入、重复准备复用副本，以及只读进程句柄对 PID、创建时间和进程退出的校验。CI 不注入实际 DWM。

CFG 回归使用启用 CFG 的独立 fixture DLL，其中两个查询函数均未进入 GFIDS 表。测试检查正式查询绑定页为只读、两个封装均可正确调用，以及 64 位桌面参数不被截断；另在调试器控制的测试子进程中运行原来的调用方式，确认退出状态为 `0xC0000409`、异常参数为 `FAST_FAIL_GUARD_ICALL_CHECK_FAILURE`（`0xA`）。正常测试进程及正式代理的 CFG 均保持开启。离线适配检查还核对两个 helper 的直接调用属性及三个虚方法的 CFG 目标资格，并拒绝损坏的 CFG 元数据样本。

旧客户端曾把“模块枚举未找到代理”统一转换成 1114，无法据此判断 DLL 初始化是否失败。现已删除该替换，界面区分打开进程、准备副本、加载器失败和线程失败，只显示实际存在的 Win32/HRESULT/线程退出码。Windows 的加载错误属于调用线程；回执必须在执行 `LoadLibraryExW` 的同一线程读取，参见 [LoadLibraryW 文档](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw)。

上一版给 DWM 远程线程设置调用者模拟令牌。跨账户条件不满足时，系统可将模拟级别降为只允许查询身份；随后加载器返回 `ERROR_BAD_IMPERSONATION_LEVEL`（1346）。同账户测试进程加载成功不足以验证该跨账户方案，现已删除远程线程的令牌复制、设置和挂起恢复逻辑。此机制见 [PsImpersonateClient 的权限与降级说明](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psimpersonateclient) 和 [Identification 级别不能调用 LoadLibrary 的说明](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nc-wdfrequest-evt_wdf_request_impersonate)。

随后报告的十进制退出码 `3221226505` 是 `0xC0000409`。本机 WER 的 `BEX64` 记录给出的异常参数为 `0xA`，明确对应 CFG 间接调用校验失败。核对精确 uDWM 的 GFIDS 表发现，`FindWindowDataByHwnd`（`0x30290`）和 `GetWindowListForDesktopCanFail`（`0x57660`）没有登记为间接调用目标，而三个虚方法均已登记。原来的通用函数指针调用会触发快速失败；普通测试进程在运行时校验阶段即返回，未覆盖这两个内部调用。现在只对两个不可内联、各自仅执行一次查询调用的封装使用 `guard(nocf)`，并将其目标地址绑定到只读页；其他代码和三个排序回调继续启用 CFG，不修改系统模块的 CFG 表。异常线程退出码单独以十六进制显示，不再冒充 Win32 错误。关于此类小型封装及只读绑定的要求，参见 [Microsoft PE/CFG 元数据文档](https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata)；快速失败的异常码、子码和不可捕获行为见 [__fastfail 文档](https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail)。

上述结果不等同于实际桌面注入通过。实际验收仍须检查普通窗口跨 UIAccess 窗口的画面遮挡、持续激活其他窗口、参照关闭、目标关闭、恢复和停止，以及多显示器与窗口动画。图形合成结果和鼠标命中必须分别观察。
