---
name: ksword-ui-architecture
description: KSword 主程序 UI/主题架构要点（theme.h token 体系、全局样式块链路、WindowChrome、透明背景与毛玻璃、Dock 懒加载）
metadata:
  type: project
---

KSword 主程序位于 `Ksword5.1/Ksword5.1`（Qt 6.9.3 Widgets + Qt Advanced Docking System，MSVC vcxproj 构建）。

- 2026-10-01 虚拟化 Dock 按驱动后端适配：AMD 使用“准备 → 全核 SVM 自检 → 常驻”，隐藏 EPT watch/分离视图/执行域/Hook/VMCS 策略/SOAK，保留通用内存、事件、停止和释放。第三方 VM 页为四步嵌套 SVM 流程，Intel 仍五步；实际启用必须读取驱动位，不能从本地开关或 VMware 服务 Running 推断。证据页校验 metrics 版本/长度/行数、代次与 CPU 身份，raw/general/hotspots 各自检查有效位与偶数序列，无效显示暂不可用。
- 离屏 UI 回归入口 `tools/hvm_lab/build-ui-tests.cmd`：链接实际 Dock、Guest、Evidence、KvmControl 与 DriverClient，仅替换 IOCTL 传输、确认和 SCM。测试源码由该独立构建清单登记，不进入主程序 vcxproj。Windows Qt offscreen 需显式加载中文字体，配合 `SetDarkModeEnabled` 与完整 palette（包括 PlaceholderText/AlternateBase/disabled roles）；否则缺字或默认浅色 palette 会制造错误的窄窗口/深色截图。Qt DLL 需部署到测试 exe 目录。

- QADS 已升级到 **5.1.1**（`v5.1.1`，commit `023ce95934fecfd4cf5c672c9c404fabe0f54923`）。版本、许可证与复现步骤见 `third_party/qt_advanced_docking_system/NOTICE.md`；CMake 包装保留 `qtadvanceddocking[d].dll/.lib` 文件名，避免改名 DLL 后 import library 仍指向上游新文件名。`include/ads/ads_version.h` 是构建生成的必要头文件，升级时须与其余头文件、Release/Debug import library 和 DLL 一起更新。
- ADS 5.x 默认跟随 palette 自动加载内部 QSS。KSword 必须在创建 `CDockManager` 前设置 `DisableStylesheet=true`；仅在外观应用末尾 `setStyleSheet("")` 不够，后续 palette 事件仍会重新加载默认样式。`include/ads/` 属于上游头文件，Git 用 `-text` 保留混合 LF/CRLF，避免升级产生整文件换行 diff。

## UI 主题架构

- 顶部ADS导航使用独立的`DockTabState`角色（`theme.h::DockTabBackgroundColor/TextColor/GlyphColor`）：三态背景分别沿用背景种子的`SurfaceColor/SurfaceMutedColor/SurfaceAltColor`偏移，只有强调文字、图形与`DockTabHighlightColor`选中底边从主题色派生；底边两像素同时扣减底部padding，保持既有高度。`DockNavigationStyleSheet`最后追加，覆盖旧基础属性hover和背景图透明兜底；普通业务QTabBar不受影响。自绘hover必须补回选中底边，局部文字共用`UI/DockThemeIcons::ApplyDockTabTextColor`，自有工厂在选中/hover/主题事件后调用。Qt在选中标签上仍可能请求Normal图标，导航图形需要对三态都保持对比，背景变化后允许前景做对比度校准。2026-10-04本次背景/强调分离回归5921条断言通过，覆盖主体色变化时三态背景不变、背景种子驱动真实三态底面、选中/选中悬停标记及图标对比；日志`.codex-build-logs/titlebar-background-offset-ui.log`。MainWindow自绘工厂仅静态核对，未启动生产GUI。本次两次主程序Build尝试均在i18n门禁被并行MemoryWorkbench持续新增的文本缺项阻断（已定点补齐11条双语提示）；最新失败日志`.codex-build-logs/ksword-build-check-20261004-213558.raw.log`，不报告整库编译通过。
- 2026-10-04全项目配色审计见`docs/全项目配色审计.md`，后续修复及验证见`docs/配色问题修复记录.md`：全局旧色补偿只改QWidget显式palette/QSS，不覆盖item brush、QTextCharFormat/ExtraSelection、模型HTML或成员缓存；已有颜色角色也不能证明存量内容会随主题刷新。独立产品的固定设计/状态语义/数据原色不自动算缺陷。
- 表格交替底/搜索normal-hover-selected的多底组合可能没有共同达到4.5:1的单一文字色，要按实际绘制选项求前景，不能降低门槛或猜model row奇偶。`ThemeItemForeground`专属语义角色仅用于明确标记项，换色不重新枚举、不reset模型或隐藏/选择快照。自有插件日志页的热主题通过`DebuggerBackend/KswordPluginTheme.h`颜色快照传递，Qt宿主排队限时发送、Win32接收页更换成对画刷；第三方调试器主窗口保持独立。

- `theme.h`（KswordTheme 命名空间）：design-token 中心。中性表面色（Window/Surface/SurfaceAlt/SurfaceMuted/Border）由 RGB 偏移从种子色派生；强调色 PrimaryBlueColor 可由用户自定义；提供 EnsureTextContrast 等 WCAG 对比度工具。
- `theme.h` 的颜色访问器分两族，名字只差一个词，用错编译器和 Qt 都不报错：**动态** token（`SurfaceHex()`、`TextPrimaryHex()`、`PrimaryBlueHex` 等，共 14 个）返回 `palette(base)` 这类样式表角色，Qt 每次重绘重新求值，天然跟随主题；**静态** token（`*ColorHex()`）在调用瞬间固化成 `#RRGGBB`。
- `palette(...)` 是 QSS 专有扩展，**只有样式表能解析**。写进 QLabel/QTextEdit 富文本（走 QTextDocument 的 CSS 解析器）、`QColor` 字符串构造、`setForeground`/`QPen` 等绘制路径，或通过环境变量传给插件进程，都会被**静默丢弃**——声明整条失效、元素退回继承色，没有任何警告。这类误用已经犯过 5 次（HardwareDock 的 CPU 详情单元格、GlobalUiSearch 的结果副标题、NotificationCardManager、PluginHost）。上述场景一律改用 `*ColorHex()`。
- 构建期有门禁：`tools/theme_token_audit.py`（vcxproj Target `AuditKswordThemeTokens`，`BeforeTargets="ClCompile"`）。token 清单从 theme.h 现场解析，新增 token 自动纳入；语句定界会跳过字符串字面量，否则内联 CSS 里的 `padding-right:18px;` 会把语句在 HTML 标签前截断而漏检。脚本自带 `--self-test`，对照 `tools/theme_token_audit_fixture/` 双向校验（标记行必须报出、未标记行不得报出），构建时先自测再扫源码。跳过用 `/p:KswordSkipThemeTokenAudit=true`。
- 语义状态色（信息/成功/警告/错误/空闲）没有对应的 palette 角色，统一走 `UI/ThemeStatusRole`：控件用 `ks::ui::ApplyStatusRole()` 只记状态，颜色由全局样式块的 `QLabel[ksword_status_role="..."]` 规则下发。控件因此不持有自己的 styleSheet，也就不必再依赖 `ThemeColorRemap` 的存量字符串扫描（该扫描按旧值建映射，撞色时只能整组跳过）。属性名用下划线：驼峰会被 i18n 审计当成待翻译文本。
- `SurfaceMuted` 和 `TextDisabled` 没有动态版本，且不该硬造：QSS 的 `palette()` 选不到 disabled group，剩余空闲角色（light/bright-text/shadow）都会被 QStyle 用于原生控件的立体边框绘制。用到它们的页面必须自己具备重建入口（`changeEvent` 处理 `ApplicationPaletteChange`，或每次显示时重新生成样式）。
- 纯图标按钮的几何同样由 `theme.h` 收口：紧凑工具栏使用 `ApplyCompactIconButtonMetrics`（28px 按钮 / 16px 图标），独立或强调动作使用 `ApplyStandardIconButtonMetrics`（32px / 18px）；页面不得继续新增 30/34/36px 的临时组合。
- `MainWindow::applyAppearanceSettings`：主题应用唯一入口，设置 QApplication palette + 调用 `applyGlobalApplicationStyleBlocks`（带 marker 的 QSS 块替换机制，marker 常量在 MainWindow.cpp 顶部匿名命名空间）。
- 外观设置的`UI/ThemePreviewWidget`展示未应用的深浅模式/主体色/背景色，选色器`currentColorChanged`仅更新样例，取消还原待应用值。`theme.h::ScopedThemePreview`借用线程局部种子同步求值，所有颜色复用生产角色算法并绕过全局角色缓存；禁止在该范围内处理事件或应用设置，不得用临时修改全局种子或QApplication palette实现预览。
- 全局 QSS 块顺序：BaseControl（`UI/GlobalUiBaseStyle.cpp`）→ Tooltip → ContextMenu → ControlContrast → ComboBox，依次追加到 app stylesheet，基线块在最前，局部样式可覆盖。
- `QComboBox` 弹出列表是独立 `Qt::Popup` 顶层窗口。禁止在 Popup 的 `Show`/`Resize` 事件内同步调用 `setMask`、`setStyleSheet` 或其它可能 repolish 子树的操作：Qt 此时可能仍在 `QWidgetPrivate::showChildren` 中遍历内部子对象，重入修改会留下悬空 child。Popup palette/QSS 必须用零延时 queued 更新并做幂等去重；圆角只保留 QSS 绘制，不再修改原生窗口 mask。
- `UI/GlobalDialogTheme.cpp`：QApplication 事件过滤器给所有 QDialog 补主题（palette + 追加 QSS）；QMessageBox 由 `UI/ThemedMessageBox` 专管。
- `UI/WindowChrome.cpp`：事件过滤器对所有原生标题栏顶层窗口用 DwmSetWindowAttribute 染色（IMMERSIVE_DARK_MODE=20、BORDER=34、CAPTION=35、TEXT=36），主题切换时 `RefreshAllWindowChrome()`。
- 大型独立窗口的初始尺寸和最低尺寸统一调用 `ks::ui::applyResponsiveWindowGeometry`，以父窗口所在屏幕的 `availableGeometry` 为边界；不要再直接写 1000px 以上的硬 `setMinimumSize`，否则高 DPI、小屏或远程桌面会把窗口撑出工作区。
- 独立窗口中的懒加载 `QTabWidget` 必须隔离页面动态 `minimumSizeHint`：页面栈使用零最小尺寸和 `QSizePolicy::Ignored`，顶层窗口只保留响应式最低尺寸，禁止用 `maximumWidth` 对抗内容传播。纵向表单页应放入 `QScrollArea`，使切页和异步控件挂载不改变用户当前窗口尺寸，同时保留自由拖大和最大化能力。
- 主窗口是 FramelessWindowHint + 自绘 `Framework/CustomTitleBar`；其余子窗口全是原生标题栏。
- 硬件利用率浮窗跨不同缩放显示器时，不要用 `QMouseEvent::globalPosition()` 的增量反复调用 `QWidget::move()`：窗口位置与鼠标坐标在 DPI 切换后可能落在不同逻辑坐标系，使尺寸累积漂移。达到拖动阈值后调用 `QWindow::startSystemMove()`，Windows 兜底走原生 `WM_NCLBUTTONDOWN/HTCAPTION`；边缘缩放仍由原生 `WM_NCHITTEST` 处理。
- 利用率浮窗的缩放、背景不透明度、置顶、独立主题保存在 `AppearanceSettings` 的浮窗专用字段。只在浮窗上设置 `WA_TranslucentBackground` 并自绘带 alpha 的表面色，不能使用 `setWindowOpacity`，否则文字和图表一起变淡。Windows 分层窗口的背景在配置为 0% 时仍需绘制 1/255 alpha，以保留空白区域的鼠标命中和整窗拖动；配置值继续记为 0%。
- 利用率浮窗缩放内容时，以借用页面原本的字体、QSS 字号、布局边距/间距为基线重算，回主窗口前恢复原值；左侧卡片还需同步缩放列表行高与自绘坐标。浮窗独立切深浅色时，只改根 palette 不足以覆盖子控件已有的 `palette(text)` QSS；对子控件用浮窗 palette 的实色替换文字 token，并保存原 QSS/palette 供返回时恢复。Shift+滚轮在 Windows 可能作为水平滚轮到达，处理 `angleDelta().y()` 为零时的 `x()`。
- 利用率浮窗跟随外部窗口时，原采样与绘图控件仍留在浮窗，主界面原插槽用独立的原生标签、设备卡和图表控件呈现同一采样结果。不要用 `QWidget::render()` 后按主窗口尺寸缩放位图，字体和图表会一起变形。用 `WindowFromPoint` 选顶层窗口，按完整标题与进程路径重找；跟随事件使用 `SetWinEventHook` 的异步回调加定时兜底。目标与浮窗矩形用 DWM 扩展边框的物理坐标读取，持久化相对位移时按目标屏幕 DPI 转成逻辑单位；只在用户结束拖动/缩放时改写偏移，不能把程序主动 `SetWindowPos` 产生的 Qt `Move` 事件当成用户拖动，否则跨 DPI 屏幕会累积漂移。目标置顶时拒绝跟随；跟随时浮窗自身强制非置顶，普通模式保留用户原置顶配置。点击穿透仅对跟随态设置 `WS_EX_TRANSPARENT`，主界面性能区双击负责退出穿透。
- 利用率左侧窄窗和详情浮窗共用 `utilization_floating_scale_percent`；键盘/滚轮修改立即保存，原生边缘缩放必须在 `WM_EXITSIZEMOVE` 后按最终窗口尺寸保存，Qt 鼠标释放事件不会可靠地收到非客户区缩放结束。左侧列表的滚动条宽度、圆角和最小滑块高度跟着浮窗内容比例变化，颜色使用 palette 角色以适应独立深浅主题。跟随目标从遮挡中唤到前台时，在 WinEvent 回调中先用原生 `SetWindowPos` 调整浮窗 Z 序，再排队同步 Qt 视图，避免图表刷新延迟层级调整。
- 硬件利用率页的网络来源是 `GetIfTable2`，该表还含每个网卡上挂载的 WFP、杀软、QoS 等过滤模块行；仅检查 `OperStatus == Up` 会把一个网卡绘成多张卡并重复累计流量。网络性能卡应跳过 `MIB_IF_ROW2.InterfaceAndOperStatusFlags.FilterInterface`，再按接口 LUID 与 `GetIpInterfaceTable(AF_UNSPEC)` 返回的 IP 接口交叉验证；不要用驱动名称字符串筛选，因为名称受产品和语言影响。IP 表查询失败时仅回退到非过滤、广播型接口。
- 网络利用率页用 `MIB_IF_ROW2.InterfaceAndOperStatusFlags.HardwareInterface` 区分实体和虚拟 IP 接口：实体网卡保留独立导航项，虚拟网卡合入一个滚动详情页。虚拟页复用每接口采样和 `QChartView`，按 viewport 宽度排成一列或两列；新增接口时重排网格，并在详情浮窗中重新捕获缩放样式。实体接口断开后保留卡片，重新连接首帧重置计数器增量基线。

**全局基线样式只允许颜色/边框，禁止 min-height/padding 等几何属性**——app 级几何会穿透局部样式破坏紧凑布局（曾导致主窗口标题栏按钮被撑高、最大化后标题文字上偏）。

## 角落通知卡片的点击穿透

- `Framework/NotificationCardManager.cpp` 的卡片是独立顶层浮窗。`WM_NCHITTEST/HTTRANSPARENT` 只继续命中同线程窗口，不能保证穿透到其他程序；`NoTextInteraction` 也仅禁用文本交互。
- 卡片本体使用 `WindowTransparentForInput`，复制与展开按钮放在独立的 owned Tool 窗口中，以两个按钮矩形的并集设置原生窗口 mask。正文、标题、背景、按钮间隙直接命中紧邻下层窗口，包括主窗口，不做跨进程消息转发或基于光标轮询的样式切换。
- 按钮窗口的区域内绘制 1/255 alpha，避免分层窗口的零 alpha 像素使按钮空白处也穿透；位置、布局占位尺寸、展开/收起、主题、显隐和淡入淡出必须同步，销毁卡片时按钮窗口随 owner 销毁。
- 自动化验证禁止写入真实系统剪贴板：即使最终恢复原文本，也会污染用户剪贴板历史。复制动作需替换剪贴板写入端或仅作源码检查；不得以“恢复剪贴板内容”作为可无影响验证的依据。

## 透明背景与毛玻璃（MainWindow.cpp）

配置项：`backgroundTransparencyEnabled`（总开关）+ `backgroundTranslucencyMaterial`（auto/mica/desktop）。

- 总开关需要 `WA_TranslucentBackground`，**必须在原生窗口创建前设置**，因此改动只能重启生效；材质选项可运行时切换。
- **DWM 云母（DWMWA_SYSTEMBACKDROP_TYPE）与 `WA_TranslucentBackground` 互斥**：云母要求窗口不透明、由 DWM 在其背后合成，遇到分层透明窗口会回退成系统浅色 fallback 底，表现为整窗发白。已改用 `SetWindowCompositionAttribute` + `ACCENT_ENABLE_ACRYLICBLURBEHIND`（Win10 1803+/Win11 通用），配置值仍叫 `mica` 仅为兼容旧配置。
- 毛玻璃生效时着色由系统随模糊合成，根容器必须画完全透明；未生效（旧系统/调用失败）才回退自绘半透明着色层保证文字可读——由 `applyMainWindowBackdropMaterial` 的返回值驱动。
- Acrylic 不会自动跟随窗口移动重采样，失焦后还会降级为静态回退色：`scheduleWindowBackdropRefresh()` 在 move/resize/WindowStateChange/ActivationChange 时重新下发组合特性，40ms 节流合并。
- 首次外观应用早于原生窗口创建，组合特性会被句柄守卫跳过，因此 `showEvent` 必须补调一次 `refreshWindowBackdropMaterial()`。
- **Dock 内容透明不能只看背景图**：`enableDockContentTransparency = 背景图就绪 || 窗口透明`，否则 DockManager 与各 Dock 的不透明表面会盖住底层，只剩菜单栏可见。KernelDock 会自绘实底，三处决策统一走 `shouldRenderTransparentDockContent()`。

## Dock 懒加载机制

- `ensureDockContentInitialized` 按 `ks_lazy_key` 创建真实 widget（成员指针 m_processWidget 等允许为 null，占位页 `createDockPlaceholderWidget`）。
- 外部 Tab 插件需要提供属于插件进程、直接挂在 KSword 容器下的 `WS_CHILD` 窗口供 `PluginHost` 握手；这不要求第三方程序的主窗口也成为子窗口。Cheat Engine 的 Tab 只嵌入日志转发窗口，CE 主窗口保持自己的顶层窗口和原生主题，关闭 Tab 时只关闭转发器进程，不向 CE 发送 `WM_CLOSE`。
- CE 日志页消费 `PluginHost` 的主题角色颜色与语言快照，使用 Consolas 等宽字体，HVM 开关通过独立会话控制/状态文件等待 CE 确认。CE Lua 只给主窗口 Caption 增加 `[KSword R0]` 或 `[KSword HVM]`，不改颜色、字体、控件、窗口父级或尺寸。
- 跨 Dock 打开独立详情窗口时，只用 `ensureDockContentInitialized` 创建内部控制器和窗口管理状态；不要对其所属 Dock 调用 `raise()`、`setVisible(true)` 或 `setAsCurrentTab()`，否则会无条件改变用户当前标签。进程详情入口遵循此规则，`ProcessDock` 仍负责 identity 校验、窗口复用和详情页导航。
- 主功能 Dock 一律 `DockWidgetClosable=false`（Tab 无关闭按钮）。曾实现过"Tab 关闭按钮=卸载内容"（CustomCloseHandling + unloadDockContent），最终整体撤销（23251d80）；若再有此需求注意：welcome 无懒加载工厂，kernel↔driver 有共享自驱动页 `attachKswordSelfDriverPage`，卸载会悬空。
- 跨 Dock 的进程详情入口仍可调用 `ensureDockContentInitialized(m_dockProcess)` 来复用 `ProcessDock` 的详情窗口管理与 identity 校验，但不得随后 `raise()` 或 `setVisible(true)` 激活进程 Dock；`ProcessDetailWindow` 是独立顶层窗口，打开它时应保留用户当前页签。

## 启动单实例与权限切换

- `AppearanceSettings::preventMultipleInstances` 默认为 `true`，对应 JSON 字段 `prevent_multiple_instances`；只限制普通启动，关闭后新进程不再查找或激活旧主窗口。
- Admin、SYSTEM、UIAccess 等权限切换重启必须携带 `--ksword-privilege-restart`，保证默认开启防多开时仍能启动接管实例。使用 `CreateProcessWithTokenW` / `CreateProcessAsUserW` 时不能把 `lpCommandLine` 留空，应通过 `argumentsWithPrivilegeRestartMarker` 组装命令行并保留当前参数。
- 权限接管不能只绕过单实例检查：旧实例启动新实例成功后必须进入正常关闭流程，新实例应复用 `--ksword-crash-restart-wait-pid <PID>` 的同路径/直接父进程校验并等待旧实例退出，再继续主程序初始化，避免两个实例同时读写设置或争用 R0 服务。透传当前参数时先替换可能遗留的旧 wait PID。

## SOS 救援桌面（2026-10-03）

- `S O S Enter` 通过 `Taskbar/RescueDesktopHost.cpp` 的独立无 Qt 引导入口先请求 UAC，再由管理员监护进程启动私有 Win32 桌面中的高权限 KSword。取消/提权失败/令牌查询失败均结束本次启动；内部提权尝试标记不能跳过真实 `TokenElevation` 校验。常驻 Taskbar 不必整体提升，UAC 等待不占用 SOS Hook 线程。已有实例留在原桌面；救援桌面不是 Winlogon/UAC 安全桌面，既有 HWND 不能跨桌面平移。
- 原桌面名称必须在 UAC 前捕获并传给高权限入口；批准后按名称 `OpenDesktopW`，等原桌面重新活动与 KSword 就绪再切入，避免此时 `OpenInputDesktop` 取到 UAC 安全桌面。每个引导/监护进程把阶段及 Win32 错误写入 exe 同目录 `logs/sos-rescue-<PID>.log`，不记录输入或句柄。2026-10-03 修正后，用户确认窗口正常且管理员状态已启用；日志确认真实令牌提升、客户端就绪、切入、返回和双方正常退出。此验收只覆盖该次正常 UAC/桌面流程，不扩展为锁屏、焦点骚扰或所有输入方式的验收。
- 桌面 DACL 不含允许 ACE，并拒绝 OWNER RIGHTS 的全部访问，避免同账号所有者依靠隐式 `WRITE_DAC` 重新开放桌面。只向客户端继承救援桌面、两个未命名事件和监护进程同步句柄。`HANDLE_LIST` 可继承桌面句柄，但实测不能假设 USER32 自动选中它；`UI/RescueDesktopSession` 必须在 Qt/启动页创建窗口前显式绑定并回读桌面名。
- 独立监护线程的鼠标/键盘低级 Hook 检查注入标志；客户端再检查原生消息来源与非自然 Qt 点击/键盘事件。`IMO_HARDWARE` 可能来自 UIAccess 注入，不能只靠它证明物理设备。虚拟 HID、驱动级输入和进程被篡改超出 R3 鉴真能力。
- 返回按钮和物理 `Ctrl+Alt+Shift+F10` 恢复原桌面。监护进程等待窗口/过滤器就绪后才切入；退出恢复只作用于活动的救援桌面，不覆盖 UAC/锁屏。客户端备用观察线程不依赖 Qt；正常退出不自动停止其他实例正在使用的 R0 服务。救援模式不得自动缩放/提权重启，也不能透传这些内部句柄参数去做权限接管。
- `tools/Invoke-RescueDesktopTests.ps1` 在已有 Taskbar Release 中间目录做真实隐藏桌面回归：按名称访问拒绝、继承/绑定、已有窗口迁移 `ERROR_BUSY`、窗口过程拒绝 SendMessage/PostMessage；测试不切换输入桌面。完整切入、真实鼠标/键盘与中文输入法、锁屏及骚扰条件下的 GUI 验收另行记录，不从编译或该回归推断。

## 通用表格交互

- 2026-10-07：窗口列表由 `WindowDock` 内嵌的 `OtherDock` 实现，默认筛选“所有窗口”，仍叠加外部 PID 与关键字过滤，包含退出保留一轮的无效窗口。自动刷新默认开启、间隔 1000 ms；在信号连接完成后勾选以实际启动定时器。定时采样调用 `refreshWindowListAsync(false)`，不注册或更新全局 `kPro` 任务，手动刷新保留进度通知。
- 窗口列表列宽由 `WindowListInteraction.h::configureWindowListColumnSizing` 收口：关闭该树的全局 `TableColumnAutoFit`，标题列 Stretch，其他列使用 Qt 原生 ResizeToContents，按实际子节点、字体与进程图标定宽，窄视口允许横向滚动。全局适配会接管成 Interactive，并按 48 行抽样/压缩，单纯 setColumnWidth 会被再次覆盖；不要叠加全局和原生两套列宽控制。
- 2026-10-05：窗口列表（`OtherDock`，含进程详情内嵌列表）支持 Ctrl/Shift 多选；批量置顶/取消置顶、显示/隐藏、启用/禁用采用统一目标状态，避免混合选区逐项反转。防截图操作按顶层 HWND 去重，进程操作按 PID 去重；菜单打开前复制窗口快照，不能持有异步枚举缓存的指针跨越 `QMenu::exec` 或反馈弹窗。树刷新使用通用菜单/Ctrl 提交屏障，并按 HWND/PID/TID/进程创建时间恢复选区；屏障期间新快照替换后也必须核验旧树项身份，不能仅凭 HWND 找到新快照就操作。
- 2026-10-05 后续按用户要求将“闪烁窗口”改为“标记位置”：`OtherDock/WindowListInteraction.h` 的 `WindowPositionOverlay` 用一个原生透明窗口覆盖整个虚拟桌面，把所有选中窗口的物理矩形统一换算到该窗口的逻辑绘图坐标；全部淡主题色填充/边框先画，不透明信息卡片和文字最后画，卡片尽量避让。保持显示直到一次左/右键按下即销毁；没有计时闪烁、没有 `FlashWindowEx`、不改变目标显示或前台状态。空白像素必须有 1/255 alpha 以捕获整屏点击，不能设置 `WindowTransparentForInput`；顶层 Tool 必须显式复制 owner 的 palette/font，强调色取 Active Highlight，避免非活动窗口默认灰色调替代主题色。最小化顶层窗口取 `WINDOWPLACEMENT` 还原矩形并转换 workspace/screen 坐标；不实际恢复窗口。`tools/Invoke-WindowListTests.cmd` 在不切换输入桌面的测试桌面验证真实 Qt 多选、身份恢复、混合状态批量操作、单层覆盖多选、重叠填充不盖信息、主题色/透明点击区/前台保持、左/右键按下销毁，并输出绘制预览。Qt `grab()` 图像带 DPR，合成到 DPR=1 的 QA 图时需先清除图像 DPR，避免预览被再次缩小。多 DPI 查询显式使用可恢复的线程 `PER_MONITOR_AWARE_V2` 上下文，所有目标共用标记层 backing-store DPR；Qt DPR/屏幕变化后排队重设原生虚拟桌面范围。`--dpi-matrix` 已在两个物理显示器上通过原生缩放及 Qt 100%/125%/150%/200% 混合组合，还测试负坐标/跨屏的绘图不变式与 DPI-unaware 调用方的坐标虚拟化隔离。此回归不代表主程序 GUI 或更改真实 Windows 显示布局的验收。

- 进程列表顶部的历史利用率图共用 `ProcessDock::m_activitySamples` 中的完整进程快照；绘图与比例计算会遍历这些样本，不能只限制横轴显示而保留大量旧快照。2026-10-04 改为默认最近 50 次，上方下拉框可选不记录、全量、最近 N 次；齿轮设置中的旧“不记录历史”复选框已移除。不记录仅停止追加并保留已有历史；减少 N 或由全量切回最近模式立即裁剪。淘汰后必须按实际移除数量同步时间轴与快照下标，保留选中样本的身份；选中样本被淘汰则回到实时列表并吸附最新。此设置针对进程列表图，独立进程详情窗口仍有自己的图表缓存策略。
- 全局滚轮只由 `UI/SmoothScrollSupport.cpp` 接管；`MainWindow.cpp` 的 `GlobalSliderWheelFilter` 仅管理数值滑块是否允许滚轮调值。不要重新加入另一套平滑滚动，否则关闭设置仍会滚动，或将同一事件交给不同单位的算法。
- `CodeEditorWidget` 的 13 个工具图标须与真实状态同步：撤销/重做看文档历史，剪切/复制看选区，粘贴看剪贴板，换行用 checked 呈现。快捷键限定到 `WidgetWithChildrenShortcut`，包含 SaveAs，避免同窗口多个编辑器冲突；结构页的查找/跳转/换行先切到文本页，复制走结构控件当前选区或完整报告。SVG 必须按 palette 生成普通/悬停/禁用/选中状态，并在 palette 变化时重建，否则蓝色图标遇蓝色 hover 底会消失。新建/打开文件须清除旧的生成报告翻译缓存，全文替换应合成一个 undo edit block。
- 2026-10-08 文本编辑器统一：`CodeEditorWidget` 已退役私有 `EmbeddedCodeTextEdit`，与普通输入、日志、报告共用真实 `UI/CodeTextEdit`（须在主工程登记）。语法模式、行号、括号匹配、空白显示和缩进只改变展示或显式编辑；`setRawText`、打开文件与原始报告后缀不得自动格式化。短表单用 `setCompactMode(true)` 的 2px 视口留白，并可隐藏行号；保留原有高度、追加日志及最大块数。`QTextDocument::setDocumentMargin` 会产生框架格式撤销记录，后续布局切换只改 viewport margins；仅构造完成时清除初始化装饰历史。`editorFont()` 收口等宽字体和中文回退，结构报告地址也使用它；主题重高亮须保留文本、光标、历史和 modified 标记，不通知业务内容变化。工具栏在窄窗口把次要动作移入菜单，结构视图切换参与布局，不盖住正文。`contentChanged` 在下一轮事件循环合并为最新正文通知，不能在 Qt 原生 `setPlainText` 栈内同步让观察者销毁编辑器；仅在调用后检查 QPointer 不足以保护该原生栈。保存用 QSaveFile 并核验流状态和 commit；合法 UTF-8 的 U+FFFD 不代表解码失败，应检查 QStringDecoder::hasError。便携 Qt 编辑器/文件夹具不能等同完整 MSVC Release 或主程序 GUI 验收。
- `QPlainTextEdit` 纵向滚动条的 value/pageStep 是视觉行（包含自动换行），禁止套用像素动画；普通视口沿用 Qt 的一页限幅。结构报告里被外层裁切的固定高度代码块要按真正露出的视觉行数限幅并保留小增量累积。像素视图按 viewport 的 `visibleRegion` 与 pageStep 限幅并保留重叠，连续滚轮的待滚终点也须限制在当前位置的一屏内；反向从当前位置立即反向，缩小视口时停止旧动画。验证必须覆盖 38px 文本视口、47px 实际报告属性树、裁切的 320px 代码块、换行、开关切换、连续/反向/像素滚轮、Ctrl/Shift、局部禁用与嵌套边界传播。
- 周期性后台刷新（例如进程监视采样）不得注册为全局 `kPro` 任务；否则每轮采样都会进入“当前任务”和顶部进度通知。`kPro` 只用于有明确开始/结束、需要用户感知的有限操作，常驻监视状态应留在页面状态标签与诊断日志中。
- 把系统枚举放进工作线程仍不足以保证主界面流畅：结果回到 UI 线程后，`QTableWidgetItem`、`QTreeWidgetItem` 与文件图标解析也可能形成长时间事件循环占用。启动项页把单阶段排序留在工作线程，每个枚举器完成后按固定顺序发布独立结果批次；UI 必须等上一批用零间隔单次 `QTimer`（目标 7ms、最多 24 单元）分时落表完成后再累计下一批，先填当前分类，未完成视图保持禁用，且只有“后端全部结束 + 阶段队列清空”才能结束同一刷新任务。后台枚举进度通过 UI 无关的稳定阶段枚举回调上报，翻译文案必须先在 UI 线程取得，不能从工作线程并发读取 `LanguageManager`。
- FileDock 的大目录使用不可变枚举快照模型，按需提供单元格，排序与选区统计只读缓存；重解析点、磁盘状态及单项属性查询留在后台。详见 [FileDock 大目录响应性](ksword-filedock-latency.md)，不要恢复逐行 UI 查盘或整批 `QStandardItem` 回填。
- 周期采集的缺失证据或查询失败若使用 `Warn`，必须按规范化错误集合做状态变化去重：首次出现或错误集合改变时记录一次，连续相同采样只更新页面状态；错误清除后再复发才允许重新通知。否则默认 Warn 通知阈值会把固定失败放大成通知卡和日志风暴。
- `UI/TableInteractionSupport.cpp` 通过应用级事件过滤器统一接入 `QTableView/QTableWidget`；表头点击排序由 `UI/TableHeaderSortingSupport.*` 负责。
- 通用复制/导出右键菜单只在实际 `ContextMenu` 事件且当前策略为 `Qt::DefaultContextMenu` 时由全局过滤器显示。禁止构造期把 Default 改成 Custom 并提前连接 `customContextMenuRequested`：表格设置列、样式时就可能触发全局配置，随后页面接入的业务菜单会被先弹出的通用菜单遮住（回调遍历已复现）。业务 Custom 菜单继续由页面处理，全局只补复制/导出动作与刷新屏障。
- `VisibleTableWidget` 与 `TableActionTableView` 共用嵌入式 `TableActionBar`，两者默认都提供冻结、暂停、快照和差异比对的完整条；窄小或纯展示表格可用 `SetTableActionBarMode(..., Compact/None)` 降级或禁用。通用表格搜索入口只显示图标按钮，点击后把范围切到当前表格并激活标题栏搜索框，不在表格操作条内重复放置输入框。操作条会同时出现在 Dock 和普通 `QDialog` 中，因此按钮、快照滚动区等几何/字体样式必须由操作条自身用 palette 角色封装；不能继承宿主弹窗的 `ThemedButtonStyle`，否则弹窗中的 padding/粗体会把同一套按钮放大并挤压固定高度操作条。
- 普通 `QTableView/QTableWidget` 的横纵表头由 `TableInteractionSupport` 强制应用同一套 palette 基线，页面不要再用蓝色粗体等局部表头 QSS 制造层级差异；十六进制编辑器等确实需要专业表头语义的控件须在设置局部样式前调用 `SetPreserveCustomTableHeaderStyle(table, true)` 显式声明例外。
- 线程表的“线程亲和性”右键入口（全局枚举、Ksword5.1 进程详情、KswordARKLight 进程详情）统一以 `shared/ThreadAffinityR3.h` 的 CPU Set/Group R3 API 实现。Ksword5.1 使用与进程 CPU 亲和性相同的 `QWidgetAction` 处理器矩阵；Light 保留原生子菜单。操作前必须核验 TID、所属 PID 和线程创建时间，R0-only/hidden 行不可走 R3 入口。
- 未显式开启 Qt 持续排序的 `QTableWidget` 使用“一次点击、一次排序”，不改变 `sortingEnabled`。这样后续 `setRowCount/setItem` 批量或分批填充不会因实时搬行而写错列组。
- 手动排序后遇到增删行、模型重置或单元格更新会撤销排序箭头，不自动重排半成品数据。具有帧序、加载序、采集序等固定行序语义的表格调用 `SetTableHeaderClickSortingEnabled(table, false)`。
- 进程表使用 `QSortFilterProxyModel` 与友好分组专用排序；点击表头时首次为升序、同列再次为降序。父子树状视图点表头后保持“进程友好视图”未勾选，只把内部投影切成没有父子关系的普通扁平枚举并交给代理排序；用户再次切换友好视图复选框时退出该临时扁平模式。搜索结果与历史快照同样走代理原生排序。
- 进程友好视图不得维护独立的列比较 `switch`：数值列必须与普通列表共用 `processNumericSortValue`，非数值列复用 `formatColumnText` 的实际展示值。资源/工作量数值列的单元格染色统一由 `processUsageHighlightValue` 按同列幅值归一化，未采集值不染色，PID/会话 ID/优先级/布尔状态等非占用数值不进入染色。否则“专用 GPU 内存”等后续追加列会出现排序箭头变但行序不变，且单元格没有强度染色的漂移。
- 句柄页等大型 `QTreeWidget` 结果必须先建立轻量摘要节点，展开分支时每批最多创建 300 个明细节点，并用末尾“继续加载”节点追加下一批。摘要始终保持业务配置顺序，表头排序只重排各摘要下已加载的明细；占位节点和“继续加载”节点固定在分支末尾。进程图标等异步资源只为已创建的明细解析，回填必须同时校验树重建代次，并允许同一源记录出现在多个规则分支。
- `UI/DetailLayoutHost` 复用既有 `QSplitter` 时，必须确认表格与详情控件位于两个不同的 splitter 直接子面板；只判断“同属某个 splitter 祖先”会把整个页面面板误认成详情区，折叠后只剩箭头。页面仍在构造、详情面板尚未加入 splitter 时，统一布局接管应延迟到下一轮事件循环重试。
- 行内详情不得向现有 `QTableWidget/QTreeWidget` 插入合成业务行或子节点，否则页面原有的行号到缓存映射、排序和右键逻辑会整体漂移。统一详情布局只在视图层扩展源行高度并覆盖只读文本框，以 `QPersistentModelIndex` 跟踪源项；大型树的 SVG 状态图标更新必须合并频繁的 `rowsInserted`，并按固定批次让出事件循环。
- 行内详情展开后发生排序时，必须在模型的 `layoutAboutToBeChanged` 阶段清理详情：`QPersistentModelIndex` 会在布局完成后跟随数据项，但 `QHeaderView` 行高仍绑定排序前逻辑行；等 `layoutChanged` 后再恢复会留下旧行空白并裁剪新行编辑器。

## Taskbar AppBar 重启

- Taskbar 的设置重启与显示器变化重启统一走 PID 感知的接替路径：旧实例启动携带 `--restart-after-pid <oldPid>` 的同程序，新实例在创建窗口、AppBar 或后台采样线程前用 `OpenProcess(SYNCHRONIZE)` / `WaitForSingleObject` 等待旧实例真正退出。禁止用固定延时近似旧进程退出，否则同步线程清理和 AppBar 注销可能与新实例重叠。

## 踩坑记录

- 2026-10-08 窗口详情置顶/透明度编辑：基础页置顶与 `WS_EX_TOPMOST` 勾选双向同步，回填用 `QSignalBlocker`。Alpha 滑块与数值输入共用 0–255 待应用值，用户修改自动勾选 `WS_EX_LAYERED` 并启用应用按钮；读取/刷新不能触发用户修改链路。应用时只对 Alpha 有改动或新启用分层的目标调用 `SetLayeredWindowAttributes`，保留已有 `LWA_COLORKEY`，不因仅调整置顶改动逐像素透明机制。置顶和 Alpha API 的错误必须纳入应用结果，不能只检查 SetWindowLongPtr。`.codex-build-logs/window-detail-layout/appearance.cpp` 从生产基础页、状态同步及应用逻辑抽取夹具，使用自建隐藏 HWND 实际验证置顶/取消、Alpha 回读、输入同步、颜色键保留与 0/255；错误路径注入 API 失败。33 项检查通过，未操纵外部程序窗口。

- 2026-10-08 窗口详情基础属性布局：`OtherDock.cpp::WindowDetailDialog` 使用 `AdaptivePageScroll` 隔离基础页内容尺寸，主标签栈同时隔离最小尺寸；初始/最低窗口尺寸通过 `applyResponsiveWindowGeometry` 钳制。常规字段双列、坐标/尺寸成对，样式/扩展样式/明细占独立子页的完整宽度。样式复选框页不再嵌套滚动，由基础页统一滚动；只读报告保留自身滚动。长类名/状态值的 QLabel 除 wordWrap 外还需水平 `Ignored`，否则无空格长文本的 minimumSizeHint 仍会撑宽内容。离屏预览按生产基础页布局片段构造，使用真实 CodeEditorWidget、主题基线与字体，验证深浅主题的 1000×820 / 800×640 / 640×480、子页切换、控件尺寸和长文本；不等同于完整主程序 GUI 验收。预览位于 `.codex-build-logs/window-detail-layout/`。

- 2026-10-04 主题恢复：`theme.h::AccentSeedOffset` 记录角色相对默认强调色的 RGB 偏移，角色不能重新固化成独立配色；`UI/ThemeControlGlyphs` 按实际底色生成控件图形，QSS 调用方所属目标必须链接其 `.cpp`。
- QADS provider 注册只影响后续生成的图标，现存标题栏和标签按钮还须由 `UI/DockThemeIcons` 刷新。其按钮带 `ksword_theme_icon_managed` 属性，通用图标扫描必须跳过，避免覆盖 Disabled/Selected/DPR 状态。模型项中的自制单色图标使用 `UI/ThemeAccentIcon` 保留源图并在绘制时读取当前主题；Shell/进程多色图不要接入该包装。
- 可复现主题回归入口为 `tools/Invoke-ThemeRecoveryUiTests.ps1`，使用真实 QADS、项目 `shared/ui/KsPainterChart` 与 Qt offscreen，不启动主程序或访问驱动。项目自有 `QChart/QLineSeries` 不能误当成 QtCharts 同名类型。历史三方集合与功能入口审查见 `docs/合并功能恢复审查.md`；范围语言审计通过不能替代整库语言门禁或生产 GUI 验收。
- 构建带 **i18n 审计钩子**：源码中任何"可提取"字符串字面量（中文日志、英文句子、无路径分隔的头文件名、甚至 `GetProcAddress` 的函数名）都必须在两个语言包的 `source_translations` 有条目，否则构建直接失败。QSS 选择器行要与 `{` 写在同一字符串片段内才会被审计排除。
- 语言包**只能定点编辑**：用脚本 json.load/dump 会重排键序与缩进，产生 5 万行无意义 diff。
- 约 1374 处散落 `setStyleSheet` 分布在 136 个文件（多带 `!important`），未来渐进收敛到全局基线。
- 构建产物被运行中的 exe 占用会导致 `LNK1104`；`vctip.exe` 残留会导致 obj `Permission denied`。

## 仓库规范（详见 AGENTS.md）

- 新增源码必须同步 `.vcxproj` 和 `.vcxproj.filters`。
- 用户可见文本必须同步 `languages/zh-CN.json` 与 `en-US.json`，并通过 `tools/i18n_language_pack.py audit`。

## 2026-10-09 逐页按钮与悬浮滚动条

- 共享按钮颜色由 `UI/FlatButtonTheme` 的明确标记拥有；更新时必须检查本地与祖先 QSS 的所有权，未知数据色不能被旧主题绑定重新覆盖。显式 tone 在 queued 首次刷新之前也必须优先；ThemeBinding 会复制回调，首次应用状态不能只保存为 mutable 闭包 bool。
- 共享实心按钮的 SVG 必须按该按钮实际 normal/hover/focus/pressed/checked/disabled 底色校准，不能沿用通用图标 Active 的强调底假设。默认主题的共享强调按钮也需要上下文；菜单、模型、多色图标和 ADS 自管图标不跟随按钮上下文。
- `UI/FloatingScrollbars` 保留原生条对象和业务信号，用自己的零厚度样式块收回布局位置，仅另画悬浮细线；不能强设 AlwaysOff、改 viewportMargins 或添加另一套滚轮算法。步长/追踪开关没有值变化信号，需要条件刷新。硬件浮窗归还时恢复所有捕获滚动区的倍率，Hex 检查器复制区显式避让。
- 逐页范围、用户审查基线与最终验证记录见 [逐页主题与悬浮滚动条回归](../../docs/逐页主题与悬浮滚动条回归-20261009.md)。组件、硬件 GL 夹具与完整 Release 编译分别报告，不推定生产 GUI 已全部实机验收。

### 同日实机反馈后的修正

- `7b986859` 的全按钮常态实底被真实截图否定：标题/图标工具不应铺底，普通操作需要与页面区别，交互态必须用主题色。`FlatButtonAppearance` 明确区分 Auto/Solid/Flat；Auto 尊重既有 setFlat 和纯图标工具语义，危险标题关闭仅交互态着色。
- Qt 透明父 QSS 会将 Base/Button/Window 同时设为透明黑；不能只强制 alpha=255，也不能靠黑色 lighter 恢复高亮。查询实际 backgroundRole 与透明祖先回退，QSS/SVG/自绘共用状态配方。未知局部/祖先数据样式的所有权保护仍保留，遗漏工具在构造点显式登记。
- 原生 `QLineEditIconButton` 与 `_q_qlineeditclearaction` 的圆底和 X 不能用 SourceIn 合并成一种颜色；按钮及动作两路均跳过并恢复历史原图。
- 专用表格搜索使用 `BindSearchFieldTheme`，有区别的实底、无框、显式不透明 PlaceholderText；保留具体提示、输入、选区、过滤和尺寸，排除扫描值/地址/命令/编辑器查找。树表及外层 Tab 搜索需逐页显式接入，不能假设内层 QTable 元数据会发现它们。
- 透明控件验证必须采样整窗合成；QPushButton hover 需真正 MouseMove 更新私有 hovering，不能只设 WA_UnderMouse。Qt offscreen 要显式加载系统字体，避免把方框当文字。新夹具 200+110 项覆盖真实透明父和原生 clear；仍不替代生产 GUI 逐页验收。

### 同日视觉层次与自动隐藏调整

- 主窗口最终 QSS 曾有 `%1/%5` 缺号但仍逐次 `.arg(...)`，Qt 会替换当前最小编号而非保留缺位，造成背景/文字颜色错配。最终深浅主题块改用命名颜色占位符；修改长样式时必须同时核对替换链，不能只看 token 本身。
- 单行输入、搜索、数值框、组合框及普通实心按钮使用 `ControlInputSurfaceColor` 的中性表面，hover/focus 保持同一层次。内部 Spin/Combo 编辑器透明无框；主窗口末尾不能重新强制透明输入面和描边。表格操作栏与进程控制明确使用 Solid，标题/导航工具仍保留自身语义。
- 表头采用 SurfaceMuted 与单条底部分隔，详情分组采用 SurfaceAlt 与标题线；普通属性名使用可读次级文字而非 PlaceholderText。禁止为单元格添加 `border:0`，否则 Qt QSS 会吞掉模型 BackgroundRole。
- 悬浮滚动条闲置 1100ms 后用 180ms 淡出，滚动或靠近内容边缘唤醒，悬停/拖动期间保持；完全隐藏后鼠标穿透。刷新内容与范围更新不重启闲置计时，原生滚动对象、单位与信号不变。

### 进程控制与多表分区

- `UI/ToolbarMetrics.h` 只对页面显式登记的水平布局统一控件高度，按最高字体高度加留白计算，不能把高度写进全局主题。`CreateTitledTablePanel` 给并列表格增加明确标题；表格本体使用轻圆角外缘，冻结辅助窗格排除重复边界。
- 窄表格操作条将次要动作收进单一“更多”入口，菜单转发原按钮并保持启用/勾选语义；宽度恢复后原控件重新显示。不要通过压窄每个按钮制造一排省略号。
- 进程列表设置中的 GPU 选择写入 `ProcessList/GpuAccelerationEnabled`，优先于旧环境变量。即时切换仅替换 viewport；自动回退携带后端代次，旧失败回调不得覆盖用户的新选择。实际后端状态与保存偏好分开显示，设置入口不清空进程选区。
