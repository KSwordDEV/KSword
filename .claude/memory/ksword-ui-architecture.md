---
name: ksword-ui-architecture
description: KSword 主程序 UI/主题架构要点（theme.h token 体系、全局样式块链路、WindowChrome、透明背景与毛玻璃、Dock 懒加载）
metadata:
  type: project
---

KSword 主程序位于 `Ksword5.1/Ksword5.1`（Qt 6.9.3 Widgets + Qt Advanced Docking System，MSVC vcxproj 构建）。

- 2026-10-25 默认 UI 与首帧收口见 [默认 UI 状态与首帧](ksword-ui-input-first-frame.md)：普通按钮按真实输入来源显示焦点，通用几何在共享入口准备，原生 heightForWidth/sizeHint 参与首次布局；无变化 Show、颜色或焦点不重复归一。必须用首个实际 Paint 对比稳定后几何验证，不能见到 singleShot 就直接前移到 Show/UpdateRequest，Qt 子树遍历与私有视口布局可能因此新增崩溃或抖动。

- 2026-10-01 虚拟化 Dock 按驱动后端适配：AMD 使用“准备 → 全核 SVM 自检 → 常驻”，隐藏 EPT watch/分离视图/执行域/Hook/VMCS 策略/SOAK，保留通用内存、事件、停止和释放。第三方 VM 页为四步嵌套 SVM 流程，Intel 仍五步；实际启用必须读取驱动位，不能从本地开关或 VMware 服务 Running 推断。证据页校验 metrics 版本/长度/行数、代次与 CPU 身份，raw/general/hotspots 各自检查有效位与偶数序列，无效显示暂不可用。
- 离屏 UI 回归入口 `tools/hvm_lab/build-ui-tests.cmd`：链接实际 Dock、Guest、Evidence、KvmControl 与 DriverClient，仅替换 IOCTL 传输、确认和 SCM。测试源码由该独立构建清单登记，不进入主程序 vcxproj。Windows Qt offscreen 需显式加载中文字体，配合 `SetDarkModeEnabled` 与完整 palette（包括 PlaceholderText/AlternateBase/disabled roles）；否则缺字或默认浅色 palette 会制造错误的窄窗口/深色截图。Qt DLL 需部署到测试 exe 目录。

- QADS 已升级到 **5.1.1**（`v5.1.1`，commit `023ce95934fecfd4cf5c672c9c404fabe0f54923`）。版本、许可证与复现步骤见 `third_party/qt_advanced_docking_system/NOTICE.md`；CMake 包装保留 `qtadvanceddocking[d].dll/.lib` 文件名，避免改名 DLL 后 import library 仍指向上游新文件名。`include/ads/ads_version.h` 是构建生成的必要头文件，升级时须与其余头文件、Release/Debug import library 和 DLL 一起更新。
- 2026-10-21 同区 Dock 切页性能补丁：`third_party/qt_advanced_docking_system/patches/0001-keep-inactive-dock-parent.patch` 仅把 `CDockAreaLayout::setCurrentIndex` 的旧页 `setParent(nullptr)` 改为 `hide()`，保留同区父级与渲染上下文；活动布局仍只计当前页。真正移动、移除、浮动、恢复和销毁路径保持原语义。重建必须应用补丁，包装 CMake 检查源文件 SHA256；Release/Debug DLL 与导入库必须成套覆盖，禁止只换 exe。公共头及导出符号保持一致；实际布局恢复、浮动、跨 DPI、GPU/软件、主题和关闭验收由用户手测，不以编译通过认定。
- 修改 ADS 后的分发材料：`third_party/qt_advanced_docking_system/qt-advanced-docking-system-5.1.1-ksword-source.zip` 保存完整库模块/资源/接口和上下游 CMake、原许可、带日期的修改源文件及补丁；主工程 CopyQtAdvancedDockingRuntime 同步复制 LICENSE/NOTICE/source.zip 到 `licenses/third_party/`。打包须保留该目录；源码包随源码/DLL变更重做，不能只放上游链接。版本 SHA 用于测试定位，不能限制用户替换兼容 LGPL DLL。
- ADS 5.x 默认跟随 palette 自动加载内部 QSS。KSword 必须在创建 `CDockManager` 前设置 `DisableStylesheet=true`；仅在外观应用末尾 `setStyleSheet("")` 不够，后续 palette 事件仍会重新加载默认样式。`include/ads/` 属于上游头文件，Git 用 `-text` 保留混合 LF/CRLF，避免升级产生整文件换行 diff。

## UI 主题架构

- 2026-10-30 代码文本表面：`CodeTextSurfaceColors` 的当前行直接使用 Highlight 的 alpha=36 覆盖色，不能将透明 Base 的黑色 RGB 混成实底；语法对比按覆盖后的不透明参考面计算。行号栏浅色模式显式白底，深色模式保留对应表面，普通编辑器与虚拟只读日志共用此入口。透明 Base 的对比计算先回退/合成主题 Surface，不修改正文视口的透明背景。

- 2026-10-12 标准主题默认安装在首个业务窗口之前，普通控件按Polish/Show目标接入现有ThemeBinding，无全树扫描；专业内部、显式紧凑尺寸和真正业务QSS保留。`StandardWidgetTheme`的默认GroupBox按`ksword_parameter_body`祖先使用ParameterSection，独立组使用PrimaryGroup内部标题卡片。仅判断`ksword_parameter_surface`会误把结果区卡片也变成参数分区；两者不能混用。原生QSlider共用6px轨道/18px把手，原生QProgressBar保留对象/信号，由细轨道与独立数值绘制接管，忙动画仅可见时运行并遵守系统开关。Combo的QSS最小高度是内容高度，配方上下padding2px要扣除，不能全局替换Popup item的min-height。基础按钮/Tab/slider规则必须在同一个起止标记块中防止换肤累积。新页必须选择AGENTS布局规范，默认主题不从控件集合推断布局、危险操作或表格操作模式。
- 主工作区的底板/数据面/交替行/工具带/表头由 `UI/MainSurfaceStyle` 从现有种子派生，不改变 QApplication 的全局角色。主窗口与 ADS 浮动窗口明确登记顶层身份，独立属性/设置窗口不沿父链继承；有背景图或穿透模式时继续沿用原透明策略。`TablePresentation` 只改视图容器底面、交替底和结构边界，不声明 item 背景/边框，保留模型热度/风险刷子与自定义表格 opt-out；进程 GPU 视口继续读取真实 Base，图表外壳由 PrimaryContentPanel 显式接入。
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

- 2026-10-26 用户报告启动图预览空白：独立无窗口检查已确认六种组合均生成832×468有效图像（不透明像素约99.67%），不能把空白直接归为资源缺失。预览的minimumSizeHint原为(0,0)，heightForWidth未按最大832宽钳制，居中画布又位于所有启动选项下方；修正为按实际宽度同步非零固定高度、钳制请求宽度并顶部对齐。启动页复用CreateSecondaryColumns把启动行为与启动图选项/预览在宽窗并列、窄窗纵排，仍保留原唯一滚动区。对象桥本次因privilege_mismatch无法读取，Computer Use也未发现现有KSword窗口；未启动主程序或添加事件日志。尺寸修复的实际GUI仍待用户验收，无窗口绘制检查不替代该验收。

- 2026-10-26 追加启动图设置预览：UI/StartupSplashPreview在设置→启动→启动画面显示当前待应用的布局/底图，复用StartupSplashLayout的品牌、版权、状态、底图和进度绘制；不打开真实启动窗、不保存选项。图片解码和GDI+绘制通过单个在途QtConcurrent任务完成，GUI线程先捕获语言/发行元数据，修订号丢弃过期结果，同轮变化合并，隐藏页按需生成，静态缓存只在选项/语言/DPI或显式刷新时重建。缩放保持源图比例，原生画布/轨道/默认进度色共用常量；失败态提供刷新图标入口，应用/取消及下次启动语义不变。参照配色预览和MCP配置预览，保持共享设置表单/工具行与单一外层滚动。实际预览、六组组合及深浅主题/DPI的GUI验收仍由用户完成。

- 2026-10-26 用户要求三种布局和两张底图全部保留：设置→启动→启动画面新增左右布局、上下布局、上下布局简化版及独立的代码/蓝色背景选择，采用既有SecondaryPageLayout/Form/Section/ScrollPage和标准ComboBox主题，保存后下次启动生效。AppearanceSettings以startup_splash_layout(0/1/2)、startup_splash_background(0/1)保存；缺项/非法值默认简化版+代码图，main在首次show前setPresentation，运行期复用保持本次选择。左右版显示左列品牌/版本/构建时间/作者与许可说明；上下版在中央品牌/版本下增加构建时间与作者；简化版保留当前居中稿。三种模式均完整显示同一背景画布、不裁切/不加遮罩、不改变原始比例，底部加载状态与版权共用既有缓存/进度语义。Resource/Splash/StartupLandscape.png保留汇编HEX图，StartupWindows.png恢复此前用户提供的蓝色粒子Windows/剑图，两图都登记工程并复制到Release/Style，发行包流程及验证清单也必须包含两图。以下单一居中稿描述现为三种可选样式之一。实际GUI和保存后重启验证由用户验收，源码/构建通过不等于六组画面均已实机确认。

- 2026-10-25 最新稿改为用户提供的居中品牌布局：Resource/Splash/StartupLandscape.png 原样替换为用户第二张1600×900汇编/HEX底图，第一张仅作版式参考，不能把烘焙标题/版本当底图。窗口仍832逻辑宽、按源图比例得到468高，方角、完整显示、不裁切、不加遮罩。中央图标、粗体KSword和连续版本文本纵向居中，版本阶段保留原大小写（如5.2.1.0 Pre），不再绘制PRE边框、构建时间、作者或数字百分比。加载状态左下、精简版权右下，统一可见中心线；4px全宽底轨/确定与不定进度仍保留。StartupSplashLayout只按完整逻辑画布绘制，取消旧270高页脚变换；drawStatic根据版权实际宽度返回状态可用区域，核心缓存保存该区域，字幕仅文字变化/静态重建/强制绘制时重画，百分比变化只更新进度条。独立原生UI线程、调用者桌面、DPI钳制、PARGB/UpdateLayeredWindow和发行素材拷贝链不变；公共Branding/Legal接口保留兼容，完整发行资料仍由ReleaseMetadata提供且可在主程序查看。以下左侧品牌/信息行方案为历史迭代，不再代表当前启动画面。实际GUI仍由用户验收。

- 2026-10-25 历史左侧品牌稿（已被上方居中方案替代）：初版曾采用900×270横幅；随后用户明确要求严格按背景原始比例、不加颜色遮罩，此前采用896逻辑宽度，用户进一步要求稍微缩小，现采用832逻辑宽度、高度直接由图片宽高推导（当前1920×1080图对应整数832×468），完整显示源图。信息区按270高参考编排整体贴底；过宽图片的信息区整体等比缩小以留在图内。方角、无外框、无左右分栏。左下52px图标与44px粗体KSword标题共用中线（用户最新要求恢复品牌粗体，其余文字仍为常规字重），下方一排依次显示数字版本、PRE/RC后缀、编译日期/时间和双作者；`setVersionText`单独接收发行版本，原`setBrandingText`三参接口保留。用户后续要求底部版本/PRE/构建日期时间/双作者必须为单行，按同一字体的实际内容宽度以10px间距排列；底部元信息与版权共用距底30px的文字基线；上行标题和状态/百分比按实际字形轮廓墨迹边界与图标共用垂直中心，不再只按字体cell ascent/descent推算；文字测量和填充共用GraphicsPath轮廓，状态与百分比同色，PRE边框也以实际字形边界加3px上下内距定位，状态与百分比同字体紧邻10px且组合右对齐。用户后续明确移除网址和装饰性斜杠：日期时间仅保留空格，作者保留发行名单原中点，版本/PRE/构建于/作者仅按10px空隙分组。原生页脚布局集中在Framework/StartupSplashLayout.h/.cpp，不使用Qt控件；StartupSplash只管理线程、DPI、背景与分层缓存。右侧上行展示加载状态及真实百分比，最后一行仅保留精简版权，不再展示网址，完整许可/第三方数据仍保留原调用接口且主程序许可证入口不变。底部进度轨道从x=0铺满当前832px画布，按用户后续要求由2px加粗为4px，默认进度色#4C8DEB、底轨为8%白；不确定阶段隐藏百分比、保留经过时间驱动滑块。运行期外观切换和大句柄列表两个复用入口在show前显式恢复Determinate，show自身保留调用方选择。原背景完整等比显示，不裁切、不拉伸，不叠加暗色/渐变/半透明底板，不改资源文件。状态和百分比作为完整动态组，仅stateRevision变化或强制重画时恢复并绘制；不确定动画帧只恢复底轨，避免字形叠色和重复测量。状态变化不再令整张背景失效，缩放比例变化也参与geometryRevision。仍保留调用者桌面、独立原生线程、窗口DPI/工作区钳制、缓存修订号、消息合并及UpdateLayeredWindow。页面归属为原生独立启动/辅助窗，参照Light LoadingOverlay、Launcher原生窗口和Welcome品牌摘要；QApplication前不能套用Qt参数/详情布局。作者显示名在WelcomeDock唯一贡献者表中去掉WangWei_CM末尾句点，头像资源文件名保持不变。元信息来自唯一ReleaseMetadata，“构建于”/“Built on”短标签、精简版权与首帧完成状态接入中英文。源码和构建核对不替代用户的实际GUI验收。

- 2026-10-24 旧版启动页使用16:9 的 800×450 逻辑画布，完整显示用户提供的背景图，左侧文字底板为深色 RGB(10,20,34)、alpha=190，从窗口左沿铺至 x=320，右侧与图片直边衔接；不绘外框，窗口外轮廓使用方角（不对全画幅做圆角裁剪）；仅底色参与半透明合成，文字与图标保持不透明。主工程 CopyKswordSplashAssets 将 Resource/Splash/StartupLandscape.png 与 Resource/Logo/KswordLogo.png 复制到 exe 同目录的 Style/；画面缺失时 show=false，Logo 缺失则画回退标志。标题采用 KSword + 版本号，并显示本次编译时间与两位作者；Framework/ReleaseMetadata.h 提供轻量访问接口，值仍由 WelcomeDock.cpp 的发行标记和 contributorEntries 维护，编译时间由该翻译单元的 __DATE__/__TIME__ 生成。新增标签和法律说明均接入中英文；正文为浅色，标题/元数据下移并保留中间留白。用户最新要求恢复两倍字号：正文/元数据/链接14px、状态12px；顶部标题按可用宽度在26px至22px间适配并与40px图标居中对齐。编译时间与作者继续位于顶部标题下方（时间 y=70、作者 y=92，按14px字号保留行距）；仅法律段落按真实文字高度向下锚定到链接上方，链接及加载区固定在底部，中间剩余空间留白。底图按用户提供的 PNG 原样保存。法律文案、网址和实时状态由 GDI+ 绘制，不烘焙进图。窗口按 GetDpiForWindow 和监视器工作区 90% 宽、88% 高共同限制大小，直接从源图采样到目标物理像素。独立线程、调用方桌面、确定/不定进度、缓存和 UpdateLayeredWindow 机制仍沿用。发行包从旧包搭建时还需覆盖这两项 Style 素材，步骤见仓库根 AGENTS.md。下方 2026-10-11 段落记录旧版 640 宽图片方案，不再描述当前默认资源。用户自行验收实际 GUI。

- 2026-10-11 原生启动页以独立 Win32 UI 线程播放伸缩不定进度条，仍使用 `Framework/StartupSplash` 的 `kSplash` 接口。背景仅从 exe 同目录的 `Style/KswordHome_2.png` 读取，缺失时 `show=false`，暂不回退嵌入资源。图片按 640 逻辑像素宽度等比绘制，200% 为 1280 物理像素（用户已确认采用标准倍率），不能先生成 640px 中间位图再放大；底部文本和进度条按图片实际高度定位；用户确认右移24逻辑像素后，又要求状态字更小且整体远离分割线；最终状态字号上限12逻辑像素（先23→18→16，用户要求恢复旧字体后回到原12）；与替换前相同的Microsoft YaHei UI常规体，移除新增的AntiAliasGridFit文字渲染设置，使用GDI+默认渲染，状态布局顶点为画布高度减60、文本框高24，较原高度减83下移23，更靠近进度条，右侧状态/进度区域起点260、宽354，较首次右移结果再右移16，保留26逻辑像素右边距；底轨、不定滑块和百分比填充均按半条高绘制圆角（8高/4半径，短填充按宽度收小半径）。线程在创建窗口前绑定调用方 `GetThreadDesktop` 并设置自身 Per-Monitor DPI awareness，以保留 SOS 私有桌面和 QApplication 创建前的真实 DPI；窗口创建后通过 `GetDpiForWindow` 取缩放，不能依赖 DPI-unaware 进程的 `GetDpiForMonitor`。`hide` 停止动画定时器；启动状态及编译日期在主线程先完成双语解析；左下角三行统一14逻辑像素常规体，无邮箱下划线，统一20逻辑像素行高绘制；颜色随后改为区域背景自适应。`.codex-build-logs/startup-splash/splash_fixture.cpp` 在不切换输入桌面的私有桌面调用生产实现，42 项检查通过，覆盖 exe 相对路径、非 16:9/正方形图、96/144/192 DPI、阻塞调用方时动画刷新、重复显隐及图片缺失；192 DPI 为夹具注入，不等于实机修改缩放验收。

- 同次完整 Release/x64 构建最终通过（`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`、主程序产物更新），日志 `.codex-build-logs/ksword-build-check-20261011-171913.raw.log`，双语审计28665条通过。初次构建在既有 GPU 表格/平滑滚动的裸 `QOpenGLWidget` 包含上报 C1083；两处改用 `QtOpenGLWidgets/QOpenGLWidget` 明确模块路径后通过，未修改 Qt SDK 或滚动行为。未启动生产主程序加载驱动，完整 GUI 由用户运行验收。

- 后续状态字号18、起点260及圆角进度条的完整 Release 构建通过（`EXIT_CODE=0`，产物更新），日志 `.codex-build-logs/ksword-build-check-20261011-172707.raw.log`；同一私有桌面夹具42项及100%/200%生产绘制预览通过。

- 同日用户要求前期保持百分比填充，仅在“即将完成...”切换滑动样式。`MainWindow::StartupProgressCallback` 透传稳定阶段键，`main::updateStartupSplash` 识别 `queue_kernel_dock_check`、`main_window_ready`、`show_main_window`、`wait_first_frame` 四个收尾阶段；不比较中文/英文显示文本。`setProgressMode` 同模式更新不重启动画。当前夹具44项通过，额外输出50%填充预览 `Style/preview-percent.png`；完整 Release 日志 `.codex-build-logs/ksword-build-check-20261011-183837.raw.log`。

- 状态字号16、文字下移23后的完整 Release 构建通过（`EXIT_CODE=0`，产物更新），日志 `.codex-build-logs/ksword-build-check-20261011-202246.raw.log`；夹具44项和百分比/滑动预览通过。

- 旧版状态字体核对为Microsoft YaHei UI常规体、12逻辑像素、默认GDI+文字渲染；按用户要求恢复这些设置，并将左下角三行统一14逻辑像素常规白字、去邮箱下划线、20逻辑像素行高。44项夹具与预览通过，包含这两项的完整 Release 构建通过（`EXIT_CODE=0`，产物更新），日志 `.codex-build-logs/ksword-build-check-20261011-203007.raw.log`。

- PNG透明与自适应文字：普通Win32窗口配不透明深色`Clear`会把透明PNG像素铺成深色，不等于桌面透出。现改为`WS_EX_LAYERED`、清空为透明、在DIB像素上包装`PixelFormat32bppPARGB`并以`Gdiplus::Graphics(Bitmap*)`绘制，最后`UpdateLayeredWindow(ULW_ALPHA/AC_SRC_ALPHA)`提交；不能仅改Clear alpha而继续用HDC/BitBlt当窗口透明合成。首次显示前先提交像素，动画消息直接提交新帧。状态区和左下角三行分别在缩放后的背景像素上取5×3网格样本，且在绘制文字前取样；只要采到alpha<255就用白字，否则RGB加权平均亮度>=150用黑字，深色用白字。进度底轨随状态字黑/白选择，蓝色填充不变。197项私有桌面夹具通过，含100%/200%浅/深/左右不同底色、透明/半透明、背景alpha=0/128/255保留、RGB预乘约束及每次真实UpdateLayeredWindow成功；不代表启动生产主程序或切换真实桌面验收。

- 透明与文字取色改动的完整Release/x64构建通过（`EXIT_CODE=0`、产物更新、双语与主题审计通过），日志 `.codex-build-logs/ksword-build-check-20261011-204031.raw.log`。

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

- Issue #220 的复制菜单能力统一由 `UI/TableContextMenu` 管理。业务 QAction 创建后用 `SetTableContextActionRole` 声明 CopyCell/CopyRows/ExportRows；检查递归包含已创建子菜单，不依赖翻译标题。共享层只补缺失能力，复用菜单时重绑实际来源与右键单元格，表头菜单不追加正文复制项。覆盖和验证记录见 [表格复制菜单核对](../../docs/Issue-220-表格复制菜单核对.md)。

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
- 悬浮细线不能声明WA_NoSystemBackground或不透明Paint：透明/淡出绘制必须恢复下面的视口像素。滚动、缩放、范围/步长改变、悬停宽度变化和隐藏前，只对覆盖条对应的视口窄带update；不能在Paint中反向update视口形成循环，也不无条件刷新整表。外观用透明局部QScrollBar规则隔离全局轨道底色，原生条、坐标、数据与动画逻辑保留。进程详情内嵌内存区域表的滚动条残影截图触发此修复，用户自行实测。

### 进程控制与多表分区

- `UI/ToolbarMetrics.h` 只对页面显式登记的水平布局统一控件高度，按最高字体高度加留白计算，不能把高度写进全局主题。`CreateTitledTablePanel` 给并列表格增加明确标题；表格本体使用轻圆角外缘，冻结辅助窗格排除重复边界。
- 窄表格操作条将次要动作收进单一“更多”入口，菜单转发原按钮并保持启用/勾选语义；宽度恢复后原控件重新显示。不要通过压窄每个按钮制造一排省略号。
- 进程列表设置中的 GPU 选择写入 `ProcessList/GpuAccelerationEnabled`，优先于旧环境变量。即时切换仅替换 viewport；自动回退携带后端代次，旧失败回调不得覆盖用户的新选择。实际后端状态与保存偏好分开显示，设置入口不清空进程选区。

### 进程活动图表连续移动

- `ProcessActivityChartWidget` 使用独立 16ms 绘制节拍与单调时间轴，实时窗口跨度由采样间隔和留存数量决定；不再用每次采样后的 260ms 缓动。图表显示缓冲一个采样周期以连续揭示已知数据，列表采样不延迟；暂停固定时间轴，隐藏时停止绘制节拍。
- 归一化数值与单调 Hermite 切线按样本/指标/选区变化缓存，逐帧只绘制可见窗口；控制点限制在相邻采样值之间，避免平滑制造额外峰值。刚淘汰的左缘采样保留到移出画布，悬停点、提示和点击共用真实时间映射，鼠标离开即隐藏点。
- 用户进一步明确内容分组应使用完整线框：`QGroupBox` 恢复 1px 中性边界和 6px 圆角，按钮保持纯色；主窗口、全局基线及详情局部覆盖一起更新，不能只恢复其中一处。进程控制行统一 8px 间距，移除额外分组 spacer，伸缩空白放在所有控件之后。

### 二级窗口导航分类

- `UI/DetailNavigationGroups.h` 以明确类型和原 Tab 索引登记分组，只重排导航按钮，保留惰性初始化、点击路由、禁用状态和原始页签序号。统一详情壳、进程与文件自建侧栏共用排列和外观；附加批量说明不随重排删除，隐藏页签不留下空组标题。
- 详情导航使用专门的 `FlatButtonAppearance::Navigation` 状态配方，选中底色混入少量侧栏表面；QSS 与动态图标查询共用实际底色。导航与按钮的水平策略使用 Ignored，左右留白统一，长标题不能撑宽 QScrollArea 内容并裁切高亮右边缘。

### 滚动节拍与图表悬停

- 普通像素滚动使用 `SmoothScrollSupport.cpp` 的 `ScrollBarAnimator`：精确定时器按所属屏幕刷新率选择间隔，单调时钟计算缓动位置，结束后停止；保留一屏距离限制、反向立即响应、原生滚动条及冻结窗格同步。外部定位或拖动取消旧动画，不能让旧终点拉回新的位置。GPU 表格仍在主线程处理模型和委托，启用 OpenGL 不等于保证满刷新率。
- 被动表单内容（标签、分组、普通容器、只读单行字段）的滚轮可沿 viewport 归属接入平滑滚动；编辑器、组合框、自定义滚轮控件和禁用属性保留自身处理。Resize 只按原视口身份取消动画，不能因为任意子控件布局变化取消外层滚动。
- 进程图表鼠标进入绘图区时显示全部可见真实采样点，离开后全部隐藏；提示与焦点线仍定位最近采样。圆点与折线使用同一时间窗口，缓冲区内尚未显示的采样不提前出现。

- GPU 视口滚动不能调用普通 QTableView 的 `scrollContentsBy` 位图复制路径：仅按 Qt 原有单位同步 QHeaderView 偏移、更新编辑器几何并请求完整 FBO 帧，光栅路径才保留基类调用。GL 帧通过原生清屏恢复颜色写掩码、裁剪和模板状态，表格只创建一个 QPainter；普通 paintEvent 不得绕过 paintGL 直接向未绑定 FBO 绘制。出现黑条、文字残影或彩色噪点时，先检查这两个路径，不能靠提高更新频率或额外补一次 update 掩盖。

- GPU 平滑滚动改由 `QOpenGLWidget::frameSwapped` 的 queued 回调推进下一帧，避免定时器与阻塞交换的相位错开；普通视口仍按屏幕频率计时。GPU 定时器只作交换回调停滞的看门狗，旧回调用动画代次取消；整数像素未变化的缓动尾段仍安排下一帧，停止后断开链路，不持续空转。GPU 设置状态以活跃表格交换回调计算 FPS，并显示对应 CPU 绘制均值；不计静止间隔或其它控件独立合成，读数不等同于硬件扫描帧率或 GPU 执行耗时。

### 页面控件与表格操作条的明确选择

- `UI/PageControlStyle.h` 提供页面明确调用的搜索和普通 Tab 外观，不扫描所有字段。搜索色面使用既有 ThemeBinding，几何 marker 随局部主题重建恢复；普通 Tab 绑定自身栏，避免替换整个页面已有主题回调。自绘 HexViewSegmented 必须同步实际绘制配方。
- `NormalizeToolbarRow(row, spacing)` 只统一直接单行控件，不固定内容视图和多行说明；普通间距8，A/B/C显式0。图标方形判断依据明确图标工具或既有固定方形，不能因文字按钮尚未翻译而误锁成方块。后续局部 QSS 重建时补回登记几何。
- `FlowLayout::addExpandingWidget` 用于工具行最后一个目录组合或状态说明：宽窗占满剩余行宽，放不下最小宽度时整体换行，换行标签按实际宽度计算高度；隐藏的扩展项不占位。C 伪代码页的高级 Ghidra 目录和动作后状态共用此入口，不能把长状态重新放到独立大行或让输入框挤掉动作文字。
- 表格在构建入口逐用途登记 Full/Compact/None，禁止改全局默认后当作完成。现场清单保留快照对比，静态导出结果精简为复制导出，属性/目标选择/已有业务工作流隐藏重复操作条。逐页记录见 `docs/UI控件逐页整理-20261010.md`。

### 配置与工具二级窗口

- `UI/SecondaryPageLayout` 仅由明确的配置、编辑和工具窗口调用；属性/详情继续使用原框架。`ksword_secondary_window` 让全局弹窗兜底退让，避免重新铺上 GroupBox 卡片与强色 Tab。主题刷新只替换自身样式块，表单、分区、标签栏和固定底栏分别登记。
- 设置窗口不再外包整体滚动，五个分类各自滚动，Tab 与应用/取消保持可见。外观双栏按宽度和字号切换，布局变化不重建控件、不应用配置。双栏初始按并列测量，避免宽窗先按纵排最小高度被撑高。
- 设计取舍是保持有用信息密度并降低视觉负担，允许改布局和增加 Tab；需要同时比较的参数与结果保留同屏，独立任务才按分类组织。具体范围见 `docs/设置与二级工具页面布局-20261010.md`。

- 普通轻底色 Tab 的 `Selected/On` 图标不能使用实心强调按钮的底色假设。`MakeThemeTabAccentIcon` 按窗口、内容与轻选中底校准，管理器仅对明确登记的普通 Tab 使用此策略，按原图及强调色缓存，避免换图标触发无休止重绘。
- 分区留白应明显大于区内行距：设置外观列及功能页分区间距为24，区内仍为8。中性 Surface/Alt/Muted 的层次从主题种子统一派生，输入底面保留最低可辨认差异；不能靠局部新增强边框代替背景层次。
- 普通下拉 Popup 在显示栈结束后执行130ms透明度淡入，关闭时停止并恢复不透明；尊重 Windows 客户区动画开关，不修改菜单几何、焦点、选区或业务自定义弹层。

### 主页面组件

- `UI/PrimaryPageStyle` 只接收页面明确登记的 Combo、Group、Toolbar、SectionTitle，不自动扫描全局控件。组合框完整状态绑定在本体以覆盖 Dock 透明祖先；工具带只保留轻底面和下分界，功能参数组保留完整细线框。保留现有业务控件和模型，工具区不能吞掉图表或结果区域高度。
- `BindWidgetTheme` 在同一对象再次登记会替换旧回调；已有业务主题绑定需在构造处明确协调。旧局部透明表头与强色选中规则应在原来源收口，不能只叠加通用样式后假定已生效。主页面取舍见 `docs/主页面组件样式整理-20261010.md`。

- 内核导航中的 `selectedTabIcon` 也必须使用中性表面的动态图标，不能在 currentChanged 后重新写入 `OnAccentColor` 位图。父级标签使用连续次级底面和下划线，显式 `StyleChildPageTabs` 使用轻选中块、8px左缩进与6px顶部间隔；原页序和惰性初始化不变。
- 下拉动画不应与主题所有权绑定：带自定义QSS的组合框、QMenu及子菜单也可淡入，原配色继续由业务拥有。弹层关闭恢复原始透明度，用代次取消快速重开前的排队帧，不修改菜单几何或选择逻辑。

- `UI/TabHierarchyTransition` 在父级激活时仅滑动子栏快照，方向取父级Tab实际矩形的左右关系（含RTL），不搬动内容页或模型。父级在惰性构建前登记，子栏显示/跨Dock迁移时接入当前宿主；180ms动画遵循系统动画开关，连续切换、隐藏、字号/主题/尺寸变化取消旧帧。

- 悬停图标底色查询必须排除 `ToolbarMetrics` 的两段明确几何规则与 `PrimaryPageStyle` 记录的完整非按钮样式块，不能将这些规则当作未知业务配色而拒绝按钮上下文。只移除查询副本中的精确拥有片段，真正的额外局部/祖先规则继续保留保护；Navigation 外观也参与状态查询。
- `ApplyFlatButtonTheme` 的首次异步应用与 pending 过滤都必须比较剔除已拥有几何片段后的配色 QSS。登记后再 `NormalizeToolbarRow` 会追加尺寸规则，若比较整份样式，会误以为业务换色而退出，造成多页按钮无底色、前景退回旧颜色。首次之外的数据色接管保护保持不变；独立纯图标动作需由页面明确传 Solid，Auto 仍允许标题栏和内嵌工具使用透明语义。
- `GlobalTabIconContrastFilter` 对 `ksword_page_tabs_style` / `ksword_secondary_tabs` 登记的中性页签让出图标所有权；若登记较晚，只恢复过滤器本人写入的旧图标，先清缓存再还原。实心选中底用的 `OnAccentColor` 位图不能覆盖普通父子 Tab 的动态图标。

### 网络端口诊断

- `NetworkDock/PortDiagnosticsPage` 是独立网络工具 Tab，使用 PrimaryPageStyle、统一按钮几何和 AsyncOperation；占用表与绑定表隐藏无用途的冻结/快照条。只查询本地同号端口，覆盖 TCP/UDP 与 IPv4/IPv6；短暂 SO_EXCLUSIVEADDRUSE 绑定不监听、不收发，IPv6 使用 V6ONLY，探测后关闭 socket。
- 解除明确区分结束整个占用进程与断开单条 IPv4 活动 TCP；后者不承诺关闭监听。进程快照在端口枚举前建立创建时间基线，动作前复核身份与占用，终止使用现有 IfCreationTimeMatches 工具并排除系统/自身/关键或未验证目标。API 成功只表示提交动作，重新枚举和绑定结果单独呈现；部分失败不能报为空闲。用户要求只编译，自行运行验收。

### 设置阅读层级与共享分段控件

- 设置排版以行的视觉中心为准：`StyleSettingsForm` 仅接管明确登记的设置表单，标签与右侧控件共用字体测量得到的单行最小高度，组内行距 4px、主要分区间距 20px。正文和普通动作使用常规字重，分区标题与当前导航适度加重；数据字体保留字号单位，避免像素字号被重置为点字号后独自变大。多行说明保留换行，字号和局部布局变化后合并同步尺寸。
- 禁止把复合行未经宽度约束的 `sizeHint().height()` 写成标签最小高度；可换行说明的估算会把滑块行撑大。复合行纵向使用 Preferred，说明保留真实宽度建议，由布局按实际宽度算换行。`StyleStandaloneInput` 只接入页面明确确认的独立输入面（当前进程/线程工具行），圆角与同排按钮统一为 5px；不批量替换连体组、内层编辑器、Popup 或 Tab。
- `UI/SettingsPresentation` 仅提高设置正文的阅读字号下限，保留用户字体家族；导航、分区标题、色值数据与说明有独立层级。设置输入使用较暗中性底与细边界，字体选择限制为适当宽度；滑块读数与说明同排并跟随真实 Enabled 状态，减少孤立长轨道。配置保存与预览/应用语义不变。
- `UI/SegmentedControl` 对明确登记的原 QAbstractButton/QTabBar/自绘编辑器提供共享圆角底面与 160ms 选中面动画；保留原对象及点击、键盘、提示、禁用和列自定义空选态，不扫描或替换全部按钮。QSignalBlocker 改状态也由 Paint 身份兜底同步；旧只靠 QSS 的预设明确调用 SetSegmentedButtonSelected，不能从颜色猜语义。
- 分段整组底色使用 `ControlInputSurfaceColor`，与页面维持可见对比；不能再用 Window/SurfaceAlt 的中间混色，它会在内存工作台等页面与底板重合。按钮组、搜索范围 QTabBar、自绘 HexViewSegmented 三种适配器共用，文字/图标继续按实际选中和未选底面校准。
- 动画中在选中面内外裁剪绘制两种对比度前景，避免过渡时字/图标与底色相同；原按钮 setParent 后需恢复隐式可见，显式业务隐藏继续保留。节拍按所在屏幕频率，遵循系统动画开关；隐藏与布局变化停止旧几何。编辑器查找/跳转/类别分段通过只读快照适配，原命中矩形和提示不变。
- `UI/ThemedSlider` 保留 QSlider 的输入与信号，用原 QStyleOption 的真实 handle 位置绘制连续填充、浅轨道和圆把手，包含 RTL、反向及禁用态；设置、窗口透明度和 DWM 两处透明度均明确接入。


## 参数表单页框架（2026-10-11）

- `UI/ParameterWorkspace` 将参数独立滚动、固定执行区与结果区分开；窄窗口改上下分栏。使用 `StyleParameterSection` 明确选择标题分隔线，用 `FoldParameterSection` 折叠非 checkable 的低频参数分组。只有显式登记的参数区补齐输入底色、下拉和数值框主题，不全局重排或扫描业务页面。
- 用户在两页试用后已批准逐页推广；当前 26 个同类参数操作页接入工作区，另有 5 处专业页面只统一明确参数区。纯列表、仪表盘、专业编辑器与 HVM 生命周期页保留原结构。具体范围和接入限制见 `docs/参数表单框架接入.md`；直接编译交用户验收，不启动审计。
- 参数框架参考图使用无描边的色块，禁止复用带 1px 外框的 `StylePrimaryContentPanel`。只保留低对比度分隔线；原生 QToolButton 的 arrowType 会产生亮色大三角，折叠标题改为自绘小号空心折角。参数分组使用自然高度，避免 QGridLayout 将额外高度均分为巨大行距。编辑区应同时绑定 QSS 和 palette，保证 CodeTextEdit 行号、当前行与语法色采样到真实底色；只读结果与面板同底，编辑输入单独铺底。
- 参数面板和结果面板采用 16px 等边内边距、至少 10pt/14px 字号。横向适配同时依赖页面拆多列、组合框最小内容宽度、QFormLayout 换行和长选项文字换行，不能仅隐藏水平条。原 QCheckBox/QRadioButton 保留对象/文本/可访问性/信号，只在明确参数区自绘换行标签与测量高度；标签点击仍交给原生按钮处理。折叠标题自绘省略文本后必须同步缩小 minimumSizeHint，否则原生长标题仍会撑宽参数栏。
- 参数/日志并非固定窄左宽右。页面可用 `useWideParameterLayout(percent)` 明确分配宽屏比例，`ArrangeParameterColumns` 显式指定两列分区，窄屏恢复原阅读顺序；保留用户拖动比例。请求构造与创建进程等日志较少页面默认展开常用参数。普通状态/专业页使用 `StyleWorkspacePage`、无描边 `StylePrimaryContentPanel(false)`、`StyleWorkspaceTextViews` 单独更新，不因不适合参数框架就保留旧透明控件。无描边面板在独立窗口也必须有实底；边框 QSS 的替换参数保持连续，不能把带未替换 %N 的字符串再作为参数注入。

## 导航连接与固定表面层级（2026-10-11）

- 普通页签由 `UI/PageControlStyle.cpp` 共用完整状态样式；最新外框通过 `StylePageTabsContentFrame` 明确接入，只在最外层绘圆角。旧“首工具条补角”和自动清零父布局顶部的路径已删除。保留原 TabBar/StackedWidget、页序与命中，子栏缩进仅作用于 tab-bar，不再右移内容；ADS 外壳自身间隔为0。
- 主窗口底板、内容、工具带、表头、输入直接从 `MainWindowSurfaceColors` 固定求值，不能从每层父 palette 再抬高明度。大面板/工具底统一 8px，独立按钮/输入 5px；同一组件内部拼接处允许 0px（参数执行区、冻结辅助窗格和数值框内部编辑器）。背景图/穿透模式仍走既有保护。
- `StyleStandaloneInput` 为未绑定的明确独立输入补完整颜色绑定，已有业务绑定只对齐圆角；单行字段用 `BindLineEditTheme`，搜索沿用同一配色但保留原过滤行为。主页面按钮、搜索、数值框和下拉框共用固定输入层，正常/悬停/焦点文字单独校准对比，输入背景校准保留中性色相。线程 A/B 不得在状态更新时重写旧 FlatButton QSS；纯工具动作需明确实底，内部清除/导航等例外按用途选择。
- `PageTabMotion` 与 `DockTabSelectionAnimation` 仅移动导航选中底面和下划线，180ms、经过时间插值、按实际屏幕刷新率使用 PreciseTimer，遵循系统客户端动画开关。原业务页不截图或位移，原文字/图标/输入与子栏滑动保持；ADS 工厂基类绘制后调用动画绘制入口，覆盖旧静态标记，避免双重高亮。
- QSS border-radius 不裁剪表头或视口子控件，不能只声明圆角就认为实际可见。`RoundedViewSurface` 对普通表/树的四个 8px 圆外极角补真实祖先背景，鼠标穿透、无 setMask/整父截图；专业自绘 opt-out 与冻结辅助窗格保持原外壳。角片背景只走微型 palette/PE_Widget，防止大视图重绘或父面板圆外再次被填实。
- 主窗口 3px 外沿 overlay 是缩放命中层，非置顶时不绘制蓝色外框/角标，置顶保留提示。不能直接删除 overlay 或取消原 WM_NCHITTEST 缩放；置顶成功和外观刷新都需同步其视觉状态。
- 表格内部 `ComparisonTableView` 复用源表操作条并声明 `InheritedTableActionBarProperty`，全局登记不再安装第二条；比对期间无用途的冻结/新增快照隐藏，返回实时、快照清理仍由源条负责。差异过滤改变行数后须更新复制/导出可用性；零行禁用属于有效状态，不能靠开启无效按钮掩盖重复宿主。
- 顶部进程图提交快照前冻结原可见窗口的右端与跨度，禁止按所选时间加半个跨度居中。图上任一点（含最新点）均进入快照状态，后台刷新不得仅因索引在最右侧而重新吸附。查看时只暂停顶部历史队列追加/自动裁剪，系统枚举和独立详情性能记录继续；播放、清空等明确动作恢复实时，保留数量的用户调整仍执行原裁剪。
- 凹角反馈中的全高1px竖线曾被误当作导航覆盖层残留：实际截图 `#3d5670` 对应 ADS `depthOverlayStyle` 外框，后置 MainSurfaceStyle 只换底色不会取消边框。原规则与最终宿主规则均需 border:0。历史上向首工具条内角填 rail 色的方案已被用户否定并删除，不得恢复。
- 用户明确圆角必须落在最外层框架，不能覆盖内部控件已有圆角。`StylePageTabsContentFrame` 登记6px pane留白，进程/线程页外围layout归0；页坐标先向外扩展这6px还原外框，再以外半径14px（内部8px+留白6px）绘四角，使内外圆心重合、弧线间隔也为6px。pane留白沿用page底色，角片只填最外弧线之外的rail色；无描边，不新增全高覆盖层。未登记页不批量改变。
- 用户随后明确要求全软件UI复查和推广。本轮扩展到51个导航/结果/页根入口，见 `docs/UI标准覆盖复查-20261011.md`。框架只接管明确页根/自适应滚动内容的外围边距，内部卡片16px保留；纯嵌套Tab只计最内层，惰性代理用 `ksword_page_frame_host` 明确标记。竖向Tab同样支持；服务/欢迎通过 `StyleWorkspaceContentFrame` 登记页根。背景穿透模式不绘实色角片，专业编辑器内部及原生插件窗口不强行接入。
- 最新适用条件是“方角外框包着圆角内容”，有留白不等于有外框。`StylePageTabsContentFrame` 默认只整理留白；直接承接方形工作区的11个主导航用 `StyleSquarePageTabsFrame` 明确方框身份，资格仅沿完整单子Tab/已标记惰性壳传递，遇工具条、splitter、并列内容或已有圆角面板停止。Cross-View、注册表右侧、WinAPI等结果Tab不画外角。内存/启动项/窗口/Other/HVM/Scanner/Minidump有页头或页尾，改在整页根登记Workspace；Workspace被嵌入已有页面框架或根margin被接管后也不再画内层外圆。保留14/8/6同心几何和首帧生命周期保护。
- 上方工具/状态区后接结果Tab，使用 `StyleJoinedResultTabs` 与直接父子导航区分：工具带与Tab共用toolbar色、接缝侧底圆角为0，局部分组零spacing；这组与下方“表格操作条+表格”之间保留6px，pane只在朝向Tab的一侧留间隔，左右不重复内缩以保持同宽。仅普通QWidget页壳的外围layout归0；专业自定义控件（含无Q_OBJECT类型）与明确卡片内部留白保留，使用C++动态类型区分而不能只看Qt元对象。重绑工具带只在拼接角色改变时触发，首显主题与Tab动画沿用原入口。逐页覆盖见 `docs/UI结果Tab连体布局-20261012.md`。


## 详情窗口与弹窗更新（2026-10-11）

- 用户要求详情窗口采用全宽对象摘要、左侧分组导航、右侧无描边卡片；允许系统决定窗口外沿方圆角。`DetailDialogChrome` 使用 Window/Surface 两层，导航选中为中性底加主题色文字，侧栏由 `DetailPresentation` 按窗口宽度调整。
- `DetailPresentation` 提供内部标题卡片和字段双列，复用 `ArrangeParameterColumns`，窄窗回到单列、QFormLayout 允许长行换行。进程概览去掉 660px 最小宽度和页外重复滚动区；详情只保留分组卡片，字段数据仍来自同一 StructuredFieldView 文档。
- `StyleStandaloneInput` 使用共享 ToolbarMetrics 高度公式，独立输入字号变化时更新高度；必须排除 QComboBox/QAbstractSpinBox 内部的 QLineEdit，不能重复撑高组合控件。
- `ThemedMessageBox` 淘汰悬浮自绘标题栏与强制无边框，不改变按钮角色和关闭返回值。主题操作合并到事件队列；Qt 在样式应用时会重建 QMessageBox 网格，因此最低宽度 spacer 必须在套样式、处理按钮之后加到当前网格，而不是只设窗口 minimumWidth 或提前加到旧网格。
- 原生窗口 `WindowChrome` 使用 DWMWCP_DEFAULT；方圆角、最大化和贴靠由系统决定。主窗口及其它原本无边框的专用窗口不由本模块强改窗口类型。
- 用户在本轮明确要求停止自动测试，由用户实测。停止后只完成 Release 编译及源码收尾；既有离屏结果不等同于真实窗口、DWM 外沿或业务验收。

- **UI 验证方式（用户明确要求）**：创建伪窗口/独立 UI 夹具只适用于开发机无法正常编译主程序的情况。能够编译时必须直接使用主程序查看和验证，不再构建离屏替代窗口。若用户要求自行测试，则停止自动测试，仅继续已授权的编译。


## 共享详情框架统一安装（2026-10-11）

- 用户纠正实现方式：详情必须使用共享框架，不逐窗复制/维护摘要、导航或卡片布局。统一入口 `InstallDetailWindowFramework` 只登记控制器；`PrepareDetailWindowForShow` 在构造结束后的首个Show、首帧绘制前完成窗口摘要/原Tab导航/文档卡片/自适应字段及滚动区安装。各模块只提供实际身份、字段和动作配置，业务模型不由框架复制。
- `GlobalDialogTheme` 为普通业务QDialog安装结构，已登记二级工具同样装结构，但根QSS只由Secondary拥有，详情框架不得追加根配色块。Qt文件/颜色/字体/单项输入选择器和带 `ksword_detail_keep_layout` 的共享设置页保留已有结构。ProcessDetailWindow为QWidget，明确从ConfigureDetailDialogRoot接入。
- `DetailFieldProjection` 直接复用原StructuredFieldView搜索/复制/导出控件，原source仍持规范文档。详情固定分组卡片，`setDocumentOnly()` 删除旧树与格式下拉，停止隐藏树重建、列测量和其排队回调。字段分组匹配时保留整组搜索语义；数值刷新原位更新，只有结构变化重建卡片。
- 卡片实底由DetailCard绘制，正文间隔和滚动Canvas走Window层，避免QSS对子面板再次铺矩形实底导致错误色块/黑色角缝。共享框架根QSS必须让GlobalDialogTheme保持唯一所有权，否则双方增删末尾块会产生StyleChange循环。
- 只有投影自身有滚动区才关闭多余外滚动壳；自然高卡片scrollBody=false必须保留唯一外层纵向滚动。QSplitter替换使用占位并保留非零用户比例，隐藏页首次布局前全零sizes不应恢复为显式折叠。
- 文件自建侧栏Tab必须标记ksword_detail_tabs避免重复导航；启动项卡片须来自同一完整文档，不能按section拆source而改变复制全部/导出范围。覆盖清单见 `docs/详情共享框架接入-20261011.md`。不运行自动测试/伪窗口，原Release编译交用户实测。

- 结构观察只接入布局/惰性页面宿主的ChildAdded，合并最小子树；主题或字体变化只刷新根样式，不监听全部叶控件的Show/FontChange并扫描整窗。卡片投影与专业编辑器内部不参与通用结构遍历。
- `MemoryWorkbenchView`、`WorkbenchDiagnosticsHost`、`WorkbenchTextView` 使用 `ksword_detail_keep_layout` 保留整个专业子树：业务代码仍依赖Stack内原fields身份及tree指针，不能把它们替换成详情卡片。详情窗口外壳仍照常接入；父控制器也不能进入有独立控制器的子窗口。
- 根QSS必须单一拥有：GlobalDialogTheme拥有普通QDialog；进程详情以 `ksword_detail_theme_owner` 声明业务拥有Chrome。框架不得追加又被业务changeEvent删除的相同块，StyleChange也不能触发文档重建。根样式/调色板及卡片标签只有实际变化才写入，禁止逐按钮手工重复polish。
- 字号下限统一安装处补齐14px/10pt，保留更大字号及字体家族。`StyleSecondaryTabs` 与普通Tab同用PageTabMotion，静态下划线透明让动画唯一绘制，不另设持续全页刷新计时器。
- 文档投影以documentRevision/语言/主题/搜索键合并通知；隐藏Tab只留dirty，Show首帧同步使用最新快照。规范字段相同的document-only快照不增代次、不发通知，纯搜索/主题不重新flatten；真实数值变化原位更新，值样式与行可见状态只在变化时写入。
- 普通详情卡片仍以完整 StructuredFieldView 文档负责搜索、复制和导出；大分区在后台用冻结翻译快照准备纯值索引，界面只挂载视口字段，保留共享卡片、双列、说明及原 QLabel 选区。清空 QFormLayout 重排行时必须用 takeRow 移除行槽，不能仅 takeAt 留下空行；旧可视控件按预算退休，大值快照最终释放放在后台。复杂报告与专业布局不因这条普通卡片优化而改入口。
- `StructuredFieldView` 本身直接作为Tab/Stack页时不能替换页对象：清掉旧布局后在source内部安装 `CreateDetailFieldProjection(source, source)`，保持原页索引/标题/currentWidget及业务指针。该模式不重挂或隐藏source，重复接入查其直接投影子节点，避免父子循环和重复宿主。

## UI 适配与性能补漏（2026-10-11）

- 文件详情同样以 `ksword_detail_theme_owner` 保留完整业务根主题；GlobalDialogTheme为其安装共享结构但让出颜色。`ApplyDetailDialogChrome` 与框架维护同一个完整拥有块，不重复追加或覆盖根主题。侧导航比较源图标身份，不能拿主题加工后的显示图标key误判源变化。
- ThemeBinding登记使用稳定节点并在destroyed时原位删除，pending哈希只作去重，真正队列仍是QPointer且保持登记顺序。drain先分离队列/清membership，保留嵌套新请求；销毁时清pending地址，避免同址新对象误判。禁止恢复每次新增绑定的全表清理或增长队列逐项contains。
- 主页面外框/圆角控制器区分几何与底色dirty；宿主、几何、样式不变时不重装事件过滤器/重画，真实主题、重挂、DPR仍更新。单面板outline变化只刷新自己的绑定，不能广播全软件换肤。
- 参数编辑器只在真实样式/palette变化时全文重高亮，重复finish不累加padding。浮动详情隐藏后不替换全文，显示入口先从规范源回填；相同文本不重建镜像文档。
- 进程历史、CPU核心历史和磁盘ETW/速率采样不因隐藏停止；隐藏的图表向量转换、动画、线程排序和活动表UI提交延后Show。CPU主题/语言重绘不能重复追加历史；身份清理必须真正清空图形。逐核表复用item，只更新真实变化的文本。
- BCD、磁盘编辑外部参数、权限访问评估/身份启动、HWID和电源字段已补共享输入接入；专业HEX内部保留。实际范围与源码触发链见 `docs/UI适配与性能补漏-20261011.md`，不得把编译通过当逐页视觉/性能验收。

## 全导航逐页补漏（2026-10-11）

- 从 MainWindow 17 个主入口和 3 个辅助 Dock 展开实际 Tab、惰性子页及动态工厂；逐页矩阵见 `docs/UI逐页复查-20261011.md` 及其三份分区清单。不得只统计调用样式 helper 的父入口，或把不可达旧页面、动态实例数当成已运行页数。
- ParameterWorkspace 容器 QSS 也会阻断 FlatButtonFilter 的祖先样式判定。记录 `ksword_parameter_surface_style_block` 完整精确块，仅从颜色所有权判断中排除该块和已登记几何；额外业务规则仍保留。固定底栏的未绑定普通直接动作明确 Solid，已有 Danger/Accent/专用状态 binding 不接管。
- 安装 Segmented 后禁止业务刷新再写旧 FlatButtonStyle；只更新共享选择态。Scanner/Minidump 的动态宽表应在创建工厂一次安装，覆盖全部生成页并保留右键自定义空选态。
- 页内详情同样必须淘汰隐藏旧树：Handle Object Header/Type 直接提交唯一 FieldDocument，不再先 clear/new QTreeWidgetItem 再生成同字段文档。持续事件表模型兼任归档/保留职责，不能用隐藏提前 return 改变采集语义。
- WMI/ETW/进程定向折叠主题在工厂分别绑定段、内容、标题，禁止 StyleChange 再 findChildren 扫全页。ProgressDock 同一进度更新不重写相同卡片 QSS。LogDock 隐藏周期刷新不更新 revision，Show 经过原菜单屏障同步最新管理器历史；全量导出不受显示条数限制。

## 主题与首开延迟（2026-10-11）

- DetailWindowFramework 只收当前 Stack 页；真正换宿主后才重收结构。Qt Stack 先 Show 后 currentChanged，详情旧字段树的 Show 回填必须合并排队，让同步投影先消费；未投影源继续回填。专业 keep_layout 仍保留同步 tree() 模型行为。
- ThemeBinding 的 pending membership 保留到真实取出，不能先清整批再应用父样式，否则尚待处理子项被 PaletteChange 再次排队。FIFO 分片约6ms让出事件循环，销毁清地址、同址新对象和真正语言/应用主题广播继续保留；单个 setStyleSheet 仍不能被中断。
- 组合框主题不能为所有 QWidget Show 递归 findChild，也不能换肤时调用所有 Combo.view() 提前创建隐藏 Popup。只按真正 Popup 的 Qt 所有权父链定位，已打开列表换肤，下次展开接当前主题。
- TablePresentation 自身QSS有 applying 门禁，已初始化隐藏表延后Show；主题委托已按可见项实时取语义色时，不在 Palette 广播扫全部模型回写画刷。冻结辅助窗格复用源委托。
- RelativeLuminance 8位通道线性化预算256值，保持原公式/阈值；MainSurfaceColors按主题代次缓存但preview旁路；两个按钮selector同外观复用五态配方。不是预加载全部业务窗口，也不把源码优化当作实机耗时测量。说明见 `docs/UI主题与弹窗延迟修复-20261011.md`。
- R0“需要启用”是QMessageBox，不进入详情卡片框架。提示前SCM只读检查须后台化并在查询前合并通知；回UI不仅探析构lifetime，还要核验实际退出/服务启停代次，不能让旧STOPPED结果覆盖新启停或退出时再弹启用框。消息框图标复用现成QIcon或已映射原生资源缓存，禁止每次polish走EXE Shell图标查询。
- SecondaryPageLayout也记录完整中性拥有块；FlatButtonTheme只精确排除该块，不忽略业务附加QSS。明确二级底栏的无配色普通动作补Solid，残留managed标记不能抢回已被业务重写的颜色；显式Flat/风险色和专用binding保留。控件检查工具动作使用真实SVG/16px/实底，不能用Unicode箭头和暂停符号代替可辨图标。用户要求全部修改收齐后统一编译，不每个截图/按钮单独编译。

### 按钮闪掉与单次换肤硬开销补漏

- Dock 构造后禁止下发全后代 `QWidget` 透明规则；只给明确 Dock 根节点属性声明透明，并记录完整 `ksword_dock_root_surface_style_block` 供按钮颜色所有权精确排除。
- 图标替代文字不改变普通 QPushButton 的动作语义；`ThemedButtonStyle` 明确 Solid，Auto 对 QPushButton 只按 `isFlat()` 决定透明。旧 Auto 标记不能撤销页面已经声明的 Solid/Flat/Navigation，显式 API 仍能重新声明。
- SVG 同一按钮的原图/强调色包装须复用。逐帧状态配方/对比度/着色分别按真实输入缓存，保留预览旁路、业务覆盖、完整色精度、mode/state/DPR 和原生禁用输入。增量补色也应按共享预算合并排队，不能每个 Polish 单独开计时回调。
- 定时权限刷新只在实际样式变化时写 QSS。CustomTitleBar 状态更新不得反复 Shell 查询 EXE、重建原图和重登记相同按钮绑定；真实主题代次和资源变化仍更新。普通浮动纯色使用 solid QBrush，不分配整窗纹理。
- 主题事件不重建进程/线程业务表；动态数据角色和风险委托在绘制时读取当前色。普通审计表中性色交给 palette/alternating，保留业务风险原色。
- 全应用旧色补偿主入口使用分片队列；新主题取消旧调度时必须保留未完成的 A→B→C 基线链，分别检查局部 QSS 和显式 palette 的业务接管。只读快照及单个 Qt 样式调用不承诺时间硬上限。详情见 `docs/UI按钮消失与换肤卡顿修复-20261011.md`，未经用户实测不报告耗时提升。

### 页面首帧与后续分片必须分开

- 首次 ThemeBinding 若只排队，页面会先绘旧外观再换色。完整挂载/详情根 Show 后用 `PrepareWidgetThemeBindingsForShow` 消费当前显示分支的既有请求，QStackedWidget只取当前页，隐藏页/独立子窗口/Popup不提前准备。首次动态叶控件Paint前补颜色，已应用过的隐藏控件重显消费dirty；构造期Polish/初次Show不调用未知绑定。
- 同步首显和分片共用dirty标记；旧FIFO保留membership去重但已消费项不重复执行。新主题/重登记/嵌套请求继续生效，不把正常全应用换肤恢复为同步整树操作。
- 惰性子页不能仅依赖父Dock首次准备，currentChanged时还可能只是占位壳。统一工厂用 `ScopedWidgetThemePreparation` 在构造/服务接线/挂载全部完成后准备当前可见分支，覆盖内核、杂项、硬件/监控惰性页、内存工作台/调试和进程详情；进程内嵌Dock在延迟构造阶段退出时也共用守卫，必须等业务范围/内部页选择/show全部结束再准备最终分支。不可见构造不提前执行未知绑定，也不逐分支复制主题实现。
- 表格Show前统一frame/grid/header；页框Show/currentChanged前准备留白与pane，Paint只改已有overlay几何。侧栏首显同步定宽，角片先确定几何再显示；已消费几何回调按代次失效。14/8/6无描边等宽标准不变。
- SVG首次颜色与首次实际图标标记分离，不能因首次Paint无图标而丢掉迟到图标的准备机会。内核初始化禁止全应用processEvents，只repaint明确等待反馈；延迟Dock可见回调复核实际可见性。
- 不禁绘全树或预加载全部业务页。共享回调及overlay的Show/Hide/raise可关闭宿主或换页，QPointer探活之外还须复核当前页身份。说明见 `docs/UI首帧闪动修复-20261011.md`，用户自行测试，不把源码或编译结果当实机闪动验收。

- ParameterWorkspace参数滚动区不能只给外部面板绑定实底：QScrollArea视口和setWidget后的表单会填充继承的Window色，透明分区于是露出页根深色黑块。scroll/viewport/form三层须通过原共享surface绑定保持同一卡片色，内部canvas半径0，外部卡片8；沿用完整中性拥有块，避免新增规则被按钮所有权误判为业务覆盖。系统变速页截图反馈触发此修复，不改分区或滚动结构。
- 2026-10-12 CKS截图再次暴露嵌套Tab正文误用StyleWorkspacePage而铺成页根黑底；参数内普通页壳改用StyleParameterCanvas，pane按参数祖先沿用content色。普通共享Tab的PageTabFocusStyle只在键盘输入后绘原生焦点primitive，鼠标点击隐藏焦点矩形，保留原栏焦点策略与输入语义。

## 透明模式圆角回归（2026-10-12）

- 透明不改变外方框资格：PageTabEnvelope / WorkspaceFrame 继续使用原 hasSquare 判断与14/8/6几何，但不能因 main_surface_hierarchy=false 隐藏外角。历史“穿透模式不绘外角”的说明不再适用。用户最终确认深色导航连接处无误。
- RoundedViewSurface 的微型背景必须从透明色开始，不能用继承的不透明 Window 色垫底；圆外用 Source 替换，包括真实 alpha。仅改混合模式仍会把浅色极角补成不透明 Window 方块。主根自绘背景是特例：只借 ksMainRootContainer 对应8px区域的背景绘制，不带 DrawChildren，保留图片、直透着色和alpha=1命中底，不做整父截图。
- 真实主程序两张表四角及主Tab外角通过浅/深×透明/普通四组合，服务页检查整页入口，另检查热换肤和缩放重显。验收与后端/DPI边界见 `docs/透明模式圆角回归修复-20261012.md`；像素采样要重定位 HWND/frame 偏移，外角参照未选中导航底面，不误采选中标签色。

## 主窗口圆角外沿（2026-10-12）

- 用户随后明确要求主窗口边缘圆角，主窗口通过WindowChrome的显式InstallRoundedFramelessWindowFrame接入8px顶层区域；普通原生窗口继续按系统策略。逐像素透明宿主不能依靠DWM提示保证圆角，区域仅作用于窗口外形，不用于表格或专业内部。最大化/全屏清除mask，保留自绘标题栏、原缩放命中和句柄生命周期。
- 新外沿Release构建通过；用户按物理Escape停止Computer Use，未完成新外沿实机验证，不可沿用表格圆角验收结论。范围、Qt跨DPI源码依据及待验收项见 `docs/主窗口圆角外沿-20261012.md`。

## 子级导航连续性（2026-10-12）

- 普通父子Tab使用同一固定内容层轨道，子级以紧凑全圆角选中面与短强调标记表达层级，不再使用页面深底配父级贴边形状。QSS内缩和PageTabMotion绘制须一致，状态前景按三个真实底面校准；动画只更新原栏，不添加业务页计时器。
- 纯单子Tab或明确惰性壳转交导航时，父级默认6px接缝不得再叠加；工具行/splitter/并列内容仍终止转交。StyleJoinedResultTabs即使有child标记也保留连体结果形状及下方6px间隔，不能套成独立子导航圆角面。
- 标签起点对齐共享6px留白，不能把整页内容跟着缩进。检查对象命名空间、内核I/O管理、驱动对象结果Tab三种结构，六处明确入口及待用户实测项见 `docs/子级Tab导航衔接-20261012.md`；不把共享代码或编译结果当全软件视觉合规。

## 参数折叠标题与只读资料（2026-10-12）

- `FoldParameterSection` 将组标题交给折叠按钮时，必须通过 `LanguageManager::moveTextBinding` 转移显式词条并清除源控件的运行时 text/title 翻译缓存，再清空组标题；只复制构造期文字会导致热换语言后原标题恢复、按钮仍用旧语言。镜像提示可复用同一词条，原组不再拥有标题显示。
- CKS 第三子页的历史样本与实时系统证据分开，继续嵌入既有 `ParameterWorkspace`，不新增页根背景。只读资料需要导出时显式启用 `CodeEditorWidget::setReadOnlyExportEnabled`；导出完整文档，不改变原路径、编码或修改状态。该能力不开放打开、普通保存或替换操作。

## PEB 与详情投影边界（Issue 222，2026-10-13）

- 惰性构造的新子控件也可能 `isHidden()`；替换宿主只继承 `isHidden() && WA_WState_ExplicitShowHide` 所证明的业务隐藏，否则字段投影消失、剩余操作行被布局摊出大空白。
- `DetailLayoutRegistry::hostFor(fields)` 已登记的字段保留原对象和 splitter 直接子身份，只在源内部安装投影；不能重挂源后让宿主缓存继续控制隐藏的数据对象。
- `ParameterWorkspace` 自身声明 `ksword_parameter_workspace` 布局边界，详情框架与字段树延迟判定识别它。不能复用 `ksword_detail_keep_layout`，后者还会让 `StandardWidgetTheme` 将普通参数控件当专业内部跳过。
- 参数框架内的显式投影沿用其正文底色；祖先查询止于当前窗口，主题缓存记录实际画布、表面和文字色。PEB 只读说明默认显示并共用参数滚动，动作固定、摘要独立滚动。
- 最终 Release/x64 与双语审计通过，真实 PEB 深浅主题、窄窗、最大化、搜索及重入已验证；线程四种方案、R0 采样、真实 DPI/背景矩阵未验收。范围与证据见 [Issue 222 修复记录](../../docs/Issue-222-PEB布局修复.md)。

## 进程活动图全量留存（2026-10-14）

- 进程 → 进程列表 → 顶部活动图保留专用绘制与时间轴，外壳沿用 `StylePrimaryContentPanel`、`NormalizeToolbarRow` 和原表格结构。历史缓存不限量不代表图表全量可见：`ProcessActivityChartWidget` 的全量模式必须按实际首尾时间扩展 X 轴跨度，不能读取隐藏的“最近次数”输入；右端至少包含最新已留存样本，短历史保留非零跨度。
- 最近模式继续使用固定时间跨度滚动。快照冻结窗口的优先级高于留存模式，点击后不能因新增采样或切模式重排原 X 位置。回归入口 `python tools/process_activity_timeline_tests.py` 抽取生产窗口、投影和命中方法，覆盖 33 项检查；它不是实际 GUI 验收，当前 GUI 桥因客户端管理员权限不足而未能连接。

## 复杂报告投影（Issue 223，2026-10-13）

- 用户否定了逐字段卡片方案的信息密度与查找成本，明确低效主要在操作路径。结构报告现在默认进入“进程结构 / _EPROCESS”，用范围和类型选择器直达，不把诊断与九个目录串成长报告滚动。
- 显式 `ksword_complex_report_source` 仍经 `DetailFieldProjection` 接入共享 `ComplexReportView`。规范源保持 document-only；`FieldNode::ReportRole` 由生产者标记目录、类型、记录和元信息，不从文字猜用途。
- 正文使用原生三列树表和 `TablePresentation::Compact`，操作条 None。字段、偏移、类型/值一行对齐；Offset/Type 已投影到列后不重复占属性行，展开只呈现位域、别名等额外信息。删除原整卡行背景、嵌套属性卡和逐行复制按钮实现。
- 用途固定的报告列调用 `SetTableColumnAutoFitEnabled(false)` 并由该共享报告模块管理名称/偏移/剩余值宽度；否则全局内容加权会在隐藏偏移列后把诊断名称压成省略号。目录和诊断分别记住手动名称列宽，主题更新不能再次按内容覆盖。
- Ctrl+C 复制当前单元格，Ctrl+Shift+C/上下文菜单复制完整字段；更多菜单复制当前范围，原工具动作仍复制/导出完整报告。原文模式懒建共享只读 `CodeEditorWidget`，直接序列化同一规范快照，包含隐藏元信息，不受搜索/折叠截断。
- 范围必须进入 `ComplexReportFilter` 的接受条件，不能只设 tree root：所选根被过滤为无效索引时，视图会意外退回全部根。多词搜索匹配完整规范上下文和显示短标题；清空恢复状态，搜索中换范围清掉旧范围的位置。
- 原文、字段表与数值增量通知共用规范身份；三列分别提供真实可访问文本。首份数据才选择默认范围，刷新不重新选择类型。可选 toolbarPrefix 合并既有业务刷新与文档工具行，不给普通详情强加额外布局。
- 验证使用真实主程序与生产目录；已观察正常/799px窄窗约23行字段、深浅主题、单元格复制、类型记忆和原文切换。驱动不可用时只验错误态和静态目录；不能推定实际采样、所有旧详情或DPI/背景矩阵均已通过。证据见 [Issue 223 记录](../../docs/Issue-223-复杂报告子页.md)。

## 性能采集与 Dock 现场（2026-10-18）

- `QApplication` 全局过滤器在 `QWidget::event()` 前收到 Paint/LayoutRequest；入口至 queued 回调只代表可重叠的墙钟/队列延迟，不是该事件的 CPU 耗时或实际呈现。指标已更名 `perf_scroll_paint_queue_latency`/`perf_scroll_layout_queue_latency`，合并状态仅存采集器，不写控件动态属性。范围仍仅为既有表格/滚动壳，不能宣称全控件事件测量。
- Dock 现场直接缓存既有 `currentChanged`/`focusedDockWidgetChanged` 标记给出的身份；注册初态单独记录。不要每条记录或焦点变化时重新 `widgetAt`/`findChildren` 查 UI 树。主窗口只显式 `InitializePerfTrace`，旧现场查询回调已删除。
- 心跳明确保存整个单调 ns 区间并标为未归因；末尾 Dock 标记不能解释此前整段工作。已有 `PerfScope` 记录配对 scope_id 起止；UUID/UTC/Qt/构建戳和 writer 读取的 EXE SHA256 区分会话。没有测得 input-to-ready/present、notify self CPU 或实际 FPS。
- trace 默认 `KSWORD_PERF_TRACE_ENABLED=0`；MainWindow 诊断连接/动态属性/扫描块也由宏隔离。开启后仅值记录进入 2048 项有界队列，JSON/EXE hash/QFile 全由纯值 writer 处理，溢出记录丢弃数。退出关闭 admission 后异步 drain，不在 GUI 等 I/O；进程终止或 OS 写入阻塞仍可丢尾，不能声称持久化退出屏障。
- `perf_scroll_driver_sync_work` 用 ns 记录包括最后一帧的同步驱动；动画墙钟另有 completed/canceled/replaced。正常帧等待不叫阻塞，驱动次数和滚动值变化不叫呈现帧数。此轮仅静态检查，累计构建与实际诊断/GUI仍待用户验收。

## 移动滚动画布的不透明契约（2026-10-20）

- `QScrollArea` 移动正文若仅靠QSS实底，Qt仍可能把正文视为nonopaque，普通小步滚动会使整个可见正文失效。不能把所有Widget全局标成`WA_OpaquePaintEvent`；只有专用画布在`paintEvent`对完整矩形实填、实际alpha为255时才声明该属性。
- `ParameterWorkspace`的form是明确0圆角实底，使用同一content颜色源填充。`AdaptivePageScroll`普通主宿主使用固定`MainSurface.canvas`；共享详情Chrome已明确给`QScrollArea`及viewport设置`WindowColor`，详情画布只认当前顶层的`ksword_detail_shell`角色。未知独立窗口不沿祖先跨窗猜底色，主宿主壁纸/透明分支保留原合成。
- 外部卡片/页根的圆角与内部移动正文是不同职责。正文全矩形实填须与其既定底面同色；未来新增不同背景角色时应先扩展共享surface策略，不能继续沿用默认canvas。主题绑定放在滚动壳上，避免业务给content绑定`StyleWorkspacePage`时替换该契约；只监听明确canvas的Show/Parent/Style/Palette生命周期。
- 当前这组补丁只做源码、HostX64编译与抽取生产policy的纯逻辑验证；真实主程序Paint region、DPI/背景/外角和首帧仍由用户手测。paint面积变化不能直接宣称FPS或耗时倍数。
## 异步事务与退出资源（2026-10-20）

- Shell 关联备份保留 native value 类型/原始 bytes、root/view/path；旧 v1 只能合并已明确记录的键值，不能从缺失数据推断删除。其安全备份/当前 witness 也须显式保留 mergeOnly 语义，不能只让文件 decode 通过，却在真实 prepare→export→apply 链中丢失该语义。
- 原生键路径和值名可能含孤立 UTF-16 surrogate；JSON 可读文本不能作为唯一身份。v2 同时保存原始 UTF-16 base64，读取严格校验 bytes 与可读投影的一致性，并兼容旧 text-only 文件。
- 临时注册表测量先取得独立 cleanup lease，再做完整 worker 备份；Stop/退出先置原子停止，不等串行锁。恢复后再次核 Stop 再决定是否启动下一次 probe。关闭只请求首次 cleanup，不能把失败恢复变为隐式重试；仅显式 Retry 再尝试。新建空键使用非递归删除，避免空态见证后外部新建子键被递归删除。

- Checked STOP失败仍拥有session/consumer/thread时，使用`RetainedCleanupJob`强持独立值owner和旧epoch的lease；false/throw不释放也不自动循环。退出提示的用户Retry显式调用`RetryRetainedCleanupJobs`，只重试已请求且失败的job一次；Cancel仅重开新admission，不撤销旧cleanup。只有后台确认STOP/close/join完成并销毁最后值闭包才归还lease。`create(null)`也可能已接纳旧epoch收尾，调用侧必须废弃该service/lifecycle，不能Reopen复用，否则旧STOP会撞新Start。

- 有已接受reservation的持久资源先同步closing拒绝新reserve，再用`RetainedCleanupJob::ReadyToAttempt`短值检查count0；false只延后，不标failed、不占池线程。最后reservation在资源gate外调用`notifyReadyToAttempt()`，只交接初始调度机会；迟到就绪不能把刚失败的initial当成显式Retry。`requestCleanup()`保留外部显式失败重试语义。谓词与reserve共gate且closing后count只能减少，避免lost trigger和单池线程互等。reservation强持job至通知完成，resource owner仅weak job且不持reservation；全部实际cleanup成功后，attempt/stop/readiness值闭包在后台销毁才归还lease。

- `AsyncOperation` CAS赢家将cleanup闭包移到局部，调用后在归还事务lease前销毁闭包，连同只由capture强持的最后值owner。不能只调用cleanup后把闭包留在request/丢投递残余Job里，否则pending先归零、原生资源后析构；成功、失败、throw、drop、close保持同一次收尾。

- `AsyncOperationToken::deliver`的投递构造异常走同一`DeliveryDropped`物理收尾，不得把已完成副作用误报worker失败后再deliver。取消functor析构与异常fallback复用shared.active已有的受锁身份移除结果，防止双重状态通知；GUI恢复只尽力投递一次，恢复自身失败不递归。通用dispatcher的值取消回调异常不得穿出Qt functor析构。

- `AsyncOperation::submit` 保留一个实际 worker 与一个最新 pending；尾部 `Cleanup={}, int workerPriority=0` 直接传 Qt 线程池排队优先级，不是 OS 线程优先级，也不抢占已运行调用。
- 写操作/导出等已接受副作用使用独立 `submitTransaction` 控制器：worker 仅接值请求、不接取消令牌，busy 返回0与 `BusyRejected`；接受后先入线程池再通知状态，close/cancel/新查询不能吞事务。apply/failure 仍只留 UI 控制器，关页后不回投；值 cleanup 必须等 worker 完成且只执行一次。构造/排队异常属于“没有未完 worker”，必须先标记完成，再允许 failure 回调同步 close/delete。
- `AsyncCleanupRegistry` 的 lease 只持值，不保活 QObject。事务由共享控制器自动登记；常驻会话在线程启动前登记弱 session 的 stop 回调，只置停止标志/唤醒，不在 UI join。STOP、归档/句柄等实际资源收尾后才归还；同一 session 不能通过 lease 回调强持自身形成环。
- 主窗口先通过原内存退出守卫，再冻结新 lease、请求会话停止并用计时器等已接受收尾；最后才查询/停止 R0 服务。超时保持可见，提供重试/取消，不能用固定毫秒直接 quit 杀掉事务。取消退出不撤销已经接受的 STOP；等待期间新建的 MemoryDock 在就绪边界重新进入原退出确认。
- 正常关闭、UIAccess/Admin 与功能级提权重启共用弱 owner 的协调退出入口，派生析构第一步撤销登记。运行期先冻结启动器值意图，等全部 cleanup/SCM 就绪才启动替代进程，避免子进程35s先超时而父级32s后Retry到40s才退出；Retry保留意图，用户Cancel和首轮内存确认拒绝清除意图，晚到MemoryDock重新确认保留意图。仅替换既有 wait-PID 键和值、保留其它 argv；父侧验证实际存活的 direct-child/same-exe 后才退出，失败恢复旧窗口及真实R0状态。子侧在首业务窗口/采样前验证父关系、映像及创建时间；超时或验证失败停止启动，不能靠 privilege marker 绕过等待。原崩溃报告 bool API 保持旧语义，正常接管使用独立状态矩阵。
- 验证边界：真实 HostX64 翻译单元、QtCore 慢 STOP/事务与生产状态函数的假 WinAPI 矩阵可证明调度/值资源约束；不替代用户的实际 GUI、UAC/AppInfo、R0 STOP、语言/主题与 DPI 验收。

- 2026-10-20 启动接管竞态：父进程已退出时，只要另一个句柄仍保活其进程对象，`OpenProcess` 仍能成功，而 `QueryFullProcessImageNameW` 可失败并返回 31。正常接管应先保留 direct-parent 与创建时间校验，区分“映像查询失败”及“已知映像不匹配”；仅查询失败后零超时 wait 确认退出才返回 AlreadyExited。活父不可查询、错映像、较新/无法核验创建时间和 wait 失败仍拒绝。独立 Console 父子夹具复现旧源码误拒绝；这不等同真实主程序/UAC验收。

- 同次收缩：首次 Qt 业务窗口创建前的自动 UAC/缩放重启只保留 privilege marker 与业务 argv，并剥离继承的 runtime wait PID；这些简单启动不接入运行期清理/严格父进程接管。主入口只在显式 wait-PID 请求存在时执行严格失败门禁。运行期重启仍等待已接受清理和旧进程退出。

- 主窗口全部内存许可、accepted cleanup及SCM完成后的唯一终点必须在UI线程调用`QCoreApplication::exit(0)`。Qt6.9.3的`quit()`发送Quit事件，QApplication会再次closeAllWindows；此时`m_shutdownFinalizing=true`的主窗口Close守卫会ignore，从而否决Quit。timer已停后所有后续Close仍被否决，形成永久关不掉。不能靠删资源等待或强制计时退出修复；前置守卫/Retry/Cancel保持。

## 窗口快照清单与一次性排序（2026-10-20）

- `QTableWidget::setSortingEnabled(false)` 仅关闭持续排序，旧共享入口仍可安装一次性表头点击；迁移为普通 `QTableView`/只读源模型时不能据此删除该交互。当前 `ConfigureResultTableInteractions` 的旧分支仍向 `QTableWidget` 转型，普通 view 须在 `bindModel` 后显式使用共享 `InstallTableHeaderClickSorting(QTableView*)`。视图排序可用既有 `QSortFilterProxyModel`；字符串表沿旧 DisplayRole/case/locale 规则，dynamic sorting 关闭。
- 消息规范 FIFO 与用户的一次性显示排序是不同职责。新采样依旧撤销旧手动排序；选区范围、当前单元格和滚动锚点必须在 proxy/source 间映射后按 sequence 身份恢复，不能把 view 行号交给源模型。右键复制读选中 view index 的 sibling，完整导出继续读取唯一规范归档。
- 本批按用户要求仅静态落地，最后统一构建与实际 GUI 排序/采集/复制组合由 root 和用户分别验收，不以候选或历史 TU 声称已实机通过。

## 不可变权限表格与后台翻译入口（2026-10-20）

- `ImmutableValueTable` 刷新后会保留相同规范身份，此时不重复触发 `currentRowChanged`。账户的所属组、所选组的成员等关联详情须同时接入 `sourceReady`，否则主表刷新先清空详情后，恢复原选中身份不会再次查询，详情会一直留空。普通搜索/排序不改变内容代次，不借此重做业务查询。
- 账户、组和成员以 SID 作为稳定身份，显示名称或启用标志变化不应改变选择键；同一 SID 的多条直接权限以权限名和 SID 组合区分。SID 不可用时才使用名称回退。
- 权限 worker 在 GUI 调度边界捕获 `SourceTextSnapshot`，用值作用域查询精确 `contextText`，不能从后台转回 `LanguageManager` 单例。跨翻译单元的权限快照采集也显式传入该值；嵌套作用域退出时恢复外层上下文。只有没有上下文的兼容入口保留规范源文。
- 本轮仅有既有纯值/假原生检查与最终静态核对；后续按用户要求统一构建一次，真实 GUI、账号/令牌业务、语言/主题和 DPI 由用户验收。


## 2026-10-21 异步模板与主程序体积

- 对照精确匹配RSDS的Ksword-nice与固定85a8fc87，主程序从25,105,304增至31,042,560字节；差异主要为代码与数据，不能因Qt动态链接或资源较小便认定整轮增量合理。两版间还含10月15日至原审计10月19日的其它源码变化，不能把总差异全归于某单项优化。
- MSVC会把多层lambda/模板完整类型名字放入PE可写数据；此对照中的类型名字从215,465增至1,097,893字节，带AsyncOperation的名字从10,241增至504,990字节。后台模板只需Request/Result/Worker类型；已由GUI Job拥有的Apply/Failure不应贯穿后台模板参数，也不必为事务再包一层适配lambda。既有Job、线程池、取消/事务/异常/退出租约保持，避免为缩体积增加运行时分配或删安全语义。源码/QtCore回归/同配置二进制A-B/用户GUI分开记录，不能据未测的源码简化宣称节省MB。

## 2026-10-21 Dock热切与几何通知

- KernelDock的同步准备、Show及末次ADS排队兜底继续读取实际当前分支并调用原ThemeBinding准备；不能用“已建页”跳过隐藏页主题dirty或惰性子页。初始化入口返回此次是否真实构造UI，首次显示或真实构造后才补原四个updateGeometry/update。普通热切不再无变化重复请求布局；真实字体/主题/尺寸/布局变化仍由原Qt事件和样式拥有者失效，不另缓存sizeHint或建立观察器。
- 此步仅源码/累计构建核对，实际ADS恢复、首帧、字体/DPI/亮暗及主题色由用户验收，不据此声明实测切换耗时。

- 七张KernelDock结果表的语言搜索缓存复用既有结果发布定时器分片，元数据模式保留原items、源索引及完整行域，暂关排序、完成后恢复原排序/显式禁用状态。新源接管须继承最初状态并取消旧定时器；每次可重入Qt调用后复核当前代次，旧分片不能解除新任务门禁。每片遵守完整值捕获屏障，过期语言不标记接纳。单次缓存退役、最终Qt排序和首次Minifilter建树仍有同步成本，不能据分片宣称整项完成或实测帧率。

- Minifilter首次父/子节点填充及展开也已分片；源代次只在完整回调快照替换时递增，隐藏树不循环唤醒，Show继续同一游标。新树仍一次接入模型，首次完整过滤完成后才恢复原更新/显式禁用状态；字段、源索引、重复父键归属和匹配逻辑沿用原实现。每片接入原UiCommitCoordinator完整值捕获屏障。旧树与脱离模型的新树会短暂共存，取消的脱离树销毁、Qt clear/整批接入及最终排序仍有同步成本，不能宣称降低峰值内存或完成KCB-003。

- 七表首次筛选也复用结果发布定时器：原最终排序后先让出，再按256行/4ms目标扫描原完整搜索字段；关键词或共享行布局修订变化重启匹配。完整canonical排除集合接纳并清理隐藏选择后才解除preparing/恢复输入/调用原onReady，回调树准备仍在回调表首筛后。空关键词/分隔行沿原同步帮助函数语义；Qt最终排序、共享排除集合规范化及集合/缓存最后引用退役仍同步，不能据遍历分片认定KCB-003全部完成。

- `AsyncOperation`的回投包装拥有本次Result，现有`apply(*result, ticket)`可接收`Result&`；一次性PreparedRows在页面完成代次/可见性/模型修订/完整捕获门禁后直接move给模型，避免GUI再复制整份行向量及差异数组，不需新增共享指针或控制器。门禁延期只重新请求最新值，不保留对回投局部Result的引用；消费后不可重用计划。`setPreparedRows`仍按值拥有参数，保证模型通知中页面/控制器被销毁时计划活到提交退出。普通setRows、最终Qt结构提交/排序及旧值退役仍有原同步成本，不据此宣称整项完成或量测内存改善。

- 诊断开启时，主程序在真实QApplication::notify前后用PerfNotifyScope记录分派墙钟及线程CPU；直接嵌套notify按scope/parent身份分出inclusive/self，不把后续0ms回投或其它事件时间塞进Paint/Layout。线程cycles保留原单位，不能换算毫秒；GetThreadTimes的100ns累计值保留OS计账精度，短事件为0不代表无CPU。probe_setup_ns/probe_until_enqueue_ns分别说明探针准备和截至受锁保护入队的墙钟开销，不包含最后unlock/notify尾部，也不能当CPU开销。receiver标签在派发前复制，之后不解引用；初始化后才采样，退出关闭前停用。默认宏0时仍直接构造QApplication，notify覆盖和CPU采样均编译移除。该边界是Qt分派，不等同物理呈现；输入到呈现及退出持久化仍由MR-003/004单列。


- 2026-10-21 KCB-003后续已由七表/Minifilter完整后台值模型替代此前timer/items及detached树流程。源数组共享不可变根；字段/role/筛选/原Qt比较排序在既有worker准备，旧值在既有CompleteExport退役lane释放。sourceIndex、失败分隔行、persistent映射和捕获门禁继续保留；必要Qt通知/选择/展开仍在GUI。静态及HostX64构建44通过，真实GUI、原生事务与峰值内存没有代用户验收。此前分片段落记录历史阶段，不代表当前仍使用旧流程。

- 速率时间轴的完整采样与绘制投影分开：后台对64点叶块建立小索引，绘制按物理像素列分别保留上下行首末及极值，最后一个原样本独立按原动画插值；最大Y值仍来自目标时间范围内全部原始值，不能改用动画值或降采样值。无序/非有限兼容输入保留原顺序和原扫描语义。投影缓存只按值源、目标/动画范围、物理宽度失效；主题和选区不重建原数据。纯值等价/峰谷守恒不等同GUI逐像素栅格一致或实测FPS证明，实际视觉由用户验收。

- 网络审计/防火墙完整值模型接纳使用worker预备的持久范围树，使原begin/end增删通知内不再erase/shift/copy整个Row数组；最终回到连续根，固定模型/identity proxy保留persistent索引。排序比较在worker按实际显示QString和当前语言进行，切列时同值必须沿原Qt proxy的先前显示顺序稳定排列，不能每次从canonical顺序重排。root的真实QSortFilterProxyModel三次切列对照发现并纠正了此差异。必要Qt通知/真实persistent映射仍随规模增长，不能宣称常量时间。

- 抓包主表的展示版本与规范缓存必须共享同一个PacketRecord负载所有者，不能为后台格式化再深拷贝packetBytes；R0/R3已消费批次move到该所有者。remoteDomain只在GUI更新，后台只读独立捕获的PacketMonitorRecord::domain，不能从后台读/复制可变的remoteDomain成员。展示快照/元数据COW只复制句柄和QString，旧值沿既有退役lane释放；真实复制/内存峰值仍须区分canonical、采集队列、NIDS独立队列与实际视图。root受控1MiB负载检查证明规范/展示字节缓冲身份相同，未量测实际应用峰值内存。

- 网络值接纳后续已简化：用worker预备的连续值阶段替代持久范围树，先按稳定身份把待删行转到尾部，再一次尾删/尾插，最后按原target映射恢复顺序；正常路径最多两次layout、一批remove、一批insert和一个覆盖全部真实变化的dataChanged矩形，不能对5000个离散删除在GUI发5000组通知。公开模型和persistent身份保持，重复/无效键才用原reset回退；所有Row复制及阶段/旧值退役在后台。QtCore10000行/5000离散删除仍0次GUI Row复制，通知收敛到1次删除、2次layout；必要persistent remap仍在GUI，不宣称恒定时延。此前范围树段落为已替代历史。

- 抓包展示Row后续只持字段、sequence/PID/地址和指向规范Record的weak_ptr；不能让隐藏旧表继续强持已被6000+320规范缓存裁掉的原始字节。后台输入仍强持一次完整源，保证准备期间安全；接受后的展示/导出只需完整表字段，详情/重放仍按规范序号查缓存，保持原清理语义。弱源过期时重建当前字段，元数据只按sequence查当前规范记录；未知域名另存布尔状态，不能用已本地化占位文字推断查询状态。15项受控所有权检查证明旧展示字段保留时字节所有者可释放，不代表实机退役时延/峰值测量。

- 诊断探针的writer关闭请求不等于尾部日志已落盘。默认宏0不启动writer也不等待；显式启用时在app.exec返回后、Qt销毁前进行默认100ms有界等待（调用上限1000ms），不改退出码。writer排空全部已接纳记录并明确统计overflow丢失，QFile flush与Windows FlushFileBuffers均成功后才原子发布带session/实际路径/字节数的completed回执；单独writer_drain_end标记不能作为成功依据。超时、无法写入/flush/发布回执或进程异常退出都不得宣称完成；这不是物理呈现或整条输入因果链证据。

- 插件结果固定source/identity proxy，完整块值及显示顺序在原AsyncOperation后台准备，GUI只接纳布局与persistent映射；完整捕获在请求时即标preparing，不能等下一轮timer才关屏障。同值沿实际先前显示顺序；原Qt dynamicSortFilter=false时，新发布批次只在批内排序后追加，不能静默整表重新排序，合并后台请求仍保留发布批次边界。sort(-1,Descending)也必须按原canonical行号降序；失败恢复原已应用列/方向，reentrant尾部发布保留新行身份。真实Qt旧代理对照140821项（10362行）通过；未验证产品GUI、捕获UI或实机退役时序，极长wrapped段落仍有Qt单次布局成本。

- NIDS不能用TTL、单调时钟或删除历史流键解决驻留增长：原系统时间允许回拨/迟到，必须保留完整FIFO、累计值和cooldown。现将三类状态的合计热键限制为1024，旧键完整序列化到分析worker独占的系统winsqlite3临时库，成功写入后才移出热表；无provider/写失败保留全部热状态并回退RAM，冷读失败走原显式失败通道，不能当新键。零时间原本不记录cooldown，因此0只作未记录哨兵。Reset同时销毁临时库，沿原后台退役lane清理；不新增GUI等待/状态时钟。旧引擎逐包106450输入/38841告警全字段差分通过，资源/故障90012项通过。30000个冷流受控样本private增长旧26.72MB、新1.36MB，但worker耗时168ms→383ms；这是驻留历史键优化及其I/O代价，不能宣称全进程硬内存上限或实机UI提速，活动单键事件和原待处理队列仍完整保留。

- 诊断操作身份来自真实notify入口的输入事件，Qt转发同一个QEvent复用ID，嵌套事件循环的不同输入另建ID；spontaneous与synthetic分开。AsyncOperation只在诊断宏1下捕获两个整数action/request ID并沿原worker、投递、apply、cleanup传递；请求ID全局唯一，子请求记录parent，0明确表示没有已证明的输入父项。UiCommitCoordinator与滚动动画/延迟probe也保存接纳时的值上下文，不能在回投时借用最新输入。取消settled可能早于query worker返回，不能叫ready；input_dispatch_end、apply和GL frameSwapped都不是物理呈现。心跳区间始终无单一action归因。writer提供QPC对时上下界，供外部WPR证据关联；没有自动运行产品采集。真实生产QtCore检查488项及原异步153项通过，普通宏0不保留新字段/worker调用/连接；完整input-to-present与非共享异步路径仍未完成。

- 标题栏CurrentPage搜索的nested prepare必须与游标的visibleOnly范围一致。Memory/Misc的prepareNavigationPages(true)只准备当前选中根及当前工作台/调试视图，不置全局prepared；false默认仍保留完整兼容发现。搜索层传UiSearchScope，MainWindow只把CurrentPage映射为true，Taskbar及旧路由默认false；不通过改searchComplete伪造冷页正文索引。133项QtCore抽取实际方法/原路径对照证明全范围工厂调用顺序相同、当前页不调用其它工厂及重入销毁保护；实际GUI/可见正文/主题仍由用户验收，GN-009/FP-003全范围冷正文尚未完成。

- 2026-10-21 全范围搜索的Memory/Misc嵌套准备按既有工厂逐次推进，返回未完成时由原搜索generation排下一轮；取消停止后续构造，已完成游标可续用。当前页保持所选分支；真实目标激活和Taskbar兼容fallback仍请求完整准备。每页内部构造仍原子、冷正文仍需构造，不能据此宣称全文零实例化或整项关闭。

- 2026-10-21 诊断writer以实际EXE SHA匹配有大小上限的发行build-info，再记录commit/构建边界tracked dirty；没有匹配清单或旧清单没有dirty时明确unavailable，不从运行机器的Git猜身份。ADS当时只记录exe目录部署文件hash。运行条件仅在原Dock/外观事件记录值快照（窗口、DPI、系统报告刷新率、动画/主题/背景/字体与聚焦模型数量），不扫描隐藏页、不回调worker内UI；屏幕刷新率不是FPS，快照不是呈现或完整因果证明，普通宏0移除调用。

- 2026-10-21 插件只读输出/诊断接入共享`AsyncLogTextView`：保留2000段落上限及逐次append顺序，规范化/前缀淘汰与完整QTextLayout均在既有异步worker，GUI按可见QTextLine绘制。不能只将超长字符串分批append而继续让GUI排版完整段落；也不能用私有Qt绘制ABI。搜索沿原QTextDocument::find规则在禁用布局的worker文档执行，复制按操作接纳点快照，旧命中按已知前缀身份映射，已淘汰范围拒绝。普通CodeTextEdit与新视图共用六项surface颜色公式；不变更可编辑器业务/语法。源/布局分别退役，关闭不等待worker；QtCore纯值对照及编译不代表GUI栅格、DPI、选择/拖出、辅助功能或实测帧率验收。连续写入时显示仍可滞后，首版必须由用户手测三处插件日志及原编辑器主题。

- 2026-10-22 诊断ADS身份现从真实导入的`CDockManager::configFlags`地址记录整数值，既有writer以`GetModuleHandleExW(FROM_ADDRESS)`保活模块、解析实际路径并哈希该路径文件；不按DLL basename猜加载对象，也不在GUI读文件。旧`ads_runtime_sha256`保留且明确标exe目录文件。路径处文件hash不是已映射映像的内存证明，失败/零地址明确unavailable/error。进程GPU后端仅在原初始化/请求/回退边界写conditions，GL字符串只在原current上下文读取；记录实际格式、共享组及当前表行列数，不创建/强开上下文、不逐帧轮询。光栅记录的renderer明确为上次GL初始化值，不能冒充当前硬件。宏0编译移除新增运行工作；实际GPU/ADS GUI和开关对照仍由用户验收。

- 2026-10-22 独立输入的首次几何合成仅让明确支持的现有LineEdit/Spin/PrimaryCombo绑定接管，复用原队列和`m_hasApplied`首轮状态；不在构造期强制执行颜色，LineEdit/Spin后续换肤不新增回填被业务替换的旧几何，PrimaryCombo保留原回填顺序。参数正文8px padding也与独立圆角/颜色按原顺序合成；自定义绑定、自动Combo原策略和已准备控件保留即时几何路径，替换绑定清除旧能力。PrimaryCombo原trimmed会移除几何前导换行，原callback随后可能再次追加同一规则；合成最终QSS时必须复现这一步，不擅改层叠/去掉中间业务规则。字符串/声明映射与QObject值替身检查不能代替真实控件polish、palette、DPI或GUI视觉验收。

- 2026-10-22 篡改页HVM通道可用性改由主窗口既有后台HVM状态刷新独立读取原QUERY_WINDOW并发布；只在实际可见消费者需要时附加查询，DDMA广播只更新DDMA。页内两查询定时器和独立worker已退役；首次/再次显示、在途目标变化请求原宿主并只合并一个补查。每轮可见状态刷新都重读真实windowReady，不用SCM/HVM代次或TTL永久推定，因此同次加载内PnP最后控制器移除亦可由下一实际观察发现。consumer epoch+宿主服务失效generation+弱身份/退出门禁拒绝晚到成功；设备错误通知先于worker回投时，在新epoch明确发布失败，不能只失效后一直停在查询中。离线首次显示明确不可用，待查询时保留勾选偏好但禁用依赖动作；失败/windowReady0仍取消HVM路径。驱动/协议、HvmControl、实际扫描与REQUIRE_WINDOW严格读取保持原代码，普通HVM代次不等于私有窗口生命周期。控件/表格/详情布局及主题无改。源码/受控QtCore和产品构建与实际硬件/GUI验收分别记录。

- 2026-10-22 T00外部证据工具位于`tools/ui_perf`，独立HostX64控制台编译，不进入主程序。默认Plan只读身份/列计划，用户显式Capture才启动独立UUID的PresentMon与私有GUID system logger，采CPU SampledProfile/CSwitch栈；仅停止成功创建的句柄，保留状态/丢失计数和SHA清单。正常有界等待是WAIT_TIMEOUT=258，取消0/父进程退出1不能算完成。离线分析用整数/Decimal保留QPC精度，交换链/输出/层分别统计，JSONL仅在实际PID/EXE SHA/会话/时钟匹配时给非因果的下一显示候选；不能把候选、配置栈成功或ETL存在称为实际操作完成/完整栈/物理发光测量。普通宏0发行版没有JSONL操作链，运行日志快照不代表writer完成回执。受控控制台夹具不含ETW/GUI/产品调用；真正采集与WPA栈覆盖和同条件A/B仍由用户执行，T00残留不得据工具交付直接关闭。

- 2026-10-22 ThemeBinding首帧准备的dirty收集只在本次无回调阶段缓存共享祖先深度/不可达结论，不缓存叶绑定；缓存收集结束即释放。跨宿主公共链只检查一次，原可见/stack当前页/窗口边界、父先子后排序、回调前真实父链复核与弱寿命/新请求消费保持。不得把此临时结果带过回调、重挂或下一轮；仍逐个读取已有dirty身份，无新观察器/永久索引/全控件树扫描。53770项QtCore与冻结旧方法对照及真实TU通过；10000叶/12祖先夹具祖先读取130000→10012，非实际GUI耗时/FPS结论。

- 2026-10-22 主程序QApplication创建/应用身份确定后调用MainWindow::prepareStartupAppearance，先安装标准绘制/度量/过滤器并显式跳过临时应用基线，再复用原15项正式palette和5段全局QSS；同配置业务首帧直接继承最终配方。InstallStandardWidgetTheme的其它调用默认仍下发完整旧基线。原热换/窗口背景/字体基线/预览取消链保持；标记块内容相同时忽略外围换行，避免无变化全局重写。1751项真实QPalette/QString值检查证明去掉中间基线后完整角色与原两阶段最终值相同，原运行期方法展开等价；不等于真实GUI/首帧/性能验收。

- 2026-10-22 诊断宏1在既有Tab/ADS selected与实际冷挂载/页壳准备入口记录有界target路径/index、origin和navigation_id；ready限定shell_prepared，business_ready_proven/present_proven均false，warm Dock明确ready_unproven。宏0无新观察器/成员或业务分支。33项QtCore实际值API与3实际TU宏1检查通过，未运行GUI/采样。T00原要求包括真实受验操作链/可观测present/WPR栈与实测；不应扩张为所有无关后台任务接入或光学设备验收，也不能以外壳ready关闭T00。

- 2026-10-22 `Invoke-KSwordBuildCheck.ps1 -EnablePerfTrace`仅通过本次临时props给主工程全部ClCompile传入诊断宏1，不修改PerfTrace.h默认0或工程。普通Build仍宏0；是否禁WPO继续只由既有独立开关决定。构建日志记录BUILD_PERF_TRACE_ENABLED，需按实际构建标识区分普通/诊断产物，不能用VerifyArtifactOnly证明编译宏。真实GUI/WPR采集仍由用户执行。

- 2026-10-22 普通Neutral/Auto按钮在明确不透明主/ADS浮动宿主中，可复用宿主属性选择器的同一配方，不再逐按钮写相同局部QSS或保存五态背景列表。资格检查使用实际完整宿主QSS、主题代次、局部palette及祖先拥有块；主动作/危险色、显式外观、flat QPushButton、命名/复合按钮、未知业务QSS、透明/独立宿主保留原局部拥有者。配方和状态颜色公式保持原函数，宿主规则去除祖先拥有标记，避免误接管未声明按钮；业务QSS接管需清共享属性并重polish。重挂、样式/色板变化和迟到子控件通过原ThemeBinding队列失效；子按钮准备前先恢复已变为复合控件的父级原层叠，沿用弱寿命保护。584项QtCore/QtGui值和QObject替身检查验证拥有者/字符串/回调路径，不能代替QtWidgets层叠、真实热换肤/浮动、内存或FPS实测；真实GUI交用户验收。

- 2026-10-22 表格冻结菜单只保留原QMenu/按钮/控制器在构造期，原数量控件、六动作及七连接延至首次aboutToShow；已有updateControls不提前创建，未创建的语言/状态刷新有空检查。首次打开在原barrier和状态刷新前完成原内容，文案按当时语言、主题按原入口；冻结后端、快照、模型、主操作条布局和完整closeFreezeMenuBarrier后业务尾部保持。静态逐字搬移核对及累计构建分别记录；首次菜单尺寸/主题/键盘和冻结业务由用户手测，不声明GUI已通过。

- 2026-10-22 DDMA原串行transaction以诊断宏1值上下文关联worker/UI回投：探测完整磁盘缓存、表格/选区、标签及原会话回调完成后才记ddma_probe_business_data_ready；候选扫描只记候选规范快照ready并由原自动重探子request提供最终探测ready。队列拒绝/异常/业务失败/接收者销毁分别记录，不改变原无取消/替换准入。宏0预处理去诊断块后业务token与原文件一致；不能将此边界当paint/present，也不据源码与构建声明DDMA硬件或GUI已验收。

- 2026-10-22 诊断宏1仅为明确ScrollArea的现有viewport/两bar注册观测，4096宿主上限，无新timer/布局/paint请求。valueChanged回调保存实际双轴值和回调上下文；Qt早先slot可重入，因此它明确不是输入因果证明。实际notify Paint入口复核真实bar值，早于回调时上下文置未知，分派退出只在同viewport身份/观测revision仍相符时接纳稳定观察；GPU swap仅关联最近完整Paint scope且不重复。换viewport/换bar/重挂/销毁有弱身份和失效保护，动画关时同样观察。离线仅统计Paint分派/值观察到Paint/同Paint到GL swap的间隔，不称呈现FPS或input-to-present；缺失/重复/变化/销毁显式分开。67项实际纯值/序列化QtCore和21项离线分析通过，宏0三文件原执行tokens保持；真实QtWidgets/GL/呈现/WPR由用户验收。

- 2026-10-22 T00离线分析补齐navigation_stage及parent_request_id、路径/index/边界/原结果；无输入begin的程序化导航单列。每个ready/显式business_data_ready以QPC误差上界之后首条显示独立作非因果候选，嵌套请求不合并，重复ready拒绝、无后续为空。外壳ready不升级为业务ready/呈现证明。26离线回归通过。
- 同次按原MR-001条目复核：现有QApplication notify真实包围、inclusive/self与ns、queue指标更名、宏0探针移除及外部栈工具已实现；当前生产PerfTrace.cpp在QCoreApplication+QObject夹具重跑2ms事件/16ms外部工作，45项及宏0无日志1项通过。无QApplication/QWidget/业务/ETW采集。MR-001源码实施可以关闭，真实GUI/栈采集验收仍待用户；MR-003预热Dock的真实ready与MR-004实测不随之关闭，不要求新增全库业务封装。

- 2026-10-22 诊断宏1按实际ADS currentChanging→当前widget同步show返回→currentChanged记录同一dock_switch的begin/selected/限定ready/end。ready仅对进入前已初始化、同一Dock/同一内容实例、仍可见且未closed/initializing成立，边界名ads_current_widget_show_returned；不声称queued布局、业务数据或present已完成。嵌套替换/目标改变/内容替换/销毁不伪造ready，初始/焦点观察仍单列。原visibilityChanged的0ms挂载回调仅宏1保存/恢复输入context，原可见/寿命/构造准入保持。61项实际闭包QtCore/QObject替身检查和宏0全MainWindow token恒等通过；真实ADS/GUI/50次循环另由用户验收。没有新增主题准备、系统查询、业务等待或通用接管框架。

- 2026-10-22 用户诊断日志确认持续出现七个复选框一组的StyleChange及双倍PaletteChange。`NormalizeToolbarControl`原来向所有QAbstractButton追加只匹配QPushButton/QToolButton的几何QSS；日志面板七个复选框的独立主题绑定又恢复纯颜色QSS，两者经原队列反复覆盖。几何追加现只对真实QPushButton/QToolButton执行，复选框/单选框原高度、图标尺寸、标记和业务状态保持。不得靠停掉主题绑定、忽略真实换肤或单纯节流掩盖此循环；复用工具行时须检查其QSS选择器实际覆盖的控件类型。诊断记录存在丢失，不能据此计算完整帧率或推定普通版耗时；修复后GUI/实际性能由用户验收。

- 2026-10-22 构建35反馈的线程/模块等崩溃，匹配旧EXE/PDB的dump落在`ImmutableValueTable::startPending`完成回调读取零结果的QFuture。`watcher->setFuture({})`切到默认的已完成空Future，可在`deleteLater`前再投递finished；必须先断开该watcher到接收者的完成连接，并在读取结果前检查resultCount。空/空指针结果沿既有失败通道恢复旧表可用性，不能当作空成功覆盖数据；旧代结果继续受revision门禁。分析旧dump须匹配其实际模块路径/PE-PDB身份，反馈文件引用一个发行目录不代表所有dump都来自同一构建。

- 同轮关闭dump的真实事件为`ChildRemoved(71)`，旧EXE反汇编在事件类型分派前调用QTabWidget::currentWidget，进入已经拆除子布局的QStackedLayout崩溃。PageTabEnvelope对ChildAdded/Removed只记布局失效并合并排队，不同步读取当前页；QPointer非空不代表Qt内部布局仍可访问。既有布局/几何/动画准备实现保持，真实GUI关闭仍须用户回归。


- 2026-10-22 构建35字段反馈：DetailFieldProjection物化范围继续按原requestedFirst/requestedLast取行，但宿主clipFirst/clipLast必须覆盖这些行的完整高度；只修上边界会把最后一个长字段压缩在局部卡片内。0231346b保留两端完整行，另一列不因卡片变高而多物化。已有snapshot更新/视口预算未完成时保持原字段可见，4940582a只让首份加载使用整视口加载层。不要把QLabel大小策略调用顺序当作充分归因：本机Qt6.9.3的setText也会在updateLabel恢复height-for-width。8项纯值生产几何检查不是GUI验收。
- 2026-10-22 组合框Show后排队加不透明frame/QSS会改变实际viewport和item度量，而Qt showPopup在Show前已计算窗口高度。223c6b2a仅在既有queued主题回调内用真实列表rect补足短列表缺口（最多32项并遵守maxVisibleItems/屏幕/maximumHeight），不改焦点、选中、长列表限制或提前创建Popup；仍禁止在Show/Resize栈内同步repolish。
- 2026-10-22 保存布局和启动页：ADS 5.1.1会在各area的currentDockWidget属性保存XML Current身份。b330022f在初次外观挂载结束且restore成功时一次性收口所保存选中项；关闭/移出原area的目标跳过，没有第二份配置或重试timer。跨固定发行目录测试会使用不同exe/config，验证退出恢复必须在同一测试副本内进行。

- 2026-10-22 c1bdcc83实测反馈：权限页自身的Account/Token/Snapshot完成回调也有`setFuture({})`重复finished问题；修共享ImmutableValueTable不会修到这些独立实现，四个完成入口均须先断开接收者再解绑future。两个实际生产回调的QtCore寿命检查覆盖先完成、后完成、接收者先销毁，不代替业务GUI验收。
- 进程详情性能/CPU核心页的曝光过滤器必须在轻量页壳创建时安装。QTabWidget先Show再发currentChanged，若在惰性内容工厂才安装，会永久漏掉首次Show；这是确定事件顺序问题，不是机器速度或应增加固定延时。隐藏/最小化门禁仍保留。
- 窗口图标的规范缓存路径可以用正斜杠，但传给SHGetFileInfoW前必须转原生分隔符。本机只读对照同一notepad/主程序EXE，正斜杠查询失败、反斜杠成功。预览QLabel的pixmap不能拥有布局尺寸：Ignored策略、contentsRect缩放/回投校验及空窗口矩形回退共同避免逐次加边框尺寸的放大回路。
- USB等设备审计表的行增删通知保留，单元格批量填充阶段仅屏蔽model数据通知，结束后一次dataChanged，再恢复排序/选择/业务过滤。不得连结构信号一起屏蔽，否则持久行身份与冻结/搜索观察器失效。真实USB切页停顿仍须用户复测，不能由通知次数推算帧率。
- 网络监控已有投影可继续交互，不能每批数据禁用整表导致按钮/图标变成Disabled再恢复。趋势捕获允许尾部追加，完整旧快照可在同代/同epoch及交互参数有效时先展示，再合并dirty追上，避免高负载下连续拒绝所有完成值；速率复用原接收/淘汰维护的秒桶。R0进入原预算消费通道前按队列余量限制查询，满则不前移cursor，不新增用户态丢包；R3原策略保留。设备打开失败且ENABLE未发出时才免除R0停用义务，真正IOCTL失败仍保留失败回执。
- 透明主宿主的数据衬底统一由MainSurfaceStyle的TransparentMainDataSurfaceAlpha控制（192/255），表头节与工具带同入口；表头画布不再额外叠同色alpha层，前景按同一alpha的黑/白极端背板校准。独立窗和无背景模式保留原不透明配方，不用setWindowOpacity淡化文字。亮暗/主题色/背景模式热切换和GPU/普通表格实际合成仍由用户验收。

- 同日用户要求可调控件背景：原固定192由AppearanceSettings::controlBackgroundOpacityPercent（默认75，0..100，control_background_opacity_percent）替代。设置→外观→背景的共享滑块只改待应用值；应用/取消/重载沿原流程。MainSurfaceStyle维护GUI线程运行值，变化时只失效原颜色/QSS代次、主/浮动宿主样式和已登记ThemeBinding，单改alpha不走业务枚举、背景文件重读或全局旧色扫描。表格/表头/工具带/标准按钮与输入/页签/ADS/监控时间轴复用现有绘制；Collapse与页根外壳透明，参数滚动三层由现有外板负责底面，避免重复同色铺底。参数正文只有实际alpha255才保留opaque快路径。下拉popup/独立窗和原生插件边界保持原实底，控件文字图标与语义颜色不整体淡化。82项实际alpha/cache/Combo弹层/ADS QSS纯值检查通过，无QApplication/QWidget；实际GUI与性能仍由用户测。

- 2026-10-24 进程列选择器：导航为进程列表→选择列（字段选择二级工具，SecondaryPageLayout）→保存为视图（名称输入二级工具，同共享入口）。ProcessDock 懒建并复用同语言下的唯一列选择窗口，重开只同步复选框/搜索/删除动作，语言变化才重建；回调状态由窗口拥有，禁止捕获已返回构造函数的临时变量。保存名称使用显式输入/OK/回车连接，空白名禁用确认，只有保存函数成功才关闭选择器；QSettings 同步状态失败返回错误并恢复原内存视图，列未实际变化时不额外枚举。源码与构建验证不等于实际确认点击、保存后重开或性能验收，真实GUI由用户测试。

- 2026-10-24 二级弹窗根QSS双拥有者：SecondaryPageLayout::SetOwnedStyle 与 DetailWindowFramework::applyStyle 都采用移除自身块再追加末尾的算法，会把 A+B 与 B+A 来回改写；Qt 6.9.3 的 polish 先 unsetPalette 再 setPalette，进而让根 ThemeBinding 的 PaletteChange 与详情控制器的 StyleChange 互相排队。选择列/保存名称的卡顿与按钮失效不能只修业务连线。详情框架及 ApplyDetailDialogChrome 必须让出 ksword_secondary_window 的根QSS；StyleSecondaryWindow 首次接管时移除既有详情块，仍保留共享结构与标准控件主题。独立弹窗点击不属于 ProcessDock 页面空白点击，不得清空进程选区及刷新图表。纯静态分析和构建不代表已完成用户实际点击验收；不保留事件日志、轮询或诊断观察器。

- 2026-10-24 用户已确认前述选择列/保存弹窗修复解决实际问题。启动画面方角调整按用户明确要求仅源码核对、提交和推送，不重新编译。

- 2026-10-25 截图布局复核：启动品牌组顶部与进度条底部统一20px，GDI+文字使用同一GenericTypographic测绘以消除额外侧向留白。StyleParameterSection共扫描37文件87处调用，DDMA之外21处构造顺序依赖由StylePrimaryGroup既有首帧主题回调补布局（当时标题top22、无标题top4；后续统一标题配方已替代layout标题边距），不加observer/timer；StyleParameterFields不得侵入StructuredFieldView、CodeEditorWidget及专业视口内部。四个Memory ParameterWorkspace页面去掉整页外层滚动，DDMA仍保留专业主体例外并把候选字段从参数grid分离，多动作行复用FlowLayout，ToolbarRowMetrics通过NormalizeToolbarLayout复用到Flow/grid并保留字号变化同高更新。StructuredFieldView工具行按宽度多行重排并保护documentOnly转移；窗口预览的不可用空态不得占固定黑图，失败占位图不得作为成功截图保存。自动列宽保留实际表头尺寸下限及Fixed/手动语义，动态表头只失效headers缓存。覆盖与验证边界见docs/UI布局扫描与修复-20261025.md，GUI仍由用户验收。

- 2026-10-25 分区标题默认值：GroupBoxStyle统一普通/参数/设置/弹窗/详情的卡片内部标题与字号预留；组框layout归零，QSS独占正文padding。独立卡片左右16、标题left16/top10；embedded借外卡16、left0/top0，区内8/参数分区16，无标题top4保留。StylePrimaryGroup已绑定后改变参数角色也要替换同一ThemeBinding回调；字体事件沿现有队列且!m_applying。默认组框可忽略完整共享GLOBAL_DIALOG_THEME/DETAIL_FRAMEWORK根块，但残余业务QSS仍阻止接管。不要再从finish/Fold写layout标题top22/8。热键/钩子的程序快捷键复用唯一WindowGlobalHotkeyTab首显后台枚举，PE Accelerator资源与R0注册热键保持分表，不能用资源填充掩盖驱动失败。详见docs/UI分区标题与热键页面修复-20261025.md；启动法律正文独立legalFont13，其余字号不变。
