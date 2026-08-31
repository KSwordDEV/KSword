---
name: ksword-ui-architecture
description: KSword 主程序 UI/主题架构要点（theme.h token 体系、全局样式块链路、WindowChrome、透明背景与毛玻璃、Dock 懒加载）
metadata:
  type: project
---

KSword 主程序位于 `Ksword5.1/Ksword5.1`（Qt 6.9.3 Widgets + Qt Advanced Docking System，MSVC vcxproj 构建）。

## UI 主题架构

- `theme.h`（KswordTheme 命名空间）：design-token 中心。中性表面色（Window/Surface/SurfaceAlt/SurfaceMuted/Border）由 RGB 偏移从种子色派生；强调色 PrimaryBlueColor 可由用户自定义；提供 EnsureTextContrast 等 WCAG 对比度工具。
- 纯图标按钮的几何同样由 `theme.h` 收口：紧凑工具栏使用 `ApplyCompactIconButtonMetrics`（28px 按钮 / 16px 图标），独立或强调动作使用 `ApplyStandardIconButtonMetrics`（32px / 18px）；页面不得继续新增 30/34/36px 的临时组合。
- `MainWindow::applyAppearanceSettings`：主题应用唯一入口，设置 QApplication palette + 调用 `applyGlobalApplicationStyleBlocks`（带 marker 的 QSS 块替换机制，marker 常量在 MainWindow.cpp 顶部匿名命名空间）。
- 全局 QSS 块顺序：BaseControl（`UI/GlobalUiBaseStyle.cpp`）→ Tooltip → ContextMenu → ControlContrast → ComboBox，依次追加到 app stylesheet，基线块在最前，局部样式可覆盖。
- `QComboBox` 弹出列表是独立 `Qt::Popup` 顶层窗口。禁止在 Popup 的 `Show`/`Resize` 事件内同步调用 `setMask`、`setStyleSheet` 或其它可能 repolish 子树的操作：Qt 此时可能仍在 `QWidgetPrivate::showChildren` 中遍历内部子对象，重入修改会留下悬空 child。Popup palette/QSS 必须用零延时 queued 更新并做幂等去重；圆角只保留 QSS 绘制，不再修改原生窗口 mask。
- `UI/GlobalDialogTheme.cpp`：QApplication 事件过滤器给所有 QDialog 补主题（palette + 追加 QSS）；QMessageBox 由 `UI/ThemedMessageBox` 专管。
- `UI/WindowChrome.cpp`：事件过滤器对所有原生标题栏顶层窗口用 DwmSetWindowAttribute 染色（IMMERSIVE_DARK_MODE=20、BORDER=34、CAPTION=35、TEXT=36），主题切换时 `RefreshAllWindowChrome()`。
- 大型独立窗口的初始尺寸和最低尺寸统一调用 `ks::ui::applyResponsiveWindowGeometry`，以父窗口所在屏幕的 `availableGeometry` 为边界；不要再直接写 1000px 以上的硬 `setMinimumSize`，否则高 DPI、小屏或远程桌面会把窗口撑出工作区。
- 独立窗口中的懒加载 `QTabWidget` 必须隔离页面动态 `minimumSizeHint`：页面栈使用零最小尺寸和 `QSizePolicy::Ignored`，顶层窗口只保留响应式最低尺寸，禁止用 `maximumWidth` 对抗内容传播。纵向表单页应放入 `QScrollArea`，使切页和异步控件挂载不改变用户当前窗口尺寸，同时保留自由拖大和最大化能力。
- 主窗口是 FramelessWindowHint + 自绘 `Framework/CustomTitleBar`；其余子窗口全是原生标题栏。

**全局基线样式只允许颜色/边框，禁止 min-height/padding 等几何属性**——app 级几何会穿透局部样式破坏紧凑布局（曾导致主窗口标题栏按钮被撑高、最大化后标题文字上偏）。

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
- 跨 Dock 打开独立详情窗口时，只用 `ensureDockContentInitialized` 创建内部控制器和窗口管理状态；不要对其所属 Dock 调用 `raise()`、`setVisible(true)` 或 `setAsCurrentTab()`，否则会无条件改变用户当前标签。进程详情入口遵循此规则，`ProcessDock` 仍负责 identity 校验、窗口复用和详情页导航。
- 主功能 Dock 一律 `DockWidgetClosable=false`（Tab 无关闭按钮）。曾实现过"Tab 关闭按钮=卸载内容"（CustomCloseHandling + unloadDockContent），最终整体撤销（23251d80）；若再有此需求注意：welcome 无懒加载工厂，kernel↔driver 有共享自驱动页 `attachKswordSelfDriverPage`，卸载会悬空。
- 跨 Dock 的进程详情入口仍可调用 `ensureDockContentInitialized(m_dockProcess)` 来复用 `ProcessDock` 的详情窗口管理与 identity 校验，但不得随后 `raise()` 或 `setVisible(true)` 激活进程 Dock；`ProcessDetailWindow` 是独立顶层窗口，打开它时应保留用户当前页签。

## 启动单实例与权限切换

- `AppearanceSettings::preventMultipleInstances` 默认为 `true`，对应 JSON 字段 `prevent_multiple_instances`；只限制普通启动，关闭后新进程不再查找或激活旧主窗口。
- Admin、SYSTEM、UIAccess 等权限切换重启必须携带 `--ksword-privilege-restart`，保证默认开启防多开时仍能启动接管实例。使用 `CreateProcessWithTokenW` / `CreateProcessAsUserW` 时不能把 `lpCommandLine` 留空，应通过 `argumentsWithPrivilegeRestartMarker` 组装命令行并保留当前参数。
- 权限接管不能只绕过单实例检查：旧实例启动新实例成功后必须进入正常关闭流程，新实例应复用 `--ksword-crash-restart-wait-pid <PID>` 的同路径/直接父进程校验并等待旧实例退出，再继续主程序初始化，避免两个实例同时读写设置或争用 R0 服务。透传当前参数时先替换可能遗留的旧 wait PID。

## 通用表格交互

- 周期性后台刷新（例如进程监视采样）不得注册为全局 `kPro` 任务；否则每轮采样都会进入“当前任务”和顶部进度通知。`kPro` 只用于有明确开始/结束、需要用户感知的有限操作，常驻监视状态应留在页面状态标签与诊断日志中。
- 把系统枚举放进工作线程仍不足以保证主界面流畅：结果回到 UI 线程后，`QTableWidgetItem`、`QTreeWidgetItem` 与文件图标解析也可能形成长时间事件循环占用。启动项页把单阶段排序留在工作线程，每个枚举器完成后按固定顺序发布独立结果批次；UI 必须等上一批用零间隔单次 `QTimer`（目标 7ms、最多 24 单元）分时落表完成后再累计下一批，先填当前分类，未完成视图保持禁用，且只有“后端全部结束 + 阶段队列清空”才能结束同一刷新任务。后台枚举进度通过 UI 无关的稳定阶段枚举回调上报，翻译文案必须先在 UI 线程取得，不能从工作线程并发读取 `LanguageManager`。
- 周期采集的缺失证据或查询失败若使用 `Warn`，必须按规范化错误集合做状态变化去重：首次出现或错误集合改变时记录一次，连续相同采样只更新页面状态；错误清除后再复发才允许重新通知。否则默认 Warn 通知阈值会把固定失败放大成通知卡和日志风暴。
- `UI/TableInteractionSupport.cpp` 通过应用级事件过滤器统一接入 `QTableView/QTableWidget`；表头点击排序由 `UI/TableHeaderSortingSupport.*` 负责。
- `VisibleTableWidget` 与 `TableActionTableView` 共用嵌入式 `TableActionBar`，两者默认都提供冻结、暂停、快照和差异比对的完整条；窄小或纯展示表格可用 `SetTableActionBarMode(..., Compact/None)` 降级或禁用。通用表格搜索入口只显示图标按钮，点击后把范围切到当前表格并激活标题栏搜索框，不在表格操作条内重复放置输入框。操作条会同时出现在 Dock 和普通 `QDialog` 中，因此按钮、快照滚动区等几何/字体样式必须由操作条自身用 palette 角色封装；不能继承宿主弹窗的 `ThemedButtonStyle`，否则弹窗中的 padding/粗体会把同一套按钮放大并挤压固定高度操作条。
- 普通 `QTableView/QTableWidget` 的横纵表头由 `TableInteractionSupport` 强制应用同一套 palette 基线，页面不要再用蓝色粗体等局部表头 QSS 制造层级差异；十六进制编辑器等确实需要专业表头语义的控件须在设置局部样式前调用 `SetPreserveCustomTableHeaderStyle(table, true)` 显式声明例外。
- 线程表的“线程亲和性”右键入口（全局枚举、Ksword5.1 进程详情、KswordARKLight 进程详情）统一以 `shared/ThreadAffinityR3.h` 的 CPU Set/Group R3 API 实现。Ksword5.1 使用与进程 CPU 亲和性相同的 `QWidgetAction` 处理器矩阵；Light 保留原生子菜单。操作前必须核验 TID、所属 PID 和线程创建时间，R0-only/hidden 行不可走 R3 入口。
- 未显式开启 Qt 持续排序的 `QTableWidget` 使用“一次点击、一次排序”，不改变 `sortingEnabled`。这样后续 `setRowCount/setItem` 批量或分批填充不会因实时搬行而写错列组。
- 手动排序后遇到增删行、模型重置或单元格更新会撤销排序箭头，不自动重排半成品数据。具有帧序、加载序、采集序等固定行序语义的表格调用 `SetTableHeaderClickSortingEnabled(table, false)`。
- 进程表使用 `QSortFilterProxyModel` 与友好分组专用排序；点击表头时首次为升序、同列再次为降序。父子树状视图点表头后保持“进程友好视图”未勾选，只把内部投影切成没有父子关系的普通扁平枚举并交给代理排序；用户再次切换友好视图复选框时退出该临时扁平模式。搜索结果与历史快照同样走代理原生排序。
- 句柄页等大型 `QTreeWidget` 结果必须先建立轻量摘要节点，展开分支时每批最多创建 300 个明细节点，并用末尾“继续加载”节点追加下一批。摘要始终保持业务配置顺序，表头排序只重排各摘要下已加载的明细；占位节点和“继续加载”节点固定在分支末尾。进程图标等异步资源只为已创建的明细解析，回填必须同时校验树重建代次，并允许同一源记录出现在多个规则分支。
- `UI/DetailLayoutHost` 复用既有 `QSplitter` 时，必须确认表格与详情控件位于两个不同的 splitter 直接子面板；只判断“同属某个 splitter 祖先”会把整个页面面板误认成详情区，折叠后只剩箭头。页面仍在构造、详情面板尚未加入 splitter 时，统一布局接管应延迟到下一轮事件循环重试。
- 行内详情不得向现有 `QTableWidget/QTreeWidget` 插入合成业务行或子节点，否则页面原有的行号到缓存映射、排序和右键逻辑会整体漂移。统一详情布局只在视图层扩展源行高度并覆盖只读文本框，以 `QPersistentModelIndex` 跟踪源项；大型树的 SVG 状态图标更新必须合并频繁的 `rowsInserted`，并按固定批次让出事件循环。
- 行内详情展开后发生排序时，必须在模型的 `layoutAboutToBeChanged` 阶段清理详情：`QPersistentModelIndex` 会在布局完成后跟随数据项，但 `QHeaderView` 行高仍绑定排序前逻辑行；等 `layoutChanged` 后再恢复会留下旧行空白并裁剪新行编辑器。

## Taskbar AppBar 重启

- Taskbar 的设置重启与显示器变化重启统一走 PID 感知的接替路径：旧实例启动携带 `--restart-after-pid <oldPid>` 的同程序，新实例在创建窗口、AppBar 或后台采样线程前用 `OpenProcess(SYNCHRONIZE)` / `WaitForSingleObject` 等待旧实例真正退出。禁止用固定延时近似旧进程退出，否则同步线程清理和 AppBar 注销可能与新实例重叠。

## 踩坑记录

- 构建带 **i18n 审计钩子**：源码中任何"可提取"字符串字面量（中文日志、英文句子、无路径分隔的头文件名、甚至 `GetProcAddress` 的函数名）都必须在两个语言包的 `source_translations` 有条目，否则构建直接失败。QSS 选择器行要与 `{` 写在同一字符串片段内才会被审计排除。
- 语言包**只能定点编辑**：用脚本 json.load/dump 会重排键序与缩进，产生 5 万行无意义 diff。
- 约 1374 处散落 `setStyleSheet` 分布在 136 个文件（多带 `!important`），未来渐进收敛到全局基线。
- 构建产物被运行中的 exe 占用会导致 `LNK1104`；`vctip.exe` 残留会导致 obj `Permission denied`。

## 仓库规范（详见 AGENTS.md）

- 新增源码必须同步 `.vcxproj` 和 `.vcxproj.filters`。
- 用户可见文本必须同步 `languages/zh-CN.json` 与 `en-US.json`，并通过 `tools/i18n_language_pack.py audit`。
