# 默认 UI 状态、输入焦点与首帧

- 普通动作按钮不能把鼠标持有的焦点当成 hover。`FlatButtonTheme` 通过既有过滤器记录 `ksword_flat_button_keyboard_focus`，QSS、图标底色和 Hex 自绘共用实际输入来源；保留 Tab/ShiftTab/快捷键、checked/disabled/pressed，不使用 clearFocus/NoFocus 规避。直接 `MouseButtonDblClick` 也须改变来源，不能假定之前必有 Press 或 FocusIn。
- `TabFocusReason` 不等于实际按过 Tab：禁用、隐藏或移除当前焦点控件也会产生它。Qt 的原生键盘标志还可能在同焦点鼠标点击后陈旧。既有应用过滤器先记录真实键鼠输入，再判断自动转焦；Ctrl/Shift/Alt/Meta 等纯修饰键不点亮按钮。其他窗口的真实输入更新恢复来源，程序化关闭保留已有来源；不要只保留按钮自身的旧标志。
- 进程页设置齿轮是共享 Neutral/Solid 普通按钮；非模态设置窗关闭后保留焦点是正常 Qt 行为，外观须区分鼠标与键盘。性能指标开关的真实 checked 高亮须保留。
- 默认几何由共享入口在首次布局/绘制前准备。ThemeBinding 仅追踪尚未完成首次应用的绑定，在普通窗口 UpdateRequest 补首轮并合并激活该批已登记可见控件的祖先布局；后续主题热刷新仍分片，Popup/Tooltip 和隐藏业务不提前处理。
- 参数分栏应以原生 heightForWidth 提前报告目标列宽下的高度，已登记分区显隐直接 updateGeometry 失效外层缓存，不能等待两层原生列布局传递；换行选择项缓存真实字体、文本、宽度和 DPI。工具行构造默认一次，纯颜色/焦点/重复 Show 不重算整行；字体/DPI 变化只改必要几何，几何规则确实丢失才修复。
- Qt Show 遍历中重挂/删除 QObject 子树会导致 QWidgetPrivate::showChildren 崩溃；详情兼容包装须在安全完成边界准备，保留构造、代次与弱引用保护。不能仅将所有 timer 改成 Show 同步。
- 消息框自身 showEvent 还会修改文字/固定尺寸；默认样式和最终尺寸的两个阶段都要在首个实际绘制前验证。Table/Floating 组合也须联测：Floating 原队列稳定，抢先安装会制造 14px 视口变化；表格仅用一次初配队列边界，拒绝/取消/销毁时不能饿死绘制。
- 硬件导航使用列表默认 sizeHint=300 和原 QSplitter 约束，取消隐藏页按构造宽度早锁 140px 的校准标记；实际列表变化、非 opaque splitter 松开仍保留安全后续更新。Monitor 不再每次 Show 固定 0/80ms 遍历图表。
- Taskbar/HUD 是独立进程且不编译主程序标准主题实现。PageEntry 自绘须局部追踪输入来源；HUD 默认高度用已知页面和 CPU viewport 的实际 Resize/Show 收口，保留真实采样，不再用固定 0/80ms 校准。完整辅助项目与 Win32/FLTK 边界见审计文档。
- 范围、组件回归及准确边界见 [UI 默认状态与首帧修复](../../docs/UI默认状态与首帧修复-20261025.md)。统一入口为 `python tools/run_shared_ui_regressions.py --qt-dir <Qt prefix>`；Windows 须 HostX64/x64，并给 `--msbuild`。组件 offscreen 回归不是全产品 Windows GUI 或整体性能结论。
- Qt 6.9.3 在 MSVC 头内强制 `/permissive-`。测试直调 cl 要显式提供；临时 MSBuild 工程设 `ConformanceMode=true`。不能仅检查 `/Zc:__cplusplus` 或依赖 C++20 隐式启用，C++17 回归尤其会触发静态断言和后续比较模板连锁错误。
- 按钮回归不能先 clearFocus 再禁用，从而跳过焦点承接者。除单控件矩阵外，用 `test_button_theme_integration_ui.py` 编译真实 StandardWidgetTheme、ThemeBinding、MainSurfaceStyle、GlobalUiBaseStyle 和应用调色板，验证未点击邻居及跨窗输入；Windows 须链接 User32。此集成仍不等于完整产品 GUI 验收。

- 2026-11-01 表格先全屏再缩小时，快照/比对按钮仍停在初始宽度：全局 Resize/LayoutRequest 队列虽正常触发，但 `ResultTableHost::refresh()` 的 `m_configured` 门禁跳过了操作条定位。`TableInteractionSupport::configureTable()` 在宿主刷新后单独调用已有条的 `updatePosition()`；保留合并队列和 QPointer，不为几何变化重跑主题/模型初始化。覆盖进程列表的 TableActionTableView 和连接等列表的 VisibleTableWidget，Full/Compact 沿用原布局及窄窗“更多”入口，无新用户文本或页面皮肤。
- 回归入口 `tools/result_table_tests.ps1 -ResizeOnly` 编译实际操作条、宿主与表格几何：宽→窄→宽、RTL、隐藏后改尺寸再显示均通过（168 项）；换回修改前的操作条对象，同一检查报 24 项失败。完整旧夹具还存在 10 项相同基线失败（暂停恢复、搜索换绑/隐藏行、冻结菜单断言和工具行等高），本次不将其算作通过或扩大修复范围。输出/剪贴板与标题栏搜索为未调用的适配口，不据此验收这些能力；主程序 GUI 仍由用户查看。
- 本轮主程序 HostX64 Release、i18n 和主题门禁通过；额外 `test_table_default_first_frame_ui.py` 夹具虽编译成功，运行以 `0xC0000135`（依赖 DLL 缺失）退出，补 Release 搜索路径后仍相同，不能记为首帧回归通过。此夹具不是前述已通过的实际操作条缩放检查。
