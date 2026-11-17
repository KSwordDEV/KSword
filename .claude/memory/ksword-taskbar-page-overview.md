# Taskbar 页面平铺导航

- 救援模式由 `Ksword5.1.exe` 自身的监护入口负责。主菜单与两个程序的 SOS 监听共用 `shared/rescue/SosHotkeyLauncher`，Taskbar 只负责派发。监护入口先于 Qt 和普通实例互斥处理，使用自身模块路径启动客户端。实际会话仍需验证 UAC、物理输入和桌面返回。见 [SOS 救援桌面](../../docs/SOS救援桌面.md)。

- 入口在独立 `Taskbar` 右侧网格按钮，不在 KSword 主窗口标题栏。`PageOverviewWindow` 是置顶无边框透明工具窗，一级 Dock 各占一列、二三级页缩进，支持名称/完整路径搜索、Enter 跳首项、Esc 收起、拖动和缩放。RGB 只用于列顶和交互面；可见时更新并遵守系统动画开关。底板半透明，文字保持完整不透明度。
- 真实目录由主程序 `UI/PageNavigationBridge` 读取，不在 Taskbar 硬编码菜单。目录在一级 Dock 框架准备好后发布，逐 Dock 初始化并分片发送；不遍历表格单元格、不切换 Tab 以采集。QTabWidget 的显式隐藏项和禁用态保留，内存工作台的五个自绘分段内容页通过 `ksword_navigation_page_titles` 登记。
- R3 协议在 `shared/usermode/KswordPageNavigation.h`，使用有长度上限的 UTF-8 JSON / WM_COPYDATA。双方校验窗口所属 exe 位于同一发行目录，请求令牌和目录代次隔离旧响应；Taskbar 只请求目录或服务端已登记的页面 ID，不传控件指针/函数地址/命令。实际路由保存 QPointer，激活时按外到内恢复 Tab 链并复核可见和启用状态，过期页面要求刷新目录。
- Taskbar 未找到新版 KSword 时显示显式启动入口；运行时点开页面会收起总览并把焦点交给 KSword。主程序和 Taskbar 都要重新构建至统一 `Ksword5.1/x64/Release`，使用者需运行匹配版本。GUI 与跳转效果由用户验收，不能把编译成功当成运行验收。

## 可调背景模糊与字号

- `PageOverviewBackdrop` 在 Qt layered 前景下方维护独立的无激活、无输入原生合成窗口。Windows 11 的 `DWMWA_USE_HOSTBACKDROPBRUSH` 允许桌面采样，`HostBackdropBrush` 自带系统柔化，再接自定义 D2D GaussianBlur 效果；滑条实时写入 `Blur.Amount` 标准差，不以透明度冒充模糊强度。0 隐藏整个模糊层，非零范围为 1–40，默认 20。旧系统或合成初始化失败保留原透明导航，并将调节器标为不可用。
- 背景位置与层序在 `WM_WINDOWPOSCHANGED` 同步，从前景 HWND 读取物理矩形，避免跨 DPI 重复缩放。隐藏时立即隐藏背景，析构关闭合成目标；不截屏、不读取桌面像素、不排除用户截图。底栏调节值保存在 EXE 同目录 `TaskbarPageOverview.ini`。
- 页面正文 11pt、列标题 12pt，顶部控件 10.5pt；仍使用 184px 列宽、25px 页面行、34px 列标题和原窗口尺寸比例。顶部按原 9pt 工具行测量并锁定高度，再增大字体；模糊控件放入原底栏，不新增工具行。GUI 模糊和字号效果仍由用户实机验收。
