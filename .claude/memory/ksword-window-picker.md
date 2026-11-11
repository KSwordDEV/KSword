# 进程/窗口准星拾取与 Ctrl 预览

## 2026-11-08 补丁：统一不透明与 60°/75°

- 用户最新要求替代下述历史参数：默认右倾 60°，唯一悬停/键盘检查态 75°，全部截图均为 100% 不透明。深度轴继续缩短为 1/2，75° 分量为 `(-0.129409522551, 0.482962913145)`。信息列以默认截图的中心计算纵向位置，不再保留最初 45° 时的固定 y=38。
- 保留统一投影绘制/描边、两态预留 bounds、稳定 hover 命中、Z 序和全屏语义；没有新增用户文本或导航页面，布局仍由 SecondaryPageLayout 加专业 QGraphicsView 承担。
- 四组 Qt 缩放因子 1/1.25/1.5/2 各 44 项通过（176 项），日志 `.codex-build-logs/window-target-picker-tests/opaque-60-75-result.log`，默认与检查态实际像素 alpha 均验证为 255。WGC 与生产 GUI 仍沿用后文的未完成验收边界。
- 首轮 `.codex-build-logs/ksword-build-check-20261108-043142.raw.log` 编译/语言包/主题门禁通过，链接因运行中的 exe 报 LNK1104。用户手动关闭后，另一项相同 Release/x64 构建先完成链接；随后本任务的最终构建 `.codex-build-logs/ksword-build-check-20261108-043820.raw.log` 明确 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，复用新产物（`ARTIFACT_UPDATED=False`）：33,027,992 字节，SHA256 `11BCFB61A9531E44333463DB87D8F8BAFB402A2D26218D47DC900D19F19919DD`。未为更新产物终止用户进程或并发启动链接。

## 2026-11-08 悬停检查态与全屏

- 用户追加要求按悬停态处理：唯一高亮的截图采用 100% 不透明度及 60° 右倾投影，移出后恢复 60% 不透明度与 45°。斜深度轴长度继续为 1/2，60° 分量为 `(-0.25, sqrt(3)/4)`；图像、边框使用同一投影。信息列及各层 x 位置不移动，保持真实 Z 序。
- 图形 boundingRect 从构造起覆盖两种角度，避免悬停改变滚动范围；高亮态命中包含原进入轮廓与当前 60° 轮廓的并集，防止截图变形后从静止鼠标下缩走导致反复 enter/leave，同时保证新增可见区域可点击。
- 预览窗由 Qt::Tool 改为普通 Qt::Window，保留 SecondaryPageLayout 和响应式尺寸，启用原生最小化/最大化按钮与 size grip。F11 在普通/最大化与全屏间切换，退出恢复进入前是否最大化；全屏 Esc 先退出全屏，普通态 Esc 仍取消。最小化产生的失焦不关闭窗口，其余失焦取消语义保留。双语帮助提示同步 F11/Esc 语义。
- 四组 Qt 缩放因子 1/1.25/1.5/2 各 44 项通过（共 176 项），记录 `.codex-build-logs/window-target-picker-tests/fullscreen-hover-result.log`。新增角度、100% alpha、稳定 hover 轮廓/布局范围、viewport 内 F11、Esc 退出全屏及最大化恢复验证。原生窗口状态消息需要排空后再执行下一次切换，不能把同一调用栈内连续切换的暂态当作最终状态。主程序实际 GUI 与 WGC 仍沿用下文未完成边界，组件窗口测试不代表生产 GUI 验收。
- 最终 HostX64 Release 构建、i18n 和主题门禁通过：`.codex-build-logs/ksword-build-check-20261108-040222.raw.log`，`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，主程序 33,019,392 字节。

## 2026-11-08 用户实测后的预览修正

- 右倾指上沿相对下沿向右：投影的 y 基向量改为 `(-1/sqrt(8), +1/sqrt(8))`，再平移到左边界 0。Z 层只沿 y 轴间隔 88，不再逐层额外右移；原 18px 的 x 偏移是实现附加的摆放，与斜二测本身无关。
- `QGraphicsItem::isUnderMouse()` 是几何包含判断，不能表达遮挡后唯一命中；和 `hasFocus()` 相或还会保留旧层高亮。`PreviewScene` 只存一个高亮层，由实际 hover enter/move/leave 和键盘焦点事件交接，绘制只读取此状态；鼠标经过其它层会清除旧焦点层的描边。
- 窗口标题、进程图标/可执行文件名/PID 和捕获状态移到截图右边 24px 外的独立信息列，按层居中对齐，保持不透明；信息列也参与所属层命中。名称和 Shell 图标在原枚举 worker 里按本次 PID 去重查询，传回 QImage，失败时使用进程占位图标及明确不可用文本。没有新增业务页面，导航与 SecondaryPageLayout/专业视口例外沿用下表。
- 截图不透明度从设定的 76% 改为 60%。截图像素下不能再铺同透明度实底，否则 60%+60% 合成会变成 84% 不透明；底色仅填 letterbox/无截图区域。信息列、主题描边和文字不跟着淡化。
- 新增真实组件回归覆盖右倾、各层相同 x、外部信息列、进程名及原生图标、残留键盘焦点下的独占 hover、信息列命中、实际像素 alpha 和截图下沿无标签遮盖。四组 Qt 缩放因子 1/1.25/1.5/2 各 33 项通过（共 132 项），日志 `.codex-build-logs/window-target-picker-tests/right-lean-result.log`；WGC 仍因非输入桌面明确跳过。Qt 的 QWidget `QTest::mouseMove` 在 Windows 依赖原生光标队列，非输入桌面需向 viewport 发送局部 MouseMove，以验证实际 QGraphicsScene 的 hover 分发，不用 `isUnderMouse()` 当作事件已送达的证据。
- 本轮最终 HostX64 Release 构建、i18n 和主题门禁通过：`.codex-build-logs/ksword-build-check-20261108-034945.raw.log`，`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`；主程序 33,017,856 字节。上一版已获用户实测反馈，本轮实际主程序的方向/信息列/透明度和深浅主题视觉仍待复测，不把组件像素检查记为生产 GUI 验收。

- 2026-11-08：`ProcessDock` 和 `OtherDock` 原有拖拽按钮把 Qt 全局逻辑坐标直接传给 `WindowFromPoint`，混合 DPI/非 100% 缩放会偏移。两页改为共享 `UI/WindowTargetPicker`，在左键释放处理开始处以原生 `GetCursorPos` 和 `GetAsyncKeyState(VK_CONTROL) & 0x8000` 同时采样；原生调用使用可恢复的线程 PMv2 上下文。拖拽阈值也使用物理点，保留负坐标，不能把整个虚拟桌面坐标简单除以单个 DPR。
- 不按 Ctrl 仍直接拾取原始 HWND；Ctrl 松开枚举包含该物理点的可见、非最小化、非 DWM cloaked 顶层窗口，保留遮挡窗口，排除预览窗本身。按原生 Z 链排列，不枚举子控件。用户确认窗口画面本身变为斜二测平行四边形，按 Z 序上下分层，半透明图像，悬停主题色描边；窗口标题和状态文字保持水平且不透明。滚轮滚动、Ctrl+滚轮缩放，Esc/右键/关闭/失焦取消，一个候选仍需点击，无候选明确提示。
- 静态截图通过单帧 Windows Graphics Capture 获取独立窗口合成内容；不能以屏幕 BitBlt 代替被遮挡窗口画面。使用 `CreateFreeThreaded`、MTA、单个在途 `AsyncOperation` 和有界取帧等待；截图/缩放不在 GUI 线程。关闭先关闭异步门禁，失败/受限/窗口失效分别显示状态。选择完成后传递选中的 HWND，不得再次按原始点调用 `WindowFromPoint`，否则会重新选到遮挡窗口或预览窗。

## 导航与布局接入

| 导航入口 | 页面类型 | 本次接入 |
| --- | --- | --- |
| 进程列表 → 工具行准星 | 主列表工具动作 | `WindowTargetPickerButton`、共享中性按钮及 CompactIconButtonMetrics；原 Full 表格操作条、过滤/快照/详情路径保留 |
| 窗口 → 窗口管理 → 窗口列表 → 准星 | 树清单工具动作 | 同一共享按钮；原 NormalizeToolbarRow、树/详情/导出/列语义保留 |
| 进程详情 → 惰性窗口列表 → 准星 | 同上 | `ProcessDetailWindow.BaseAndUi.cpp` 工厂创建 `OtherDock(WindowListOnly)`，自动复用相同接入 |
| 上述准星 Ctrl 松开 → 选择目标窗口 | 非属性类二级工具窗＋专业图形视口 | `SecondaryPageLayout` 的窗口/内容/底栏、`applyResponsiveWindowGeometry`、`ThemeBinding`；QGraphicsView 保留投影、缩放和内部滚动，不套详情卡片或参数双栏 |

- 按松开点的原生 HMONITOR 匹配 QScreen，再使用该屏的逻辑工作区放置二级窗。主题色描边附加对比底线；文本来自主题 token，外部窗口标题强制纯文本并省略过长内容。中英文包只定点增补，新源码登记 vcxproj/filters。

## 验证边界

- `tools/Invoke-WindowTargetPickerTests.cmd --dpi-matrix` 编译实际共享拾取器、AsyncOperation 和 LanguageManager。装饰/通用布局是明确的测试适配口，不能据此验收生产布局。四组 Qt 缩放 100%/125%/150%/200% 各通过 22 项（共 88 项）：重叠枚举、Z 序、隐藏/最小化排除、负物理坐标、原生点命中、上下层图形命中、hover/点击、右键/Esc 取消、选择 HWND 的一次回投、关闭窗口状态与异步关闭。
- 受控 WGC 真截图/遮挡像素断言仅在当前线程桌面与输入桌面一致时执行。Codex 默认 exec 在 `CodexSandboxDesktop-*`，输入桌面是 `Default`；现场 `GraphicsCaptureSession::IsSupported`/`CreateForWindow` 返回 `0x8007000E`，不能把它记为已捕获或简单归为图像尺寸问题。该环境下回归明确输出 `CAPTURE_SKIPPED`/`OCCLUDED_CAPTURE=SKIPPED`，图形命中用测试图，不能算截图成功。
- 主程序真实 GUI 的 Computer Use 启动授权超时，重试返回未获授权；未完成生产窗口截图、实际 Ctrl 松开、多显示器原生混合 DPI、深浅主题/背景模式、长文本和窄窗视觉验收。用户需在正常桌面验收；组件缩放矩阵不代表这些实机项目通过。
- 最终 HostX64 Release 主程序构建、i18n 和主题门禁通过：`.codex-build-logs/ksword-build-check-20261108-033319.raw.log`，`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，产物 `Ksword5.1/x64/Release/Ksword5.1.exe` 为 33,010,688 字节。组件结果在 `.codex-build-logs/window-target-picker-tests/result.log`。这不替代上述未完成的正常桌面截图及真实主程序 GUI 验收。
