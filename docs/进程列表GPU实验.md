# 进程列表 GPU 绘制实验

进程列表保留原来的 FlatTableModel、排序代理、ProcessRowHighlightDelegate 和表格动作条，
仅在明确启用时把可见区域绘制交给 OpenGL。进程枚举、性能采样、排序与模型增量发布仍在 CPU 上执行。

## 启用和对照

先退出已运行的主程序，避免单实例机制只激活旧实例。从仓库根目录启动：

    $env:KSWORD_PROCESS_LIST_GPU = '1'
    & .\Ksword5.1\x64\Release\Ksword5.1.exe

关闭实验后，重新启动即使用原光栅视口：

    Remove-Item Env:KSWORD_PROCESS_LIST_GPU -ErrorAction SilentlyContinue
    & .\Ksword5.1\x64\Release\Ksword5.1.exe

如需在光栅模式使用同一 CPU 提交计时口径，启动前设置
KSWORD_PROCESS_LIST_PROFILE=1。默认光栅模式不计时。

构建依赖新增 Qt OpenGL 和 OpenGLWidgets，主程序既有的 windeployqt 步骤负责部署
Qt6OpenGL.dll、Qt6OpenGLWidgets.dll。不能只替换 exe 而遗漏新增依赖。

## 实现和回退

- ProcessGpuTableView 继承原动作条宿主，只应用于进程主列表。
- Paint 先交给 QOpenGLWidget 创建上下文、绑定 FBO，再在 paintGL 内调用原表格绘制。
  不能在 QAbstractScrollArea 的事件过滤器中抢先绘制到尚未绑定的 FBO。
- GL 帧使用不透明 Base 底色并重绘整个可见区域，不依赖 QWidget backing-store 的位图滚动。
  这避免局部刷新、滚动、缩放后残留旧行，但也可能增加小面积更新的成本。
- 创建上下文/FBO 失败、发现常见软件 renderer 或运行于 offscreen/minimal 平台时回退。
  软件 renderer 检测是常见名称过滤，不是覆盖所有第三方实现的硬件鉴别机制。
- 回退在下一轮事件循环替换视口，不在 paintGL 内销毁 GL 控件；保留模型、selectionModel、
  选区、滚动位置、动作条和冻结预留，并重新接入进程行委托的悬停过滤器。
- 没有改变应用全局 surface format、进程刷新策略、驱动接口或默认渲染后端。

GUI 线程可读取以下动态属性判断实际后端：

| 属性 | 含义 |
| --- | --- |
| ksword_process_render_backend | raster / opengl_pending / opengl |
| ksword_process_gpu_renderer | 真实 GL_RENDERER 名称 |
| ksword_process_gpu_fallback | 回退原因 |

CPU 提交计时通过 paintCount()、lastPaintNs()、totalPaintNs() 读取。
不逐帧发布 Qt 动态属性，避免额外触发全局动作条属性事件。
这些数据不包含 GPU 执行完成等待、呈现延迟或进程采样耗时。

## 独立验证

从仓库根目录运行：

    & .\tools\Invoke-ProcessGpuViewTests.ps1
    & .\tools\Invoke-ProcessGpuViewTests.ps1 -Offscreen

夹具直接编译生产视图，使用真实 Qt 模型、委托和 GL framebuffer。
窗口设置 DontShowOnScreen，不启动主程序、不枚举或操作用户进程。

2026-10-09，本机 NVIDIA GeForce RTX 4060 Ti 硬件回归通过 20 项检查，
覆盖实际单元格像素、滚动、缩放、冻结区域预留、委托绘制、计时及回退后的模型/选区/
滚动位置/动作条/悬停过滤器。offscreen 回归通过 6 项检查。

一次 1000 行、3 列、相同尺寸与同类委托的隐藏窗口实验各绘制 80 帧：
光栅 CPU 提交均值约 696 us，OpenGL 约 625 us；包含事件处理的墙钟时间分别约 79 ms、76 ms。
测试时主程序仍在编译，负载与缓存会影响结果；多次观察有明显波动，不据此承诺生产性能提升。

## 待验收边界

尚未以主程序真实进程列表验证复杂 CPU 单元格、图标、树状缩进、大量可见列、主题背景图片、
Dock 浮动/重新挂载、跨 DPI 显示器、远程桌面和设备丢失等场景。GL 视口采用不透明底色，
透明背景/背景图片组合需单独评估。冻结区域测试只验证预留几何，没有运行完整冻结控制器。

Qt 6.4 起，向已显示窗口懒加载首个 QOpenGLWidget 可能重建顶层原生窗口，
而整个顶层窗口的最终合成也会转为 OpenGL。进程 Dock 恰好采用懒加载，
因此必须验证原生 HWND 关联、标题栏、透明背景和其他 Dock 的合成兼容性；
本实验不能被解释为完全局限于单个表格的呈现变化。这也是默认关闭的原因之一。

下一步应在相同真实进程快照、列布局和刷新间隔下比较滚动、局部刷新和 CPU 占用，
同时观察真实呈现延迟，再决定是否扩大试用或默认启用。
Qt 官方绘制及生命周期依据：
[QOpenGLWidget 6.9](https://doc.qt.io/archives/qt-6.9/qopenglwidget.html)。

## 主程序构建验证

2026-10-09，标准 x64 MSVC Release Build 在全核 /MP24 续编后通过。
BUILD_RESULT=SUCCESS、EXIT_CODE=0、I18N_AUDIT_PASSED=True，耗时 224 秒。
产物 Ksword5.1/x64/Release/Ksword5.1.exe 为 24,132,504 字节。
SHA256：9D10EC580BE7093E440C8728D5D6EDC1D465B74EF74AA2262CDCE227BD6DBD39。
原始日志：.codex-build-logs/ksword-build-check-20261009-162151.raw.log。
编译与链接完成不替代上述真实主程序 GUI 场景验收。
