# 硬件 Dock 的字段回填

- 2026-10-30 USB 设备、设备栈、键盘与鼠标、系统总线的普通字段页共用 `HardwareDock.cpp::createReadOnlyFieldPage`，必须调用 `StructuredFieldView::setValueModelProjection()`。审计查询已在后台，但兼容原生树仍会在 GUI 线程整树创建、展开、搜索和测量；R0 全风险摘要可达 1024 行、上万字段。不能仅把查询搬到后台便认为 UI 工作已解决，也不要恢复同步 `tree()` 依赖。
- `queryPowerShellFieldsSync` 的失败“采集状态”节点使用 `initiallyExpanded=false`；状态和原始诊断仍保留在唯一 `FieldDocument` 中，搜索/复制/导出不因折叠丢数据。用户显式展开后由共享值模型保留同身份阅读状态。
- 独立回归 `tools/test_hardware_field_page.py` 抽取真实工厂/失败处理并链接当前 Release 对象，提供 1024 行/13312 字段、深层搜索、隐藏恢复和销毁保护检查。只替换 PowerShell 输出，不执行 CIM/R0 或操作系统剪贴板；不是完整产品 GUI 验收。
- 本次 Release/x64、语言包/主题门禁与 23 项组件检查通过。`FieldTreeModel` 每批 128 项，但实际视图可能因 Qt 布局自动取后续批次，不能对连接视图后的 rowCount 强断言始终为 128。真实主程序启动未获 computer-use 批准，实际 USB 响应性、深浅主题/背景/DPI/首帧仍未完成验收。准确证据与范围见 [修复记录](../../docs/硬件USB响应性修复-20261030.md)。
