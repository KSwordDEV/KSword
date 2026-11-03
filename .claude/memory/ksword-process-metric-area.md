# 进程列表矩形面积视图

- 导航：进程 Dock → 进程列表（全部列预设/自定义列）→ 可量化度量列表头右键 → 矩形面积视图。仅进程主列表接入，线程、交叉视图和其它 Dock 没有新增入口。
- 页面类型：独立二级图表工具窗，使用 `UI/MetricAreaWindow`、`SecondaryPageLayout::StyleSecondaryWindow`、共享工具行和内容面；零值/不可用项使用 `TablePresentation`，操作条明确为 None。`MetricAreaCanvas` 是专业自绘图表，保留内部几何与命中，不套字段详情框架。窗口几何通过 `applyResponsiveWindowGeometry`。
- 窗口显式启用原生最小化/最大化按钮，关闭帮助按钮并启用缩放手柄；尺寸仅由响应式初始/最低边界约束，允许拖动缩放和最大化，画布按 resize 重新分配矩形。
- 入口按资源/计数白名单：复用 `processUsageHighlightValue` 的语义分类并补 CPU核心原始数值；不是凡能数值排序都接入。PID/PPID/Session、优先级、地址、时间、状态码/布尔、注入面和已淘汰 RAM 列不接入。
- 面积取原始数值的绝对值，文本沿用原表格式；负增量保留正负号并说明面积口径。私有进程值只计一次，父矩形总量为自身与子树之和，自身仍有独立叶格；友好模式使用共享投影器已作出的分类和应用根，包含主列表折叠分组中的进程。搜索或扁平排序时平铺。
- CPU/CPU核心图按主表 CPU 汇总的同一规则排除 PID=0 或名称为 System Idle Process 的行，面积分母和零值列表均不含 Idle；删除后重映射父索引。其它度量保留原进程范围。
- 窗口没有采样计时器。仅 `rebuildTable` 成功提交后捕获同一数据源；暂停/历史状态变化只更新状态，图标和换肤通过合并回调重投影已有快照，不查询当前进程值。每列复用一个窗口，多列可同时打开。
- 图标→名字→PID 按空间显示；双击可放大，返回按钮/Backspace 返回父级。零值和不可用有明确状态并列于下方，不伪造最小面积；极小矩形保留命中和悬停。替换数据立即更新命中，放大范围按稳定 key 恢复。
- 矩形面积画布随“启用界面动画”实时切换：启用时使用共享鼠标跟随光照；关闭时恢复早期表格背景色与 Base 合成的平面外观，无数据背景时回退 AlternateBase，并停止该画布的光照计时器。动画设置通过弱引用观察者仅通知已登记画布，不遍历控件树；共用渲染器的 NTFS 空间图保留原行为。
- 进程格的右键复用 `showBoundProcessContextMenu`，原主表也走该实现；动作仍由原身份校验执行。右键值冻结为 PID＋创建时间及对应度量行，不从当前位置重新取目标。复制单元格/行使用右键冻结行；测试不写真实剪贴板。
- 验证入口：`python tools/metric_area_tests.py`（真实 Qt 画布及生产度量白名单，100%/150%）和 `python tools/process_activity_tree_tests.py`（历史树/友好投影）。实际主程序 GUI 验收、构建与剩余项按当次报告，不以组件测试替代完整 GUI。
- 2026-11-01 首轮主程序 HostX64 Release 已构建成功；Computer Use 对启动该程序返回 `Computer Use was not approved to use 1`，未绕过权限换用其它 UI 自动化。因此完整主程序菜单、多个窗口和主题/背景的实机视觉仍待用户验收。用户明确本轮不提交，改动留在工作区。
- 同日进程列表“数值一变就取消单选”的确定路径：ApplicationAggregate 允许选中且活动图会展开其 actionIdentityKeys，但 syncTrackedSelectionFromTable/rebuildTable 原来只接纳真实 Process 行，把聚合行当作非法选区清空。选择跟踪、当前行比较和索引恢复统一使用 processTableSelectionKey：进程仍是 PID＋创建时间，聚合为 aggregate:＋稳定 expansionKey，分类标题返回空键。m_trackedSelectedIdentityKey(s) 因而是 UI 行身份，不能直接当成驱动进程身份；菜单动作仍从行数据解析真实成员，活动图仍读取真实进程键。原目标消失且没有可恢复选项时同时 clearCurrentIndex，防止相邻行成为隐式回退目标。
- 选择回归入口 `python tools/process_selection_tests.py`，抽取生产选择跟踪/恢复/活动图目标方法，编译实际 FlatTableModel 和 Qt 视图，通过真实左键及 Ctrl 点击验证数值刷新、代理重排、模型重置、实时/历史标记、混合多选、PID 复用与父行移除。132 项通过；`--source-ref HEAD` 对旧代码同一组检查报 94 项失败。只替换业务采样/图表外壳，不访问驱动、剪贴板或用户进程；这不代替主程序实机 GUI 验收。
- 选择修复后的 HostX64 Release 构建成功（`ksword-build-check-20261101-072153.raw.log`，退出 0），语言包/主题门禁通过；主程序视觉和连续实时操作仍待用户重启正式 EXE 查看，未提交。
