# 共享 UI 组件重构验收记录

日期：2026-10-08。本轮覆盖批准的全部七项组件；七个功能节点已分别提交，独立审计所报问题全部闭环。以下断言来自实际生产类或提取的完整生产方法；后端端口使用受控替身。

## 实现与专项验收

源码路径相对 `Ksword5.1/Ksword5.1/`；MetricHistory、MetricChartBinding 位于仓库 `shared/ui/`，HUD 调用方位于 `KswordHUD/`。

| 组件 | 实现和代表接入 | 通过断言 | 提交 | 验收日志 |
| --- | --- | ---: | --- | --- |
| 结果表宿主 | UiCommitCoordinator 与 ResultTableHost 统一延迟/原子提交、搜索基线和列能力；TCP/UDP 连接页实接。 | 56 | `5f0c9331` | `output/result_table_tests.log` |
| 任务中心 | 显式 Running/Waiting/Success/Failure/Canceled 与兼容终态；100ms 共享快照、稳定任务 ID、增量复用卡片；服务操作实接。 | 1304 | `9e37d0f0` | `output/task_center_tests.log` |
| 异步操作 | 单运行、最新 pending、代次与取消门禁；后台只携带值请求，模块/句柄详情及菜单延期回填实接。 | 54 | `b60c056f` | `output/async_operation_tests.log` |
| 指标历史 | MetricHistory 与 MetricChartBinding 统一 ID、时间、有效性、容量及轴策略；Hardware/MonitorPanel/HUD QSeries 实接，Hardware 镜像共用模型。 | 68 | `9be310f3` | `output/metric_history_tests.log` |
| 通用时间轴 | EventTimelineModel 保留原始事件并按像素预算聚合；定向 ETW、全局 ETW、TCP/UDP 网络流量三类实接。 | 65 | `10a1e2ae` | `output/event_timeline_tests.log` |
| 详情布局 | 显式登记 splitter/main/detail，四布局策略与模型重绑；DeviceManager、NamedPipe 实接，旧注册调用保留适配。 | 54 | `6760c4df` | `output/detail_pane_tests.log` |
| 主题绑定 | 显式弱引用登记、合并刷新与 FollowApplication/PreserveLocal 策略；标题栏、命令弹窗实接，保留未登记节点补偿。 | 29 | `51c19e54` | `output/theme_binding_tests.log` |

七项专项共 **1,630 条断言通过**。三个指标消费者、五个时间轴生产源文件（涉及三类调用方）、TCP/UDP 连接页以及两处显式详情接入均完成真实源码独立编译。主程序新增 19 个、HUD 新增 4 个源/头文件的 project 与 filters 注册均唯一且文件存在；新拆分源码均少于 1,000 行。

## 审计修复

| 触发条件 | 修复后的行为 | 主要证据 |
| --- | --- | --- |
| 同键旧提交延期后又立即提交新结果，或搜索回捕后更换模型 | 丢弃旧提交，按模型代次核验搜索回捕；无效目标不能把原子组降为部分提交。 | `UI/UiCommitCoordinator.cpp:206`，结果表 56 项 |
| 首次订阅或发布期间重入、销毁 receiver/feed | 先冻结快照与 callable，检查弱引用；嵌套刷新排到下一 revision。 | `Framework/TaskSnapshotFeed.cpp:33`，任务中心 1,304 项 |
| 状态回调重投、关闭对象或抛错，菜单内延后结果回填 | 重新核验对象、请求代次与实体身份，资源释放与任务启动各仅一次。 | `UI/AsyncOperation.cpp`，`output/async_operation_tests_red_*.log` |
| GPU/PDH 读取失败、每核部分失败、有效零值、HUD 延迟送达 | API 状态、CStatus 与有限值决定独立有效位；进入共享历史的无效点形成 line/baseline gap；采样时间保留后台完成时刻。 | `output/metric_history_cpu_red.log`，指标 68 项及实际/动画像素图 |
| UInt64 全幅时间窗缩放或选区回调替换/销毁自身 | 有界整数缩放与乘除计算保留端点；先复制 callable/区间，再通知外部。定向 ETW 使用 eventName 区分线程/映像。 | `output/event_timeline_wheel_baseline.log`、`output/event_timeline_callback_baseline.log` |
| Show 注册新 host 并关闭 owner，浮窗 Show 或 inline Resize 同步切布局，旧排队点击遇到原地数据重建 | 注册表与几何迭代持弱引用快照，每步探活并核验代次；浮窗不再解引用旧成员。prepareDataRebuild 取消旧点击。 | `output/detail_pane_registry_red.log`、`detail_pane_floating_red.log`、`detail_pane_geometry_red.log`；最终 54/0 |
| 绑定刷新忙时嵌套登记新策略，图标在瞬时按下背景上缓存，取消按下后按钮无 Paint | 刷新请求保留至当前回调结束；编辑器透明图标读实际父表面，QSS 完成后重绘，Palette/Style/取消事件合并补刷。 | `output/theme_binding_nested_red.log`、`output/component_theme_probe.log`；主题绑定 29 项、主题集成 796 项 |

普通 QTableView 的 Embedded 使用原生逻辑行高；普通 QTreeView 的 `supportsInlineDetails=false`，保留 requested=Embedded 并以 effective=Right 显示详情，避免静默隐藏。缺少时间的历史样本原样保留，ElapsedTime 投影排除 timestampMs=0；不会把未知时间当成 epoch。

## 集成与完整构建

| 检查 | 最终结果 | 日志 |
| --- | --- | --- |
| 主题组件及编辑状态、真实图标像素往返、父工具栏独立调色板 | 796 / 0 | `output/component_theme_integration.log` |
| 共享文本视图，最终生产源码 `/W4 /WX` | 148 / 0 | `output/component_detail_integration_final.log` |
| 搜索历史与标题栏/命令弹窗 | 1,044 / 0 | `output/component_search_integration.log` |
| 主题恢复、旧补偿与图表渲染 | 6,402 / 0 | `output/component_theme_recovery.log` |
| 双语全量审计 | 28,890 source strings，通过 | `output/component_i18n_audit.log`，最终主构建同步通过 |
| 主程序 HostX64 Release/x64 | BUILD_RESULT=SUCCESS，EXIT_CODE=0，23,792,640 bytes | `output/component_main_build_final.log`；`.codex-build-logs/ksword-build-check-20261008-214659.raw.log` |
| HUD HostX64 Release/x64 | Build 成功，452,608 bytes | `output/component_hud_build_final.log` |

下列哈希对应本轮成功验收构建时的标准 Release 产物读回：

- `Ksword5.1/x64/Release/Ksword5.1.exe`：`171C7D75FE2770E35FA17D6DE24FF8FDE5DEAD9AA703B18FB91F21495FEA490A`。
- `Ksword5.1/x64/Release/KswordHUD.exe`：`C7BB7E381EB5CBB372746C0DB933670DF64B40D71D66CB4126E6782677453910`。

保留的中间失败日志 `output/component_main_build_final_fail.log` 记录并行 HexCanvas.Layout.cpp 缺少 QPointer 包含导致的编译失败；该并行源补齐后，最终完整构建成功。本轮没有收编 Ghidra、HexCanvas 或其它并行功能修改。旧主题回归的括号着色与按钮背景假设已按迁移后的真实词法/ExtraSelections/QSS 契约更新，保留文本、光标、滚动、modified、undo、对比度、SVG 身份和精确像素还原断言。

提交后再次读回，共享 Release 主程序的哈希已更新为 `99E8638F1FC77203738EAC7C56315713D74AF70CD8D9457D281E87E0E624FF20`，不同于上述验收快照；HUD 哈希未变。本轮验收固定引用成功构建日志及当时的产物哈希，不将后续共享目录产物混作该次构建。

## 保留边界

- 这是共享组件层与上述真实调用方的迁移；不表示仓库所有旧调用点、图表或局部样式已全部替换。旧表格/详情注册与主题 RGB 补偿仍承担兼容工作。
- 旧 progress=100 没有明确结果时记为 LegacyCompleted，界面保留旧接口立即隐藏行为。旧无代次复用调用继续兼容，不推断业务成功。
- HUD 专用每核 CPU sparkline、Hardware 内存组成自绘、PerformanceNavCard 的专用短历史保留原底座。HUD 复用模型算法，跨进程不共享模型实例。
- 离屏 Qt 与受控后端回归、静态审计及编译链接不替代正式 GUI、实机 PDH/GPU、真实 ETW/网络、模块/句柄/服务或驱动验收。本轮未部署、签名或加载驱动。
- 所有提交按确认文件/条目定点暂存；并行未提交改动保留。本轮完成本地提交，未推送。
