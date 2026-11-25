# ActionAnalyze ETW 原始段回读

正式 CLI 启动自有 Provider 并写入 Stored 原始段。样本包含 12 条文件操作观察、采集计划和覆盖回执。QtCore 与 Light 的生产读取器从同一个段读回 12 条记录并逐字节核对。两端保留原始报头上下文和接收时钟。Qt 详情核对归档中实际保留的字节。Light 详情保留原始 JSON 和十六进制预览。

Qt 从「监控 → 行为分析 → 总览」进入监控时间线和结果表。ETW 行沿用 `ResultTableHost` 的 Compact 操作条、详情布局登记及 `StructuredFieldView`。Light 从「监控 → ActionAnalyze」进入原生瀑布、列表与只读详情。ETW 标记在独立泳道。

## 验收回执

- Qt HostX64 Release 构建及语言包审计通过。正式程序 SHA-256 为 `AE3EFCD1D8DF371156187DD48D9E8DAC907ECE76E75D8748845FE8E7A34D6ADA`。构建日志 `.codex-build-logs/ksword-build-check-20261125-011203.raw.log`。
- 正式 Qt 浅色窗口通过归档打开、记录选中、ETW 过滤及选择保留。14 行过滤为 12 行，取消过滤恢复 14 行。载荷详情为 `00 00 00 00 1c 00 00 00`，采集代次和报头 PID 与同一个归档段一致。文件选择步骤使用 Qt 文件对话框。窗口退出 `0`，外观配置逐字节恢复，测试项目删除。日志 `.codex-build-logs/action-analyze-qt-etw-replay.log`。
- Light HostX64 Release 构建通过，复用现有驱动镜像并核对其哈希。正式程序 SHA-256 为 `4A68F2752CBB5DF2E48D77CE7724DC202651A215C5343AB6E880AD79606BFF8C`。Light 验证器通过 35 项 Stored 向量和 2 项 Win32 文件用例，QtCore 通过 17 项 Stored 回归。两端验证器逐条核对正式 CLI 采样。构建及回读日志 `.codex-build-logs/action-analyze-light-etw-replay-build.log`、`.codex-build-logs/action-analyze-cross-reader-etw.log`。

Light 的工作台交互、两端窄窗、DPI、深色及背景模式，以及跨流检查点继续按发布 ToDo 验收。

Light 的「监控 → ActionAnalyze」新增「只看 ETW」复选框，单独作用于瀑布和虚拟列表的显示投影。已选记录被筛掉时继续显示详情。归档没有可识别的 ETW 记录时禁用该条件。HostX64 Release 构建通过，正式程序 SHA-256 为 `D09B10C8ADBE0DA68ABFCC2E62E210A52CC722639346A1AD5C2E612B04070D98`，驱动镜像哈希一致。构建日志为 `.codex-build-logs/action-analyze-light-etw-filter-build.log`。当前会话的启动提权未完成，复选框、键盘、窄窗和主题的正式窗口验收待执行。

## Qt 项目目录回放

在「监控 → 行为分析 → 项目与采样」打开测试项目，选中已登记采样并点击「打开采样归档」。正式窗口切换到总览，显示项目和采样 ID 均匹配。ETW 筛选执行 `14 → 12 → 14` 行切换并保留原详情。加载器回归另验错采样不发布行。窗口退出 `0`，配置已恢复，测试项目已删除。正式程序 SHA-256 为 `36F6FABA9F64EF0C9F3402D72EAA8B757778F1C8B2607762D44147738602A221`。日志为 `.codex-build-logs/action-analyze-qt-etw-project-replay.log` 和 `.codex-build-logs/action-analyze-bound-reader-etw.log`。本次覆盖固定首个 Stored 原始段。

重试验证将测试文件临时替换为同项目的另一采样段。点击原位重读后，窗口报告采样不匹配，原表及选中详情保持不变。恢复文件字节后，原位重读回到文件末尾状态，保留同一选择。窗口退出 `0`，配置逐字节恢复，测试项目删除。日志为 `.codex-build-logs/action-analyze-qt-etw-project-retry.log`。

## 目录身份绑定复验

项目与采样是主列表页，使用共享工作台内容框、工具行、`ResultTableHost` Compact 操作条和 `StructuredFieldView`。显式打开冻结项目路径和采样 ID，然后由同一总览发布结果。总览保留时间线和结果表，读取失败留在原位置重试。读取器同时核对冻结目录推导的路径、打开句柄的最终路径和段头身份。QtCore 的 17 项 Stored 断言通过，并读回正式 CLI 的 12 条 ETW 观察及原始字节。使用相同 UUID 和其他项目目录的请求被拒绝。日志为 `.codex-build-logs/action-analyze-qt-project-reader-audit.log`。

正式主程序 HostX64 Release 构建、双语审计和主题门禁通过。`Ksword5.1/x64/Release/Ksword5.1.exe` 的 SHA-256 为 `E9AE806F29994C332D0D992ADD0B78D2E8ACE7BF87F51B3A2EA504B4B9C39047`。在同一产物上复验目录直达、`14 → 12 → 14` 行筛选、错采样保留详情和恢复后重读。实时活动分析读回同一 PID 的两个区间，首条为 1000 毫秒、CPU 218.750 毫秒、读写各 3,670,016 字节。无效 PID 保留前次结果，启用权限受限的 Kernel-File 后仍能继续进程活动采样并报告来源失败。窗口与目标退出 `0`，测试项目和样本文件已删除，外观配置已逐字节恢复。

构建与实测日志为 `.codex-build-logs/ksword-build-check-20261125-021117.raw.log`、`.codex-build-logs/action-analyze-qt-project-bound-final.log` 及 `.codex-build-logs/action-analyze-qt-live-integrated.log`。实际窗口验证覆盖浅色主题与右侧详情布局。键盘全路径、窄窗、DPI、深色、背景模式、完整列与导出操作、框选和恢复实时继续按桌面矩阵验收。项目直达当前读取首个 Stored 原始段，跨流检查点仍由 CLI 校验。
