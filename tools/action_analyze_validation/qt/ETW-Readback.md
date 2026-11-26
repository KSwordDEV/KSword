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

## Qt 项目检查点

「监控 → 行为分析 → 项目与采样 → 打开采样归档」继续通过总览的共享工作台、Compact 结果表及结构化详情显示结果。读取器复用 CLI 的只读项目校验，核对冻结的采样描述散列、`raw/1` 和 `records/1` 的提交水位及散列。实际投影从本次打开的句柄复核原始前缀，再读取水位以内的记录。缺少标记的旧档会显示未发布检查点，独立段仍走原预览入口。

正式 Qt 与 CLI 的 HostX64 Release 构建均退出 `0`。产物分别为 `Ksword5.1/x64/Release/Ksword5.1.exe` 和 `KswordCLI.exe`。Qt 的 SHA-256 为 `53739C55F616F3E9CE0FDFBAF3B567E6EA31A2BA7895DF6D37D43A743C8BF4BF`，CLI 为 `BE9EC3FA0F35289D84EF2C7A4058CBA727D346001CCCC3DED50165BE78389D98`。双语审计通过 31,643 条文本，主题门禁通过。QtCore 通过 17 项 Stored 回归，并用正式 CLI 的自有样本核对 12 条记录、载荷及冻结描述负控。

正式窗口显示 14 条原始记录，ETW 筛选显示其中 12 条。两条流末尾追加未提交的字节后，重读仍保持原表与选中详情。替换成另一采样的原始段或删除 Coverage 段时，窗口报告检查点失败并保留原结果。移走标记时显示旧档回退，恢复标记后再次显示检查点已验证。窗口退出 `0`，外观配置已恢复，测试项目已删除。日志 `.codex-build-logs/action-analyze-qt-checkpoint-gui.log`，构建日志 `.codex-build-logs/ksword-build-check-20261125-022100.raw.log`。本轮使用浅色主题和右侧详情布局，其余桌面矩阵继续验收。

## 项目工作台与三端同采样

- Qt 默认进入「监控 → 行为分析 → 项目与采样」。正式 HostX64 Release 核对空项目的新建入口、同一项目两轮独立扫描、断点定义修订冻结、重启后回查第一轮及坏中段重读。第一轮有 21 条观察，含 12 条 ETW 报头。外观与 ADS 配置均已恢复，固定测试目录已删除。Qt 产物 SHA-256 为 `0df858036bd833f751f32e19a0fd9492855c55b5810ceb6b2b99223e81ae3334`。
- CLI 导入同一个五类合成 API 采样 `40ee5116-3d82-4098-8fea-bdbca03b7759`，Qt 和 Light 均在目录选择时自动预览并完整回放。Qt 的「查看采样记录」定位最新线索，`QT_SAMPLE_TRACE_TO_RECORD=PASS` 对应记录 5、源行 7。两端均核对五类原始坐标、来源筛选、坏尾隔离和修复重读。
- CLI、Qt、Light 串行核对同一自有 ETW 采样 `9582d8b7-8bfe-4e79-a8be-d8052c38bda6`。CLI 写入 8 个运行段和 1 个终段，处理 4,101 个查询 ID，停止时 ETW 事件和队列报告丢失均为 0。Qt 和 Light 各回放 642 条记录，ETW 筛选各显示 624 条，最后一条 ETW 观察位于第 8 段的记录 639。Light 首段自动预览 14 条，缺第二段标记时保留 14 条，第三段覆盖流损坏时保留 28 条。恢复后读回 642 条。窗口退出 0，配置恢复，固定项目目录已删除。
- Light 正式 HostX64 Release 从默认页新建空工程，在同一自有 PID 上连续采样两轮，各写 2 段，分别核对 12／14 条 ETW 载荷和 16／18 条原始记录。两轮终态报告 ETW 丢失、队列丢弃均为 0。重启后可打开同一工程，回放第二轮 `4d3d0309-d979-439a-b2e9-5c695bb38f86`。两次窗口退出 0，配置恢复，固定目录已删除。Light 产物 SHA-256 为 `768e1db335e6c91e99456cda05373615edb159c66e92da9b0624c4f8257437b3`。
- Qt 正式窗口在采样 `dbed4f1f-893c-466a-ab4c-51a3555c3b85` 选择第一条线索，进入总览后核对 `raw/1 #1`、源行 `2`。五条线索的 64 字节预览、独立筛选、坏尾恢复和选择保留通过。浅色窗口退出 0，配置恢复，固定目录已清理。Qt 产物 SHA-256 为 `cb78935a504b45cc07f5e08a6d995606361172d799bd4d04d9e974ca2b89dd51`，构建日志为 `.codex-build-logs/ksword-build-check-20261125-071036.raw.log`。
- 同一 Qt 产物在深色主题下复验全部操作，采样 `fef5d4c4-a3b2-4e1b-b40f-303362051992`。窗口退出 0，配置恢复，固定目录已清理。窗口自动化核对了操作与实际数据，颜色对比、DPI 和背景模式待验。
- 同一个合成采样 `82a181e8-f3f3-473d-b524-ef801b0c7219` 在 Qt 和 Light 的正式窗口逐条核对。Light 键盘选类别并定位原包，已应用的筛选隐藏记录时详情仍能回读。清除筛选恢复表格选中，首段预览转正式回放后保留同一锚点。Light SHA-256 为 `f511a5874d53a3a48b044843879ad23497257592f9e299ba4b5e11095bb7c43c`，日志为 `.codex-build-logs/action-analyze-light-chosen-clue.log`。两窗口退出 0，配置恢复，夹具清理完成。
- 三端共用 API 跟随采样 `d94d14b2-6ad9-4465-95ce-fe0b671b3a90`。CLI 确认 8796 字节截止、四段 SHA-256 与六个原包，重开无需源文件。正式 Qt 和 Light 各在缺第 2 段标记、截断第 3 段和修复后显示 2、4、6 条 API 记录。两端定位到 `raw/3 #9`、源行 `6`，按窗口偏移核对磁盘序号。窗口退出 0，配置恢复，固定夹具清理完成。Qt SHA-256 为 `083bd3508c9ef2fa6ffe79dd77ffd4d35e3c933c66c0956cf50a64d050cae31b`，Light 为 `43b329886d7c5b234972a18425dfa56fc1caa697dfde588d38355bba7bc95205`，CLI 为 `dff9892270f67cfc29a019cf21ee78bf1fe845fbd61375355f705ad73790b5fe`。日志 `.codex-build-logs/action-analyze-three-client-api-checkpoint.log`。
- 正式 Qt 在「总览 → 打开归档段」读回合成网络档，核对 IPv4 出站、IPv6 入站、实际 300 字节与窗口预览 256 字节。完整、物理截断和 CRC 损坏分别显示 9、7、7 行。两种坏档的核验前缀均为 5922 字节。窗口退出 0，配置恢复，固定夹具清理完成。日志 `.codex-build-logs/action-analyze-qt-network-archive.log`。
- 同一合成网络段登记到正式 CLI 项目后，JSONL 与 REPL 返回相同的 300 字节与 IPv6 入站元数据。采样 `dad49ffa-6bd0-4574-8c14-6d12bb71e8e7` 通过记录头坐标、元数据空载荷、错位、无记录和 CRC 损坏检查。坏块之前仍返回核验至 5922 字节的记录。正式 Qt 紧接着以浅色回放同一段正文，退出 0，配置恢复，固定夹具已清除。日志 `.codex-build-logs/action-analyze-qt-cli-network-project-current.log`。
- 正式 CLI 的图视图回读跟随采样 `fdc90ef9-1828-447e-bf3b-62c7cbc57ad6`，使用同一 SHA-256 续页，候选坐标为 `raw/3 #8` 和 `raw/3 #9`。缺第 2 段标记时第 3 段返回 `project-data-not-found`。终段返回已核验空页。回归同时覆盖缺已发布 raw、错误散列和坏尾。固定目录已清理。CLI SHA-256 为 `f1c206ff2ead98c4e6394778eb927cfc926448fd6760dd6e47e954f2f8376699`，日志 `.codex-build-logs/action-analyze-cli-verified-graph-test.log`。
- 最新产物复跑三端同一采样 `61d0b194-7cb1-4ead-b84d-b08cafbfa56e`，Qt、Light 均再次通过 2／4／6 行及 `raw/3 #9` 定位。Qt SHA-256 为 `1fdb0e556422f7f6105efecd7435c17ec64581a7321ff43ac4c675449ad5b459`。两窗口退出 `0`，配置恢复，固定夹具清理完成。日志 `.codex-build-logs/action-analyze-three-client-api-final-graph.log`。

从仓库根目录使用统一 Release 产物，逐条运行以下回归。脚本使用独立非输入桌面。

```powershell
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/qt/live_archive_reopen.py
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/qt/archive_api_preview.py
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/qt/archive_api_preview.py --dark
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/archive_etw_preview.py --api
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/archive_api_follow_preview.py
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/qt/archive_network_preview.py
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/archive_etw_preview.py --cross-client
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/live_project_preview.py
```
