# Light 集合内存模块 SOURCE 接线与纯模型负控验收（本轮无构建 / 无 GUI）

执行者：CodeBuddy｜Light集合内存模块（按主协调者任务单，仅新增文件，不改任何工程/语言/既有文件）。
授权边界：本轮不构建 GUI、不构建核心、不开窗口、不用测试桌面、不暂存提交。
Light 集合主页面和 session 由并行作者创建中；本模块未触碰其任何文件，也未登记任何 `.vcxproj`。

## 0. 先读的强制上下文

- `AGENTS.md`（构建优先级、共享记忆、构建产出位置、i18n 定点编辑约束）
- `.claude/memory/MEMORY.md`（含 `ksword-arklight-investigation-workbench`、`ksword-action-analyze-engineering` 索引）
- 底层只读源码：`KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.h/.cpp`、
  `Control/OwnedProcessGroup.h`、`Memory/SelectedMemorySnapshot.h/.cpp`、`Memory/PassiveDirtyMemory.h/.cpp`、
  `Project/ProjectMemorySnapshot.h/.cpp`、`Project/ProjectDocument.h`、`Project/ProjectRawEvidence.h`、
  `Archive/RawEvidenceArchive.h`
- Qt 实际接法参考：`Ksword5.1/Ksword5.1/ActionAnalyze/ProcessGroupSession.h/.cpp`、
  `ProcessGroupMemoryPane.cpp`（只读参考，未修改）

## 1. 本轮新增文件（全部为未跟踪新文件）

| 文件 | 角色 | 行数 |
| --- | --- | --- |
| `KswordARKLight/Features/ActionAnalyze/LightProcessGroupMemory.h` | 后台 State 类 + 纯值 projection 头 | 127 |
| `KswordARKLight/Features/ActionAnalyze/LightProcessGroupMemory.cpp` | 实现 | 360 |
| `tools/action_analyze_validation/light/process_group_light_memory_source.py` | 独立 SOURCE + 纯模型负控检查 | 新增 |
| `docs/action-analyze-planning/process-group-light-memory-source.md` | 本回执 | 新增 |

未修改：任何 `.vcxproj` / `.vcxproj.filters` / `languages/*.json` / 既有源码。
检查脚本已断言 `KswordARKLight` 下所有工程文件不含 `LightProcessGroupMemory` 登记项
（`SOURCE_PROJECT_UNREGISTERED=PASS`）。工作树中其他并行作者的既有改动未被触碰。

## 2. 模块接口（供主调用者接入 Light session/page）

命名空间 `Ksword::Features::ActionAnalyze`；别名 `process_group_native = ks::cli::action_analyze::control`。

### 2.1 纯值函数（无副作用、无系统调用，可在任意线程）

| 接口 | 语义 |
| --- | --- |
| `bool PrepareHeldMemoryRequest(const process_group_native::ProcessGroupResult& group, const ProcessGroupTarget& target, std::string_view trackingEpoch, const std::wstring& baseText, const std::wstring& bytesText, ProcessMemorySnapshotRequest& out, LightMemoryInputRejection& rejection)` | 把页面输入解析为一次 HeldEvent 只读读取请求。base 文本 `0x`/`0X` 前缀十六进制、否则十进制；bytes 只收十进制；无符号严格解析，拒绝空/0/非法字符/64 位溢出/`base+bytes` 溢出/空代次/成员未持 HeldComplete。`sampleId` 取 `member.control.group.sampleId`；stop 原样复制；`rounds=2`；`authorizedOwnedProcess=true`；machine/boot 为会话局部标签（注释明确不宣称系统身份）。64 页范围上限复用底层 `PassiveDirtyMemory::Begin` 按真实页大小复核，本层不新增隐藏范围。失败时 `out` 不变。 |
| `std::wstring FormatLightProcessGroupMemory(const process_group_native::ProcessMemorySnapshotResult& read)` | 字段文本投影：目标 PID/创建 FILETIME/范围/采样/来源 HeldEvent/读前读后停点与同一性/原生诊断/Win32 错误；成功页数、失败页数、实际字节数、完整标志、QPC 频率与轮次起止；逐页状态/错误/readQPC；成功页有界原字节预览（`kLightMemoryPreviewBytesPerPage = 256`）。读取失败仍保留快照内部分证据，不填零。 |
| `std::wstring FormatLightProcessGroupMemoryArchive(const LightProcessGroupMemoryProjectView& view)` | 项目路径/采样/项目结果/Win32 错误 + 归档回执（段号/归档字节/失败页/verified/刷盘末序号与字节端点/SHA-256）+ blocked 诊断。与读取文本分开保留。 |

### 2.2 后台状态类（不开线程、不接 owner，由 Light session 同串行工作线程持有）

`class LightProcessGroupMemoryState`；全部方法须在持有对应 `OwnedProcessGroup` 的同一串行线程调用，
与 Continue/Close 的互斥由持有会话保证，类内不加锁。

| 方法 | 语义 |
| --- | --- |
| `ProjectResult CreateNewProject(const std::wstring& path, process_group_native::OwnerIdentity& owner)` | `ProjectDocument::Create`（拒绝已存在项目，不抢别页 writer）+ `CreateSample`；成功时更新 `owner.sampleId` 供会话重建原生组，并重置本端 raw-memory lane（`blocked=false`、`ordinal=1`、清前序/回执；旧项目失败段保留在原目录）。失败保留既有身份不变。 |
| `std::shared_ptr<const ProcessMemorySnapshotResult> Read(OwnedProcessGroup& group, const ProcessMemorySnapshotRequest& request)` | 仅接受 `HeldEvent` 且带完整停点令牌，否则本层拒绝（`light-process-memory-held-only`），**不回退 Live**；通过后同串行调用 `CaptureProcessGroupMemory`，完整令牌与 sample 一致性由底层读前读后核对。失败仍保留快照部分证据。`archiveBlocked` 时新读取不清除失败回执诊断。 |
| `ProjectResult Save(const std::shared_ptr<const ProcessMemorySnapshotResult>& displayed)` | 只保存当前显示的同一指针不可变结果（指针核对，不匹配即拒绝 `lightMemorySnapshotSelection`）。按 `ordinal + previousSequence` 调 `WriteSelectedMemorySnapshot`；仅当结果成功且 `receipt.verified && receipt.raw.flushed` 时前序取真实 `flushed->lastSequence` 再 `++ordinal`；失败保留原段置 blocked，不跳段不覆盖；异常路径置 `RecoveryRequired` 且 blocked。无项目/blocked/无快照均拒绝。 |
| `LightProcessGroupMemoryProjectView ProjectView() const` / `LatestRead() const` / `SampleId() const` | 只读投影，仅复制值；跨线程发布由持有会话的锁负责。 |

拒绝阶段枚举 `LightMemoryInputStage`（None/BaseEmpty/BaseInvalid/BaseZero/BytesEmpty/BytesInvalid/
BytesZero/RangeOverflow/EpochEmpty/MemberNotHeld），稳定 detail 串 `lightMemory*`。

## 3. SOURCE 核对结果（真实运行）

命令与真实输出（退出码 0）：

```
python -B tools/action_analyze_validation/light/process_group_light_memory_source.py
```

```
SOURCE_INCLUDES=PASS 底层=6 相对路径=Light目录
SOURCE_INTERFACE=PASS 接口=8 语义标记=13
SOURCE_STATE_CLASS=PASS 无线程=无owner=仅HeldEvent通道=不回退Live
SOURCE_REJECT_STAGES=PASS stages=12
SOURCE_PROJECT_UNREGISTERED=PASS 按约束未改任何工程/语言/既有文件
SOURCE_SHA256 LightProcessGroupMemory.h=e32c2877712a5a91a3d056308b648a9d3b8365abf80b4aaf2216e27e477e5363
SOURCE_SHA256 LightProcessGroupMemory.cpp=7b9e9751bdcbdc565005b024ed94d9a13e9b2cdbefcce8675431b73b43a9cfc3
```

核对要点：头文件按 Light 目录相对包含 `Core/Win32Lean.h` 与 6 个 CLI 底层头；
后台类无 `std::thread`/`CreateThread`/`SuspendThread`/`WriteProcessMemory`/`OpenProcess` 等；
实现中不存在对 `LiveRead` 请求的构造；保存/blocked/指针核对等 13 个语义标记逐一在位；
两文件均 <1000 行。

## 4. 纯模型负控结果（真实运行，同一脚本）

模型逐条移植解析与 Save/Read 状态机语义，正例 + 负控 24 项全部通过（退出码 0）：

```
MODEL_PARSE_POSITIVE=PASS 0x/0X/十进制/空白/满溢值=5
MODEL_REJECT=PASS 空起始 -> BaseEmpty / 0x无数字 / 正号 / 负号 / 内部空格 /
                 十六进制溢出(0x+17位f) / 十进制溢出(2^64) / 零起始 / 0x零起始 /
                 空字节数 / 字节数十六进制拒绝 / 小数拒绝 / 零字节数 /
                 范围和溢出(UINT64_MAX-8+16) / 空代次 / 未持停点   （各 1 项 PASS）
MODEL_ACCEPT=PASS 边界内=2 上限复核归属底层PassiveDirtyMemory
MODEL_PREVIEW_BOUND=PASS 每页=256
MODEL_NO_PROJECT=PASS 保存拒绝=读取允许按owner采样
MODEL_SAVE_ADVANCE=PASS 前序=真实lastSequence 段号=1/2/3 连续
MODEL_BLOCKED=PASS 失败不跳段=新读取保留失败回执
MODEL_NEW_PROJECT=PASS 拒绝已存在=成功重置blocked与段号
MODEL_SAVE_GUARDS=PASS 指针核对=异常置blocked
RESULT: LIGHT_PROCESS_GROUP_MEMORY_SOURCE_OK 无构建=无GUI=未注册工程
```

说明：模型首轮跑出 3 个脚本自身的用例缺陷（`0x` 前缀十六进制语义、负控元组解包、
守卫用例漏建项目），均为测试脚本缺陷并已修正；C++ 模块语义在负控下未发现矛盾。
64 页页数上限按任务要求不在本层复制常量推算，交由底层按真实 `dwPageSize` 复核
（`PassiveDirtyMemory.cpp:326-328`），模型仅验证该归属关系。

## 5. 未构建 / 未 GUI 验收边界（如实区分）

| 层 | 本轮结论 |
| --- | --- |
| 源码核对 | 已完成（第 3 节），接口签名与底层头逐一比对 |
| 纯模型 | 已完成（第 4 节），真实运行退出码 0 |
| 编译 / 链接 | **未做**：任务禁止构建 GUI 与核心重复测试；两文件尚未登记工程，单独语法编译需要跨项目包含链，等同预构建，未执行 |
| 实机 GUI | **未做**：Light 集合主页面/session 由并行作者创建中，本模块无入口可运行 |

因此本轮**不能**宣称：模块编译通过、Light 页面视觉合规、真实停点读取或归档落盘成功。
以下留待主调用者接入后验收：HostX64 Release 构建（登记 `.vcxproj`/`.filters` 后）、
Light session/page 接线、真实 OwnedProcessGroup 停点下的 Read/Save 实测、
归档回执与坏尾 blocked 的实机验证、深浅主题与窄窗视觉。

## 6. 主调用者接入清单（建议顺序）

1. 在 `KswordARKLight` 工程登记 `LightProcessGroupMemory.h/.cpp`（含 filters），同步语言文本（如 Light 页需要）。
2. Light session 串行工作线程持有一个 `LightProcessGroupMemoryState`；`Configure` 前（或之后）用
   `CreateNewProject` 显式建项目，成功后用更新后的 `owner.sampleId` 重建 `OwnedProcessGroup`。
3. 页面输入经 `PrepareHeldMemoryRequest`（传会话 trackingEpoch）生成请求后，在同串行线程 `Read`；
   用返回的 shared_ptr 作为页面显示身份，点击保存时把同一指针传给 `Save`。
4. `ProjectView()`/`LatestRead()` 复制进会话快照发布；字段文本用 `FormatLightProcessGroupMemory`
   与 `FormatLightProcessGroupMemoryArchive` 两段分开呈现。
5. 接入后按第 5 节列出的边界补构建与实机验收，并自行派发 CodeBuddy 回执。

未暂存、未提交、未推送；除第 1 节四个新文件外无任何文件改动。
