# API 转移桌面参数接入：源码与语言包检查回执

本轮只做定向源码检查、工程登记检查、i18n audit 与必要语言包定点修正。按用户要求，**禁止 Qt/Win32 GUI 实测和桌面构建**；源码读取与语言审计不代表 GUI 实测。复用 CLI／原生消费者既有回执，未另做全项目运行审计。

- 导航入口：Qt「监控 → 行为分析 → 归档行详情」；Light「监控 → ActionAnalyze → 归档行详情」。
- 页面类型：原清单详情（归档 API 线索行）。复用现有 `StructuredFieldView`／原生详情文本外壳，**无新布局、无新页面、无新控件皮肤**。
- 同类对照：`CallbackArchivePresentation.{h,cpp}`（Qt 详情字段投影）与 `NetworkReplayPresentation.{h,cpp}`（Light 详情文本投影）。

## 1. SOURCE 定向检查

| 检查项 | 实际结果 |
| --- | --- |
| 工程登记 | Qt：`Ksword5.1.vcxproj:455`（ClCompile）、`:1042`（ClInclude），filters `:918`／`:2925`。Light：`KswordARKLight.vcxproj:125`（ClCompile，含 `/utf-8`）、`:384`（ClInclude），filters `:212`／`:648`。两端 `.h/.cpp` 均已登记，无漏登记。 |
| 实际接线（Qt） | `ActionAnalyze/ApiTransferPresentation.cpp:28` 定义 `AppendApiTransferFields`；调用点在 `ActionAnalyze/OfflineSegmentOverview.cpp:1361`，位于归档 API 线索详情分支，`clue.apiTransfer` 存在时投影，不存在时走 `:1365` 的未知说明回退。 |
| 实际接线（Light） | `Features/ActionAnalyze/ApiTransferPresentation.cpp:7` 定义 `ApiTransferDetails`；调用点在 `Features/ActionAnalyze/ActionAnalyzePage.cpp:670`，位于既有 `UpdateDetails`（`:590`）的同一详情文本，排在 API 分类之后、关系文本与预览之前。未新建第二个详情模型。 |
| 版本化字段保存 | 两端读侧均用共享显式解码：`OfflineSegmentReader.cpp:229-232`、`StoredEvidence.cpp:189-192` 调 `ReadApiInjectionFields` 并以 `ApiInjectionCallOutcome` 解释结果。共享契约 `shared/evidence/ApiInjectionFields.h:13` 标记 `0x49505631`、`:14` 前缀 `AAIP1|`、`:47` 固定 14 值、`:75-109` 严格解码（版本号／大小／事件种类／强类型／标记／尾零／小写 hex／范围约束全部失败即回 `nullopt`），旧摘要与截断文本不会变成结构化字段。 |
| 新版字段与旧摘要回退 | Qt：`clue.preview` 的原包十六进制前缀始终显示，结构化字段另起 `API 转移参数` 分区；无 `apiTransfer` 时只显示 `:1365` 的未知说明，二者不混用。Light：无 `apiTransfer` 时 `ApiTransferDetails` 返回空串（`:9-12`），既有 `row.preview` 继续承担原包摘要；有结构化字段时叠加到同一详情文本。详见第 3 节遗留项。 |
| 未知字段不补零 | 两端投影都按有效位显示：Actor/Target/Thread 身份、CompletedLength、Address、StartAddress、TargetStable 分别由 `ApiInjectionActorIdentity` 等 flags 判定（Qt `:43-76`，Light `:31-63`）。无有效位的字段不出现；有效的零值仍显示。输入句柄只作原始参数显示，不授予对象操作资格。 |
| 实际写入与请求入口分列 | 请求写入 `requestedBytes`（仅 `MemoryWrite`）、实际完成 `completedBytes`（`ApiInjectionCompletedLength`）、线程请求入口 `startAddress`（`ApiInjectionStartAddress`）分别独立字段；两端均注明「请求线程入口不代表实际执行」（Qt `:77`，Light `:64`），不把成功创建请求写成执行证明。 |
| 原采样坐标不变 | 详情先保留原坐标再叠加参数：Qt 的 `归档段号／记录序号／文件偏移／源归档行号／FILETIME／来源头 PID/TID` 与 Light 的 `归档记录序号／所属段号／块号／文件字节偏移` 均在新字段之前原样显示；`sourceSequence`、`segmentOrdinal`、`offset` 未被改写或重新编号。 |
| 结果枚举 | 成功／失败／部分成功／未知按 `ApiInjectionOutcome` 四态转换，未知保留未知，不按 API 名称推断成功（Qt `OutcomeText:10-24`，Light `:17-19`）。 |
| 注释与风格 | 新增 4 个文件全部中文注释、普通风格；每个函数均有用途注释：Qt `AppendApiTransferFields`（头 `:12`）、`OutcomeText`（`:9`）；Light `ApiTransferDetails`（头 `:9`、实现 `:6`）。仅共享契约与同类对照的同风格 helper，无 `.inc` 堆叠。 |
| 编译／include 接线 | 未发现明确编译或 include 接线错：Qt 经 `OfflineSegmentReader.h` 取得 `ApiInjectionFields.h` 与 `SegmentApiClue`，经 `../UI/StructuredFieldView.h` 取得 `FieldDocument`；Light 经 `StoredEvidence.h` 取得 `EvidenceRecord` 与共享字段契约，`<string>`／`<cstdint>` 已覆盖。本次未构建，编译结论仅为源码检查，不等于编译通过。 |

与同类对照一致：Qt 侧与 `CallbackArchivePresentation.cpp:55-91` 一样只向 `FieldDocument` 追加分区／字段／说明，不自建详情框架；Light 侧与 `NetworkReplayPresentation.cpp:86-135` 一样只返回既有文本外壳可读的 `std::wstring`，不查询现场、不创建对象句柄。

## 2. i18n audit 与语言包修正

审计命令（根目录 `E:/Projects/Ksword5.1`）：

```
py -3.12 tools/i18n_language_pack.py audit --source-root Ksword5.1/Ksword5.1 --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json --en-pack Ksword5.1/Ksword5.1/languages/en-US.json
```

- 首次：退出码 `1`，`i18n audit failed with 2 issue(s)`，仅报 `sourceSha256` 在 zh-CN 与 en-US 各缺一条 source translation。**本批 17 个新增标签全部已在两包，无缺失。**
- 定点修正：在 `zh-CN.json` 与 `en-US.json` 的 `imageSha256` 之后各插入一条恒等条目 `"sourceSha256": "sourceSha256",`。该词来自 CLI 规则 JSON 键名（`ActionAnalyze/PassiveApiCaptureOwner.cpp:66`、`BehaviorPresetReplay.cpp:203`），与既有 `imageSha256`／`snapshotSha256` 的恒等登记同风格；只补键，不改其他条目、不改键序或缩进。
- 复跑：退出码 `0`，`i18n audit passed: 31997 source strings`。
- 并发说明：检查期间另一工作流正在编辑 `ActionAnalyze/PassiveApiCapturePane.cpp`，其未完成词条曾让全项目 audit 短暂退出 `1`；未代他人补词或改动。该工作流补齐后最近一次复跑仍为退出 `0`／31997 source strings。
- 新增标签重复键检查：对两包全部 JSON 对象用 `object_pairs_hook` 计数，本批 17 个标签在两包均只出现一次，无重复键。两包各有一个与本批无关的既有重复键 `转储文件`，未触碰。
- 双语语义：Qt 的字段值 `成功／失败／部分成功／未知／是／否` 在 `field(..., true)` 中标为可翻译，en-US 对应 `Success/Failed/Partial success/Unknown/Yes/No`；说明与字段源文本在两包齐全。Light 原生详情文本沿用现有中文外壳，与 `NetworkReplayPresentation` 同口径，无运行时双语外壳。

本批标签：`API 转移参数`、`调用结果`、`API 输入句柄`、`调用进入 QPC`、`调用返回 QPC`、`源进程创建 FILETIME`、`API 目标 PID`、`目标进程创建 FILETIME`、`目标身份前后稳定`、`API 返回线程 TID`、`返回线程创建 FILETIME`、`请求写入字节数`、`API 写入起始地址`、`实际完成写入字节数`、`请求线程入口地址`、`字段来自本次 API 调用；请求线程入口不代表实际执行。`、`目标身份、实际写入范围、执行和归因未知。`

## 3. 遗留项（源码检查发现，未擅自修改）

Light 的 `StoredEvidence.cpp:197` 在 `row.preview` 中无条件写入旧摘要声明「目标身份、实际写入范围、执行和归因未知。」；`ActionAnalyzePage.cpp:670` 叠加结构化字段后，`:695` 又把该 preview 接到同一详情文本。于是当 `apiTransfer` 存在时，同一详情会同时显示「API 目标 PID／实际完成写入字节数」和「目标身份、实际写入范围未知」的旧结论。Qt 侧无此问题（旧未知说明只在 `:1365` 的 `else` 回退分支）。

该处属于详情语义而非编译／include 接线错，超出本轮授权的直接修复范围，未改他人源码。建议由 Light 作者按「有结构化字段时旧摘要只保留原包前缀、不再重复未知结论」对齐 Qt；本项列入第 4 项桌面 GUI 验收的必查点。

## 4. 待 GUI 边界（未执行）

以下均未做，符合用户「桌面实测后置、少构建」要求：

- 未启动 Qt／Win32 GUI 自动化，未切换桌面或抢焦点，未做离屏 GUI 测试。
- 未做任何桌面／HostX64 构建，未使用正式 IntDir／OutDir 产物；源码阅读与 i18n audit 不是编译或运行结论。
- 未验证：深浅主题、DPI 缩放、窄窗换行、键盘遍历与 Enter 定位、字段说明的可读性、Light 第 3 节旧摘要并存的实际显示、复制／导出与详情搜索、真实合作采样下的字段与坐标对账。
- 未提交、未暂存、未改动他人源码；仅改两个语言包各一行并新增本回执文档。

## 5. 旧摘要矛盾：已源码修复，实机仍后置

第 3 节遗留的 Light 旧摘要矛盾**已由主协调者源码修复**，本批复核确认：

- `Features/ActionAnalyze/StoredEvidence.cpp:198-202` 现在按 `row.apiTransfer` 分支：有版本化字段时写「目标身份与写入范围见本次 API 字段；实际执行和跨事件归因未知。」，无字段的旧档仍写原「目标身份、实际写入范围、执行和归因未知。」回退，二者不再并存。
- 该修复属源码层；**实机显示仍后置**，本批未做 Light GUI 实测，未验证深浅主题、DPI、窄窗和该详情行的实际渲染。第 4/9 项按此范围记录。

## 6. 11 项状态同步

在第 4、9 项证据栏定点补入本轮源码／语言包结论与 GUI 待验边界，不调整百分比（本轮未新增运行时证据）。正式 CLI 活采候选链的实测证据另见 [活采候选链定向验收回执](live-api-transfer-validation.md)。
