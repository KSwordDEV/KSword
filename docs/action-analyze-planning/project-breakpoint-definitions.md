# ActionAnalyze 项目断点定义契约

共享离线项目文档保存断点定义，正式 Qt 和 CLI 提供编辑与读回入口。Light 可打开同一项目并按当前项目修订登记采样。定义支持模块 RVA 和精确模块符号，武装与运行状态由调试会话持有。[项目方法契约](../../schemas/action_analyze/method-contract-v1.md)

## 定义与身份

| 字段 | 保存约束 |
| --- | --- |
| `breakpointDefinitionId` | 项目内稳定小写非零 UUID，由 `ProjectDocument` 在保存新项时分配。编辑、启用和停用沿用原 ID。删除后重新添加分配新 ID。外部版本引用带 `projectId`、`revisionId` 和定义 ID。 |
| `definitionRevision` | 从 `"1"` 开始的规范十进制 u64 字符串。定义的模块、位置或启用值变化时加一。只改项目标题、说明或列表显示顺序保留定义修订。项目文档修订仍用 UUID。 |
| `enabled` | 必需布尔值，表示记录的配置意图。 |
| `module` | 对象含 `name` 和 `imageSha256`。`name` 是 1–255 UTF-8 字节的模块基础文件名，拒绝 Windows 路径分隔符及保留字符、首尾 ASCII 空格、末尾点和控制字符。`imageSha256` 是精确映像文件的 SHA-256，编码为 64 个小写十六进制字符，缺失时显式写 `null`。 |
| `location` | 二选一。`{"kind":"module-rva","rva":"4096"}` 中 `rva` 为规范十进制 u32 字符串，允许 `"0"`。`{"kind":"module-symbol","symbol":"Fixture::Entry","pdb":null}` 中 `symbol` 是 1–512 UTF-8 字节的精确符号名，保留大小写及内部空格，拒绝首尾 ASCII 空格及控制字符。`pdb` 为 `null` 或已知的 `{"guid":"<RSDS GUID>","age":"<正 u32>"}`，GUID 格式同项目 UUID。 |
| `condition` | 可选 `{"expressionProfile":"predicate-expr-v3","source":"stop.tid != 0u64"}`。原文为非空单行严格 UTF-8，最多8192字节，无 C0 控制字符。无条件省略整个字段，不写 null；未知 profile 拒绝。条件变化递增定义修订。 |

条件与位置一起进入原配置散列、修订链及采样冻结快照。无条件旧定义仍输出原五字段形状；新含条件定义需本次新增读取能力，旧读取器会拒绝额外字段，不能指望旧版本忽略规则。Qt断点页沿原ParameterWorkspace表单编辑并调用原生停点准备器检查；CLI沿原完整settings保存。Light沿原项目定义选择器展示并激活，定义编辑能力仍为无。存储层只校验文本和固定profile，不把离线表达式当已绑定规则。

三端单目标模块RVA与执行集合（含运行中追加）在真正附加前，从本轮sample读取条件并用原生停点字段目录准备。保持各原入口的求值阶段：CLI原生单目标为Entry，OwnedDataWatchSession（桌面单目标与三端集合）为Observation；目录字段名与类型相同，不改原求值路径。空手填继承冻结条件，非空必须与冻结原文完全相同；冲突、未知字段或类型/语法错误在附加前拒绝，集合整批新成员均不附加，已有成员及writer保持原状态。没有保存条件的旧定义保留手填规则。Qt/Light实际条件回显来自原worker，不能将继承规则误报为无条件。本扩展源码已接，构建、持久往返、正式CLI条件命中及GUI待验。

文本拒绝 C0、C1、DEL、U+2028 和 U+2029，按严格 UTF-8 写入。模块名可单独保存为候选，符号的 PDB 身份也可留待补全。离线格式校验保留缺失字段的实际含义。文件散列与 PDB 标识均来自输入资料，存储层只验证格式。定义集合按 `breakpointDefinitionId` 的 ASCII 字节排序，ID 不重复。同一定位以模块名 ASCII 不区分大小写、所指定映像散列、定位种类及其值比较，重复项整批拒绝。定义上限为 64 条。

## 项目提交与迁移

`RevisionSettings` 保存标题、说明和可选的完整定义集合。含定义能力的配置必须有 `title`、`notes`、`breakpointDefinitions` 三个键，明确清空写 `[]`。旧配置严格只有 `title`、`notes`。两种格式及各层对象均拒绝未知字段、非法类型、重复键和超界值。

```text
project.ksaproj
  → journal/<generation>.json → revisions/<revisionId>.json → config
  → catalog/<generation>/manifest.json → 页内 sample 摘要
    → samples/<sampleId>/sample.json
      → samples/<sampleId>/snapshots/<snapshotId>.json → config 的完整副本
```

新项目可选择创建时写扩展配置。旧项目按原样打开和读取，缺少定义的有效旧配置在展示层可呈现为零条。首次携带定义集合保存时发布一个新 `saveRevision` 提交。清单保持 `version:1`，其 `requiredFeatures` 从 `["cli-offline-project-v1"]` 变为 `["cli-offline-project-v1","project-breakpoint-definitions-v1"]`。此后写入保留能力标记，清空定义仍属于扩展配置。旧读取器遇到该标记报告不支持。读取已升级项目内的历史快照时按该快照自身 `config` 的精确形状选算法。

- 旧 `configSemanticHash` 保持 `SHA256("KSAA\0cli-offline-config-v1\0" + aa-cjson-v1(config))`。
- 扩展 `configSemanticHash` 使用 `SHA256("KSAA\0project-breakpoint-config-v1\0" + aa-cjson-v1(config))`。定义集合排序后参与规范化。两个 `\0` 都表示单个零字节。
- `revisionHash`、`snapshotHash`、`descriptionHash`、journal 和 catalog 引用继续使用目标文件原字节 SHA-256，含末尾 LF。旧文件及其引用保留原字节。旧采样与扩展采样允许共存。[基础契约](../../schemas/action_analyze/base-contract-v1.md)

## 写租约、草稿和冻结

`ProjectDocument` 通过 `.locks/writer.lock` 的 byte 0 独占租约串行提交。Qt、Light、CLI 传入来自同一个项目已提交视图的完整草稿和 `expectedRevisionId`。持锁后重新读取正式指针及直接依赖，核对当前项目、修订 ID、原字节散列和目录代次。定义修改、清空及旧项目升级均要求基于明确修订。旧双字段原生调用保留现有兼容行为，升级后省略定义的保存请求失败。

草稿中新增项使用空 ID 和定义修订 `0`。保留项带基准修订中的 ID 和定义修订。项目写入器拒绝调用方自选的新 ID 和不在基准中的旧 ID，在提交时分配 UUID 并更新逐项修订。完整草稿中缺少某个旧 ID 表示删除。无变化的完整草稿保留项目修订。冲突时客户端保留草稿，重读并明确决定是否重提。项目定义只有修订链这一处持久源，遵守同一租约、暂存、journal 及头指针发布顺序。

扩展配置下，`CreateSample(title, out, expectedRevisionId)` 在同一写租约下检查指定修订，将已提交配置及其两种散列一起复制到不可变快照，再通过目录和 `addSample` 提交发布。冻结项包含停用定义及其版本。读取历史样本时以描述文件和快照为准。样本之后的保存、清空、刷新或项目目录搬动均保留原快照身份及内容。新建离线样本沿用 `not-collected`，后端和初始目标字段为 `null`。 [现有方法契约](../../schemas/action_analyze/method-contract-v1.md)

## 后续接线与验收判据

| 用例 | 应观察的结果 |
| --- | --- |
| 旧项目、旧样本及首次升级 | 原配置 hash 和样本文件字节一致。新头在旧产品中报告不支持，新读取器能读取旧样本。 |
| 从两个客户端修改同一项目 | 繁忙返回 `writerBusy`。后续持锁携带旧基准返回 `staleRevision`。两种失败均保留当前头与本地草稿。 |
| 先保存 A，再创建样本 S，保存 B 并重开 | S 中的定义、逐项版本和配置散列等于 A。B 中编辑项保留 ID 并递增版本，删除后再新增得到新 ID。 |
| 完整保存的重排、清空与遗漏 | 重排不产生新修订。`[]` 提交明确清空。旧保存请求在扩展项目上失败，防止意外删除。 |
| 坏数据及上限 | 未知功能标记报不支持。未知配置字段、错误类型、非法名称、越界 RVA、重复 ID 或定位等拒绝整次输入。带有效文件散列但配置散列不匹配的快照仍报告损坏。 |
| 发布故障与恢复 | `.staging`、文件刷盘或头切换故障返回失败，并按已提交指针读取。可用的前一清单仅供只读恢复。不得从孤立修订文件或未提交的采样推测新版本。 |

Qt 已验证正式项目保存、重开和采样冻结。CLI 方法、REPL 帮助和输入输出架构已更新，正式项目基本生命周期回归通过。三端使用扩展项目的同样本交叉验收及 Light 定义编辑仍待完成。[项目存储接口](../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h) · [11 项产品验收](../ActionAnalyze产品验收清单.md)
