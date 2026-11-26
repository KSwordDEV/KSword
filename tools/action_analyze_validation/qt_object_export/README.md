# ActionAnalyze Qt 对象身份与归档导出验证

`ArchiveExportTests.cpp` 使用独立合成字节验证产品文件导出路径。`ArchivedObjectIdentityTests.cpp` 使用 `identity.schema.json` 已定义的进程和线程值验证严格只读解析、强身份和线程归属。两个夹具都在统一 Release 使用 QtCore，身份验证不创建样本文件。

## 接入依赖

- A0 的 `identity.schema.json` 定义独立进程、线程正文值和采样内对象引用。`archive-format.json` 给对象观测、身份解析和证据引用保留类型 5、6、17。`SegmentBodies.cpp` 目前只解码类型 3 和 4 的 v1 正文，因此类型编号不能赋予正文语义。[A0 既定边界](../../../schemas/action_analyze/base-contract-v1.md) · [共享正文读写](../../../KswordCLI/ActionAnalyze/Archive/SegmentBodies.cpp)
- `Project/SampleCatalog.cpp` 校验的是 `offline-sample` 及其配置快照。现有文档字段集合封闭。证据清单路径及字段在存储设计中仍是提案。需要 A0 与归档所有者共同约定证据目录的受信入口和版本。[项目读写](../../../KswordCLI/ActionAnalyze/Project/SampleCatalog.cpp) · [存储设计](../../../docs/ActionAnalyze项目存储格式与恢复设计.md#3-小文档修订与规则快照)
- 冻结时需要明确已提交且可校验的索引入口，索引的项目／采样身份和完整度，以及证据 ID 到清单原字节 SHA‑256 的绑定。清单应绑定独立身份解析得到的对象和线程所属进程，记录实际格式、作用域、实得长度、SHA‑256 和部分原因。首批可支持单文件 blob，使用已定义的采样内内容散列布局，并规定多份证据时的选择语义。缺少承诺完整的索引或缺少强身份时回报 `Unresolved`。完整索引查询成功且没有匹配项时回报 `Absent`。证据损坏或读失败时回报 `Failed`。

`ArchivedObjectIdentity.{h,cpp}` 是独立验证模块。解析函数只接受归档所有者已核验归属的 A0 正文值，借助 `EvidenceJson` 拒绝重复键和非法字段，并返回值类型 `ObjectSelection`。A0 已知零值能通过语法解析，当前菜单的 Dump 目标模型将其归为不可执行。Qt 可先通过段头和事件字段生成只读 `ObjectMenuRef`。只有背景解析已发布独立 `verifiedSubject` 和匹配的 `ArchivedDiagnostic` 时，菜单才启用导出。
