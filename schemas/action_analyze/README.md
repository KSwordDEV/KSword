# ActionAnalyze 机器契约草案

这里是 ActionAnalyze 机器契约的唯一目录。当前内容包括停止组查询投影草案、基础类型与 Stored v1 子集，以及 A0.2 离线 CLI 契约。工程阶段记录见[工程推进记录](../../.claude/memory/ksword-action-analyze-engineering.md)。

显式选择 `--backend r3` 时，CLI 还接受 `session.open/query/findings/stop/close`。省略时限可持续采集。方法目录列出会话及继承的项目方法、请求和回执定义。输出包络覆盖握手、响应、协议错误和最终回执。[R3 方法目录](live-etw-method-catalog.json) · [R3 输出包络](live-etw-message.schema.json) · [会话方法 schema](live-etw-session.schema.json) · [请求向量](vectors/live-etw-session-v1.json)

## 停止组只读投影草案

| 文件 | 范围 |
| --- | --- |
| [stop-group-snapshot.schema.json](stop-group-snapshot.schema.json) | 外部所有者发布的只读快照。`stopId` 可做定位引用。授权、继续、恢复和时序回执归真实控制接口 |
| [vectors/stop-group-snapshot.json](vectors/stop-group-snapshot.json) | 手写正反例。每条用 `set` 的顶层键替换 `base` 的同名值，未列的键沿用 `base`。成员 hash 为结构测试用值 |

`threadId` 解析到同一采样中的强实例。逻辑集合由 `membershipRevision` 和 hash 表示，原生附带暂停另列并携带集合质量。`not-collected` 配空数组表示未取得清单，`verified` 配空数组表示已核对且无附带成员。`futureThreadGate` 描述当前后端及作用范围的证据，完整区域屏障由区域、探针修订和所需执行者闭包决定。`ended` 要求冻结组均已退出并且额外保留的命中线程责任已经清退。

该草案描述整组逻辑快照。`control.query` 的传输响应应按现有帧上限组织摘要和成员页。页绑定同一 `sampleId`、`stopGroupId`、`membershipRevision` 与 `stateRevision`，过期返回 `staleCursor`。页结果采用独立 schema，避免用某个页内成员得出整组已停结论。运行期 receipt、分页形态、逐项停止和释放时刻与原生错误由 A0.2 与 A4 共同冻结。

从仓库根目录用已有 Python `jsonschema` 校验结构和向量。此检查所需文件均为文本。

```powershell
@'
import json
from pathlib import Path
from jsonschema import Draft202012Validator

root = Path('schemas/action_analyze')
schema = json.loads((root / 'stop-group-snapshot.schema.json').read_text(encoding='utf-8'))
vectors = json.loads((root / 'vectors/stop-group-snapshot.json').read_text(encoding='utf-8'))
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
for case in vectors['cases']:
    instance = vectors['base'] | case['set']
    errors = list(validator.iter_errors(instance))
    if (not errors) != case['valid']:
        raise SystemExit(f"{case['id']}: unexpected validation result: {errors}")
print(f"Passed {len(vectors['cases'])} stop-group snapshot vectors.")
'@ | python -
```

`923e36acc` 的 96 项离线向量通过。原生所有者另校验 u64 数值上界、实例及成员唯一性、集合 hash、成员修订、实际停止、异常所有权及恢复。跨字段及跨时序用例随后按相同产物目录进入运行时／三端一致性测试。[基础身份及字段契约](base-contract-v1.md)

## A0.1／A0.3 基础与 Stored v1 子集

| 文件 | 范围 |
| --- | --- |
| [base-contract-v1.md](base-contract-v1.md) | 已选定的契约、兼容边界、A1 输入和待定的项目清单语义 |
| [value.schema.json](value.schema.json)、[identity.schema.json](identity.schema.json) | 无损类型、值状态、采样内引用、进程／线程身份、事件角色和原始时钟 |
| [field-catalog.json](field-catalog.json) | 基础字段的类型、单位、阶段、来源、可用性、字节上限和文本处理 |
| [archive-format.json](archive-format.json) | 段、块、记录和事件核心的字段偏移、UUID 字节序、CRC 覆盖、限制与编号 |
| [vectors/base-v1.json](vectors/base-v1.json)、[vectors/stored-v1.json](vectors/stored-v1.json) | 独立的预期值、规范 JSON 字节与 hash、Stored 正反字节向量 |

从仓库根目录运行 `python -B schemas/action_analyze/check_base_v1.py`。检查器使用本机 `jsonschema` 和 `referencing`，离线校验结构、数值边界、实例与角色、规范字节、CRC 域和可读前缀。产品互读和恢复有独立验收。[基础契约检查器](check_base_v1.py)

Light 独立验证器使用仓库的 Stored v1 字节向量。本次正式 Release 构建通过，位于 `Ksword5.1/x64/Release/KswordARKLightStoredEvidenceValidation.exe` 的验证器通过 35 项 Stored 向量和 2 项 Win32 文件用例。[Light 构建与验证回执](../../docs/ActionAnalyze总览交互与验收.md#light-构建与验证回执)

## A0.2 离线 CLI 子集

方法契约覆盖离线 shell、项目及采样方法和 `archive.inspect`。从仓库根目录运行 `python -B schemas/action_analyze/vectors/validate-request.py` 可校验 62 项基础、54 项项目及 37 项归档检查向量。正式 CLI 已在已登记的采样上验证归档封装检查。[方法契约](method-contract-v1.md) · [请求契约检查器](vectors/validate-request.py) · [正式 CLI 归档验证回执](../../tools/action_analyze_validation/cli/README.md#archive-v1-build-and-test-receipt)

## 被动 ETW 归档覆盖记录

[`etw-coverage-v1.schema.json`](etw-coverage-v1.schema.json) 定义 `records` 流中必需的 `Coverage` 正文。使用 type 14、record schema version 1 及 `kind: "etw-coverage-v1"`。同一采样内的计划与终态引用之间为连续的原始观察序号，允许零条观察。系统 STOP 统计三项同时为已知计数或同时为 `null`。跨流引用与已提交水位由检查点读取器核对。

被动 ETW 会话在停止后依次刷盘并复核 `raw/1` 和 `records/1`，随后发布第 1 代终态检查点。重开验证项目、采样、冻结描述、各流独占字节端点和 SHA-256。超出端点的尾部仍可单独检查。[终态检查点 schema](etw-terminal-checkpoint.schema.json)

## 网络证据

网络归档沿用 Stored v1 的 `RawRecord`。记录内最多保留 1,536 字节元数据和 65,536 字节实际捕获内容。旧 R3 `PacketRecord` 来源最多提供 4,096 字节。来源有截断证据时保留截断状态，ETW 计数按仅元数据处理。出站链接需要同一采样的规范事件、原始记录、来源代次和强进程身份。检查点还须覆盖两条流及其依赖。参见[网络证据契约](network-evidence-draft.schema.json)和[正反向量](vectors/network-evidence-draft.json)。

用 `python -B schemas/action_analyze/check_network_evidence.py` 校验向量中的 JSON 结构、长度、队列边界和出站引用。原生读写、真实采集和检查点恢复分别验收。
