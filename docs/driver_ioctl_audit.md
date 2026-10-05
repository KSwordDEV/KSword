# KswordARKDriver IOCTL 协议/访问控制一致性审计

最近核对：2026-10-05。本页区分当前源码扫描与保留的历史快照；历史风险表不是当前未修复问题清单。

## 工具用途

`tools/ioctl_audit/ksword_ioctl_audit.py` 是一个驱动侧治理用静态审计脚本。它只读取仓库源码，不构建项目、不执行驱动代码、不修改业务 handler。

该工具用于检查：

- `shared/driver/*Ioctl.h` 中的 `IOCTL_KSWORD_ARK_*` 是否都能解析出 `CTL_CODE` 参数。
- `KswordARKDriver/src/dispatch/ioctl_registry.c` 是否完整注册 shared header 中定义的 IOCTL。
- registry 是否引用了 shared header 中不存在的 IOCTL。
- function id 和 IOCTL 名称是否重复。
- IOCTL method 是否符合当前项目约定 `METHOD_BUFFERED`。
- 名称看起来会修改系统状态的 IOCTL 是否仍为 `FILE_ANY_ACCESS`。
- 名称看起来只读的 IOCTL 是否错误要求 `FILE_WRITE_ACCESS`。
- handler 名称是否和 IOCTL 名称出现明显偏离。

规则文件位于：

```powershell
tools\ioctl_audit\ioctl_audit_rules.json
```

规则文件支持：

- `allowedAnyAccess`：允许保持 `FILE_ANY_ACCESS` 的完整 IOCTL 名称白名单。
- `mutatingKeywords`：默认视为写操作或状态变更的关键词。
- `queryKeywords`：默认视为查询/只读的关键词。
- `ignoredHeaders`：审计时跳过的 header 路径或文件名。
- `notes`：人工解释，不参与自动判断。

## 如何运行

在仓库根目录运行：

```powershell
python tools\ioctl_audit\ksword_ioctl_audit.py --repo-root . --format markdown --out tools\ioctl_audit\out\ioctl_audit_report.md
python tools\ioctl_audit\ksword_ioctl_audit.py --repo-root . --format json --out tools\ioctl_audit\out\ioctl_audit_report.json
```

如需在 CI 或提交前检查中遇到高风险项直接失败：

```powershell
python tools\ioctl_audit\ksword_ioctl_audit.py --repo-root . --fail-on-risk
```

该模式发现 `HIGH` 风险时返回退出码 `2`。

## 报告字段含义

### 顶层字段

- `schemaVersion`：报告 JSON schema 版本。
- `generatedAt`：报告生成时间，UTC ISO-8601。
- `repoRoot`：扫描时传入的仓库根路径。
- `inputs.headers`：实际扫描的 shared IOCTL header 列表。
- `inputs.registry`：扫描的 central registry 源文件。
- `rules`：本次扫描使用的规则和白名单。
- `summary`：统计摘要。
- `ioctls`：从 shared header 解析出的 IOCTL 清单。
- `registry`：从 `ioctl_registry.c` 解析出的注册项清单。
- `findings`：一致性和访问控制审计发现。

### `ioctls` 字段

- `name`：IOCTL 宏名。
- `device_type_expr` / `device_type_value`：`CTL_CODE` 的 device type 表达式和值。
- `function_expr` / `function_id`：function id 表达式和值。
- `method_expr` / `method_value` / `method_name`：method 表达式、数值和名称。
- `access_expr` / `access_value` / `access_name`：access 表达式、数值和名称。
- `control_code`：按 Windows `CTL_CODE` 位布局计算出的最终 IOCTL code。
- `source` / `line`：定义所在 header 和起始行。
- `registered`：是否在 `ioctl_registry.c` 中注册。
- `handler` / `registry_line`：匹配到的 handler 和 registry 行号。
- `mutating_keywords`：命中的状态变更关键词。
- `query_keywords`：命中的查询/只读关键词。

### `findings` 字段

- `severity`：`HIGH`、`MEDIUM` 或 `LOW`。
- `category`：稳定分类名，便于脚本或 CI 消费。
- `name`：受影响的 IOCTL 或逻辑键。
- `message`：面向人工 review 的说明。
- `details`：结构化上下文，例如源码位置、命中关键词、handler 名称。

## 当前源码扫描（2026-10-05）

从仓库根目录执行以下命令，可重新读取源码并保存本次报告；报告文件是生成产物，扫描不修改协议、registry 或业务 handler，也不构建、加载驱动：

```powershell
python tools\ioctl_audit\ksword_ioctl_audit.py --repo-root . --format json --out tools\ioctl_audit\out\ioctl_audit_report.json
```

本次结果为：

| 指标 | 数值 |
| --- | --- |
| shared IOCTL 定义数 | 211 |
| registry 注册数 | 211 |
| 已注册 shared 定义数 | 211 |
| 未注册 shared 定义数 | 0 |
| HIGH findings | 0 |
| MEDIUM findings | 24 |
| LOW findings | 0 |

24 个 MEDIUM 均属 `query_write_access`：名称命中查询/读取关键词，但协议要求 `FILE_WRITE_ACCESS`。这是一条基于名称的复核提示，不证明接口实际产生写入，也不要求把所有查询改成 `FILE_ANY_ACCESS`。有些读取能力有意要求写权限，另有探测命令会执行真实设备传输；应逐项检查请求语义、设备权限与规则说明。`HIGH=0` 和注册一致仅说明本静态规则未发现相应问题，不证明驱动逻辑、权限设计、加载或硬件行为全部正确。

`--fail-on-risk` 只因 HIGH 返回 `2`，不会因这 24 个 MEDIUM 返回失败。重新扫描后应以生成报告的 `generatedAt` 和实际源码为准，不能把本页数字作为永久门禁。

## 历史扫描结果摘要（保留原始快照）

下列 63 项、8 个 HIGH 来自早期仓库状态；原记录未标明扫描日期，保留其命令、行号和结果供追溯，不代表 2026-10-05 当前源码。

本次扫描命令：

```powershell
python tools\ioctl_audit\ksword_ioctl_audit.py --repo-root . --format markdown --out tools\ioctl_audit\out\ioctl_audit_report.md
python tools\ioctl_audit\ksword_ioctl_audit.py --repo-root . --format json --out tools\ioctl_audit\out\ioctl_audit_report.json
```

结果摘要：

| 指标 | 数值 |
| --- | --- |
| shared IOCTL 定义数 | 63 |
| registry 注册数 | 63 |
| 已注册 shared 定义数 | 63 |
| 未注册 shared 定义数 | 0 |
| HIGH findings | 8 |
| MEDIUM findings | 0 |
| LOW findings | 0 |

结构一致性结论：

- 未发现 shared header 已定义但 registry 未注册的 IOCTL。
- 未发现 registry 已注册但 shared header 找不到定义的 IOCTL。
- 未发现 function id 重复。
- 未发现 IOCTL 名称重复。
- 未发现非 `METHOD_BUFFERED` 的 IOCTL。
- 未发现 query/read-only 名称却要求 `FILE_WRITE_ACCESS` 的 IOCTL。
- 未发现明显 handler 命名不一致项。

## 历史高风险 IOCTL 摘要

以下项目命中写操作或状态变更关键词，但 access 仍为 `FILE_ANY_ACCESS`：

| 风险排序 | IOCTL | 来源 | 命中关键词 | 建议 |
| --- | --- | --- | --- | --- |
| 1 | `IOCTL_KSWORD_ARK_TERMINATE_PROCESS` | `shared/driver/KswordArkProcessIoctl.h:40` | `TERMINATE` | 优先评估改为 `FILE_WRITE_ACCESS`，并确认用户态打开设备时具备写权限。 |
| 2 | `IOCTL_KSWORD_ARK_DELETE_PATH` | `shared/driver/KswordArkFileIoctl.h:18` | `DELETE` | 文件删除属于破坏性操作，应优先收紧到 `FILE_WRITE_ACCESS` 或加入明确白名单解释。 |
| 3 | `IOCTL_KSWORD_ARK_SET_PPL_LEVEL` | `shared/driver/KswordArkProcessIoctl.h:65` | `SET` | PPL/protection 相关变更应要求写权限，并保留 capability gating。 |
| 4 | `IOCTL_KSWORD_ARK_SUSPEND_PROCESS` | `shared/driver/KswordArkProcessIoctl.h:53` | `SUSPEND` | 进程状态变更应避免 `FILE_ANY_ACCESS`。 |
| 5 | `IOCTL_KSWORD_ARK_SET_CALLBACK_RULES` | `shared/driver/KswordArkCallbackIoctl.h:24` | `SET` | callback 规则变更应要求写权限，避免只读句柄更新策略。 |
| 6 | `IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT` | `shared/driver/KswordArkCallbackIoctl.h:45` | `ANSWER` | 回答 pending event 会改变驱动内部决策状态，应评估写权限。 |
| 7 | `IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS` | `shared/driver/KswordArkCallbackIoctl.h:52` | `CANCEL` | 批量取消 pending decision 是状态变更，应评估写权限。 |
| 8 | `IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL` | `shared/driver/KswordArkFileMonitorIoctl.h:19` | `CONTROL` | monitor start/stop 或配置控制应评估写权限；如实际只读，需在规则白名单中说明。 |

当前源码中，上述 8 个历史条目已采用 `FILE_WRITE_ACCESS`：进程终止/挂起/PPL、文件删除、Callback 规则与 pending 决策、File Monitor 控制。历史表的 `FILE_ANY_ACCESS` 和源码行号保留原样，不应再作为当前缺陷定位依据；检查当前权限需读取对应 `shared/driver/` 定义和新报告。

## 历史建议修复清单

1. 对破坏性和权限敏感操作优先改为 `FILE_WRITE_ACCESS`：
   - `IOCTL_KSWORD_ARK_TERMINATE_PROCESS`
   - `IOCTL_KSWORD_ARK_DELETE_PATH`
   - `IOCTL_KSWORD_ARK_SET_PPL_LEVEL`
   - `IOCTL_KSWORD_ARK_SUSPEND_PROCESS`

2. 对驱动内部策略或 pending 状态变更补齐写权限：
   - `IOCTL_KSWORD_ARK_SET_CALLBACK_RULES`
   - `IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT`
   - `IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS`
   - `IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL`

3. 如果某个 `FILE_ANY_ACCESS` 是兼容性或协议设计要求，不要直接忽略：
   - 在 `tools/ioctl_audit/ioctl_audit_rules.json` 的 `allowedAnyAccess` 加入完整 IOCTL 名称。
   - 在 `notes` 中写明原因、补偿控制和复查日期。

4. 后续新增 IOCTL 时建议把本脚本加入提交前检查：
   - 新 shared header 定义必须能被工具解析。
   - 新 registry 项必须能和 shared 定义双向匹配。
   - 新写操作默认不要使用 `FILE_ANY_ACCESS`。

## 生成的报告

- Markdown：`tools/ioctl_audit/out/ioctl_audit_report.md`
- JSON：`tools/ioctl_audit/out/ioctl_audit_report.json`
