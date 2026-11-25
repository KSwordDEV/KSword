# ActionAnalyze 规划来源资料

日期：2026-11-24。本目录仅为规划、只读来源研究与目录审查，不是产品schema、可执行规则包或支持声明。入口见[规则施工清单](../ActionAnalyze规则来源与转换施工清单.md)、[施工任务](../ActionAnalyze施工任务与契约落点.md)和[原来源研究](../行为语义规则模板收集与并入规划.md)。

| 文件 | 实际含义 |
| --- | --- |
| [source-lock.json](source-lock.json) | 9个上游固定repo／commit、完整树状态、候选路径规则、许可原字节hash，加本地601候选的固定文件hash |
| [上游文件分片清单](upstream-files/manifest.json) | 固定树的所有blob路径／mode／Git blob SHA／报告字节数。`candidateFile`为路径／扩展名保守分类，规则枚举状态另记。 |
| [local-candidates.jsonl](local-candidates.jsonl) | 本地固定JSON中601条ID／JSON Pointer／选择字符串／标签及明确阻塞；不复制匹配正文，也不授予复制发行许可 |
| [inventory-check.json](inventory-check.json) | 生成时计数、实际数据文件和分片清单的SHA-256及采集错误。规则验证和产品验收另行记录。 |
| [license-evidence/](license-evidence/) | 7个可定位上游包级许可文本的原字节证据；CAPE／Cuckoo没有已确认统一包级依据，不补虚构文本 |

上游文件清单分为11个JSONL文件，每个最多2000行。按分片清单的`parts`数组顺序读取，`path`相对清单目录，`firstLine`从原始清单第1行开始计数。校验时可先核对各分片SHA-256，再按顺序直接拼接原始字节，保留LF和末尾换行。拼接后的21468行、7569550字节及SHA-256记录在`concatenated`。12810行为保守候选文件。

本地源路径约定为`../KswordSandbox`，文件`rules/behavior-rules.json`。基线固定commit为`79525023f5c0373a6d31bbca896db2db9b7be5f4`，文件SHA-256为`65134e89e199340e342c8e241a229eb4063653ec57bd48d69f9a597f3ba61337`。`jsonPointer`指向该固定原文件，而不是本目录的简化记录。选择字符串不是typed字段目录。

上游正文未全量读取，因此`bodySha256=null`、`bodyStatus=not-collected`、`ruleEnumerationStatus=not-parsed`。文件数不等于规则数；不支持语法、helper／抽象类、多文档／多类／多rule均须下一步解析后单独登记。`treeComplete=true`只表示GitHub返回的该棵递归树未截断且根SHA一致，不表示symlink／submodule／LFS／外部lookup已取回；完整blob清单保留相关路径供复核。

本机开发诊断脚本`.codex-build-logs/behavior-planning/build_planning_inventory.py`曾生成原始单文件。复建时按source-lock逐源请求`https://api.github.com/repos/{owner}/{repo}/git/trees/{commit}?recursive=1`，核根SHA和`truncated=false`，将所有blob按source顺序／path排序。候选依据lock中的roots/extensions，许可从对应固定raw路径取原字节算SHA-256。若树截断应显式遍历子树，核实覆盖后再记录完整。网络失败时保留错误和pending及原固定commit。生成器需接入分片输出，按原字节每2000行切分并复核拼接SHA-256。

本地601条均标`validated=false`、`releasable=false`、三端`not-implemented`，含授权／字段／语义／验证阻塞。上游的`ruleCount=null`表示尚未枚举，不是0；来源包级许可已核实也不表示所有文件没有例外或已完成KSword分发兼容审查。许可原件只为研究证据，不将全部规则标为已授权。

本目录保存来源审查资料。A0 机器契约与黄金向量使用[独立目录](../../schemas/action_analyze/README.md)，已有停止组快照草案，三端真实读写与规则验证进入各自工程工单。[工程开工基线](../ActionAnalyze工程开工基线.md)
