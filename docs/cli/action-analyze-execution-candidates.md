# 已归档私有执行范围候选

`analyze execution candidates` 只读当前项目某次采样内已提交的 API 原包前缀，将 AAIM1 Allocate、Protect、Free 调用投影为可分页目录。它复用 `execution correlate` 的 `ReadArchivedEvidenceGraph`，不访问活进程，不创建 writer 或采样，也不调用 `AddPrivateExecutionRange`。

```text
KswordCLI.exe analyze execution candidates --project PATH --sample UUID --through-ordinal N [--limit N] [--after-ordinal N --after-sequence N --snapshot TOKEN] [--select-ordinal N --select-sequence N --address N --bytes N] [--json]
```

| 参数 | 含义 |
| --- | --- |
| `--project PATH` | 原项目目录，只读打开。 |
| `--sample UUID` | 项目内已登记的规范采样 UUID。 |
| `--through-ordinal N` | 从第 1 段连续核验到第 N 段，范围 1–128；这是显式历史截止点。 |
| `--limit N` | 每页生命周期调用数，1–8，默认 8；Free 和失败调用也占一行。 |
| `--after-ordinal N --after-sequence N` | 上页 `nextAfter` 的原 Stored 坐标，必须同时提供。不是原包流水号。 |
| `--snapshot TOKEN` | 完整复制已显示页的 `snapshot`，续页和显式选择必填；建议由 JSON 客户端保存，命令行传递时整体引用。 |
| `--select-ordinal N --select-sequence N` | 当前页中用户明确选中的原调用 Stored 坐标。 |
| `--address N --bytes N` | 选中候选实际输出内的明确子范围。必须与两个 select 参数一起提供；数字沿用 CLI 无符号数解析。 |

目录只接收发布了 API 检查点的流，完整旧导入档、ETW 和回调流返回不支持。每次请求重新核验显式前缀，成功后一次发布纯值结果。未选取的后续段不在本次核验范围；`finalSegment=false` 表示截止段尚不是来源声明的终段，不能据此声称整个采样已完整结束。

## 条目语义

- Allocate 必须真实返回成功，且实际输出 base/size 两个有效位均存在、范围非零且无溢出，才产生范围候选。保留原初始保护；不要求初始就是可执行保护。
- Protect 同样要求成功及有效实际输出，并且新保护基础值是 PAGE_EXECUTE、PAGE_EXECUTE_READ、PAGE_EXECUTE_READWRITE 或 PAGE_EXECUTE_WRITECOPY。
- Free 始终显示为释放请求及真实返回。即使成功或请求 size=0，实际释放范围、allocation generation 和当前存活状态仍未知。
- 未满足条件的调用保留在目录，`rangeCandidate=false`。有实际范围但缺少目标查询强身份或调用前后稳定身份时仍保留线索，`strongTargetReportedStable=false`，不提供范围草稿。
- 同目标、同地址或范围重叠不意味着同一 allocation。每次原调用独立保留；本模块不跨来源合并范围或比较跨来源 QPC。

每行 `origin` 包含项目/采样、原来源 ID/epoch、源序号、实际源 PID/TID 提示、段号、Stored 记录序号、块号、字节坐标和已核验 SHA-256。`apiMemoryLifecycle` 复用唯一 AAIM1 JSON 投影，完整保留源/目标创建 FILETIME、有效位、请求与实际输出、源位宽、类型/新旧保护、NTSTATUS、returnValid、来源会话与原 QPC。

`freeRequests` 仅在以下条件全部成立时附到某个范围候选：同一来源 ID/epoch、同一源 PID＋创建 FILETIME、同一包会话、相同稳定目标 PID＋创建 FILETIME，源序号严格增加且前一调用返回 QPC 小于 Free 进入 QPC，Free 的请求地址落入实际范围或其非零请求范围与实际范围相交。原 QPC 缺失或来源不同均不关联。返回失败的 Free 仍可作为“发生过此请求”的关联，原 status 不变。

该关联只说明原请求与范围有地址及时序关系，不证明同一 allocation，不令候选失活。每行最多保留 4 个完整关联，`freeRequestCount` 保留完整前缀中的匹配数量，`freeRequestsTruncated` 明确表示显示截断。

## 范围草稿与现有 held 纳入流程

`wholeRangeDraft` 仅在整个实际输出范围已满足以下条件时出现：原目标强身份有效并在调用前后稳定、地址和长度均 4KiB 对齐、非空、地址加长度不溢出。NX草稿无固定页数上限。否则保持 null，不自动裁剪或扩大范围。用户可通过 select/address/bytes 明确选择实际输出内部满足相同约束的子范围，得到 `selectedRangeDraft`；选择必须命中当前页中的真实原调用，并传回已显示页的 `snapshot`，防止同坐标文件变化后静默沿用旧选择。

Qt 与 Light 的页数参数使用正十进制uint64输入，先检查页数乘4096再检查完整地址范围；整段回填不经过32位整数。实际纳入仍可能因原分配、保护、容器容量或系统资源失败而拒绝。这里解除的是NX执行关注范围额度，内存快照的独立64页读取限制保持原语义。

Qt/Light 在原归档 worker 调用共享接口：

```cpp
// document为原项目对象；request冻结原sample、截止段、分页坐标及snapshot。
Detection::PrivateExecutionCandidatesPage page;
auto result = Detection::ReadPrivateExecutionCandidates(document, request, page);

// 用户选择page.rows中的真实原调用后，再明确输入整页子范围；成功才替换draft。
Detection::PrivateExecutionRangeDraft draft;
auto prepared = Detection::PreparePrivateExecutionRangeDraft(selectedRow, address, bytes, draft);
```

以上 API 只输出纯值，不能从历史结果取得停止令牌。实际纳入仍由原工作流冻结当前 held 停点及明确目标，核对 `draft.targetPid` 和 `draft.targetCreationFileTime`，再调用已有 `AddPrivateExecutionRange`。当前完整 held、MEM_PRIVATE、实际 allocation、保护兼容性及恢复责任全部留给原 owner 核验。历史目标创建时间存在不表示当前 live；`memPrivateVerified=false`、`allocationVerified=false`、`controlIssued=false` 不因生成草稿而改变。

## 分页、缺口与失败

`snapshot` 是精确比较 token，包含项目/采样、冻结描述散列及从第 1 段到截止段的每个已核验摘要；它不是新的加密摘要。续页必须同时使用原截止段、`nextAfter` 和完整 token。任一已读段发生变化返回 `stale-revision`，未知游标返回 `project-data-not-found`。

单次前缀最多扫描 32768 条已分类 API 观察，保留 2048 条合法生命周期调用，输出每页至多 8 行。预算超限返回 `project-limit-exceeded`，不静默淘汰成完整目录。坏 AAIM1 与旧摘要分别计入 `malformedLifecycleCount`、`legacyLifecycleCount`，不从摘要猜范围。只有合法 AAIM1 条目进入 `rows`，因此 `rows=[]` 时还必须查看两类缺口计数及 `observationCount`。

缺段、未发布检查点、原读取器发现的坏尾/格式错误、摘要不一致、来源不支持和预算超限均返回错误且不附带局部候选。成功空目录与错误不是同一状态。核验只覆盖所选已提交前缀，不把未提交尾部认证为完整证据，也不保证历史生产者认证、当前存活、实际执行或因果。
