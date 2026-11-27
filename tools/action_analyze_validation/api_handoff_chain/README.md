# 456 连续接管 CLI 验收夹具（仅夹具源码，下一批授权实测）

本目录只提供夹具源码与驱动脚本。**本任务不构建、不运行、不改产品、不提交、不派发、不 GUI。**
默认 `python -B run_api_handoff_chain.py` 只打印入口说明并返回 0，既不编译也不调用 CLI。
下一批实测由原目标授权，无需再让用户确认。

## 目标

在原 B 已证明「单跳真实 stub 副作用」（`stubRan=true`/`counter=1`/目标退出 0）之上，补齐「连续下一跳 C」
和 B 的第二范围/新线程准入，并核对真实归档证据：

- **A（自有 x64 源）**：正式 CLI 附加到 A；仅在真实 Agent Ready 之后向 B 私有 block1 发一次真实
  `NtQueueApcThreadEx`。**A 不对 block2 或 launcher 设防、没有 launcher，只触发 block1。**
- **B（被接管目标）**：block1 私有短跳板调用导出 `AA_OnBlock1` → `AA_HopToC`，由 **B 自身代码**对 C 发
  真实跨进程 `NtQueueApcThreadEx`（不是 Python 代发）；随后在**同一导出例程中由 B 自己的 `CreateThread`
  直接以 block2 私有入口启动第二范围**，触发产品的同进程私有入口调用前接管与追加范围/线程准入。
- **C（下一目标）**：分配一块私有 RX/RWX 存根并发布地址，由 B 的 APC 触发，产品自动解析其私有范围；
  **CLI 从不接收任何私有地址**。

三者各自打印 `stubRan`/`counter`/`exit`/`pid`/`creation`。顺序由共享内存 `goHop1`/计数器/`stop` 与 stdout
显式握手，不盲 Sleep 假定 Ready。

## 入口与命令

| 文件 | 用途 |
| --- | --- |
| `api_handoff_chain_target.cpp` | 自有 x64 三角色 a/b/c 夹具源 |
| `run_api_handoff_chain.py` | 驱动：持互斥 → 编译 → 起三目标 → 附加 CLI → 两跳 → 有限 duration 自然完成 → 取证 → 断言 → 有边界清理 |
| `obj/Release/` | 固定 IntDir（仅实测时生成） |
| `evidence/latest/` | 固定取证位置：项目独有 `<sampleId>/raw|raw-native|checkpoints|snapshots/sample.json`（**不放 .codex-build-logs**） |
| `evidence/first-run/` | 第一次失败运行的独有归档（原样保留，不被后续运行覆盖） |
| `evidence/second-run/` | 第二次运行（共享计数已发布、检查器路径未修）的独有归档 |

下一批实测命令：

```
python -B run_api_handoff_chain.py --execute
```

- CLI：`analyze api-evidence attach ... --auto-transfer --duration-ms 10000 --startup-progress 1 --json`，附加到 A。
  用**有限 duration 让 CLI 自然完成**取得退出码 0；`--duration-ms 0` 的正式取消按契约返回 `6`，
  不作为通过依据，也不得为强迫 0 而改产品。
- 编译使用 HostX64 `cl.exe`、宿主 `BelowNormal`，输出到固定 `obj/Release` 与统一 `Ksword5.1\x64\Release`。
- 全程持有 `Local\KSword.ActionAnalyze.CliValidation` 互斥。
- `CreateFileMappingW` 的 page-file 映射用 `INVALID_HANDLE_VALUE`（不是 `None`）。
- 所有共享映射/主线程句柄、CLI 与目标进程都在 `try/finally` 中：异常先正式 `CTRL_BREAK_EVENT` 取消 CLI、
  再置共享 `stop` 协作退出；超时只兜底自有 PID 并记入 `HARD` 使结果明确失败，不遗留 CLI 或目标。
- 清理 scratch 前先把项目证据复制到 `evidence/latest/`；只有绝对路径边界、目录名与自有 `owner.json`
  标记都匹配才删除 scratch，不递归删不明旧目录；会话文件按精确 `config_PID.ini`/`stop_PID.flag` 删除。

## 强判据（9 项，真实 receipt + 真实归档 + 真实 stdout/退出码）

1. `admission-a-to-b-completed`：`sourcePid=A`、`targetPid=B`、`address=B.block1` 的 admission
   `completed=true,error=0`。
2. `admission-b-to-c-completed`：`sourcePid=B`、`targetPid=C`、`address=C.stub` 的 admission
   `completed=true,error=0`。
3. `admission-b-to-b-native-second-range`：`sourcePid=B`、`targetPid=B`、`address=B.block2` 的 admission
   `completed=true,error=0` **且带原 native 成员**（`nativePageAdvance.stage` 非空、`resourcesRestored=true`），
   不是只靠 `len(admissions)>=2`。
4. `raw-native-execution-three-ranges`：按 Stored v1 结构解码正式 CLI 归档 `raw-native` 里的原生执行文档，
   要求文档**顶层 `instructionAddress`** 落入 B.block1／B.block2／C.stub 各自范围（优先等于请求入口），
   `observation` 为 `execution-enter-attempt`／`instruction-completed`，并带 `target.pid/create`、
   `thread.tid/create`、段号与 recordSequence；block2 另要求 `thread.tid` 等于 B 自报的 `newThreadB`。
   **不按原始字节包含地址判定**，也不用 `binding.executionRanges` 列表匹配（同一文档可同时列多个范围）。
5. `three-target-real-side-effects`：B `counter1=1,counter2=1`、C `counter=1`。
6. `cli-exit-0`：CLI 退出码 0。
7. `agent-hooks-cleaned`：`clean` + `hooksRemoved` + `cleanupComplete` + `cleanPipeEof`。
8. `evidence-preserved-and-cleanup`：证据已落 `evidence/latest/`、scratch 已删、自有会话文件精确清理。
9. `three-targets-normal-exit-no-leftover`：A/B/C 真实退出码均 0 且 `HARD` 为空。

失败一律非零（`1`=强判据失败、`3`=互斥失败、`4`=异常）；三目标完整 stdout 与归档命中落 `chain-run.log`
与 `strong-criteria.json`。只清自有 PID 与精确会话文件，不枚举/结束他人进程、不复制 runtime、不改语言包。

## 明确未覆盖 / 边界

- **本批已实测**：三次 `--execute` 运行（失败 / 8-of-9 / 9-of-9）的区分与实测结果见 `receipt.md`；
  最终一次强判据 9/9 全过。本批使用的 Agent 是上一批产物（`9f9318aa…`），
  **未包含当前待建的 `0134a8303`**，因此结构化 CreateThread 新包未由此批验证，不得据此声称已验。
- **即使 C 副作用成立也不证明 Hook 生效**：必须由判据 1/2 的真实归档 `B->C` 成功交接（`sourcePid/targetPid/
  address/completed/error`）和判据 4 的真实 raw-native 执行 IP 共同证明；缺少任一即失败。
- B 的 Agent Ready 由产品「调用前设防」保证 + `stubRanB1` 握手推断，夹具不读取 B Agent 的显式 ready 信号；
  若 B 存根进入时尚无跨进程拦截能力，`counterC` 为 0，由判据 2/4 真实暴露。
- 不覆盖网络/ETW、不覆盖 QueueUserAPC2 真实调用（本夹具用 NtQueueApcThreadEx）、不覆盖 R0、GUI、
  整批回归与 i18n/theme 门禁。
- CLI 退出码 0 是硬判据；此前批次曾因随包 rules 谓词配置错误得到 `CLI_EXIT_CODE=6`，本夹具不掩盖该失败。
  `--duration-ms 0` 的正式取消按契约返回 `6`，本夹具因此改用有限 duration 自然完成取得 0，
  `CTRL_BREAK_EVENT` 只保留给失败/超时清退。
- **离线字段级重验**（不构建、不运行、不重跑，只读 `evidence/latest` 现有样本）：

  ```
  python -B -c "import sys; sys.path.insert(0,'.'); import run_api_handoff_chain as m; sys.exit(m.offline_verify())"
  ```

  输出留档 `offline-native-verification.txt`；离线模式不写运行记录 `chain-run.log`。
- 若正式取消后目标未自行退出，由判据 9 失败；超时兜底 terminate 仅发生在断言记录之前写入 `HARD`，
  且只针对自有 PID，不作为通过依据。
