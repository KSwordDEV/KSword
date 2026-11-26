# Qt 进程集合页 SOURCE 接线、operation 投影与语言适配验收（无构建 / 无 GUI）

执行者：CodeBuddy｜Qt进程集合SOURCE验收 / Qt进程集合最终语言与适配（作者自行派发本轮审查与回执）。
授权边界：不构建、不开 GUI、不重跑核心原生测试、不使用测试桌面；不暂存、不提交。
禁止修改 `OwnedProcessGroup`、DataWriteWatch、步进、树等其他作者内容。

## 0. 先读的强制上下文

`AGENTS.md`、`.claude/memory/MEMORY.md`、`.claude/memory/ksword-action-analyze-engineering.md`、
`.claude/memory/ksword-ui-architecture.md`、`docs/运行时控制开发规范.md`。

## 1. 审查范围与归属修正

首轮报告把同一作者新增的内存快照代码称为“并行作者”，这是首轮审查时尚未覆盖的
新增范围，不是另一位作者。本轮已明确授权：内存快照代码属于本任务作者，
`ProcessGroupMemoryPane.*`、`ProcessGroupSession.*` 的新增双语与源码投影均由本轮完成。

| 文件 | 角色 | 本轮处理 |
| --- | --- | --- |
| `ActionAnalyze/ProcessGroupPage.cpp/.h` | Qt 页面 | 修复 operation 投影（3 处） |
| `ActionAnalyze/ProcessGroupSession.cpp/.h` | 本端串行会话 | 核对构造异常保护；未改源码 |
| `ActionAnalyze/ProcessGroupMemoryPane.cpp/.h` | 内存范围窗格 | 核对共享 API；未改源码 |
| `KswordCLI/.../OwnedProcessGroup.h/.cpp` | 只读契约 | 只读，未改 |
| `languages/zh-CN.json`、`en-US.json` | 双语包 | 定点插入，无整体重写 |

单文件行数：`ProcessGroupPage.cpp` 676、`ProcessGroupSession.cpp` 363、
`ProcessGroupMemoryPane.cpp` 198、模型 286、本报告 153，均 < 1000。

## 2. SOURCE 接线核对（一致）

工厂 `CreateProcessGroupPage`（`ProcessGroupPage.cpp:672`）、工作台挂载
（`ActionAnalyzeWorkspace.cpp:225`）、导航 ID（`MonitorNavigationSchema.h:24,42`）、
`Ksword5.1.vcxproj` 与 `.filters` 的 cpp/h 登记均存在。`Ksword5.qrc:49` 已有
`process_refresh.svg` 别名，本页只复用，无新增图片。

## 3. ProcessGroupOperation 投影修复（本轮核心源码改动）

原生 `ProcessGroupOperation` 新增 `ledgerResult/stage/win32Error`；Duplicate 时
顶层 `ledgerResult` 是 `Duplicate`，不是首次成功；拒绝票据无 outcomes。
`OwnedProcessGroup.cpp:194-204,234-263,353-369` 为契约依据。

| 位置 | 修复前 | 修复后 |
| --- | --- | --- |
| `Render()` 恢复资格 | 只看 `action==Continue`，拒绝票据也可恢复 | 增加 `AppliedOperation`（`ledgerResult==Applied && !outcomes.empty()`），拒绝票据不授予恢复资格 |
| `Render()` 状态 | 用 `lastCommandResult` 顶层 stage/win32Error | 有 operation 时展示原票据三字段；顶层 Duplicate 追加“原票据重放，非首次执行”；无 outcomes 追加“拒绝票据未执行成员” |
| `Detail()` 最近显式操作回执 | 展示顶层三字段 | 有 operation 时展示其 `requestId/action/ledgerResult/stage/win32Error`，Duplicate 标记“回读性质”；无 operation 才回退顶层 |
| `Detail()` 历史操作票据 | 只有 ID/action/outcomes | 新增原 operation 三字段；无 outcomes 标记“执行范围 / 拒绝票据未执行成员” |

新增本页匿名命名空间内两个普通风格 helper（`ProcessGroupPage.cpp:84-100`）：
`AppliedOperation`、`AppendOperationFields`。成员 `control` 仍在各 outcome 行内逐项
呈现，不由顶层三字段推断，也不把部分失败汇总为全组成功。

## 4. 适配线程启动失败 / terminate 风险（明确结论）

- 首轮审查时 `Run()` 中 `group` 构造位于 `try` 外；异常逃出线程入口函数会由
  C++ 运行时调用 `std::terminate` 结束整个进程。这是真实严重问题。
- 当前源码已修复：`ProcessGroupSession.cpp:92-110` 用
  `std::unique_ptr<OwnedProcessGroup> group;` 先声明，在 `try` 内 `project.emplace()`、
  身份拷贝与 `make_unique`，`catch (...)` 中置 `failed/retired` 并 `return`，线程正常退出。
- 该 catch 未构造成功 group，也没有原生责任可清退；主循环仅在 `cleanClose` 时
  才让 `group` 随 `Run()` 返回析构（`:264-267`），未 clean 的原 group 不会被销毁。
  本轮未改动 Session 源码，核对的是当前磁盘版本。

## 5. 无构建调度模型（扩充至 8 例，全部通过）

用例：`tools/action_analyze_validation/qt/process_group_session_model.py`。
用 FakeGroup 替身逐分支移植会话状态机与 Qt 投影逻辑，不编译、不启动 GUI、
不测试 NativeDebugOwner。

```
python tools/action_analyze_validation/qt/process_group_session_model.py
```

真实输出（EXIT_CODE=0）：

```
PASS: 后台单在途：忙时 Submit 被拒
PASS: 后台单在途：最大并发调用数为 1
PASS: 已接纳命令不被丢弃：先 Pause 后 Close
PASS: 已接纳命令不被丢弃：Pause 确实执行过
PASS: 清退未 clean：group 保活且线程未结束
PASS: 清退未 clean：重试到 clean 后才销毁并 retired
PASS: 关闭后仅 Recover 可 Submit（等待窗口）
PASS: worker 先取 pending 才转 Close
PASS: Recover 与重试完成后才销毁 group
PASS: clean 前共享状态一直保活
PASS: clean Close 后才结算
PASS: 重放：展示原票据账本结果而非顶层Duplicate
PASS: 重放：展示原票据诊断/错误而非当前集合状态
PASS: 重放：标记原票据重放非首次执行
PASS: 重放：有outcomes不算无成员动作
PASS: 拒绝票据：AppliedOperation为假
PASS: 拒绝票据：展示原拒绝三字段
PASS: 拒绝票据：标记未执行成员
PASS: 拒绝票据：不被当成成功票据
PASS: 成员control各自保留，不由顶层三字段推断
PASS: 部分失败不再被汇总为全组成功
RESULT: 8/8 cases passed
```

## 6. 双语定点补齐与正式 audit

本轮定点插入（仅锚点字符串替换，无 `json.load/json.dump`、无键序重排）：

- 首轮：本页 66+3 条 source 翻译 + `monitor.tab.action_analyze.process_group` 双语标题。
- 本轮：46 条新增源文本，覆盖 `ProcessGroupMemoryPane.*` 全部用户文本、
  `ProcessGroupSession.cpp` 的 4 条本端元数据（`Process group memory snapshots`、
  `Explicit read-only selected ranges`、`Selected process memory`、
  `memorySnapshotSelection`）、以及本轮新增的 7 条 operation 投影文本。
- 脚本先断言占位符 `%1/%2/%3` 一致、换行一致、英文包无汉字；插入后 JSON 可解析，
  BOM/换行未被破坏，未覆盖既有键值。

正式命令与真实结果：

```
python tools/i18n_language_pack.py audit \
  --source-root Ksword5.1/Ksword5.1 \
  --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json \
  --en-pack Ksword5.1/Ksword5.1/languages/en-US.json
```

```
EXIT_CODE=0
i18n audit passed: 32149 source strings
```

- **剩余缺项：0**；本轮开始时为 92 issue（46 条×双语），现已全部闭合。
- 非本范围缺项：本轮 audit 已整体通过，无需归因他人的未补词条。
- 附带发现（非本轮引入、未修改）：两包各有一个 HEAD 既有重复键 `转储文件`，
  工作树另有一个 `写入：` 重复键；不影响本次 audit 通过，归属其他作者内容。

日志：`.codex-build-logs/pg2-audit-before.txt`、`pg2-audit-after-src.txt`、
`pg2-audit-final.txt`、`pg2-report*.json`。

## 7. MemoryPane 共享 API 核对

`ProcessGroupMemoryPane.cpp` 调用的共享入口逐项对照头文件：
`StyleSecondaryForm(form,100)`、`StyleParameterSection`、`FlowLayout(actions,0,8,8)`、
`NormalizeToolbarLayout`、`LanguageManager::bindText/bindToolTip/sourceText`、
`ApplyStatusRole(m_error, Error)`、`FieldDocument::section/field/note`、
`StructuredFieldView` 冻结快照翻译，以及 `QFileDialog::getSaveFileName(..., nullptr,
DontConfirmOverwrite)`（与 `ActionAnalyzeWorkspace.cpp:407` 既有用法同构）。签名一致。
该窗格只管理草稿与显式动作，不持原生 group，执行仍交父页串行 session。

## 8. UI 规范与边界

- 按钮/静态标签均经 `bindText`/`sourceText` 或共享运行时翻译；`changeEvent` 刷新表头、
  状态与字段详情。窄窗由 `ParameterWorkspace`（<860px 纵向）与 `FlowLayout` 承载。
- 管理表 `TableActionBarMode::None`；`StructuredFieldView` 为唯一字段文档来源。
- QRC 只复用 `process_refresh.svg`。
- 未构建、未链接、未运行 Qt/Light、未开 GUI；源码与模型核对不能替代真实窗口视觉验收。
- 未重测 `NativeDebugOwner`/`OwnedProcessGroup`，未碰 DataWriteWatch/步进/树文件；
  未暂存、提交或推送。
