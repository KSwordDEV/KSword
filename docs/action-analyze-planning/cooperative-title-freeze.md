# 合作采样标题冻结（清单第 2 项）定向源码检查记录

- 日期：2026-11-26
- 范围：仅定向源码检查与记录。按用户要求本次**未构建、未启动 GUI、未改动任何产品源码**；结果不能标为正式运行完成。
- 改动主题：合作采样标题在 UI 线程启动时冻结进请求，工作线程只读取冻结副本，不再访问翻译管理器。

## 1. 核对项与实际结果

### 1.1 请求字段与实际复制链路

- `PassiveApiCaptureRequest` 新增字段确认：`Ksword5.1/Ksword5.1/ActionAnalyze/PassiveApiCaptureOwner.h:27`
  `QString cooperativeTitle; // UI 线程冻结的本次合作采样标题，后台不访问翻译管理器。`
- `PassiveApiCapturePane::start` 冻结确认（`Ksword5.1/Ksword5.1/ActionAnalyze/PassiveApiCapturePane.cpp:240-260`）：
  - `auto request = m_context`（值复制，冻结清单与修订）；
  - 合作模式时 `request.cooperativeTitle = sourceText(QStringLiteral("合作 Agent（PID %1）")).arg(request.pid);`（PassiveApiCapturePane.cpp:249），与目标身份同轮冻结；
  - 随后 `std::make_shared<PassiveApiCaptureOwner>(std::move(request))`（PassiveApiCapturePane.cpp:260），构造函数 `m_request(std::move(request))`（PassiveApiCaptureOwner.cpp:126）把整份请求（含标题）按值沉入 owner 的 `const` 成员，后台期间不再改写。
- **唯一构造/调用点**：全仓库 grep `PassiveApiCaptureOwner|collectCooperative`，构造点仅 PassiveApiCapturePane.cpp:260 一处；`collectCooperative()` 定义于 PassiveApiCaptureOwner.cpp:213，唯一调用在 `collect()` 内（PassiveApiCaptureOwner.cpp:147，经 `m_operation->submit` 的 worker lambda 调用 `owner->collect(token)`，PassiveApiCapturePane.cpp:268-269）。无第二个入口。

### 1.2 worker 不再读翻译管理器

- `PassiveApiCaptureOwner.cpp` 头部 include（PassiveApiCaptureOwner.cpp:1-11）为 Framework.h、各自有头、QScopeGuard、algorithm、thread，**无 `Internationalization/LanguageManager.h`**，`sourceText`/`LanguageManager` 在该文件零出现。
- `collectCooperative` 只做 `const auto title = m_request.cooperativeTitle.toStdString();`（PassiveApiCaptureOwner.cpp:232），注释标明「本轮启动前由 UI 冻结的标题」；标题随后传入 `project::CaptureCooperativeApi`（PassiveApiCaptureOwner.cpp:247）。
- 对照：`sourceText` 仍只出现在 UI 层文件（PassiveApiCapturePane.cpp 等）；ActionAnalyze 目录内引用 LanguageManager 的文件均为主线程 UI/报告渲染文件，owner 工作线程文件不在其中。

### 1.3 语言包条目

- zh-CN.json:8280：`"合作 Agent（PID %1）": "合作 Agent（PID %1）"`
- en-US.json:8280：`"合作 Agent（PID %1）": "Cooperative Agent (PID %1)"`
- 两个包条目均在 `source_translations` 段（zh-CN.json 从 7977 行起），两文件该行号一致。

## 2. i18n audit 执行结果

命令（仓库规定原文）：

```
python tools/i18n_language_pack.py audit --source-root Ksword5.1/Ksword5.1 --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json --en-pack Ksword5.1/Ksword5.1/languages/en-US.json
```

- 实际输出：`i18n audit passed: 31979 source strings`
- **结果：通过，无报错，无首错。**

## 3. 语言包条数

- zh-CN.json 顶层条目（4 空格缩进 `"…": "…"` 形式）：46362 条
- en-US.json：46362 条（两包条数一致）
- 语言包结构：`translations`（10 行起）、`context_translations`（2803 行起）、`source_translations`（7977 行起）三段；文件总行数 46445。audit 报告的 31979 为源码去重后的词条数，与包内条目数口径不同，均如实记录。

## 4. 边界与结论

- 源码核对 3 项全部符合预期：请求按值复制并 `move` 沉入唯一 owner、标题仅在 UI 线程 `start` 冻结、worker 仅消费 `cooperativeTitle.toStdString()` 且无翻译管理器依赖。
- 语言包中英条目均在，audit 一次通过，无首错。
- **未构建、未启动 GUI、未做运行/GUI 验收**；本记录为用户要求延后 GUI 的定向源码检查，不代表正式运行验收完成。运行/视觉验收仍按 11 项产品验收清单待后续批次执行。
