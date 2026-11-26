# 退役验证接线记录

日期：2026-11-26。范围：活动验证工程的 Sysmon 来源退役；独立记录，不修改共享 `validation-results.md`。

## 实际源码结果

- `tools/action_analyze_validation/project/ProjectValidation.cpp` 删除旧来源 include、`RunSysmon` 和旧参数分支，保留回调声明与入口、离线项目生命周期及写锁子进程探针。
- `tools/action_analyze_validation/project/ProjectValidation.vcxproj` 及 `.filters` 移除 `ProjectSysmonEvidence.cpp`、`SysmonThreadSource.cpp` 登记，保留回调相关登记。
- `KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj` 及 `.filters` 移除旧来源两个 cpp/h 的登记，保留回调及其余既有变更。
- `KswordCLI/ActionAnalyze/Project/ProjectDocument.h` 仅删除旧 `ProjectSysmonEvidenceAccess` friend 行。
- 项目验证 README 移除旧正例执行说明，注明退役范围并链接本文。
- 未删除历史来源文件或用户档，未修改 CLI/Control 或正式工程。

## CodeBuddy 静态检查

改动作者直接调用 `codebuddy-fast-dispatch`。首次派发在执行检查前被非交互权限系统拒绝（`DeferExecuteTool` 未获授权），无检查和落盘结果。按用户要求修正执行入口授权后重试同一检查，不追加检查范围。

本次 CodeBuddy 实际运行一次 `python -B -c`，解析四个 XML 文件、检查活动入口与保留来源文件、核对既有固定回调夹具存在，执行限定七个源码/工程/README路径的 `git diff --check`，并写入本文。`RETIRED_VALIDATION_WIRING_STATIC=PASS CHECKS=25`，`SCOPED_DIFF_CHECK_EXIT=0`。

- tools\action_analyze_validation\project\ProjectValidation.vcxproj: no retired source registrations
- tools\action_analyze_validation\project\ProjectValidation.vcxproj: no duplicate source registrations
- tools\action_analyze_validation\project\ProjectValidation.vcxproj: callback source and header retained
- tools\action_analyze_validation\project\ProjectValidation.vcxproj.filters: no retired source registrations
- tools\action_analyze_validation\project\ProjectValidation.vcxproj.filters: no duplicate source registrations
- tools\action_analyze_validation\project\ProjectValidation.vcxproj.filters: callback source and header retained
- tools\action_analyze_validation\project\ProjectValidation.vcxproj: project/filter registrations match
- KswordARKLight\Features\ActionAnalyze\tests\StoredEvidenceValidation.vcxproj: no retired source registrations
- KswordARKLight\Features\ActionAnalyze\tests\StoredEvidenceValidation.vcxproj: no duplicate source registrations
- KswordARKLight\Features\ActionAnalyze\tests\StoredEvidenceValidation.vcxproj: callback source and header retained
- KswordARKLight\Features\ActionAnalyze\tests\StoredEvidenceValidation.vcxproj.filters: no retired source registrations
- KswordARKLight\Features\ActionAnalyze\tests\StoredEvidenceValidation.vcxproj.filters: no duplicate source registrations
- KswordARKLight\Features\ActionAnalyze\tests\StoredEvidenceValidation.vcxproj.filters: callback source and header retained
- KswordARKLight\Features\ActionAnalyze\tests\StoredEvidenceValidation.vcxproj: project/filter registrations match
- ProjectValidation.cpp: retired include, RunSysmon and --sysmon absent
- ProjectValidation.cpp: callback declaration and dispatch retained
- ProjectValidation.cpp: offline project and writer probe retained
- ProjectDocument.h: retired friend removed
- README.md: old positive invocation and acceptance marker removed
- KswordCLI/ActionAnalyze/Project/ProjectSysmonEvidence.cpp: historical source retained
- KswordCLI/ActionAnalyze/Project/ProjectSysmonEvidence.h: historical source retained
- KswordCLI/ActionAnalyze/Detection/SysmonThreadSource.cpp: historical source retained
- KswordCLI/ActionAnalyze/Detection/SysmonThreadSource.h: historical source retained
- Existing item 4 callback fixture retained without execution
- Scoped git diff --check exit 0

## 复用第 4 项正式 CLI 回执

复用[2026-11-26 正式 CLI 定向回执](validation-results.md#2026-11-26--正式-cli-定向回执)中的第 4 项。本批没有重跑。既有 HostX64／BelowNormal 正式构建成功，产物 `Ksword5.1/x64/Release/KswordCLI.exe`，SHA-256 `0D49267C50D2D336009773475A82E17A7DC0C8C2E8AF18E43623EFB15C6C6216`。

既有 `callback_archive_graph.py --create-fixture` 退出 `0`，`NATIVE_CALLBACK_EXIT=0`、`PROJECT_CALLBACK_VALIDATION=PASS`、`CLI_CALLBACK_ARCHIVE_GRAPH=PASS`。坐标 `raw/1 #2`、源序号 `107`、记录偏移 `472`、原包偏移 `566`、长度 `1264`、通知时间 `133000000000000123`；首、续页和完整空批对账，`ARCHIVE_UNCHANGED=True`。非空采样 `43603773-9ed3-4fc7-8cf9-566f5e6bd9d8`、空采样 `960f8e66-0802-499e-a06a-ceddd8721486`。固定档 `tools/action_analyze_validation/project/x64/Release/callback-project-fixture` 原位保留，本次不运行、不修改或清理。

此回执仅证明既有版本正式 CLI 对合成自有回调档的读取，不替代本批验证工程编译，不证明真实驱动回调采集、事件时强身份或后续执行。

## 构建、运行和产出边界

本批按用户少构建要求未构建、未链接、未启动 GUI、CLI 或原生验证器，未采集、订阅或验收回放 Sysmon，未加载驱动、制作发行包或提交。现有 Release 验证器未重建，本记录仅确认源码退役接线与适用静态检查。

新增报告仅为 `docs/action-analyze-planning/retired-validation-wiring.md`；没有生成编译产物、运行副本或测试配置，没有执行清理；既有用户档、历史文件和固定回调夹具保留。共享 `validation-results.md` 未修改。
