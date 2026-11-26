# 第 11 项：外置规则内容身份

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。本任务负责规则数据库身份和已有独立无窗口规则夹具，不负责 Project、CLI 或桌面端接线，不构建正式 CLI、GUI 或驱动，不提交。

## 接口与字节契约

- `KswordCLI/ActionAnalyze/Rules/BehaviorPresets.h` 的 `ApiPresetDatabase` 提供 `std::string sourceSha256`。成功时为 64 位小写十六进制 SHA-256；任意加载失败时为空。
- 摘要输入为该次文件读取形成、实际传给现有 `Evidence::ParseJson` 的同一份完整原始字节缓冲。不是路径、`presetSet`、解析后 JSON 的重序列化，也不二次打开文件计算摘要。
- 保留现有 `profiles/action_analyze_api_rules.json` 外置入口及解析、模式和谓词检查。完整检查成功后才发布内容身份。复用 Windows BCrypt SHA-256 平台实现及现有项目使用方式，不增加第三方依赖或另一套解析器。
- 同一 `presetSet` 的不同文件内容产生不同身份；JSON 空白变化也属于字节变化。完全相同字节重新加载具有相同身份。
- 数据库拥有摘要、说明文本和已准备谓词；加载后的对象不再读取文件。覆盖或删除源文件不会改变本轮数据库与其求值结果，新一轮显式加载获取新身份。
- 规则失败仍走现有诊断数据库及 `InvalidPreset` 分析结果。已提交原包的归档、边界和回查资格独立于规则可用性；本改动不对归档增加规则成功前置条件。

## 验证范围

复用 `tools/action_analyze_validation/rules/RuleExpressionValidation.cpp`，直接编译现有生产规则、JSON 和 Stored 读写源码。重点用例：

1. 同一 `presetSet` 修改释义，身份不同且新旧对象各自产生相应释义。
2. 相同原始字节重新加载身份相同，使用独立计算的摘要常量核对完整字节。
3. 只修改合法 JSON 外部空白，身份改变而规则仍可加载。
4. 覆盖、删除源文件后，旧数据库摘要、已准备规则和原包坐标不变。
5. 缺文件、坏 JSON、坏头和坏谓词的失败数据库身份为空，不暴露部分规则。
6. 原包已成功写入并通过 Stored 边界校验时，用不可用规则分析返回 `InvalidPreset`，原归档仍可独立读回。

构建只使用 HostX64、BelowNormal 和已有固定位置：

- IntDir：`tools/action_analyze_validation/rules/x64/Release/RuleExpressionValidation/`
- OutDir：`Ksword5.1/x64/Release/`
- 独立夹具：`Ksword5.1/x64/Release/ActionAnalyzeRuleExpressionValidation.exe`
- 规则测试文件及两个 Stored 测试段只放在该 IntDir，结束清理本次创建文件；Release 中的真实规则仅供读取。
- 本任务专用文本日志及小型回执置于 `.codex-build-logs/`，不写共享 `validation-results.md`。

实际夹具构建、执行、清理由本任务作者调用 CodeBuddy 完成。其回执仅证明本次规则库与独立 Stored 夹具范围，不代表正式 CLI 或 Qt／Light 的采样持久化、回放身份核对已经验收。

## 当前状态与后续交接

2026-11-26：协调者确认正式 CLI 构建及三组本机实测结束后解除产品源文件锁。`BehaviorPresets.h/.cpp` 已实现 `sourceSha256`，BCrypt 对实际解析的同一份字节求摘要，完整加载成功后发布；摘要失败返回 `rules-profile-sha256-failed` 及空身份。构建和运行结论见下节实测回执。

已完成：产品规则内容身份、独立夹具实测与回执（见下节）。本任务范围内未完成项：无。夹具内不再保留 `requires` 兼容探测、`pending` 状态或身份缺失通行开关。

集成方下一步：消费冻结数据库的 `sourceSha256`，用于实际采样配置和回放核对；加载失败须保留原包归档。Project／CLI／GUI 的数据传递不在本任务源码授权范围，因此不能仅凭本夹具关闭第 11 项的正式产品完整身份链路。

## 本次实测回执（2026-11-26）

- 任务名：规则身份夹具修正并实测，从仓库根目录执行。用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」继续适用于本任务。
- 实际命令（由 PowerShell 工具调用 Windows PowerShell 5.1，回读子进程 `$LASTEXITCODE`）：
  `powershell -NoProfile -ExecutionPolicy Bypass -File tools/action_analyze_validation/rules/Invoke-RuleProfileIdentityValidation.ps1`
  包装进程退出码 `0`。
- 优先级：脚本把宿主进程设为 `BelowNormal`，`cl.exe`／`link.exe` 等子进程继承；未切换输入桌面，未启动 GUI 或离屏窗口。
- HostX64：编译器 `D:\Software\VS2026\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe`，链接器同目录 `link.exe`；由 `vcvars64 D:\Software\VS2026\VC\Auxiliary\Build\vcvars64.bat` 建立环境，probe 与 build 两次打印均确认 `CL=`／`LINK=` 标签来自 `KSWORD_RULE_CL`／`KSWORD_RULE_LINK`，真实保留变量 `CL`／`LINK` 未被赋工具路径。
- 固定路径（相对仓库根）：IntDir `tools/action_analyze_validation/rules/x64/Release/RuleExpressionValidation`；OutDir `Ksword5.1/x64/Release`；夹具 `ActionAnalyzeRuleExpressionValidation.exe`。实际绝对路径已在日志与 JSON 回执中打印。
- 构建：13 个源文件，`/std:c++20 /EHsc /utf-8 /W4 /WX /O2 /DNOMINMAX`、`bcrypt.lib`；构建退出码 **0**，无警告或错误行（`/WX` 下退出 0）。产物 **518656** 字节。
- 运行：完整夹具 `& $exe $intDir`（不带 `--offline-evidence-only`），退出码 **0**；输出 `ActionAnalyze preset identity contract: active` 与 `ActionAnalyze rule expression: 261 checks, 0 failures`。断言数 **261**，失败 **0**。
- exe SHA-256：`52764072BF189BE468A1D553E64B24C197DB1E66CB79619274E93D82589CF48E`（脚本在链接后计算，随后已清理）。
- 实测范围：完整规则/DSL 求值、拒绝与诊断、质量条件、窗口 Replay、草稿兼容、Stored 归档预置全部回归；身份用例覆盖同一 `presetSet` 不同 `summaryZh` 内容、相同字节重载、仅外部空白变化、覆盖/删除后旧对象身份与规则冻结、缺文件/坏 JSON/坏 header/坏谓词四类失败空身份；已部署 `profiles/action_analyze_api_rules.json` 的原字节摘要等于 `database.sourceSha256`；错误规则库分析同一原包返回 `InvalidPreset`，原 Stored 边界、导入尾记与原始坐标仍可重读。
- 授权边界：本任务作者实现 `BehaviorPresets.h/.cpp`；CodeBuddy 本轮只维护和构建独立夹具，未改产品或消费者源。整个任务未构建正式 CLI／Qt／Light／驱动，未改消费者源及工程主登记，未提交，未写共享 `validation-results.md`。
- 清理：脚本报告 `CleanupRemoved=16 CleanupSkipped=0 IntDirRemoved=True`；独立复核 `IntDirExists=False`、`ExeExists=False`、同名运行进程 0。删除前逐项核对绝对路径位于固定 IntDir 或等于夹具 EXE、Git 未跟踪、无同名进程；16 个文件逐个删除，空 IntDir 非递归删除。
- 日志：成功文本日志 `.codex-build-logs/action-analyze-rule-profile-identity-20261126-024314.log`，JSON 回执同名 `.json`，批处理与 vcvars 日志同名 `.cmd`／`.vcvars.log`。首次失败日志 `.codex-build-logs/action-analyze-rule-profile-identity-20261126-024226.{log,json,cmd,vcvars.log}` 完整保留，未隐瞒。
- 实测发现的脚本故障与修复（仅改授权文件）：首轮构建退出 0、261 断言 0 失败，但 `Test-GitTracked` 用 `git ls-files --error-unmatch` 查询未跟踪对象时写 stderr，Windows PowerShell 5.1 在 `$ErrorActionPreference='Stop'` 下转为终止错误，清理阶段退出 9。改为 `git ls-files -- <path>` 按输出判定并在函数内局部放宽错误偏好；首轮遗留的 13 个 `.obj`、2 个 `.ksaseg` 与 EXE 在核对路径/进程/Git 后逐个删除、空 IntDir 非递归删除后重跑至通过。
- 范围声明：夹具通过只证明本次规则库与独立 Stored 夹具范围，不代表正式 CLI、Qt／Light 的采样持久化、回放身份核对或 GUI 验收通过。
