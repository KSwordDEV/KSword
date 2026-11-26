# ActionAnalyze A2 offline rule validation

`ActionAnalyzeRulesValidation` is a standalone HostX64 C++20 fixture. It uses hand-built in-memory event projections and the production predicate and replay sources. The expected result is exit code `0` and `ActionAnalyze rules checks passed: 152`.

## Run the fixture

From the repository root in a dedicated x64 Native Tools PowerShell session, run the following. The intermediate directory is `tools/action_analyze_validation/rules/x64/Release`, and the shared Release output directory is `Ksword5.1/x64/Release`. The fixture creates three `.obj` files in its intermediate directory and `ActionAnalyzeRulesValidation.exe` in the shared Release directory.

```powershell
$ErrorActionPreference = 'Stop'
[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal'
$clPath = (Get-Command cl.exe -CommandType Application).Source
if ($clPath -notmatch '\\Hostx64\\x64\\cl\.exe$') { throw "Expected HostX64 compiler, got $clPath" }

$intDir = Join-Path (Get-Location).Path 'tools\action_analyze_validation\rules\x64\Release'
$outDir = (Resolve-Path -LiteralPath 'Ksword5.1\x64\Release').Path
$exe = Join-Path $outDir 'ActionAnalyzeRulesValidation.exe'
New-Item -ItemType Directory -Force -Path $intDir | Out-Null
$env:TEMP = $intDir
$env:TMP = $intDir
Write-Output "IntDir=$intDir"
Write-Output "OutDir=$outDir"
Write-Output "Compiler=$clPath"

$build = 'cl /nologo /std:c++20 /EHsc /utf-8 /W4 /WX /O2 /Fo"{0}\\" /Fe"{1}" KswordCLI\ActionAnalyze\Rules\FilterAst.cpp KswordCLI\ActionAnalyze\Rules\AnalysisRun.cpp tools\action_analyze_validation\rules\ActionAnalyzeRulesValidation.cpp' -f $intDir, $exe
& cmd.exe /d /c $build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

The generated files are disposable. After checking the resolved paths, tracking status, and process exit, remove the fixture EXE and `FilterAst.obj`, `AnalysisRun.obj`, and `ActionAnalyzeRulesValidation.obj` from the fixed directories above.

## CLI project integration

Register these paths relative to `KswordCLI/` in both `KswordCLI.vcxproj` and `KswordCLI.vcxproj.filters`. The filter columns reuse the current ActionAnalyze CLI filters.

| Item | Include path | Filter |
| --- | --- | --- |
| `ClCompile` | `ActionAnalyze\Rules\FilterAst.cpp` | `源文件\ActionAnalyze CLI` |
| `ClCompile` | `ActionAnalyze\Rules\AnalysisRun.cpp` | `源文件\ActionAnalyze CLI` |
| `ClInclude` | `ActionAnalyze\Rules\FilterAst.h` | `头文件\ActionAnalyze CLI` |
| `ClInclude` | `ActionAnalyze\Rules\AnalysisRun.h` | `头文件\ActionAnalyze CLI` |

The fixture has its own `main` and is compiled by the command above. CLI registration adds two standard-library-only translation units. The registration regression gate is a HostX64 Release CLI build and the standalone fixture. When wiring an adapter or CLI route, also check help and capability output, existing read-only commands, JSONL request and response framing, and archive reopen with a fixed committed cutoff and incomplete coverage.

## Coverage and A0 limits

- The fixture checks the Strong Kleene truth tables, phase and type rejection, UTF-8 and truncation, repeated and conflicting event IDs, strong thread scope, source order, clock comparability, resource limits, and late evidence at a new archive cutoff. It covers event counts and two-step sequences over one source epoch, actor thread, and clock.
- The adapter supplies canonical `{sampleId,eventOrdinal}` references, a thread key resolved from verified A0 actor and owner-process evidence, and a comparable event time representable without loss in 100 ns units. An absent or weak actor, an incomparable clock, and missing source order remain unknown. Equal publication sequences can represent distinct normalized events and cannot establish strict sequence order.
- Exact counts and absence require an affirmative `VerifiedCoverage` for the same scope, rule inputs, committed cutoff, and entire closed event-time window. The adapter establishes continuous coverage and an effective source watermark independently of archive commitment. Missing coverage or a relevant gap keeps exact conclusions unknown. A positive lower bound or sequence can retain its evidence references with an incomplete result.
- The C++ views are in-memory projections. Their compatibility with A0 is limited to caller-validated value state and supported bool, u64, and ordinal UTF-8 text values, plus resolved identity, phase, and time supplied by the adapter. A0 Stored framing still leaves event-kind, phase, and clock numbers opaque and leaves complete event JSON, dictionary resolution, and checkpoint semantics to integration. Wire-format and cross-end interoperability require their own fixtures. [A0 base contract](../../../schemas/action_analyze/base-contract-v1.md)

## C# 风格谓词与归档预置

Qt 入口为「监控 → 行为分析 → 行为规则」。草稿的 `step.predicate` 与 `anchor.predicate` 接受表达式字符串，旧布尔和字段测试对象仍可用。「校验规则」检查完整树，「回放合成事件」将它交给同一三值解释器。错误显示 JSON 路径及解码后谓词内的 UTF-8 字节坐标。

`predicate-expr-v1` 支持 `!`、`&&`、`||`、括号、布尔字段、`字段 比较符 字面量`、`isNull`、`isComplete` 和 `Text.Contains/StartsWith/EndsWith/Equals`。数值是带 `u64` 后缀的十进制或 `0x` 十六进制。普通和逐字字符串按 UTF-8 保存。否定字段比较写为 `!(field == 42u64)`。显式目录绑定允许调用端检查阶段和类型。

`predicate-expr-v2` 支持 `isKnown(field)` 与 `quality(field) == "truncated"`、`quality(field) != "redacted"` 等状态比较。`isKnown` 只匹配 `known`，已知空值使用 `isNull`，未投影字段报告 `notCollected`。普通值比较继续按三值逻辑求值。定位未登记状态时使用表达式内的 UTF-8 字节范围。

「运行归档预置」读取显式选择的 API Monitor 导入 `raw/1` `.ksaseg`，验证 Stored 正文、原包分类与导入尾记，分析最近 4,096 条线索。`ksword.api.memory-operation-observed.v1` 汇集内存写入和节映射 API，`ksword.api.thread-control-observed.v1` 汇集线程创建、线程上下文和 APC API。回执含项目、采样、段内序号、原始行号和导出名。目标身份、调用效果及源覆盖保持未知。损坏、尾记缺失、其它来源和配额失败保留上次结果及当前草稿。

`AnalyzeArchivedApiPresets` 的可选 `ApiPresetProfile::ByCategory` 在规则层提供上述五个类别各自的预置 ID，沿用原始坐标和窗口上限。桌面入口仍使用默认的两组汇总。

### 独立夹具

从仓库根目录在 x64 Native Tools PowerShell 中运行。需要固定 IntDir 和 Release 文件名均未占用。

```powershell
$ErrorActionPreference = 'Stop'
[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal'
$cl = (Get-Command cl.exe -CommandType Application).Source
if ($cl -notmatch '\\Hostx64\\x64\\cl\.exe$') { throw "Expected HostX64 compiler, got $cl" }
$intDir = Join-Path (Get-Location).Path 'tools\action_analyze_validation\rules\x64\Release\RuleExpressionValidation'
$outDir = (Resolve-Path -LiteralPath 'Ksword5.1\x64\Release').Path
$exe = Join-Path $outDir 'ActionAnalyzeRuleExpressionValidation.exe'
$profile = Join-Path $outDir 'profiles\action_analyze_api_rules.json'
if (!(Test-Path -LiteralPath $profile -PathType Leaf)) { throw 'Build the product to deploy its rule profile first' }
if ((Test-Path -LiteralPath $intDir) -or (Test-Path -LiteralPath $exe)) { throw 'Fixture output is occupied' }
[IO.Directory]::CreateDirectory($intDir) | Out-Null
$env:TEMP = $intDir
$env:TMP = $intDir
Write-Output "IntDir=$intDir"
Write-Output "OutDir=$outDir"
Write-Output "Compiler=$cl"
$sources = @(
    'KswordCLI/ActionAnalyze/Rules/FilterAst.cpp'
    'KswordCLI/ActionAnalyze/Rules/AnalysisRun.cpp'
    'KswordCLI/ActionAnalyze/Rules/RuleExpression.cpp'
    'KswordCLI/ActionAnalyze/Rules/BehaviorPresets.cpp'
    'KswordCLI/ActionAnalyze/Archive/RawEvidenceArchive.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentBodies.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentFormat.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentReader.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentWriter.cpp'
    'Ksword5.1/Ksword5.1/ActionAnalyze/BehaviorRuleDraft.cpp'
    'shared/evidence/EvidenceJson.cpp'
    'shared/evidence/LosslessValue.cpp'
    'tools/action_analyze_validation/rules/RuleExpressionValidation.cpp'
) | ForEach-Object { '"' + (Resolve-Path -LiteralPath $_).Path + '"' }
$build = 'cl.exe /nologo /std:c++20 /EHsc /utf-8 /W4 /WX /O2 /DNOMINMAX /Fo"{0}\\" /Fe"{1}" bcrypt.lib' -f $intDir, $exe, ($sources -join ' ')
& cmd.exe /d /c $build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exe $intDir
exit $LASTEXITCODE
```

`bcrypt.lib` 是 Windows CNG 平台依赖，供夹具自带的 SHA-256 计算使用，没有引入任何第三方库。

夹具基线读取 Release 中已部署的规则。缺失、损坏和重新装载用例只读写 `IntDir/test-api-presets.json`，并核对两次加载分别保留自己的版本、释义和原包坐标。

2026-11-25 使用 BelowNormal 和 MSVC 14.44 HostX64 运行 v1 基线，得到 `ActionAnalyze rule expression: 113 checks, 0 failures`。夹具写入和只读重开两个真实 Stored 文件，验证原包与两种序号。缺尾记的文件通过 Stored 封装验证，归档语义门禁拒绝将其交给预置。夹具 EXE 的 SHA-256 为 `455D717B9515F3A6471899DD01998B0A6A7B4CF30231297175CC2DA9994A108B`。已核对进程退出和 Git 跟踪状态，清理本次中间文件、两个段及 EXE。规则页通过 HostX64 `/Zs` 源码检查以及语言包和主题门禁。正式 Qt 构建和真实窗口验收独立进行。

本次给上述执行命令追加 `--offline-evidence-only`，在同一 HostX64 工具链下通过 **58 项局部断言**，包括质量条件、窗口 Replay、五类预置及 Stored 段原始坐标。范围限于规则和归档验证。夹具 EXE 的 SHA-256 为 `5A0555C002E192CEC5586F7B2A142E5FB4CB82013F9B0457262933DA2A19F5F9`，固定中间文件、测试段和夹具 EXE 已清理。

2026-11-25 正式 Qt 在独立桌面通过「监控 → 行为分析 → 行为规则」验收。`运行归档预置` 对采样 `9c95b560-781d-486f-9d6a-d585f6ac559a` 显示两组汇总、五类各一条和五个原始坐标，截断重试与未保存草稿保留通过。入口沿用 `ParameterWorkspace` 和 `CodeEditorWidget`。窗口退出 `0`，配置恢复，固定夹具删除。HostX64 构建日志为 `.codex-build-logs/ksword-build-check-20261125-074133.raw.log`，Qt SHA-256 为 `1fdb0e556422f7f6105efecd7435c17ec64581a7321ff43ac4c675449ad5b459`。复跑命令为 `python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/qt/rules_preview.py`。本次窗口使用浅色主题，窄窗、高 DPI、背景模式和深色视觉验收仍待覆盖。

### 规则身份契约夹具

产品规则库的 `ApiPresetDatabase::sourceSha256` 契约：完整加载成功时是实际解析的文件原始字节摘要（小写 64 位 SHA-256），任一失败为空；已装载对象的身份与已准备谓词冻结。本节记录夹具扩展、构建运行脚本及 2026-11-26 实测回执。只构建独立夹具，未构建产品、GUI 或驱动。

`tools/action_analyze_validation/rules/RuleExpressionValidation.cpp` 的扩展：

- `TestPresetIdentity` 复用固定夹具文件 `IntDir/test-api-presets.json`，覆盖：同一 `presetSet=test.v1` 只改 `summaryZh` 必须得到不同身份；同一字节再次加载身份相同；仅在 JSON 文档外部增加空白仍可解析但身份不同；文件被覆盖或删除后旧对象的身份与规则结果仍不变；缺失、坏 JSON、坏 header、坏 predicate 四类失败都是错误且身份为空、不留部分规则。
- 摘要由夹具自带的 Windows CNG SHA-256 计算，并与三个**预先独立计算**的常量比较，不只断言长度。三个测试向量的常量由 PowerShell 的 `.NET SHA256` 计算后写死在源码中：

  | 向量 | 字节数 | SHA-256 |
  | --- | --- | --- |
  | `base`（`test.v1`，`summaryZh=old-summary`） | 339 | `c554271721e6882e242951cd02e543517cfd44feff2b4f30574927569a24c8cf` |
  | `revised`（同一 `presetSet`，`summaryZh=new-summary`） | 339 | `3fcdaed50e333d84bc1b26f3d4ec502963fcd5a0e44a53fe8fd9dfd9780240b2` |
  | `spaced`（`base` 外部加 `\n`） | 341 | `26ddee915e7cb21ef95f64a64c958f3f07ffa2f66f0e66a1f4870823b0b25657` |

  写入文件的实际字节先读回核对，再参与摘要计算，避免只比较字符串长度。
- `TestStoredPreset` 增加错误规则数据库路径：用缺失规则文件得到的错误库分析同一个成功归档的原包，断言 `InvalidPreset`；随后重新扫描同一归档，断言 Stored 边界、导入尾记与原始坐标仍可读。原归档保持成功，产品写端未改动。
- 产品库已正式实现 `sourceSha256`（见 [第 11 项外置规则内容身份](../../../docs/action-analyze-planning/rule-profile-identity.md)）：完整加载成功后是实际解析的同一份原始字节摘要，失败为空。夹具直接访问 `database.sourceSha256` 断言身份，不再使用 `requires` 兼容探测、`pending` 状态或通行开关；标准输出固定为 `ActionAnalyze preset identity contract: active`。

`tools/action_analyze_validation/rules/Invoke-RuleProfileIdentityValidation.ps1` 是对应的构建运行脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/action_analyze_validation/rules/Invoke-RuleProfileIdentityValidation.ps1
```

脚本行为：

- 复用上节的 13 个源文件与 `/W4 /WX`，固定 `IntDir=tools/action_analyze_validation/rules/x64/Release/RuleExpressionValidation`、`OutDir=Ksword5.1/x64/Release`、产物 `ActionAnalyzeRuleExpressionValidation.exe`。
- 自动寻找本机 `vcvars64` 或 `VsDevCmd`（`-arch=x64 -host_arch=x64`），先探测再编译；`cl.exe` 与 `link.exe` 必须位于 `Hostx64\x64`，否则报错退出。
- 构建宿主使用 `BelowNormal` 优先级；编译前打印绝对 `IntDir`、`OutDir`、`HostX64`。
- 只构建夹具，不调用产品构建脚本，不构建产品、GUI 或驱动，也不写 shared 验证结果。
- 固定位置已被占用时报错退出并报告，不删除任何既有产物或其它作者的测试文件。
- 成功时只清理本次运行确切创建的 13 个中间对象、两份测试 `.ksaseg`、`test-api-presets.json` 和夹具 EXE；删除前核对绝对路径边界、Git 跟踪状态和同名运行进程；中间目录只在为空时删除，不递归。失败时保留产物并在回执中给出确切路径。
- 文本日志与 JSON 回执写入 `.codex-build-logs/action-analyze-rule-profile-identity-<时间戳>.{log,json}`。

预定通过条件：脚本输出 `RESULT=PASSED EXIT_CODE=0`，夹具输出 `ActionAnalyze rule expression: N checks, 0 failures` 与 `ActionAnalyze preset identity contract: active`。脚本只接受 active 且夹具零失败，不再提供身份缺失的降级通行开关。

2026-11-26 实测回执：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/action_analyze_validation/rules/Invoke-RuleProfileIdentityValidation.ps1` 由 Windows PowerShell 5.1 执行，`RESULT=PASSED EXIT_CODE=0`。BelowNormal，HostX64 为 MSVC 14.51 `Hostx64\x64\cl.exe`／`link.exe`（`D:\Software\VS2026\VC\Tools\MSVC\14.51.36231`）；13 源 `/W4 /WX` 构建退出 0，完整夹具退出 0，输出 `261 checks, 0 failures` 与 `active`。EXE SHA-256 `52764072BF189BE468A1D553E64B24C197DB1E66CB79619274E93D82589CF48E`，随后已清理。成功日志与回执位于 `.codex-build-logs/action-analyze-rule-profile-identity-20261126-024314.{log,json,cmd,vcvars.log}`；首轮清理阶段失败的日志 `...-20261126-024226.*` 同样保留。实测发现 `Test-GitTracked` 的 `git ls-files --error-unmatch` 在 PowerShell 5.1 `Stop` 偏好下把未跟踪文件的 stderr 变成终止错误，已改为按 `git ls-files -- <path>` 输出判定并在函数内局部放宽偏好。完整路径、退出码、清理与范围声明见 [第 11 项外置规则内容身份](../../../docs/action-analyze-planning/rule-profile-identity.md#本次实测回执2026-11-26)。夹具通过不代表正式 CLI／Qt／Light 验收通过。

### 协调登记与验收

Qt 工程和 `.filters` 已由协调者登记 `..\..\KswordCLI\ActionAnalyze\Rules\RuleExpression.cpp`、`BehaviorPresets.cpp` 及对应头文件。已有 `BehaviorRuleDraft`、`BehaviorRulesPage`、`FilterAst` 与 `AnalysisRun` 的登记继续使用。CLI 路由接入时登记对应源文件和帮助。双语源文案集中于 `BehaviorRulesPage.cpp` 的谓词位置、表达式说明和归档预置回执。

正式窗口验收用同一合法 API Monitor 导入段，先检查默认草稿的三条合成事件，再执行归档预置并回查显示的源行号。损坏尾记、其它来源和取消选择分别检查上次结果是否保留。随后核对草稿编辑与提交期间的回执身份、窄窗、DPI、深浅主题和首帧。同步断点的后续切片只接受显式启动的自有合作夹具目标，准备时绑定该夹具已登记的入参、阶段和预算。三值中只有确定命中可以提交给既有会话所有者，停点与恢复由所有者验证。
