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

`predicate-expr-v1` 支持 `!`、`&&`、`||`、括号、布尔字段、`字段 比较符 字面量`、`isNull`、`isComplete` 和 `Text.Contains/StartsWith/EndsWith/Equals`。数值是带 `u64` 后缀的十进制或 `0x` 十六进制。普通和逐字字符串按 UTF-8 保存。否定字段比较写为 `!(field == 42u64)`。显式目录绑定允许调用端检查阶段和类型。后续语法扩展需新增语义版本及测试向量。

「运行归档预置」读取显式选择的 API Monitor 导入 `raw/1` `.ksaseg`，验证 Stored 正文、原包分类与导入尾记，分析最近 4,096 条线索。`ksword.api.memory-operation-observed.v1` 汇集内存写入和节映射 API，`ksword.api.thread-control-observed.v1` 汇集线程创建、线程上下文和 APC API。回执含项目、采样、段内序号、原始行号和导出名。目标身份、调用效果及源覆盖保持未知。损坏、尾记缺失、其它来源和配额失败保留上次结果及当前草稿。

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
$build = 'cl.exe /nologo /std:c++20 /EHsc /utf-8 /W4 /WX /O2 /DNOMINMAX /Fo"{0}\\" /Fe"{1}" {2}' -f $intDir, $exe, ($sources -join ' ')
& cmd.exe /d /c $build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exe $intDir
exit $LASTEXITCODE
```

2026-11-25 使用 BelowNormal 和 MSVC 14.44 HostX64 运行，得到 `ActionAnalyze rule expression: 113 checks, 0 failures`。夹具写入和只读重开两个真实 Stored 文件，验证原包与两种序号。缺尾记的文件通过 Stored 封装验证，归档语义门禁拒绝将其交给预置。夹具 EXE 的 SHA-256 为 `455D717B9515F3A6471899DD01998B0A6A7B4CF30231297175CC2DA9994A108B`。已核对进程退出和 Git 跟踪状态，清理本次中间文件、两个段及 EXE。规则页通过 HostX64 `/Zs` 源码检查以及语言包和主题门禁。正式 Qt 构建和真实窗口验收独立进行。

### 协调登记与验收

Qt 工程和 `.filters` 已由协调者登记 `..\..\KswordCLI\ActionAnalyze\Rules\RuleExpression.cpp`、`BehaviorPresets.cpp` 及对应头文件。已有 `BehaviorRuleDraft`、`BehaviorRulesPage`、`FilterAst` 与 `AnalysisRun` 的登记继续使用。CLI 路由接入时登记对应源文件和帮助。双语源文案集中于 `BehaviorRulesPage.cpp` 的谓词位置、表达式说明和归档预置回执。

正式窗口验收用同一合法 API Monitor 导入段，先检查默认草稿的三条合成事件，再执行归档预置并回查显示的源行号。损坏尾记、其它来源和取消选择分别检查上次结果是否保留。随后核对草稿编辑与提交期间的回执身份、窄窗、DPI、深浅主题和首帧。同步断点的后续切片只接受显式启动的自有合作夹具目标，准备时绑定该夹具已登记的入参、阶段和预算。三值中只有确定命中可以提交给既有会话所有者，停点与恢复由所有者验证。
