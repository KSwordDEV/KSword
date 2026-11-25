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
