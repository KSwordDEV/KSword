#requires -Version 7.0
[CmdletBinding()]
param([string]$VcVars64)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
if (!$VcVars64) {
    $VcVars64 = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat'
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (!$VcVars64) { throw 'Supply -VcVars64 for an installed MSVC x64 toolchain.' }
$VcVars64 = (Resolve-Path -LiteralPath $VcVars64).Path

$intRoot = (Resolve-Path (Join-Path $repo 'KswordCLI/x64/Release')).Path
$outRoot = (Resolve-Path (Join-Path $repo 'Ksword5.1/x64/Release')).Path
$scratch = Join-Path $intRoot 'ActionAnalyzeArchiveValidation'
$exe = Join-Path $outRoot 'ActionAnalyzeArchiveValidation.exe'
$archive = Join-Path $repo 'KswordCLI/ActionAnalyze/Archive'
$test = Join-Path $PSScriptRoot 'SegmentArchiveTests.cpp'
$vectorFile = Join-Path $scratch 'a0-vector.ksaseg'

$tracked = git -C $repo ls-files -- 'KswordCLI/x64/Release/ActionAnalyzeArchiveValidation' 'Ksword5.1/x64/Release/ActionAnalyzeArchiveValidation.exe'
if ($LASTEXITCODE -ne 0 -or $tracked -or (Test-Path -LiteralPath $scratch) -or (Test-Path -LiteralPath $exe)) {
    throw 'Archive test output paths must be free and untracked.'
}
$process = Get-Process -Id $PID
$oldPriority = $process.PriorityClass
$null = New-Item -ItemType Directory -Path $scratch
Push-Location $scratch
try {
    $process.PriorityClass = 'BelowNormal'
    Write-Output "IntDir=$scratch"
    Write-Output "OutDir=$outRoot"
    $compile = 'call "{0}" && where cl.exe && cl.exe /nologo /std:c++17 /EHsc /utf-8 /W4 /WX /O2 /MT /DNOMINMAX "{1}" "{2}\SegmentFormat.cpp" "{2}\SegmentWriter.cpp" "{2}\SegmentReader.cpp" /link /OUT:"{3}"' -f $VcVars64, $test, $archive, $exe
    & cmd.exe /d /c $compile
    if ($LASTEXITCODE -ne 0) { throw "Archive test compile exited $LASTEXITCODE." }
    & $exe $scratch
    if ($LASTEXITCODE -ne 0) { throw "Archive test exited $LASTEXITCODE." }

    $vectors = Get-Content -LiteralPath (Join-Path $repo 'schemas/action_analyze/vectors/stored-v1.json') -Raw | ConvertFrom-Json -AsHashtable
    $fixtures = $vectors.fixtures
    foreach ($case in $vectors.cases) {
        $base = $fixtures[$case.base]
        $hex = ($base.hex -join '')
        if ($case.Contains('take')) { $hex = $hex.Substring(0, 2 * $case.take) }
        if ($case.Contains('append')) { $hex += ($fixtures[$case.append].hex -join '') }
        $bytes = [Convert]::FromHexString($hex)
        foreach ($patch in $case.patch) { [Convert]::FromHexString($patch[1]).CopyTo($bytes, [int]$patch[0]) }
        if ($case.Contains('truncate')) { [Array]::Resize([ref]$bytes, [int]$case.truncate) }
        [IO.File]::WriteAllBytes($vectorFile, $bytes)

        $status = $case.status
        $prefix = $case.prefixBytes
        $blocks = $case.blocks
        $optional = [int]$case.opaqueOptional
        $required = [int]($status -eq 'raw-only')
        if ($status -in @('complete', 'raw-only')) { $status = 'framing-complete' }
        # A0 的正文负例有合法封装，语义检查由 A0 校验器独立断言。
        if ($status -in @('raw.json', 'event.validityBits', 'event.validityValue')) {
            $status = 'framing-complete'
            $prefix = $bytes.Length
            $blocks = 1
        }
        $expected = "$status $prefix $blocks $optional $required"
        $actual = & $exe --a0-vector $vectorFile $base.streamKind
        if ($LASTEXITCODE -ne 0 -or $actual -cne $expected) {
            throw "Vector $($case.id) expected '$expected', got '$actual'."
        }
    }
    Write-Output "PASS $($vectors.cases.Count) A0 Stored vectors at the framing boundary"
} finally {
    Pop-Location
    $process.PriorityClass = $oldPriority
    foreach ($name in @('SegmentArchiveTests.obj', 'SegmentFormat.obj', 'SegmentReader.obj', 'SegmentWriter.obj',
                        'reader.ksaseg', 'writer.ksaseg', 'a0-vector.ksaseg')) {
        $file = Join-Path $scratch $name
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    if (!(Get-ChildItem -LiteralPath $scratch -Force)) { Remove-Item -LiteralPath $scratch }
    if (Test-Path -LiteralPath $exe -PathType Leaf) { Remove-Item -LiteralPath $exe }
}
