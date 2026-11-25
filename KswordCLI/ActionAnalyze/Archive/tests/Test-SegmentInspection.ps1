#requires -Version 7.0
[CmdletBinding()]
param([string]$VcVars64)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path
$archive = Split-Path -Parent $PSScriptRoot
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
$scratch = Join-Path $intRoot 'ActionAnalyzeSegmentInspectionValidation'
$exe = Join-Path $outRoot 'ActionAnalyzeSegmentInspectionValidation.exe'
$tracked = git -C $repo ls-files -- 'KswordCLI/x64/Release/ActionAnalyzeSegmentInspectionValidation' 'Ksword5.1/x64/Release/ActionAnalyzeSegmentInspectionValidation.exe'
if ($LASTEXITCODE -ne 0 -or $tracked -or (Test-Path -LiteralPath $scratch) -or (Test-Path -LiteralPath $exe)) {
    throw 'Inspection test output paths must be free and untracked.'
}

$vectorPath = Join-Path $repo 'schemas/action_analyze/vectors/stored-v1.json'
$vectors = Get-Content -LiteralPath $vectorPath -Raw | ConvertFrom-Json -AsHashtable
$statuses = @{
    'complete' = 'framing-complete'; 'raw-only' = 'framing-complete'; 'truncated' = 'truncated'
    'segment.headerCrc' = 'header-crc'; 'segment.identity' = 'identity'; 'segment.major' = 'unsupported-version'
    'segment.requiredFlags' = 'unsupported-flags'; 'block.headerCrc' = 'header-crc'; 'block.storedCrc' = 'stored-crc'
    'block.decodedCrc' = 'decoded-crc'; 'block.codec' = 'unsupported-codec'; 'block.length' = 'block-length'
    'block.recordCount' = 'record-count'; 'block.trailingBytes' = 'record-count'; 'block.qpcRange' = 'qpc-range'
    'record.headerCrc' = 'header-crc'; 'record.payloadCrc' = 'record-payload-crc'; 'record.length' = 'record-length'
    'record.sequence' = 'sequence'
}
$objects = @('SegmentFormat.obj', 'SegmentReader.obj', 'SegmentInspection.obj', 'SegmentInspectionTests.obj')
$files = [System.Collections.Generic.List[string]]::new()
$process = Get-Process -Id $PID
$oldPriority = $process.PriorityClass
$null = New-Item -ItemType Directory -Path $scratch
Push-Location $scratch
try {
    $process.PriorityClass = 'BelowNormal'
    Write-Output "IntDir=$scratch"
    Write-Output "OutDir=$outRoot"
    $compile = 'call "{0}" && where cl.exe && cl.exe /nologo /std:c++17 /EHsc /utf-8 /W4 /WX /O2 /MT /DNOMINMAX "{1}\tests\SegmentInspectionTests.cpp" "{1}\SegmentFormat.cpp" "{1}\SegmentReader.cpp" "{1}\SegmentInspection.cpp" /link /OUT:"{2}"' -f $VcVars64, $archive, $exe
    & cmd.exe /d /c $compile
    if ($LASTEXITCODE -ne 0) { throw "Inspection test compile exited $LASTEXITCODE." }
    Write-Output "Fixture SHA256=$((Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant())"
    Write-Output "A0 vectors SHA256=$((Get-FileHash -LiteralPath $vectorPath).Hash.ToLowerInvariant())"

    foreach ($case in $vectors.cases) {
        if ($case.id -cnotmatch '^[a-z0-9-]+$') { throw "Invalid A0 case ID $($case.id)." }
        $base = $vectors.fixtures[$case.base]
        $hex = $base.hex -join ''
        if ($case.Contains('take')) { $hex = $hex.Substring(0, 2 * $case.take) }
        if ($case.Contains('append')) { $hex += ($vectors.fixtures[$case.append].hex -join '') }
        if ($case.Contains('appendHex')) { $hex += $case.appendHex }
        $bytes = [Convert]::FromHexString($hex)
        foreach ($patch in $case.patch) { [Convert]::FromHexString($patch[1]).CopyTo($bytes, [int]$patch[0]) }
        if ($case.Contains('truncate')) { [Array]::Resize([ref]$bytes, [int]$case.truncate) }
        $file = Join-Path $scratch "$($case.id).ksaseg"
        $files.Add($file)
        [IO.File]::WriteAllBytes($file, $bytes)

        $status = $statuses[$case.status]
        $prefix = $case.prefixBytes
        $blocks = $case.blocks
        if ($case.Contains('framedBytes')) {
            # A0 将正文验证端点另报为 prefixBytes。当前向量中的正文负例有一个完整封装块。
            $prefix = $case.framedBytes
            $blocks = 1
            $status = 'framing-complete'
        }
        $expected = "$status $prefix $blocks $([int]$case.opaqueOptional) $([int]($case.status -eq 'raw-only'))"
        $actual = & $exe --vector $file $base.streamKind
        if ($LASTEXITCODE -ne 0 -or $expected -cne $actual) {
            throw "Vector $($case.id) expected '$expected', got '$actual'."
        }
    }
    Write-Output "PASS $($vectors.cases.Count) A0 Stored vectors through archive.inspect"
    & $exe $scratch
    if ($LASTEXITCODE -ne 0) { throw "Inspection test exited $LASTEXITCODE." }
} finally {
    Pop-Location
    $process.PriorityClass = $oldPriority
    foreach ($name in $objects) { $files.Add((Join-Path $scratch $name)) }
    foreach ($file in $files) {
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    if (!(Get-ChildItem -LiteralPath $scratch -Force)) { Remove-Item -LiteralPath $scratch }
    if (Test-Path -LiteralPath $exe -PathType Leaf) { Remove-Item -LiteralPath $exe }
}
