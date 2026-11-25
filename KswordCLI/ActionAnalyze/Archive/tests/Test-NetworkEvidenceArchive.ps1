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
$intRoot = (Resolve-Path -LiteralPath (Join-Path $repo 'KswordCLI/x64/Release')).Path
$outRoot = (Resolve-Path -LiteralPath (Join-Path $repo 'Ksword5.1/x64/Release')).Path
$scratch = Join-Path $intRoot 'ActionAnalyzeNetworkEvidenceValidation'
$exe = Join-Path $outRoot 'ActionAnalyzeNetworkEvidenceValidation.exe'
$tracked = git -C $repo ls-files -- 'KswordCLI/x64/Release/ActionAnalyzeNetworkEvidenceValidation' 'Ksword5.1/x64/Release/ActionAnalyzeNetworkEvidenceValidation.exe'
if ($LASTEXITCODE -ne 0 -or $tracked -or (Test-Path -LiteralPath $scratch) -or (Test-Path -LiteralPath $exe)) {
    throw 'Network archive test output paths must be free and untracked.'
}

$sourceNames = @('tests/NetworkEvidenceArchiveTests', 'NetworkEvidenceArchive', 'SegmentWriter',
    'SegmentFormat', 'SegmentInspection', 'SegmentReader', 'SegmentBodies')
$sources = @($sourceNames | ForEach-Object { '"{0}/{1}.cpp"' -f $archive, $_ })
$sources += '"{0}/shared/evidence/EvidenceJson.cpp"' -f $repo
$sources += '"{0}/shared/evidence/LosslessValue.cpp"' -f $repo
$process = Get-Process -Id $PID
$oldPriority = $process.PriorityClass
$null = New-Item -ItemType Directory -Path $scratch
Push-Location $scratch
try {
    $process.PriorityClass = 'BelowNormal'
    Write-Output "IntDir=$scratch"
    Write-Output "OutDir=$outRoot"
    $compile = 'call "{0}" && where cl.exe && cl.exe /nologo /std:c++20 /EHsc /utf-8 /W4 /WX /O2 /MT /DNOMINMAX {1} /link /OUT:"{2}"' -f $VcVars64, ($sources -join ' '), $exe
    & cmd.exe /d /c $compile
    if ($LASTEXITCODE -ne 0) { throw "Network archive test compile exited $LASTEXITCODE." }
    Write-Output "Fixture SHA256=$((Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant())"
    & $exe $scratch
    if ($LASTEXITCODE -ne 0) { throw "Network archive test exited $LASTEXITCODE." }
} finally {
    Pop-Location
    $process.PriorityClass = $oldPriority
    $artifacts = @($sourceNames | ForEach-Object { "$(Split-Path -Leaf $_).obj" })
    $artifacts += 'EvidenceJson.obj', 'LosslessValue.obj', '00000000000000000001.ksaseg',
        '00000000000000000002.ksaseg', '00000000000000000004.ksaseg', '00000000000000000005.ksaseg'
    foreach ($name in $artifacts) {
        $file = Join-Path $scratch $name
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    if (!(Get-ChildItem -LiteralPath $scratch -Force)) { Remove-Item -LiteralPath $scratch }
    if (Test-Path -LiteralPath $exe -PathType Leaf) { Remove-Item -LiteralPath $exe }
}
