#requires -Version 7.0
[CmdletBinding()]
param([string]$VcVars64)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path
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
$scratch = Join-Path $intRoot 'ActionAnalyzeRawEvidenceValidation'
$exe = Join-Path $outRoot 'ActionAnalyzeRawEvidenceValidation.exe'
$tracked = git -C $repo ls-files -- 'KswordCLI/x64/Release/ActionAnalyzeRawEvidenceValidation' 'Ksword5.1/x64/Release/ActionAnalyzeRawEvidenceValidation.exe'
if ($LASTEXITCODE -ne 0 -or $tracked -or (Test-Path -LiteralPath $scratch) -or (Test-Path -LiteralPath $exe)) {
    throw 'Raw evidence test output paths must be free and untracked.'
}

# 使用正式 Release 目录与固定 IntDir，MSVC 与链接器继承低优先级。
$process = Get-Process -Id $PID
$oldPriority = $process.PriorityClass
$null = New-Item -ItemType Directory -Path $scratch
Push-Location $scratch
try {
    $process.PriorityClass = 'BelowNormal'
    Write-Output "IntDir=$scratch"
    Write-Output "OutDir=$outRoot"
    Write-Output "Priority=$($process.PriorityClass)"
    foreach ($tool in @('cl', 'link')) {
        $probe = 'call "{0}" >nul && where {1}.exe' -f $VcVars64, $tool
        $paths = @(& cmd.exe /d /c $probe)
        if ($LASTEXITCODE -ne 0 -or !$paths -or $paths[0] -notmatch '\\Host[xX]64\\x64\\') {
            throw "HostX64 $tool is required."
        }
        Write-Output "HostX64 $tool=$($paths[0])"
    }

    $analyze = Join-Path $repo 'KswordCLI/ActionAnalyze'
    $sources = @(
        "$analyze/Archive/tests/RawEvidenceArchiveTests.cpp",
        "$analyze/Archive/SegmentFormat.cpp", "$analyze/Archive/SegmentReader.cpp",
        "$analyze/Archive/SegmentWriter.cpp", "$analyze/Archive/SegmentBodies.cpp",
        "$analyze/Archive/SegmentInspection.cpp", "$analyze/Archive/RawEvidenceArchive.cpp",
        "$analyze/Project/ProjectDocument.cpp", "$analyze/Project/ProjectArchive.cpp", "$analyze/Project/ProjectRawEvidence.cpp",
        "$analyze/Project/ProjectStorage.cpp", "$analyze/Project/ProjectLock.cpp", "$analyze/Project/SampleCatalog.cpp",
        "$repo/shared/evidence/EvidenceJson.cpp", "$repo/shared/evidence/LosslessValue.cpp"
    ) | ForEach-Object { '"' + (Resolve-Path -LiteralPath $_).Path + '"' }
    $compile = 'call "{0}" && cl.exe /nologo /std:c++20 /EHsc /utf-8 /W4 /WX /O2 /MT /DNOMINMAX {1} /link /OUT:"{2}"' -f $VcVars64, ($sources -join ' '), $exe
    & cmd.exe /d /c $compile
    if ($LASTEXITCODE -ne 0) { throw "Raw evidence test compile exited $LASTEXITCODE." }
    & $exe $scratch
    if ($LASTEXITCODE -ne 0) { throw "Raw evidence test exited $LASTEXITCODE." }
} finally {
    Pop-Location
    $process.PriorityClass = $oldPriority
    # 本脚本独占创建这两个已校验位置。测试进程退出后只清理固定产物。
    if (Test-Path -LiteralPath $exe -PathType Leaf) { Remove-Item -LiteralPath $exe }
    if ((Resolve-Path -LiteralPath $scratch).Path -ceq $scratch) {
        Remove-Item -LiteralPath $scratch -Recurse
    }
}
