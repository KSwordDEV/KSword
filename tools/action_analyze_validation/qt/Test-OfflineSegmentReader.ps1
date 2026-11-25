#requires -Version 7.0
[CmdletBinding()]
param([switch]$VerifyCliEtw)

$ErrorActionPreference = 'Stop'
# 只复用已安装的 64 位工具链、Qt 和正式 Release 运行库。
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$vcvars = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat'
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
$qt = @((Join-Path $repo '.deps\Qt\6.9.3\msvc2022_64'), 'D:\Software\Qt\6.9.3\msvc2022_64') |
    Where-Object { Test-Path -LiteralPath (Join-Path $_ 'lib\Qt6Core.lib') -PathType Leaf } | Select-Object -First 1
if (!$vcvars -or !$qt) { throw 'The approved HostX64 MSVC and QtCore development files are required.' }

# 拒绝覆盖已有或跟踪的输出，也不部署新的运行库。
$intRoot = (Resolve-Path (Join-Path $repo 'Ksword5.1\Ksword5.1\x64\Release')).Path
$outRoot = (Resolve-Path (Join-Path $repo 'Ksword5.1\x64\Release')).Path
$scratch = Join-Path $intRoot 'ActionAnalyzeOfflineSegmentReaderTests'
$exe = Join-Path $outRoot 'ActionAnalyzeOfflineSegmentReaderTests.exe'
$tracked = git --no-optional-locks -C $repo ls-files -- 'Ksword5.1/Ksword5.1/x64/Release/ActionAnalyzeOfflineSegmentReaderTests' 'Ksword5.1/x64/Release/ActionAnalyzeOfflineSegmentReaderTests.exe'
if ($LASTEXITCODE -ne 0 -or $tracked -or (Test-Path -LiteralPath $scratch) -or (Test-Path -LiteralPath $exe)) {
    throw 'Fixture paths must be free and untracked.'
}
if (!(Test-Path -LiteralPath (Join-Path $outRoot 'Qt6Core.dll') -PathType Leaf)) { throw 'The Release Qt6Core runtime is required.' }

$vectors = Get-Content -LiteralPath (Join-Path $repo 'schemas\action_analyze\vectors\stored-v1.json') -Raw | ConvertFrom-Json -AsHashtable
$names = @('valid-header-alone', 'event-segment-with-known-zeroes', 'truncated-second-block-payload',
    'bad-second-stored-crc', 'event-json-length-disagrees-with-payload', 'optional-unknown-record',
    'required-unknown-record', 'unavailable-zstd') # 来自仓库格式契约的有效与负控文件。
$sources = @(
    (Join-Path $PSScriptRoot 'OfflineSegmentReaderTests.cpp'),
    'Ksword5.1\Ksword5.1\ActionAnalyze\OfflineSegmentReader.cpp',
    # Qt 读取器用归档投影核对可识别的网络 RawRecord，链接同一组依赖。
    'KswordCLI\ActionAnalyze\Archive\NetworkEvidenceArchive.cpp',
    'KswordCLI\ActionAnalyze\Archive\SegmentBodies.cpp',
    'KswordCLI\ActionAnalyze\Archive\SegmentInspection.cpp',
    'KswordCLI\ActionAnalyze\Archive\SegmentReader.cpp',
    'KswordCLI\ActionAnalyze\Archive\SegmentFormat.cpp',
    'KswordCLI\ActionAnalyze\Archive\SegmentWriter.cpp',
    'shared\evidence\EvidenceJson.cpp', 'shared\evidence\LosslessValue.cpp'
) | ForEach-Object {
    if ([IO.Path]::IsPathRooted($_)) { [IO.Path]::GetFullPath($_) } else { Join-Path $repo $_ }
}
$artifacts = @($sources | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) + '.obj' }) +
    @($names | ForEach-Object { "$_.ksaseg" }) + '00000000000000000001.ksaseg' # 清理范围为本次生成的文件。
$hostProcess = Get-Process -Id $PID
$oldPriority = $hostProcess.PriorityClass
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$null = New-Item -ItemType Directory -Path $scratch
Push-Location $scratch
try {
    $hostProcess.PriorityClass = 'BelowNormal'
    $env:TEMP = $scratch
    $env:TMP = $scratch
    Write-Output "IntDir=$scratch"
    Write-Output "OutDir=$outRoot"
    $sourceArguments = ($sources | ForEach-Object { '"{0}"' -f $_ }) -join ' '
    $compile = 'call "{0}" && where cl.exe && cl.exe /nologo /std:c++20 /Zc:__cplusplus /permissive- /EHsc /utf-8 /W4 /WX /O2 /MD /DNOMINMAX /external:I"{1}\include" /external:I"{1}\include\QtCore" /external:W0 {2} /link "{1}\lib\Qt6Core.lib" /OUT:"{3}"' -f $vcvars, $qt, $sourceArguments, $exe
    & cmd.exe /d /c $compile
    if ($LASTEXITCODE -ne 0) { throw "Fixture build exited $LASTEXITCODE." }

    # 只物化测试所需的固定向量，不接触任何已有项目或采样。
    foreach ($name in $names) {
        $case = $vectors.cases | Where-Object { $_.id -ceq $name }
        if (!$case) { throw "Missing Stored vector $name." }
        $hex = $vectors.fixtures[$case.base].hex -join ''
        if ($case.Contains('take')) { $hex = $hex.Substring(0, 2 * $case.take) }
        if ($case.Contains('append')) { $hex += $vectors.fixtures[$case.append].hex -join '' }
        if ($case.Contains('appendHex')) { $hex += $case.appendHex }
        $bytes = [Convert]::FromHexString($hex)
        foreach ($patch in $case.patch) { [Convert]::FromHexString($patch[1]).CopyTo($bytes, [int]$patch[0]) }
        if ($case.Contains('truncate')) { [Array]::Resize([ref]$bytes, [int]$case.truncate) }
        [IO.File]::WriteAllBytes((Join-Path $scratch "$name.ksaseg"), $bytes)
    }
    Write-Output "Fixture SHA256=$((Get-FileHash -LiteralPath $exe).Hash)"
    & $exe $scratch
    if ($LASTEXITCODE -ne 0) { throw "Fixture exited $LASTEXITCODE." }
    if ($VerifyCliEtw) {
        $lightValidator = Join-Path $outRoot 'KswordARKLightStoredEvidenceValidation.exe'
        $cliTest = Join-Path $repo 'tools\action_analyze_validation\cli\live_etw.py'
        & py -3.12 -B $cliTest --readback $exe $lightValidator
        if ($LASTEXITCODE -ne 0) { throw "Live CLI readback exited $LASTEXITCODE." }
    }
} finally {
    Pop-Location
    $hostProcess.PriorityClass = $oldPriority
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
    foreach ($name in $artifacts) {
        $path = Join-Path $scratch $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path }
    }
    if (!(Get-ChildItem -LiteralPath $scratch -Force)) { Remove-Item -LiteralPath $scratch }
    if (Test-Path -LiteralPath $exe -PathType Leaf) { Remove-Item -LiteralPath $exe }
}
