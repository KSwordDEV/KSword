[CmdletBinding()]
param([string]$RepositoryRoot=(Join-Path $PSScriptRoot '..'))

# 只测量统一 Release 的同一组生产运行文件；不复制运行时、不包含配置、转储或测试 EXE。
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath $RepositoryRoot).Path # 当前仓库的真实绝对根。
$release=Join-Path $root 'Ksword5.1\x64\Release' # 构建后的唯一正式运行文件位置。
$parent=Split-Path $release # 以 Release\ 为压缩包根，不带 x64 或诊断目录。
$seven='C:\Program Files\7-Zip\7z.exe' # 使用已安装的相同压缩器与压缩参数比较。
if(!(Test-Path -LiteralPath $seven)){throw '7-Zip is required for a like-for-like package measurement.'}
$directory=Join-Path $root 'dist\layout-package-size-check-20261122' # 这里只写本轮测量压缩包，不构建或部署程序。
$output=Join-Path $root '.codex-build-logs\layout-package-size-20261122.json' # 报告也不能覆盖前一轮独有证据。
if(Test-Path -LiteralPath $output){throw 'Existing package measurement report must not be overwritten.'}
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$files=[Collections.Generic.List[string]]::new() # 明确的生产运行文件清单，不自动纳入新增测试文件。
$programs=@('Ksword5.1.exe','KswordCLI.exe','Launcher.exe','KswordARKLight.exe','Taskbar.exe','KswordHUD.exe',
    'KSwordSecureDesk.exe','KswordUacDesk.exe','KswordSetup.exe','KswordARK.sys','KswordARKDriver.inf',
    'KswordARK.pdb','APIMonitor_x64.pdb','LICENSE','COMMUNITY_COVENANT.md')
foreach($name in $programs){if(Test-Path -LiteralPath (Join-Path $release $name)){$files.Add((Join-Path 'Release' $name))}}
foreach($file in Get-ChildItem -LiteralPath $release -File -Filter '*.dll') {
    if($file.Name -notmatch '\.before-'){$files.Add((Join-Path 'Release' $file.Name))} # 不包含留存的旧备份 DLL。
}
$folders=@('platforms','styles','imageformats','iconengines','generic','networkinformation','tls','translations',
    'languages','licenses','Style','KswordARKDriver','profiles') # 三种测量共用完全相同的运行依赖。
foreach($folder in $folders) {
    $path=Join-Path $release $folder # 不进入用户配置或外部第三方工具目录。
    if(Test-Path -LiteralPath $path) {
        foreach($file in Get-ChildItem -LiteralPath $path -File -Recurse) {
            $relative=[IO.Path]::GetRelativePath($parent,$file.FullName) # 所有归档项目必须以 Release\ 开头。
            $files.Add($relative)
        }
    }
}
$all=@($files|Sort-Object -Unique) # 去重并稳定顺序，避免文件次序改变固实压缩结果。
$layoutPattern='^Release\\profiles\\(?:thread_layouts|process_layouts)\\'
$indexPattern='\\_versions\.index$'
$cases=[ordered]@{
    'without-structure-layouts'=@($all|Where-Object {$_ -notmatch $layoutPattern})
    'with-structure-layouts'=@($all|Where-Object {$_ -notmatch $indexPattern})
    'with-layout-version-indexes'=$all
}
$frozen=@{} # 压缩前后核对文件大小和写入时间，运行中构建改变文件时不能给出比较结论。
foreach($name in $all) {
    $file=Get-Item -LiteralPath (Join-Path $parent $name)
    $frozen[$name]="$($file.Length):$($file.LastWriteTimeUtc.Ticks)"
}
$results=[ordered]@{} # 保留三组实际归档字节数及完整性检查结果。
$created=[Collections.Generic.List[string]]::new() # 只清理本次自己创建且验证过的固定文件。
$process=[Diagnostics.Process]::GetCurrentProcess() # 压缩同样降低优先级，避免抢占用户前台。
$priority=$process.PriorityClass # 完成后恢复调用方优先级。
try {
    $process.PriorityClass='BelowNormal'
    foreach($entry in $cases.GetEnumerator()) {
        $archive=Join-Path $directory ($entry.Key+'.7z') # 固定名称已存在时拒绝覆盖旧证据。
        $list=Join-Path $directory ($entry.Key+'.list.txt') # 列表仅包含已冻结的生产文件相对路径。
        if((Test-Path -LiteralPath $archive) -or (Test-Path -LiteralPath $list)){throw 'Existing package measurement must not be overwritten.'}
        [IO.File]::WriteAllLines($list,[string[]]$entry.Value,[Text.UTF8Encoding]::new($false))
        $created.Add($list)
        Push-Location $parent
        try {
            & $seven a -t7z -mx=9 -mmt=2 -scsUTF-8 -bd $archive ('@'+$list) | Out-Null
            if($LASTEXITCODE){throw 'Compression failed.'}
            $created.Add($archive)
            $verification=@(& $seven t -bd $archive) # 读取完整性结果，不只相信归档创建成功。
            if($LASTEXITCODE -or ($verification -join "`n") -notmatch 'Everything is Ok'){throw 'Archive integrity check failed.'}
        } finally {Pop-Location}
        $raw=0L # 当前清单实际未压缩总字节数，不用目录属性估计。
        foreach($name in $entry.Value){$raw+=(Get-Item -LiteralPath (Join-Path $parent $name)).Length}
        $results[$entry.Key]=[ordered]@{fileCount=$entry.Value.Count;rawBytes=$raw;
            archiveBytes=(Get-Item -LiteralPath $archive).Length;sha256=(Get-FileHash -LiteralPath $archive).Hash;integrityVerified=$true}
    }
    foreach($name in $all) {
        $file=Get-Item -LiteralPath (Join-Path $parent $name)
        if($frozen[$name] -ne "$($file.Length):$($file.LastWriteTimeUtc.Ticks)"){throw 'Release changed during compression; measurement is invalid.'}
    }
    $before=$results['without-structure-layouts'].archiveBytes # 不含新结构布局的同一组运行依赖。
    $layouts=$results['with-structure-layouts'].archiveBytes # 新增完整精确布局后的大小。
    $after=$results['with-layout-version-indexes'].archiveBytes # 再纳入本轮版本边界元数据。
    $report=[ordered]@{scope='Same production-runtime allowlist; excludes configuration, dumps, test executables and external tools';
        comparisonType='controlled_feature_delta_not_historical_archive';
        format='7z -mx=9 -mmt=2';cases=$results;layoutDeltaBytes=($layouts-$before);
        layoutDeltaPercent=[math]::Round(100.0*($layouts-$before)/$before,4);
        indexDeltaBytes=($after-$layouts);indexDeltaPercent=[math]::Round(100.0*($after-$layouts)/$layouts,4);
        layoutRawDeltaBytes=($results['with-structure-layouts'].rawBytes-$results['without-structure-layouts'].rawBytes);
        indexRawDeltaBytes=($results['with-layout-version-indexes'].rawBytes-$results['with-structure-layouts'].rawBytes);
        measurementArchivesRemoved=$false;releaseUntouched=$true}
} finally {
    foreach($path in $created) {
        $resolved=[IO.Path]::GetFullPath($path) # 精确路径清理，不递归删除整个 dist 或任何正式产物。
        if((Split-Path $resolved) -ne $directory){throw 'Unexpected cleanup boundary.'}
        Remove-Item -LiteralPath $resolved -Force
    }
    $process.PriorityClass=$priority
}
# 只有 finally 确实完成清理后才写入成功报告，不能提前声称尚未执行的删除已通过。
if(@($created|Where-Object {Test-Path -LiteralPath $_}).Count){throw 'Package measurement files remain after cleanup.'}
$report.measurementArchivesRemoved=$true
$report|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $output -Encoding utf8
$report|ConvertTo-Json -Depth 7
