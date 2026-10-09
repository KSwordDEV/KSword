#include "PluginHost.Archive.h"
#include <QDir>

namespace
{
    // 路径作为 PowerShell 单引号字面量传入，拒绝代码插值或命令替换。
    QString literal(QString value)
    {
        return QLatin1Char('\'') + value.replace(QLatin1Char('\''), QStringLiteral("''")) + QLatin1Char('\'');
    }
}

namespace ks::plugin_host
{
    QString buildArchiveExtractionScript(const QString& archive, const QString& destination,
        const ArchiveLayout& layout, const ArchiveLimits& limits)
    {
        // 调用方预算必须为正且有全局硬上限，普通与上游入口无法另走无界解包路径。
        if (!QDir::isAbsolutePath(archive) || !QDir::isAbsolutePath(destination) ||
            layout.expectedWrapper.isEmpty() || layout.expectedWrapper.contains(QLatin1Char('/')) ||
            layout.expectedWrapper.contains(QLatin1Char('\\')) ||
            limits.maximumFileBytes <= 0 || limits.maximumFileBytes > 1024LL * 1024 * 1024 ||
            limits.maximumExpandedBytes <= 0 || limits.maximumExpandedBytes > 4LL * 1024 * 1024 * 1024 ||
            limits.maximumEntries <= 0 || limits.maximumEntries > 100000 ||
            limits.maximumDepth <= 0 || limits.maximumDepth > 64)
            return {};

        // PowerShell 5 的长路径处理统一使用 Native-Path。预检规范化每个路径，
        // 同时拒绝链接、别名、重复、文件/目录冲突以及所有展开预算越界。
        return QStringLiteral(R"PS(
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.AppContext]::SetSwitch('Switch.System.IO.UseLegacyPathHandling',$false)
[System.AppContext]::SetSwitch('Switch.System.IO.BlockLongPaths',$false)
$destination=%1
$wrapper=%2
$allowRoot=%3
function Native-Path([string]$path){
  $path=$path.Replace('/','\')
  if($path.StartsWith('\\?\')){return $path}
  if($path.StartsWith('\\')){return '\\?\UNC\'+$path.Substring(2)}
  return '\\?\'+$path
}
# Existing stage directories must not redirect outside their owned destination.
function Assert-Directory([string]$path){
  if([IO.Directory]::Exists($path)){
    if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse directory in ZIP destination'}
    return
  }
  if([IO.File]::Exists($path)){throw 'ZIP directory collides with existing file'}
  $parent=$path.Substring(0,$path.LastIndexOf('\'))
  if($parent -ne $path -and $parent.Length -gt 7){Assert-Directory $parent}
  [IO.Directory]::CreateDirectory($path)|Out-Null
  if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse directory in ZIP destination'}
}
$zip=[System.IO.Compression.ZipFile]::OpenRead((Native-Path %4))
try {
  if($zip.Entries.Count -gt %5){throw 'ZIP entry limit exceeded'}
  [long]$total=0
  $names=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $files=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $directories=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $rows=New-Object 'System.Collections.Generic.List[object]'
  $rootManifest=$false
  $wrappedManifest=$false
  $prefix=$destination.Replace('/','\').TrimEnd('\')+'\'
  foreach($entry in $zip.Entries){
    $name=$entry.FullName.Replace('\','/')
    if(!$name -or $name.StartsWith('/') -or $name.Contains(':') -or $name -match '[\x00-\x1f\x7f]'){throw 'Unsafe ZIP entry'}
    $isDirectory=$name.EndsWith('/')
    $relative=$name.TrimEnd('/')
    $parts=$relative.Split('/')
    if(!$relative -or $parts.Length -gt %6){throw 'ZIP path depth limit exceeded'}
    foreach($part in $parts){
      if(!$part -or $part.Length -gt 255 -or $part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part.IndexOfAny([char[]]'<>"|?*') -ge 0){throw 'Unsafe ZIP component'}
      if($part -match '^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(\..*)?$'){throw 'Windows device alias in ZIP'}
    }
    if(!$names.Add($relative)){throw 'Duplicate ZIP path'}
    $kind=($entry.ExternalAttributes -shr 16) -band 61440
    if(($kind -ne 0 -and $kind -ne 32768 -and $kind -ne 16384) -or ($entry.ExternalAttributes -band 1024)){throw 'ZIP links/reparse/special entries are forbidden'}
    if(($kind -eq 16384 -or ($entry.ExternalAttributes -band 16)) -and !$isDirectory){throw 'ZIP directory attribute mismatch'}
    if($entry.Length -lt 0 -or $entry.Length -gt %7 -or ($isDirectory -and $entry.Length -ne 0)){throw 'ZIP file limit exceeded'}
    if($entry.Length -gt (%8 - $total)){throw 'ZIP expansion limit exceeded'}
    $total += $entry.Length
    $target=$prefix+$relative.Replace('/','\')
    if($target.Length -gt 32760 -or !$target.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'ZIP escaped staging directory'}
    if($isDirectory){[void]$directories.Add($relative)}else{[void]$files.Add($relative)}
    for($partIndex=1;$partIndex -lt $parts.Length;$partIndex++){
      [void]$directories.Add(($parts[0..($partIndex-1)] -join '/'))
    }
    if(!$isDirectory -and $relative -ieq 'plugin.json'){$rootManifest=$true}
    if(!$isDirectory -and $relative -ieq ($wrapper+'/plugin.json')){$wrappedManifest=$true}
    $rows.Add([PSCustomObject]@{Entry=$entry;Relative=$relative;Directory=$isDirectory;Target=$target})
  }
  foreach($file in $files){if($directories.Contains($file)){throw 'ZIP file/directory collision'}}
  if($allowRoot){
    if($rootManifest -and $wrappedManifest){throw 'Ambiguous ZIP plugin layout'}
    if(!$rootManifest -and !$wrappedManifest){throw 'ZIP plugin manifest is missing'}
  }
  if(!$allowRoot -or !$rootManifest){
    foreach($row in $rows){
      $first=($row.Relative.Split('/'))[0]
      if((!$allowRoot -and $first -cne $wrapper) -or ($allowRoot -and $first -ine $wrapper)){throw 'Unexpected ZIP wrapper'}
    }
  }
  # Actual decompression is bounded too; forged length fields never enable an unbounded CopyTo.
  Assert-Directory (Native-Path $destination)
  [long]$writtenTotal=0
  $buffer=New-Object byte[] 65536
  foreach($row in $rows){
    $native=Native-Path $row.Target
    if($row.Directory){Assert-Directory $native;continue}
    Assert-Directory ($native.Substring(0,$native.LastIndexOf('\')))
    $ksArchiveInput=$row.Entry.Open()
    try {
      $ksArchiveOutput=[IO.FileStream]::new($native,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
      try {
        [long]$written=0
        while(($count=$ksArchiveInput.Read($buffer,0,$buffer.Length)) -gt 0){
          if($count -gt (%7 - $written) -or $count -gt ($row.Entry.Length - $written) -or $count -gt (%8 - $writtenTotal)){throw 'ZIP decompressed length exceeds budget'}
          $ksArchiveOutput.Write($buffer,0,$count)
          $written += $count
          $writtenTotal += $count
        }
        if($written -ne $row.Entry.Length){throw 'ZIP decompressed length mismatch'}
      } finally {$ksArchiveOutput.Dispose()}
    } finally {$ksArchiveInput.Dispose()}
  }
} finally {$zip.Dispose()}
)PS").arg(literal(destination), literal(layout.expectedWrapper),
            layout.allowRootPluginManifest ? QStringLiteral("$true") : QStringLiteral("$false"), literal(archive),
            QString::number(limits.maximumEntries), QString::number(limits.maximumDepth),
            QString::number(limits.maximumFileBytes), QString::number(limits.maximumExpandedBytes));
    }
}
