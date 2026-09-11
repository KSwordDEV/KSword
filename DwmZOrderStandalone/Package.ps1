param([Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($PSScriptRoot)
if (!(Test-Path -LiteralPath (Join-Path $root 'core/DwmZOrderAgent'))) { throw 'Package from an exported standalone source project; run Export-Source.ps1 first.' }
$output=[IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $output) { throw 'Choose a new package destination to avoid replacing another release.' }
$bin=Join-Path $root 'build/bin/Release'
$required=@('DwmOrderTool.exe','KswordDwmZOrder.dll')
foreach ($file in $required) { if (!(Test-Path -LiteralPath (Join-Path $bin $file))) { throw "Build Release first: $file" } }
# A stale exported core must not silently enter a compatibility test release.
$sourceManifest=Get-Content -LiteralPath (Join-Path $root 'source-manifest.json') -Raw | ConvertFrom-Json
foreach ($entry in $sourceManifest) {
    if ((Get-FileHash -LiteralPath (Join-Path $root $entry.path) -Algorithm SHA256).Hash -ne $entry.sha256) { throw "Exported source changed; refresh its manifest before packaging: $($entry.path)" }
}
$receipt=Get-Content -LiteralPath (Join-Path $root 'build/Release-receipt.json') -Raw | ConvertFrom-Json
$expectedInputs=@($sourceManifest | Where-Object { $_.path -match '(\.(cpp|h|asm|rc|manifest)$|CMakeLists\.txt$)' })
if ($receipt.configuration -ne 'Release' -or !$receipt.testsPassed -or $receipt.inputs.Count -ne $expectedInputs.Count) { throw 'A successful tested Release build from this exported source is required.' }
foreach ($entry in $expectedInputs) {
    $match=@($receipt.inputs | Where-Object { $_.path -eq $entry.path -and $_.sha256 -eq $entry.sha256 })
    if ($match.Count -ne 1) { throw "Build is stale for source file: $($entry.path)" }
}
foreach ($file in $required) {
    $hash=(Get-FileHash -LiteralPath (Join-Path $bin $file) -Algorithm SHA256).Hash
    if (@($receipt.outputs | Where-Object { $_.path -eq $file -and $_.sha256 -eq $hash }).Count -ne 1) { throw "Build artifact differs from its receipt: $file" }
}
New-Item -ItemType Directory -Path $output | Out-Null
$portable=Join-Path $output 'DwmOrderTool-x64'
New-Item -ItemType Directory -Path $portable | Out-Null
foreach ($file in $required) { Copy-Item -LiteralPath (Join-Path $bin $file) -Destination $portable }
foreach ($file in @('README.md','LICENSE','SUPPORT.md','source-manifest.json')) { Copy-Item -LiteralPath (Join-Path $root $file) -Destination $portable }
Copy-Item -LiteralPath (Join-Path $root 'build/Release-receipt.json') -Destination (Join-Path $portable 'build-receipt.json')
$hashes=foreach ($file in $required) { $h=Get-FileHash -LiteralPath (Join-Path $portable $file) -Algorithm SHA256; "$($h.Hash)  $file" }
$hashes | Set-Content -LiteralPath (Join-Path $portable 'SHA256SUMS.txt') -Encoding ascii
Compress-Archive -LiteralPath $portable -DestinationPath (Join-Path $output 'DwmOrderTool-x64.zip') -CompressionLevel Optimal
$sourceEntries=@('CMakeLists.txt','Main.cpp','Diagnostics.cpp','Diagnostics.h','app.rc','app.manifest','Build.ps1','Export-Source.ps1','Package.ps1','Test-Ui.ps1','README.md','LICENSE','SUPPORT.md','source-manifest.json','.gitignore','core') | ForEach-Object { Join-Path $root $_ }
Compress-Archive -LiteralPath $sourceEntries -DestinationPath (Join-Path $output 'DwmOrderTool-source.zip') -CompressionLevel Optimal
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($zip in @('DwmOrderTool-x64.zip','DwmOrderTool-source.zip')) {
    $archive=[IO.Compression.ZipFile]::OpenRead((Join-Path $output $zip))
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.Name) { $stream=$entry.Open(); try { $stream.CopyTo([IO.Stream]::Null) } finally { $stream.Dispose() } }
        }
        if ($zip -like '*source*' -and @($archive.Entries | Where-Object { $_.FullName -match '(^|/|\\)(build|\.deps)(/|\\)' }).Count) { throw 'Source package unexpectedly contains build/dependency artifacts.' }
    } finally { $archive.Dispose() }
}
Write-Output "STANDALONE_PACKAGE=$output"
Get-Item -LiteralPath (Join-Path $output 'DwmOrderTool-x64.zip'),(Join-Path $output 'DwmOrderTool-source.zip') | Select-Object Name,Length
