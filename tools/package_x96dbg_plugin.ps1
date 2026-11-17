[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$X64dbgDirectory,
    [string]$ProxyDll = '',
    [string]$NavigationBridge = '',
    [string]$NoAttachBridge = '',
    [string]$X64dbgSource = '',
    [string]$QtLicenseDirectory = '',
    [string]$SourceArchive = '',
    [switch]$AllowMissingSourceArchive,
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $repositoryRoot 'X96dbgExecutablePlugin'
$pluginRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'plugin\x96dbg'))
$runtimeRoot = (Resolve-Path -LiteralPath $X64dbgDirectory).Path
if ($runtimeRoot.TrimEnd('\') -eq [IO.Path]::GetPathRoot($runtimeRoot).TrimEnd('\')) { throw 'A drive root is not an x64dbg runtime directory.' }
if ([string]::IsNullOrWhiteSpace($ProxyDll)) { $ProxyDll = Join-Path $repositoryRoot "TitanEnginePlugin\x64\$Configuration\TitanEngine.dll" }
if ([string]::IsNullOrWhiteSpace($NavigationBridge)) { $NavigationBridge = Join-Path $repositoryRoot ".deps\x64dbg-navigation\x64\$Configuration\KSwordNavigation.dp64" }
if ([string]::IsNullOrWhiteSpace($NoAttachBridge)) { $NoAttachBridge = Join-Path $repositoryRoot ".deps\x64dbg-noattach\x64\$Configuration\KSwordNoAttach.dp64" }
if ([string]::IsNullOrWhiteSpace($X64dbgSource)) { $X64dbgSource = Join-Path $repositoryRoot '.deps\x64dbg-reference' }
if ([string]::IsNullOrWhiteSpace($SourceArchive)) { $SourceArchive = Join-Path $repositoryRoot 'dist\KSword-x96dbg-source.zip' }
$x64dbgSourceRoot = (Resolve-Path -LiteralPath $X64dbgSource).Path
$launcher = Join-Path $sourceRoot "x64\$Configuration\KswordX96dbgLauncher.exe"
$canonicalDef = Join-Path $x64dbgSourceRoot 'src\dbg\TitanEngine\TitanEngine.def'

# Refuse to erase an input that was supplied from a previous package, and do
# not follow a junction masquerading as the script-owned output directory.
foreach ($inputPath in @($runtimeRoot, [IO.Path]::GetFullPath($ProxyDll), [IO.Path]::GetFullPath($NavigationBridge), [IO.Path]::GetFullPath($NoAttachBridge), $x64dbgSourceRoot, $launcher, [IO.Path]::GetFullPath($SourceArchive))) {
    if ($inputPath -eq $pluginRoot -or $inputPath.StartsWith($pluginRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Package input is inside the output directory: $inputPath" }
}
$includeSourceArchive = Test-Path -LiteralPath $SourceArchive -PathType Leaf
if (!$includeSourceArchive -and !$AllowMissingSourceArchive) { throw "Corresponding source archive is required: $SourceArchive. Provide -SourceArchive or explicitly use -AllowMissingSourceArchive for a local-only package." }
if ($includeSourceArchive) {
    $archiveStream = [IO.File]::OpenRead($SourceArchive)
    try {
        $archiveSignature = [byte[]]::new(4)
        if ($archiveStream.Read($archiveSignature, 0, 4) -ne 4 -or [BitConverter]::ToUInt32($archiveSignature, 0) -ne 0x04034B50) { throw "Corresponding source archive is not a ZIP file: $SourceArchive" }
    } finally { $archiveStream.Dispose() }
} else { Write-Warning 'Corresponding source archive is omitted from this local-only package.' }
if (Test-Path -LiteralPath $pluginRoot) {
    if (((Get-Item -LiteralPath $pluginRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Package output is a reparse point: $pluginRoot" }
}
foreach ($directory in @($runtimeRoot, [IO.Path]::GetDirectoryName($pluginRoot))) {
    if ((Test-Path -LiteralPath $directory) -and (((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw "Input/output parent is a reparse point: $directory" }
}

function Assert-Range([byte[]]$Data, [long]$Offset, [long]$Count) {
    if ($Offset -lt 0 -or $Count -lt 0 -or $Offset -gt $Data.LongLength - $Count) { throw 'Invalid/truncated PE range.' }
}
function Read-U16([byte[]]$Data, [long]$Offset) { Assert-Range $Data $Offset 2; [BitConverter]::ToUInt16($Data, [int]$Offset) }
function Read-U32([byte[]]$Data, [long]$Offset) { Assert-Range $Data $Offset 4; [BitConverter]::ToUInt32($Data, [int]$Offset) }
function Convert-Rva([long]$Rva, [long]$Bytes, [object[]]$Sections, [long]$HeaderBytes, [byte[]]$Data) {
    if ($Rva -lt $HeaderBytes) { Assert-Range $Data $Rva $Bytes; return $Rva }
    foreach ($section in $Sections) {
        if ($Rva -ge $section.Rva -and $Rva - $section.Rva -lt $section.RawBytes) {
            $delta = $Rva - $section.Rva
            if ($Bytes -gt $section.RawBytes - $delta) { throw 'PE RVA crosses its raw section.' }
            $offset = $section.RawOffset + $delta
            Assert-Range $Data $offset $Bytes
            return $offset
        }
    }
    throw "Unmapped PE RVA: $Rva"
}
function Get-Amd64Pe([string]$Path, [switch]$ExportNames) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required file is missing: $Path" }
    $data = [IO.File]::ReadAllBytes($Path)
    if ((Read-U16 $data 0) -ne 0x5A4D) { throw "Invalid DOS header: $Path" }
    $pe = [long](Read-U32 $data 0x3C)
    if ((Read-U32 $data $pe) -ne 0x4550 -or (Read-U16 $data ($pe + 4)) -ne 0x8664) { throw "Only AMD64 PE files are accepted: $Path" }
    $sectionCount = Read-U16 $data ($pe + 6)
    $optionalBytes = Read-U16 $data ($pe + 20)
    $optional = $pe + 24
    if ($optionalBytes -lt 120 -or (Read-U16 $data $optional) -ne 0x20B -or $sectionCount -gt 96) { throw "Invalid AMD64 optional header: $Path" }
    Assert-Range $data $optional $optionalBytes
    $sections = @()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $offset = $optional + $optionalBytes + 40 * $i
        Assert-Range $data $offset 40
        $sections += [pscustomobject]@{ Rva = [long](Read-U32 $data ($offset + 12)); RawBytes = [long](Read-U32 $data ($offset + 16)); RawOffset = [long](Read-U32 $data ($offset + 20)) }
    }
    $exports = [Collections.Generic.List[string]]::new()
    if ($ExportNames) {
        if ((Read-U32 $data ($optional + 108)) -lt 1) { throw "DLL has no export directory: $Path" }
        $exportRva = Read-U32 $data ($optional + 112)
        if ($exportRva -eq 0) { throw "DLL has no exports: $Path" }
        $headers = Read-U32 $data ($optional + 60)
        $exportOffset = Convert-Rva $exportRva 40 $sections $headers $data
        $namesCount = Read-U32 $data ($exportOffset + 24)
        $functionsCount = Read-U32 $data ($exportOffset + 20)
        if ($namesCount -gt 65536 -or $functionsCount -gt 65536) { throw "PE export list exceeds the supported bound: $Path" }
        $namesOffset = Convert-Rva (Read-U32 $data ($exportOffset + 32)) (4L * $namesCount) $sections $headers $data
        $ordinalsOffset = Convert-Rva (Read-U32 $data ($exportOffset + 36)) (2L * $namesCount) $sections $headers $data
        $functionsOffset = Convert-Rva (Read-U32 $data ($exportOffset + 28)) (4L * $functionsCount) $sections $headers $data
        for ($i = 0; $i -lt $namesCount; $i++) {
            $ordinal = Read-U16 $data ($ordinalsOffset + 2L * $i)
            if ($ordinal -ge $functionsCount) { throw "Invalid PE export ordinal: $Path" }
            $functionRva = Read-U32 $data ($functionsOffset + 4L * $ordinal)
            if ($functionRva -eq 0) { throw "Named PE export has no implementation: $Path" }
            $null = Convert-Rva $functionRva 1 $sections $headers $data
            $nameOffset = Convert-Rva (Read-U32 $data ($namesOffset + 4L * $i)) 1 $sections $headers $data
            $end = $nameOffset
            while ($end -lt $data.LongLength -and $end - $nameOffset -lt 512 -and $data[$end] -ne 0) { $end++ }
            if ($end -eq $data.LongLength -or $end - $nameOffset -eq 512) { throw "Invalid PE export name: $Path" }
            $exports.Add([Text.Encoding]::ASCII.GetString($data, [int]$nameOffset, [int]($end - $nameOffset)))
        }
    }
    [pscustomobject]@{ Path = $Path; Machine = 'AMD64'; Exports = $exports.ToArray() }
}

if (!(Test-Path -LiteralPath $canonicalDef -PathType Leaf)) { throw "Canonical engine definition is missing: $canonicalDef" }
$navigationPe = Get-Amd64Pe $NavigationBridge -ExportNames
$noAttachPe = Get-Amd64Pe $NoAttachBridge -ExportNames
if ('pluginit' -cnotin $noAttachPe.Exports -or 'plugstop' -cnotin $noAttachPe.Exports) { throw 'No-attach bridge is missing official x64dbg plugin entrypoints.' }
if ('pluginit' -cnotin $navigationPe.Exports -or 'plugstop' -cnotin $navigationPe.Exports) { throw 'Navigation bridge is missing its official x64dbg plugin entrypoints.' }
$canonical = @(Get-Content -LiteralPath $canonicalDef | ForEach-Object { if ($_ -match '^\s+([A-Za-z][A-Za-z0-9_]*)\s*$') { $Matches[1] } })
if ($canonical.Count -ne 64 -or @($canonical | Sort-Object -Unique).Count -ne 64) { throw 'The selected canonical engine ABI is not the audited 64-export interface. Re-audit it before packaging.' }
foreach ($path in @($launcher, $ProxyDll, (Join-Path $runtimeRoot 'TitanEngine.dll'), (Join-Path $runtimeRoot 'DbgEng\TitanEngine.dll'))) {
    $pe = Get-Amd64Pe $path -ExportNames:($path -ne $launcher)
    if ($path -ne $launcher) {
        $missing = @($canonical | Where-Object { $_ -cnotin $pe.Exports })
        if ($missing.Count -ne 0) { throw "Engine DLL is incompatible: $path; missing exports: $($missing -join ', ')" }
    }
}
foreach ($file in @('x64dbg.exe', 'x64dbg.dll', 'x64bridge.dll', 'x64gui.dll', 'platforms\qwindows.dll',
    'DbgEng\dbgeng.dll', 'DbgEng\dbgcore.dll', 'DbgEng\dbgmodel.dll', 'DbgEng\TTDReplay.dll', 'DbgEng\TTDReplayCPU.dll')) {
    $null = Get-Amd64Pe (Join-Path $runtimeRoot $file)
}
# The user-directory setting is read before engine initialization. Require the
# actual patched binary marker as well as the source enum/path, rather than
# selecting value 4 in an arbitrary stock release.
$bridgeSource = Join-Path $x64dbgSourceRoot 'src\bridge\bridgemain.cpp'
$bridgeHeader = Join-Path $x64dbgSourceRoot 'src\bridge\bridgemain.h'
if ((Get-Content -Raw -LiteralPath $bridgeSource) -notmatch 'DebugEngineKSword' -or
    (Get-Content -Raw -LiteralPath $bridgeHeader) -notmatch 'DebugEngineKSword\s*=\s*4') { throw 'x64dbg source is missing the KSword engine enum/path patch.' }
$bridgeBytes = [IO.File]::ReadAllBytes((Join-Path $runtimeRoot 'x64bridge.dll'))
if ([Text.Encoding]::Unicode.GetString($bridgeBytes) -notmatch 'KSword\\TitanEngine\.dll') { throw 'x64bridge.dll does not contain the checked KSword engine path. Build the patched source first.' }

$x64dbgLicense = Join-Path $x64dbgSourceRoot 'LICENSE'
$titanLicense = Join-Path $x64dbgSourceRoot 'src\third_party\TitanEngine\LICENSE'
foreach ($license in @($x64dbgLicense, $titanLicense)) {
    if (!(Test-Path -LiteralPath $license -PathType Leaf)) { throw "Required original license is missing: $license" }
}
if ([string]::IsNullOrWhiteSpace($QtLicenseDirectory)) {
    foreach ($candidate in @((Join-Path $runtimeRoot 'licenses'), (Join-Path $runtimeRoot 'license'))) {
        if (Test-Path -LiteralPath $candidate -PathType Container) { $QtLicenseDirectory = $candidate; break }
    }
}
if ([string]::IsNullOrWhiteSpace($QtLicenseDirectory) -or !(Test-Path -LiteralPath $QtLicenseDirectory -PathType Container)) {
    throw 'Provide the original Qt/runtime dependency license directory with -QtLicenseDirectory.'
}
$qtLicenseRoot = (Resolve-Path -LiteralPath $QtLicenseDirectory).Path
if ($qtLicenseRoot.TrimEnd('\') -eq [IO.Path]::GetPathRoot($qtLicenseRoot).TrimEnd('\')) { throw 'A drive root is not a runtime license directory.' }
if ($qtLicenseRoot -eq $pluginRoot -or $qtLicenseRoot.StartsWith($pluginRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'License input is inside the output directory.' }
if (@(Get-ChildItem -LiteralPath $qtLicenseRoot -Recurse -File -Force).Count -eq 0) { throw 'The Qt/runtime license directory is empty.' }

# The input must already be the x64 runtime directory. Inspect every PE that
# will be copied, and reject x86 frontend/plugin payloads before any mutation.
$runtimeFiles = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -File -Force | Where-Object {
    $relative = $_.FullName.Substring($runtimeRoot.Length + 1).Replace('\', '/')
    $relative -notmatch '^tests(/|$)' -and $_.Name -ne 'headless.exe' -and $_.Extension -notin @('.pdb', '.lib', '.exp', '.ilk')
})
foreach ($item in Get-ChildItem -LiteralPath $runtimeRoot -Recurse -Directory -Force) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Runtime directory reparse points are not accepted: $($item.FullName)" }
}
foreach ($file in $runtimeFiles) {
    if ($file.Extension -eq '.dp32' -or $file.Name -eq 'x32dbg.exe') { throw "x86 runtime/plugin file is not allowed: $($file.FullName)" }
    if ($file.Extension -in @('.exe', '.dll', '.dp64')) { $null = Get-Amd64Pe $file.FullName }
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Runtime reparse points are not accepted: $($file.FullName)" }
}
$expectedPluginRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'plugin\x96dbg'))
if ($pluginRoot -ne $expectedPluginRoot -or !$pluginRoot.StartsWith($repositoryRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Refusing unexpected package path: $pluginRoot" }
if (Test-Path -LiteralPath $pluginRoot) { Remove-Item -LiteralPath $pluginRoot -Recurse -Force }
$payloadRoot = Join-Path $pluginRoot 'payload\x64dbg'
New-Item -ItemType Directory -Path (Join-Path $payloadRoot 'KSword') -Force | Out-Null
foreach ($file in $runtimeFiles) {
    $relative = $file.FullName.Substring($runtimeRoot.Length + 1)
    $destination = Join-Path $payloadRoot $relative
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
}
Copy-Item -LiteralPath $ProxyDll -Destination (Join-Path $payloadRoot 'KSword\TitanEngine.dll') -Force
New-Item -ItemType Directory -Path (Join-Path $payloadRoot 'plugins') -Force | Out-Null
Copy-Item -LiteralPath $NavigationBridge -Destination (Join-Path $payloadRoot 'plugins\KSwordNavigation.dp64') -Force
Copy-Item -LiteralPath $NoAttachBridge -Destination (Join-Path $payloadRoot 'plugins\KSwordNoAttach.dp64') -Force
Copy-Item -LiteralPath $launcher -Destination $pluginRoot -Force
foreach ($file in @('plugin.json', 'README.md', 'SOURCE.md')) { Copy-Item -LiteralPath (Join-Path $sourceRoot $file) -Destination $pluginRoot -Force }
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'DebuggerBackend\README.md') -Destination (Join-Path $pluginRoot 'DEBUGGER_BACKEND.md') -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'TitanEnginePlugin\README.md') -Destination (Join-Path $pluginRoot 'TITAN_ENGINE.md') -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'tools\debugger_vm_test\POLICY_TEST.md') -Destination $pluginRoot -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'NOTICE.md') -Destination (Join-Path $pluginRoot 'NOTICE') -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'LICENSE') -Destination (Join-Path $pluginRoot 'LICENSE.txt') -Force
$licenseRoot = Join-Path $pluginRoot 'licenses'
New-Item -ItemType Directory -Path $licenseRoot -Force | Out-Null
Copy-Item -LiteralPath $x64dbgLicense -Destination (Join-Path $licenseRoot 'x64dbg-LICENSE') -Force
Copy-Item -LiteralPath $titanLicense -Destination (Join-Path $licenseRoot 'TitanEngine-LICENSE') -Force
Copy-Item -LiteralPath $qtLicenseRoot -Destination (Join-Path $licenseRoot 'runtime-dependencies') -Recurse -Force
$thirdPartyRoot = Join-Path $x64dbgSourceRoot 'src\third_party'
foreach ($file in Get-ChildItem -LiteralPath $thirdPartyRoot -Recurse -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE)' }) {
    $relative = $file.FullName.Substring($thirdPartyRoot.Length + 1)
    $destination = Join-Path $licenseRoot ('x64dbg-third-party\' + $relative)
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
}
foreach ($relative in @('docs\ksword-x64dbg-backend.md', 'docs\ksword-x64dbg-validation.md', 'docs\ksword-debugger-vm-validation.md',
    'docs\ksword-x64dbg-api-review.md', 'docs\ksword-x64dbg-pr3974-validation.md', 'X96dbgIntegration\patches\x64dbg-ksword-engine.patch')) {
    $path = Join-Path $repositoryRoot $relative
    if (Test-Path -LiteralPath $path -PathType Leaf) { Copy-Item -LiteralPath $path -Destination $pluginRoot -Force }
}
if ($includeSourceArchive) { Copy-Item -LiteralPath $SourceArchive -Destination (Join-Path $pluginRoot 'KSword-x96dbg-source.zip') -Force }
$sourceCommit = (& git -C $x64dbgSourceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the supplied x64dbg source revision.' }
$manifestFiles = @(Get-ChildItem -LiteralPath $pluginRoot -Recurse -File -Force | ForEach-Object {
    [pscustomobject]@{ path = $_.FullName.Substring($pluginRoot.Length + 1).Replace('\', '/'); bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$manifest = [ordered]@{
    format = 'ksword-x96dbg-payload/1'; architecture = 'x64'; source_commit = $sourceCommit
    canonical_export_count = $canonical.Count; canonical_exports = $canonical
    engine_selection = [ordered]@{ DebugEngine = 4; user_directory = 'sessions/UUID'; path = 'KSword/TitanEngine.dll' }
    baseline_pins = (Get-Content -LiteralPath (Join-Path $repositoryRoot 'X96dbgIntegration\PINNED_BASELINES.json') -Raw | ConvertFrom-Json)
    optional_engine_query_version = 1
    navigation_protocol_version = 2
    files = $manifestFiles
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $pluginRoot 'payload-manifest.json') -Encoding utf8
[pscustomobject]@{
    PluginRoot = $pluginRoot; FileCount = $manifestFiles.Count + 1
    LauncherSha256 = (Get-FileHash -LiteralPath (Join-Path $pluginRoot 'KswordX96dbgLauncher.exe') -Algorithm SHA256).Hash
    ProxySha256 = (Get-FileHash -LiteralPath (Join-Path $payloadRoot 'KSword\TitanEngine.dll') -Algorithm SHA256).Hash
    NativeCanonicalExportCount = $canonical.Count
} | ConvertTo-Json
