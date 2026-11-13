[CmdletBinding()]
param(
    [ValidateSet('x64', 'Win32')][string]$Platform = 'x64',
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [string]$BuildRoot = '',
    [ValidateSet('Navigation', 'NoAttach')][string]$Component = 'Navigation'
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ($Component -eq 'NoAttach' -and $Platform -ne 'x64') { throw 'No-attach execution requires AMD64.' }
if (!$BuildRoot) { $BuildRoot = Join-Path $repositoryRoot (".deps\x64dbg-" + $Component.ToLowerInvariant() + "\$Platform") }
$buildDirectory = [IO.Path]::GetFullPath($BuildRoot)
if (!$buildDirectory.StartsWith($repositoryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Build output must be inside the repository.' }
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!(Test-Path -LiteralPath $msbuild)) { $msbuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' }
if (!(Test-Path -LiteralPath $msbuild)) { throw '64-bit MSBuild is required.' }
$cmake = Get-Command cmake.exe -ErrorAction Stop
$savedArchitecture = $env:PROCESSOR_ARCHITECTURE
$savedArchitectureW6432 = $env:PROCESSOR_ARCHITEW6432
try {
    $env:PROCESSOR_ARCHITECTURE = 'AMD64'
    $env:PROCESSOR_ARCHITEW6432 = 'AMD64'
    & $cmake.Source -S (Join-Path $repositoryRoot "X96dbgIntegration\${Component}Bridge") -B $buildDirectory `
        -G 'Visual Studio 17 2022' -A $Platform -T 'v143,host=x64' "-DCMAKE_MAKE_PROGRAM=$msbuild"
    if ($LASTEXITCODE -ne 0) { throw 'Navigation bridge CMake configure failed.' }
    $architectureProperties = @('/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64')
    $project = Join-Path $buildDirectory "KSword$Component.vcxproj"
    $pathProperty = if ($Platform -eq 'x64') { 'VC_ExecutablePath_x64' } else { 'VC_ExecutablePath_x86' }
    $paths = & $msbuild $project "/p:Configuration=$Configuration" "/p:Platform=$Platform" @architectureProperties "-getProperty:$pathProperty"
    if ($LASTEXITCODE -ne 0 -or ($paths | Out-String) -notmatch '(?i)HostX64[\\/]') { throw 'Navigation bridge compiler did not resolve to HostX64.' }
    & $msbuild $project /t:Build "/p:Configuration=$Configuration" "/p:Platform=$Platform" @architectureProperties /m:1 /v:minimal
    if ($LASTEXITCODE -ne 0) { throw 'Navigation bridge MSBuild failed.' }
} finally {
    $env:PROCESSOR_ARCHITECTURE = $savedArchitecture
    $env:PROCESSOR_ARCHITEW6432 = $savedArchitectureW6432
}
$suffix = if ($Platform -eq 'x64') { 'dp64' } else { 'dp32' }
$artifact = Join-Path $buildDirectory "$Configuration\KSword$Component.$suffix"
if (!(Test-Path -LiteralPath $artifact) -or (Get-Item -LiteralPath $artifact).Length -eq 0) { throw "Navigation bridge artifact is missing: $artifact" }
Write-Output ("X64DBG_" + $Component.ToUpperInvariant() + "_BRIDGE=$artifact")
