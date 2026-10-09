param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$MSBuildPath = '',
    [string]$EvidenceId = 'r3-header-boundary',
    [string]$SelectedHeadersFile = ''
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if (!$MSBuildPath) {
    $MSBuildPath = @(
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe',
        'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (!$MSBuildPath -or $MSBuildPath -notmatch '[\\/]amd64[\\/]MSBuild\.exe$') {
    throw '64-bit MSBuild is required.'
}
$backend = Join-Path $repo 'shared/usermode/backend'
$evidence = Join-Path $repo ".codex-build-logs/r3-migration/$EvidenceId"
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$headers = @(Get-ChildItem -LiteralPath $backend -Recurse -Filter '*.h' | Sort-Object FullName)
if ($SelectedHeadersFile) {
    $selected = @(Get-Content -LiteralPath $SelectedHeadersFile)
    $headers = @($headers | Where-Object { $_.FullName -in $selected })
}
if (!$headers.Count) { throw 'No shared backend headers found.' }
$items = [System.Collections.Generic.List[string]]::new()
$index = 0
foreach ($header in $headers) {
    $sourceName = 'probe{0:D3}.cpp' -f $index++
    $includePath = $header.FullName.Replace('\', '/')
    Set-Content -LiteralPath (Join-Path $evidence $sourceName) -Encoding utf8 -Value "#include `"$includePath`""
    $items.Add("    <ClCompile Include=`"$sourceName`" />")
}
$escapedRepo = [System.Security.SecurityElement]::Escape($repo)
$project = @"
<Project DefaultTargets="ClCompile" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals"><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration">
    <ConfigurationType>StaticLibrary</ConfigurationType><PlatformToolset>v143</PlatformToolset><CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup><IntDir>`$(MSBuildProjectDirectory)\obj\</IntDir><OutDir>`$(MSBuildProjectDirectory)\out\</OutDir></PropertyGroup>
  <ItemDefinitionGroup><ClCompile>
    <LanguageStandard>stdcpp20</LanguageStandard><WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError>
    <ConformanceMode>true</ConformanceMode><ShowIncludes>true</ShowIncludes><PrecompiledHeader>NotUsing</PrecompiledHeader>
    <PreprocessorDefinitions>WIN32_LEAN_AND_MEAN;NOMINMAX;UNICODE;_UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    <AdditionalIncludeDirectories>$escapedRepo;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
  </ClCompile></ItemDefinitionGroup>
  <ItemGroup>
$($items -join "`n")
  </ItemGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
"@
$projectPath = Join-Path $evidence 'BackendHeaderProbes.vcxproj'
Set-Content -LiteralPath $projectPath -Value $project -Encoding utf8
$log = Join-Path $evidence 'compile.log'
& $MSBuildPath $projectPath /t:ClCompile /p:Configuration=Release /p:Platform=x64 `
    /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 /m:1 /v:minimal /nologo *> $log
if ($LASTEXITCODE -ne 0) {
    Get-Content -LiteralPath $log -Tail 45
    throw 'Independent backend header compilation failed.'
}
$forbidden = Select-String -LiteralPath $log -Pattern 'KswordARKLight[\\/].*\.h|[\\/]Qt[\\/]|[\\/]q(object|string|widget|global)\.h'
if ($forbidden) { $forbidden; throw 'Qt or Light headers entered the backend dependency chain.' }
Write-Output "R3_BACKEND_HEADER_COUNT=$($headers.Count)"
Write-Output 'R3_BACKEND_BOUNDARY=PASS'
