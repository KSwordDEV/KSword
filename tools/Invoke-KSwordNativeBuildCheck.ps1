[CmdletBinding()]
param(
    [ValidateSet('CLI', 'Light')]
    [string]$Product = 'CLI'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# 使用仓库固定工程及发布目录，不给 MSBuild 覆盖输出路径。
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$solutionDir = (Join-Path $root 'Ksword5.1') + '\' # 保持与仓库解决方案一致的 MSVC 中间目录上下文。
$expectedOutDir = Join-Path $root 'Ksword5.1\x64\Release'
if ($Product -eq 'Light') {
    $project = Join-Path $root 'KswordARKLight\KswordARKLight.vcxproj'
    $expectedIntDir = Join-Path $root 'KswordARKLight\x64\Release\obj'
    $artifact = Join-Path $expectedOutDir 'KswordARKLight.exe'
} else {
    $project = Join-Path $root 'KswordCLI\KswordCLI.vcxproj'
    $expectedIntDir = Join-Path $root 'KswordCLI\x64\Release'
    $artifact = Join-Path $expectedOutDir 'KswordCLI.exe'
}
$candidates = @(
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
    'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'
)
$msbuild = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (!$msbuild) {
    throw '64-bit MSBuild was not found in the approved locations.'
}

# 只增量构建所选用户态工程；Light 沿用正式目录里的现有资源，不重建或签名驱动。
$buildArgs = @('/p:Configuration=Release', '/p:Platform=x64', '/p:PreferredToolArchitecture=x64',
    '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64',
    "/p:SolutionDir=$solutionDir", '/p:BuildProjectReferences=false', '/nologo')
if ($Product -eq 'Light') {
    $buildArgs += @('/p:KswordArkLightEnsureDriverBuilt=false', '/p:KswordArkLightReuseSignedDriver=true',
        '/p:KswordArkLightSkipDriverSign=true')
}
# Windows PowerShell 5.1 没有 Path.GetFullPath(string, string) 重载，这里显式拼接工程基准。
function Resolve-ProjectPath([string]$path, [string]$base) {
    if ([IO.Path]::IsPathRooted($path)) {
        return [IO.Path]::GetFullPath($path)
    }
    return [IO.Path]::GetFullPath((Join-Path $base $path))
}

$buildHost = [Diagnostics.Process]::GetCurrentProcess()
$previousPriority = $buildHost.PriorityClass
try {
    $buildHost.PriorityClass = 'BelowNormal'
    $values = & $msbuild $project @buildArgs '-getProperty:PreferredToolArchitecture,VC_ExecutablePath_x64,IntDir,OutDir,ProjectDir'
    if ($LASTEXITCODE -ne 0) {
        throw "$Product build property query failed: $LASTEXITCODE"
    }

    # 以工程为基准解析相对目录；在任何编译或链接前打印并校验实际路径。
    $properties = ($values -join "`n" | ConvertFrom-Json).Properties
    $intDir = (Resolve-ProjectPath $properties.IntDir $properties.ProjectDir).TrimEnd('\')
    $outDir = (Resolve-ProjectPath $properties.OutDir $properties.ProjectDir).TrimEnd('\')
    "IntDir=$intDir"
    "OutDir=$outDir"
    "VC_ExecutablePath_x64=$($properties.VC_ExecutablePath_x64)"
    "Priority=$($buildHost.PriorityClass)"
    if ($properties.PreferredToolArchitecture -ne 'x64' -or
        $properties.VC_ExecutablePath_x64 -notmatch '(?i)HostX64[\\/]x64' -or
        $intDir -ne $expectedIntDir -or $outDir -ne $expectedOutDir) {
        throw "Unexpected $Product compiler host or build output directory."
    }

    # 进程继承降级优先级，使用工程声明的增量构建目标及目录。
    & $msbuild $project @buildArgs /t:Build /m:1 /v:minimal
    if ($LASTEXITCODE -ne 0) {
        throw "$Product build failed: $LASTEXITCODE"
    }
    $image = Get-Item -LiteralPath $artifact
    if (!$image.Length) {
        throw "$Product Release artifact is empty."
    }
    "SHA256=$((Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash)"
    'EXIT_CODE=0'
    'BUILD_RESULT=SUCCESS'
} finally {
    $buildHost.PriorityClass = $previousPriority
    $buildHost.Dispose()
}
