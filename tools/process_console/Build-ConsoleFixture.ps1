# 构建真实双位数夹具。输入为目标架构，输出为独立日志目录中的动态/静态运行库 EXE。
param([ValidateSet('x64', 'x86')][string]$Architecture = 'x64')
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path # 仓库根目录。
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'
if (!(Test-Path $vcvars)) {
    $vcvars = 'D:\Software\VS\VC\Auxiliary\Build\vcvarsall.bat'
}
$toolArch = if ($Architecture -eq 'x86') { 'amd64_x86' } else { 'amd64' } # 始终使用 HostX64。
$environmentLines = & cmd.exe /d /s /c "`"`"$vcvars`" $toolArch >nul && set`"" # 编译器环境。
if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize HostX64 toolchain.' }
foreach ($line in $environmentLines) {
    if ($line -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}

# 两种 CRT 目标分别保留产物；测试直接编译生产实现，不在夹具中复制执行逻辑。
$out = Join-Path $repo ".codex-build-logs/process-console/$Architecture" # 架构隔离的输出目录。
New-Item -ItemType Directory -Path $out -Force | Out-Null
Push-Location $out
try {
    foreach ($kind in @('dynamic', 'static')) {
        $runtime = if ($kind -eq 'dynamic') { '/MD' } else { '/MT' } # 目标运行库链接方式。
        $arguments = @('/nologo', '/std:c++20', '/EHsc', '/utf-8', '/W4', '/WX', $runtime,
            '/DUNICODE', '/D_UNICODE', (Join-Path $PSScriptRoot 'console_fixture.cpp'),
            (Join-Path $repo 'shared/usermode/ProcessConsole.cpp'),
            (Join-Path $repo 'shared/usermode/ProcessConsoleRemote.cpp'), "/Fe:console-$kind.exe",
            '/link', 'user32.lib') # 编译器参数及链接输入。
        & cl.exe @arguments *> "build-$kind.log"
        if ($LASTEXITCODE -ne 0) {
            Get-Content "build-$kind.log"
            throw "Console fixture $Architecture/$kind build failed."
        }
    }
}
finally { Pop-Location }
Write-Output "CONSOLE_FIXTURE_BUILD=SUCCESS architecture=$Architecture"
