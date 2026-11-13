param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
# 在 x64 VS 开发环境中运行；仅构建模拟 SCM 回归，不需要管理员权限。
$ErrorActionPreference = 'Stop'
$testRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$testOutput = Join-Path $testRoot '.codex-tmp\service-delete-access'
New-Item -ItemType Directory -Path $testOutput -Force | Out-Null
$testSource = Join-Path $testRoot 'tools\service_delete_access_tests.cpp'
$testExecutable = Join-Path $testOutput 'service_delete_access_tests.exe'
$testObject = Join-Path $testOutput 'service_delete_access_tests.obj'
& cl.exe /nologo /std:c++17 /EHsc /utf-8 /W4 /WX $testSource "/Fo$testObject" "/Fe$testExecutable" /link Advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Service permission regression build failed.' }
& $testExecutable
if ($LASTEXITCODE -ne 0) { throw 'Service permission regression failed.' }
