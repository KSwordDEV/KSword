# 使用 HostX64 编译真实查询与内存夹具；不启动 GUI、不写账户或权限策略。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$rightsRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$rightsOutput = Join-Path $rightsRepository '.codex-build-logs'
if (!(Test-Path -LiteralPath $rightsOutput)) { throw 'Existing build log directory required.' }
$rightsQt = Join-Path $rightsRepository '.deps/Qt/6.9.3/msvc2022_64'
if (!(Test-Path -LiteralPath $rightsQt)) { $rightsQt = 'D:/Software/Qt/6.9.3/msvc2022_64' }
$rightsVc = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207'
if (!(Test-Path -LiteralPath $rightsVc)) { $rightsVc = 'D:/Software/VS/VC/Tools/MSVC/14.44.35207' }
$rightsSdk = 'C:/Program Files (x86)/Windows Kits/10'
$rightsSdkVersion = (Get-ChildItem (Join-Path $rightsSdk 'Include') -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'um/Windows.h') } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1).Name
$rightsCompiler = Join-Path $rightsVc 'bin/HostX64/x64/cl.exe'
$rightsLinker = Join-Path $rightsVc 'bin/HostX64/x64/link.exe'

# 包含目录和库目录成对取自同一 Qt、MSVC 与 SDK，不回退到 32 位工具。
$rightsIncludes = @(('/I' + (Join-Path $rightsVc 'include')), ('/I' + (Join-Path $rightsVc 'atlmfc/include')))
foreach ($rightsModule in @('', 'QtCore', 'QtGui', 'QtWidgets')) {
    $rightsIncludes += '/external:I' + (Join-Path $rightsQt ('include/' + $rightsModule))
}
foreach ($rightsPart in @('ucrt', 'shared', 'um')) {
    $rightsIncludes += '/external:I' + (Join-Path $rightsSdk ('Include/' + $rightsSdkVersion + '/' + $rightsPart))
}
$rightsObjects = @()
foreach ($rightsSource in @('tools/privilege_rights_query_tests.cpp', 'Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeRightsQuery.cpp')) {
    $rightsObject = Join-Path $rightsOutput ('rights_query_' + [IO.Path]::GetFileNameWithoutExtension($rightsSource) + '.obj')
    & $rightsCompiler /nologo /std:c++20 /Zc:__cplusplus /utf-8 /EHsc /MD /O1 /Gy /W3 /external:W0 `
        /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
        @rightsIncludes /c (Join-Path $rightsRepository $rightsSource) ('/Fo' + $rightsObject)
    if ($LASTEXITCODE -ne 0) { throw "Query fixture compile failed: $rightsSource" }
    $rightsObjects += $rightsObject
}
$rightsLibraries = @(('/LIBPATH:' + (Join-Path $rightsVc 'lib/x64')), ('/LIBPATH:' + (Join-Path $rightsQt 'lib')))
foreach ($rightsPart in @('ucrt', 'um')) {
    $rightsLibraries += '/LIBPATH:' + (Join-Path $rightsSdk ('Lib/' + $rightsSdkVersion + '/' + $rightsPart + '/x64'))
}
$rightsExe = Join-Path $rightsOutput 'privilege_rights_query_tests.exe'
& $rightsLinker /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF ('/OUT:' + $rightsExe) `
    @rightsObjects @rightsLibraries Qt6Widgets.lib Qt6Gui.lib Qt6Core.lib kernel32.lib user32.lib advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Query fixture link failed.' }

# PATH 仅在当前回归进程有效，退出后恢复调用环境。
$rightsPreviousPath = $env:PATH
try {
    $env:PATH = (Join-Path $rightsQt 'bin') + ';' + $rightsPreviousPath
    & $rightsExe
    if ($LASTEXITCODE -ne 0) { throw 'Query fixture failed.' }
}
finally { $env:PATH = $rightsPreviousPath }
