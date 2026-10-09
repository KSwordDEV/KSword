# 冻结磁盘写回事务的内存夹具；严格编译实际模块，不打开任何设备。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot), [switch]$CompileHostViews)
$ErrorActionPreference = 'Stop'
$captureRepo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$captureOutput = Join-Path $captureRepo '.codex-build-logs'
$captureQt = Join-Path $captureRepo '.deps/Qt/6.9.3/msvc2022_64'
$captureVc = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207'
$captureSdk = 'C:/Program Files (x86)/Windows Kits/10'
$captureSdkVersion = '10.0.26100.0'
$captureCompiler = Join-Path $captureVc 'bin/Hostx64/x64/cl.exe'
$captureIncludes = @(('/I' + $captureRepo), ('/I' + (Join-Path $captureRepo 'Ksword5.1/Ksword5.1')), ('/external:I' + (Join-Path $captureVc 'include')))
foreach ($captureModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtNetwork', 'QtXml', 'QtSvg')) {
    $captureIncludes += '/external:I' + (Join-Path $captureQt ('include/' + $captureModule))
}
foreach ($capturePart in @('ucrt', 'shared', 'um')) {
    $captureIncludes += '/external:I' + (Join-Path $captureSdk ('Include/' + $captureSdkVersion + '/' + $capturePart))
}
$captureApp = 'Ksword5.1/Ksword5.1/MiscDock/DiskEditor'
$captureSources = @('tools/tests/disk_capture_transaction_tests.cpp', "$captureApp/DiskCaptureTransaction.cpp",
    "$captureApp/DiskEditorBackend.Identity.cpp", "$captureApp/DiskEditorTab.IO.cpp")
if ($CompileHostViews) {
    # 本轮迁移的真实页面仅严格编译，不链接业务入口或启动任何扫描/驱动操作。
    $captureSources += @('Ksword5.1/Ksword5.1/MiscDock/DiskEditor/DiskEditorTab.cpp',
        'Ksword5.1/Ksword5.1/DriverDock/DriverDock.Ui.cpp', 'Ksword5.1/Ksword5.1/DriverDock/DriverDock.DebugAndUtils.cpp',
        'Ksword5.1/Ksword5.1/MemoryDock/MemoryConsumerEvidencePage.cpp', 'Ksword5.1/Ksword5.1/KernelDock/KernelKnowledgeTab.cpp')
}
$captureObjects = @()
foreach ($captureSource in $captureSources) {
    $captureObject = Join-Path $captureOutput ('capture_' + [IO.Path]::GetFileNameWithoutExtension($captureSource) + '.obj')
    & $captureCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
        /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
        @captureIncludes /c (Join-Path $captureRepo $captureSource) ('/Fo' + $captureObject)
    if ($LASTEXITCODE -ne 0) { throw "Disk capture strict compilation failed: $captureSource" }
    $captureObjects += $captureObject
}
# 只链接无设备访问的共享事务和 fake 入口；身份查询/页面 TU 仅作严格编译验证。
$captureExe = Join-Path $captureOutput 'disk_capture_transaction_tests.exe'
$captureLibraries = @(('/LIBPATH:' + (Join-Path $captureVc 'lib/x64')), ('/LIBPATH:' + (Join-Path $captureQt 'lib')))
foreach ($capturePart in @('ucrt', 'um')) {
    $captureLibraries += '/LIBPATH:' + (Join-Path $captureSdk ('Lib/' + $captureSdkVersion + '/' + $capturePart + '/x64'))
}
& (Join-Path $captureVc 'bin/Hostx64/x64/link.exe') /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO `
    ('/OUT:' + $captureExe) @captureLibraries $captureObjects[0] $captureObjects[1] Qt6Core.lib
if ($LASTEXITCODE -ne 0) { throw 'Disk capture fixture link failed.' }
$captureOldPath = $env:PATH
try {
    $env:PATH = (Join-Path $captureQt 'bin') + ';' + $captureOldPath
    & $captureExe | Tee-Object -FilePath (Join-Path $captureOutput 'disk_capture_transaction_tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'Disk capture fixture failed.' }
}
finally { $env:PATH = $captureOldPath }
