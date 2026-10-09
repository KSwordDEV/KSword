@echo off
chcp 65001 >nul
rem ============================================================
rem build-wpJ6-tests.cmd
rem 作用：构建并运行 WP-J6（MemoryWorkbenchView + WorkbenchDiagnosticsHost）
rem       离屏验证夹具。本包是装配层最后一块，链接全部阶段 1/2 真实类
rem       （HexCanvas 家族、Workbench* 全套、AddressBook*、Int3*、
rem       CodeEditorWidget 依赖链）+ 本包产物，仿 wpJ5/wpH/wpG/wpE/wpF/wpJ1
rem       各自验证过的链接写法拼成一份。
rem 用法：在任意目录执行 tools\memwb_ui\wpJ6\build-wpJ6-tests.cmd [--skip-run]
rem 产物：MEMWB_OUT 指定的目录，默认 .codex-tmp\memwb-wpJ6。
rem ============================================================
setlocal
set "REPO=%~dp0..\..\.."
pushd "%REPO%"
if errorlevel 1 exit /b 2

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" exit /b 2
call "%VCVARS%" >nul
if errorlevel 1 exit /b %errorlevel%

set "QT=%CD%\.deps\Qt\6.9.3\msvc2022_64"
if not exist "%QT%\lib\Qt6Widgets.lib" set "QT=D:\Software\Qt\6.9.3\msvc2022_64"
if not exist "%QT%\lib\Qt6Widgets.lib" exit /b 2

set "APP=Ksword5.1\Ksword5.1"
set "CORE=shared\evidence\memory_workbench"
set "UI=%APP%\UI\MemoryWorkbench"
set "FIX=tools\memwb_ui\wpJ6"
set "WPI=tools\memwb_ui\wpI"
set "ZYDIS=third_party\zydis"
if not defined MEMWB_OUT set "MEMWB_OUT=.codex-tmp\memwb-wpJ6"
set "OUT=%MEMWB_OUT%"
set "OBJ=%OUT%\obj"
set "OBJ2=%OUT%\obj2"
set "MOC=%OUT%\moc"
if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%OBJ2%" mkdir "%OBJ2%"
if not exist "%MOC%" mkdir "%MOC%"
if not exist "%OUT%\shots" mkdir "%OUT%\shots"

rem ---- moc：全部 Q_OBJECT 头 ----
for %%H in (MemoryRowCanvas HexCanvas HexInspectorPanel HexInspectorRowView HexFindBar HexViewWidgets WorkbenchTarget WorkbenchPageProvider WorkbenchBaselineFeeder WorkbenchWriteController WorkbenchHexPane WorkbenchDisasmView WorkbenchTextView WorkbenchCompareView WorkbenchSessionBar WriteModeSwitch WorkbenchStatusBar WorkbenchStringWriteDialog AddressBookStore AddressBookModel AddressBookPanel Int3Controller Int3PatchPanel WorkbenchShared MemoryWorkbenchView WorkbenchDiagnosticsHost) do (
  "%QT%\bin\moc.exe" "%UI%\%%H.h" -o "%MOC%\moc_%%H.cpp"
  if errorlevel 1 exit /b %errorlevel%
)
"%QT%\bin\moc.exe" "%APP%\UI\CodeEditorWidget.h" -o "%MOC%\moc_CodeEditorWidget.cpp"
if errorlevel 1 exit /b %errorlevel%

rem ---- rcc：本包精简图标资源 ----
"%QT%\bin\rcc.exe" "%FIX%\wpJ6_icons.qrc" -name wpJ6_icons -o "%MOC%\qrc_wpJ6_icons.cpp"
if errorlevel 1 exit /b %errorlevel%

rem ---- Zydis（C 源文件，与主程序 vcxproj 同一个宏，单独 /c 编译）----
cl /nologo /std:c11 /MD /O2 /DZYDIS_STATIC_BUILD /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I"%ZYDIS%" /c "%ZYDIS%\Zydis.c" /Fo"%OBJ2%\Zydis.obj"
if errorlevel 1 exit /b %errorlevel%

rem ---- 第二遍：CodeEditorWidget 依赖链，/W3 不开 /WX（别人代码，别人的既有
rem      警告不该挡住本包自己代码的强校验，仿 wpH/wpE/wpJ1 的做法）----
cl /nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W3 /O2 /DWIN32_LEAN_AND_MEAN /external:W0 /DNOMINMAX /DUNICODE /D_UNICODE /DZYDIS_STATIC_BUILD /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB ^
  /I"%ZYDIS%" /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /external:I"%QT%\include\QtSvg" ^
  /c "%APP%\UI\CodeEditorWidget.cpp" "%APP%\UI\CodeTextEdit.cpp" "%APP%\UI\CodeEditorFileSession.cpp" "%APP%\UI\ReportStructuredView.cpp" "%APP%\Internationalization\LanguageManager.cpp" "%APP%\UI\MemoryAssembly.cpp" "%APP%\UI\MemoryAssembly.Core.cpp" "%MOC%\moc_CodeEditorWidget.cpp" ^
  /Fo"%OBJ2%\\"
if errorlevel 1 exit /b %errorlevel%

rem ---- 第一遍：本包 + 全部阶段 1/2 真实类，/W4 /WX 干净 ----
if not defined CL set "CL=/MP"
rem 注：不在本次调用的命令行传 WIN32_LEAN_AND_MEAN/NOMINMAX——
rem memwb_wpI_common.cpp 与 WorkbenchTarget.Anchor.cpp 自己在 #include
rem <Windows.h> 之前 #define 这两个宏，命令行再传一遍会和文件内的 #define 撞成
rem C4005（宏重定义），在 /WX 下变成编译错误（wpJ5/wpI 已经踩过这个坑并在各自
rem 脚本里注释过，这里沿用同一条规避方式；第二遍 CodeEditorWidget 依赖链单独
rem 传这两个宏，因为那条链不包含会自己 #define 的文件）。
rem
rem N1（本包修复）：全部 ~100 个源文件拼进单条 cl 命令行后，宏展开（%UI%/%CORE%
rem 等）会让实际传给 cmd.exe 的字符数逼近/超过它的内部命令行长度上限——直接
rem （非嵌套）调用本脚本时偶然没有触发，但经 mutrun-j.ps1 的
rem `cmd /c "... && call build-wpJ6-tests.cmd"` 这种复合调用方式时稳定触发：
rem 命令行被截断，残留的孤立 "^" 被 cl 当成一个不存在的目标文件，最终在链接期
rem 报 LNK1181 "无法打开输入文件"^.obj""。修法：改成"分批 /c 编译到 .obj + 最后
rem 单独 link"，每批独立一条 cl 命令，单条长度远低于上限。
set "CLFLAGS=/nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /O2 /Gy /c /external:W0 /DUNICODE /D_UNICODE /DZYDIS_STATIC_BUILD /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DQT_TESTLIB_LIB /I"%ZYDIS%" /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /external:I"%QT%\include\QtTest" /external:I"%QT%\include\QtSvg""

cl %CLFLAGS% ^
  "%FIX%\wpJ6_main.cpp" "%FIX%\wpJ6_common.cpp" ^
  "%FIX%\wpJ6_tests.Identity.cpp" "%FIX%\wpJ6_tests.Embedded.cpp" "%FIX%\wpJ6_tests.Actions.cpp" "%FIX%\wpJ6_tests.Gate.cpp" "%FIX%\wpJ6_tests.Write.cpp" "%FIX%\wpJ6_tests.Nav.cpp" "%FIX%\wpJ6_tests.Visual.cpp" ^
  "%FIX%\wpJ6_tests.Review2A.cpp" "%FIX%\wpJ6_tests.Review2B.cpp" "%FIX%\wpJ6_tests.Review2C.cpp" "%FIX%\wpJ6_tests.Review2Fixes.cpp" "%FIX%\wpJ6_tests.Quit.cpp" "%FIX%\wpJ6_tests.Entry3b.cpp" "%FIX%\wpJ6_tests.Narrow.cpp" "%FIX%\wpJ6_tests.DarkLabels.cpp" "%FIX%\wpJ6_tests.Chrome.cpp" "%FIX%\wpJ6_tests.RowFit.cpp" "%FIX%\wpJ6_tests.DockFill.cpp" "%FIX%\wpJ6_tests.SubPages.cpp" ^
  "%WPI%\memwb_wpI_common.cpp" ^
  "%UI%\MemoryWorkbenchView.cpp" "%UI%\MemoryWorkbenchView.MemoryDebug.cpp" "%UI%\MemoryWorkbenchView.Ui.cpp" "%UI%\MemoryWorkbenchView.Session.cpp" "%UI%\MemoryWorkbenchView.Nav.cpp" "%UI%\MemoryWorkbenchView.HexPrefs.cpp" "%UI%\MemoryWorkbenchView.SubPages.cpp" "%UI%\MemoryWorkbenchView.RowCanvas.cpp" "%UI%\WorkbenchDiagnosticsHost.cpp" ^
  "%FIX%\wpJ6_tests.MemoryDebug.cpp" ^
  "%UI%\MemoryWorkbenchView.PointerChains.cpp" "%APP%\MemoryDock\WorkbenchPointerChainAccess.cpp" ^
  "%UI%\WorkbenchShared.cpp" ^
  "%UI%\WorkbenchHexPane.cpp" "%UI%\WorkbenchHexPane.Panels.cpp" "%UI%\WorkbenchHexPane.ViewMenu.cpp" ^
  "%UI%\WorkbenchPageProvider.cpp" "%UI%\WorkbenchPageProvider.Pool.cpp" ^
  "%UI%\WorkbenchBaselineFeeder.cpp" ^
  "%UI%\WorkbenchWriteController.cpp" "%UI%\WorkbenchWriteController.PendingStage.cpp" "%UI%\WorkbenchWriteController.Undo.cpp" ^
  "%UI%\WorkbenchTarget.cpp" "%UI%\WorkbenchTarget.Anchor.cpp" "%UI%\WorkbenchTarget.Modules.cpp" ^
  "%UI%\HexCanvas.cpp" "%UI%\HexCanvas.Scroll.cpp" "%UI%\HexCanvas.Layout.cpp" "%UI%\HexCanvas.Paint.cpp" "%UI%\HexCanvas.Input.cpp" "%UI%\HexCanvas.Edit.cpp" "%UI%\HexCanvas.Menu.cpp" "%UI%\HexCanvasFormat.cpp" ^
  /Fo"%OBJ%\\"
if errorlevel 1 exit /b %errorlevel%

cl %CLFLAGS% ^
  "%UI%\HexInspectorPanel.cpp" "%UI%\HexInspectorPanel.Rows.cpp" "%UI%\HexInspectorPanel.Edit.cpp" "%UI%\HexInspectorPanel.Menu.cpp" "%UI%\HexInspectorRowView.cpp" "%UI%\HexInspectorRowView.Paint.cpp" "%UI%\HexInspectorWidgets.cpp" ^
  "%UI%\HexFindBar.cpp" "%UI%\HexFindSearch.cpp" "%UI%\HexViewWidgets.cpp" "%UI%\HexViewWidgets.Text.cpp" "%UI%\HexViewFormat.cpp" ^
  "%UI%\WorkbenchDisasmView.cpp" "%UI%\WorkbenchDisasmView.Edit.cpp" "%UI%\WorkbenchDisasmView.Canvas.cpp" "%UI%\WorkbenchTextView.cpp" "%UI%\WorkbenchCompareView.cpp" ^
  "%UI%\WorkbenchSessionBar.cpp" "%UI%\WriteModeSwitch.cpp" "%UI%\WorkbenchStatusBar.cpp" "%UI%\WorkbenchConfirmations.cpp" "%UI%\WorkbenchStringWriteDialog.cpp" ^
  "%UI%\WorkbenchMessages.cpp" "%UI%\WorkbenchSettings.cpp" "%UI%\WorkbenchActions.cpp" ^
  "%UI%\AddressBookStore.cpp" "%UI%\AddressBookModel.cpp" "%UI%\AddressBookModel.StoreSync.cpp" "%UI%\AddressBookPanel.cpp" "%UI%\AddressBookPanel.RowActions.cpp" "%UI%\AddressBookPanel.Menu.cpp" ^
  "%UI%\Int3Controller.cpp" "%UI%\Int3PatchPanel.cpp" "%UI%\WorkbenchBookIntake.cpp" ^
  "%APP%\UI\X64DbgNavigation.cpp" "%APP%\UI\FlowLayout.cpp" "%APP%\UI\ThemeStatusRole.cpp" "%APP%\UI\GlobalUiBaseStyle.cpp" "%APP%\UI\ThemeControlGlyphs.cpp" ^
  /Fo"%OBJ%\\"
if errorlevel 1 exit /b %errorlevel%

rem 既有 MemoryRowCanvas 的 data 局部名隐藏 QWidget::data；仅此 TU 隔离 C4458，
rem 其余生产类和本次新增模式/测试仍按 /W4 /WX 编译，不降低全夹具门禁。
cl %CLFLAGS% /wd4458 "%UI%\MemoryRowCanvas.cpp" /Fo"%OBJ%\\"
if errorlevel 1 exit /b %errorlevel%

cl %CLFLAGS% ^
  "%MOC%\moc_HexCanvas.cpp" "%MOC%\moc_HexInspectorPanel.cpp" "%MOC%\moc_HexInspectorRowView.cpp" "%MOC%\moc_HexFindBar.cpp" "%MOC%\moc_HexViewWidgets.cpp" ^
  "%MOC%\moc_WorkbenchTarget.cpp" "%MOC%\moc_WorkbenchPageProvider.cpp" "%MOC%\moc_WorkbenchBaselineFeeder.cpp" "%MOC%\moc_WorkbenchWriteController.cpp" "%MOC%\moc_WorkbenchHexPane.cpp" ^
  "%MOC%\moc_MemoryRowCanvas.cpp" "%MOC%\moc_WorkbenchDisasmView.cpp" "%MOC%\moc_WorkbenchTextView.cpp" "%MOC%\moc_WorkbenchCompareView.cpp" ^
  "%MOC%\moc_WorkbenchSessionBar.cpp" "%MOC%\moc_WriteModeSwitch.cpp" "%MOC%\moc_WorkbenchStatusBar.cpp" "%MOC%\moc_WorkbenchStringWriteDialog.cpp" ^
  "%MOC%\moc_AddressBookStore.cpp" "%MOC%\moc_AddressBookModel.cpp" "%MOC%\moc_AddressBookPanel.cpp" "%MOC%\moc_Int3Controller.cpp" "%MOC%\moc_Int3PatchPanel.cpp" ^
  "%MOC%\moc_WorkbenchShared.cpp" "%MOC%\moc_MemoryWorkbenchView.cpp" "%MOC%\moc_WorkbenchDiagnosticsHost.cpp" "%MOC%\qrc_wpJ6_icons.cpp" ^
  /Fo"%OBJ%\\"
if errorlevel 1 exit /b %errorlevel%

cl %CLFLAGS% ^
  "%CORE%\HexViewport.cpp" "%CORE%\HexViewport.Cache.cpp" "%CORE%\HexViewport.Selection.cpp" ^
  "%CORE%\MemoryTextDecode.cpp" "%CORE%\MemoryDiffOverlay.cpp" "%CORE%\MemoryDiffOverlay.Patches.cpp" "%CORE%\MemoryTargetSession.cpp" ^
  "%CORE%\MemoryValueDecode.cpp" "%CORE%\MemoryAddressExpr.cpp" "%CORE%\MemoryByteSearch.cpp" ^
  "%CORE%\MemoryTargetTracker.cpp" "%CORE%\MemoryModuleDirectory.cpp" "%CORE%\MemoryProcessMatch.cpp" "%CORE%\SessionAddressResolver.cpp" ^
  "%CORE%\MemoryChannelGate.cpp" "%CORE%\MemoryPageReader.cpp" ^
  "%CORE%\MemoryWriteTransaction.cpp" "%CORE%\MemoryWriteTransaction.Commit.cpp" "%CORE%\MemoryIoByteStore.cpp" "%CORE%\MemoryKernelMutation.cpp" "%CORE%\MemoryEditJournal.cpp" ^
  "%CORE%\MemoryBaselineWindow.cpp" "%CORE%\MemoryWritePolicy.cpp" ^
  "%CORE%\MemoryAddressBook.cpp" "%CORE%\MemoryAddressBook.Serialize.cpp" "%CORE%\Int3PatchLedger.cpp" ^
  "shared\evidence\PointerChain.cpp" "%CORE%\PointerChainBindings.cpp" ^
  /Fo"%OBJ%\\"
if errorlevel 1 exit /b %errorlevel%

rem ---- 最终链接：用 /link 把两批 .obj 目录通配 + CodeEditorWidget 依赖链的
rem      .obj 一次性链起来，避免再拼一条列出全部 .obj 文件名的长命令行。----
cl /nologo /Fe"%OUT%\wpJ6_tests.exe" "%OBJ%\*.obj" ^
  /link /OPT:REF /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Test.lib Qt6Svg.lib user32.lib advapi32.lib ^
  "%OBJ2%\CodeEditorWidget.obj" "%OBJ2%\CodeTextEdit.obj" "%OBJ2%\CodeEditorFileSession.obj" "%OBJ2%\ReportStructuredView.obj" "%OBJ2%\LanguageManager.obj" "%OBJ2%\MemoryAssembly.obj" "%OBJ2%\MemoryAssembly.Core.obj" "%OBJ2%\moc_CodeEditorWidget.obj" "%OBJ2%\Zydis.obj"
if errorlevel 1 exit /b %errorlevel%

rem ---- 部署 DLL 与插件（离屏平台、SVG 图标引擎与图片格式） ----
for %%D in (Qt6Core Qt6Gui Qt6Widgets Qt6Test Qt6Svg) do copy /y "%QT%\bin\%%D.dll" "%OUT%\" >nul
if not exist "%OUT%\plugins\platforms" mkdir "%OUT%\plugins\platforms"
if not exist "%OUT%\plugins\iconengines" mkdir "%OUT%\plugins\iconengines"
if not exist "%OUT%\plugins\imageformats" mkdir "%OUT%\plugins\imageformats"
if not exist "%OUT%\plugins\styles" mkdir "%OUT%\plugins\styles"
copy /y "%QT%\plugins\platforms\qoffscreen.dll" "%OUT%\plugins\platforms\" >nul
copy /y "%QT%\plugins\platforms\qwindows.dll" "%OUT%\plugins\platforms\" >nul
copy /y "%QT%\plugins\iconengines\qsvgicon.dll" "%OUT%\plugins\iconengines\" >nul
copy /y "%QT%\plugins\imageformats\qsvg.dll" "%OUT%\plugins\imageformats\" >nul
copy /y "%QT%\plugins\styles\*.dll" "%OUT%\plugins\styles\" >nul 2>nul

if "%~1" == "--skip-run" (
  popd
  exit /b 0
)

rem ---- 运行 ----
set "PATH=%OUT%;%QT%\bin;%PATH%"
set "QT_PLUGIN_PATH=%OUT%\plugins"
set "QT_QPA_PLATFORM=offscreen"
set "MEMWB_OUT=%OUT%"
"%OUT%\wpJ6_tests.exe" %*
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%
