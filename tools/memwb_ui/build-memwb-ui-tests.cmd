@echo off
chcp 65001 >nul
rem ============================================================
rem build-memwb-ui-tests.cmd
rem 作用：构建并运行 HexCanvas 离屏验证夹具（仿 tools\hvm_lab\build-ui-tests.cmd）。
rem 用法：在任意目录执行 tools\memwb_ui\build-memwb-ui-tests.cmd [--skip-bench] ...
rem       额外参数原样传给 memwb_ui_tests.exe。
rem 产物：.codex-tmp\memwb-ui\（已被 gitignore）。
rem 说明：
rem  - 本机 MSVC 14.44 不识别 /std:c++23，会静默退回 C++14，所以使用 /std:c++latest。
rem  - HexCanvas 含 Q_OBJECT，先用 moc 生成 moc 文件再一起编译。
rem  - 夹具内嵌精简 qrc（右键菜单用到的三个图标 + 工作台 Phase 3 新增的 11 个 memwb_* 别名），需要 Qt6Svg 与 svg 图标/图片插件才能显示。
rem  - M-1：同一个可执行文件里还链接了 WorkbenchIoMapping.cpp（真实端口的纯映射函数，不含 Win32 调用）
rem        与 memwb_ui_tests.IoMapping.cpp（它的分支覆盖），两者不依赖离屏画布，只是顺路共享这一个 MSVC+Qt 链接环境。
rem ============================================================
setlocal
set "REPO=%~dp0..\.."
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
set "FIX=tools\memwb_ui"
rem MEMWB_OUT 可由调用方预先设置，让多个验证互不覆盖产物目录；默认 .codex-tmp\memwb-ui。
if not defined MEMWB_OUT set "MEMWB_OUT=.codex-tmp\memwb-ui"
set "OUT=%MEMWB_OUT%"
set "OBJ=%OUT%\obj"
set "MOC=%OUT%\moc"
if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%MOC%" mkdir "%MOC%"
if not exist "%OUT%\shots" mkdir "%OUT%\shots"

rem ---- moc / rcc：HexCanvas 的信号槽与夹具图标资源 ----
"%QT%\bin\moc.exe" "%UI%\HexCanvas.h" -o "%MOC%\moc_HexCanvas.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexInspectorPanel.h" -o "%MOC%\moc_HexInspectorPanel.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexInspectorRowView.h" -o "%MOC%\moc_HexInspectorRowView.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexView.h" -o "%MOC%\moc_HexView.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexFindBar.h" -o "%MOC%\moc_HexFindBar.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexGotoBar.h" -o "%MOC%\moc_HexGotoBar.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexViewWidgets.h" -o "%MOC%\moc_HexViewWidgets.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\WorkbenchCompareView.h" -o "%MOC%\moc_WorkbenchCompareView.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\rcc.exe" "%FIX%\memwb_ui_icons.qrc" -name memwb_ui_icons -o "%MOC%\qrc_memwb_ui_icons.cpp"
if errorlevel 1 exit /b %errorlevel%

rem ---- 编译并链接 ----
if not defined CL set "CL=/MP"
cl /nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /O2 /Gy /DWIN32_LEAN_AND_MEAN /external:W0 /DNOMINMAX /DUNICODE /D_UNICODE /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DQT_TESTLIB_LIB /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /external:I"%QT%\include\QtTest" ^
  "%FIX%\memwb_ui_tests.cpp" "%FIX%\memwb_ui_common.cpp" "%FIX%\memwb_ui_tests.View.cpp" "%FIX%\memwb_ui_tests.Edit.cpp" "%FIX%\memwb_ui_render.cpp" "%FIX%\memwb_ui_bench.cpp" ^
  "%FIX%\memwb_ui_inspector.cpp" "%FIX%\memwb_ui_tests.Inspector.cpp" "%FIX%\memwb_ui_tests.Inspector.Edit.cpp" "%FIX%\memwb_ui_tests.Inspector.Shots.cpp" "%FIX%\memwb_ui_tests.Signals.cpp" "%FIX%\memwb_ui_tests.Signals.Stage.cpp" "%FIX%\memwb_ui_tests.Signals.View.cpp" "%FIX%\memwb_ui_tests.Signals.Inspector.cpp" ^
  "%FIX%\memwb_ui_hexview.cpp" "%FIX%\memwb_ui_tests.HexView.cpp" "%FIX%\memwb_ui_tests.HexView.Compat.cpp" "%FIX%\memwb_ui_tests.HexView.Reference.cpp" "%FIX%\memwb_ui_tests.HexView.Find.cpp" "%FIX%\memwb_ui_tests.HexView.FindLogic.cpp" "%FIX%\memwb_ui_tests.HexView.Goto.cpp" "%FIX%\memwb_ui_tests.HexView.Export.cpp" "%FIX%\memwb_ui_tests.HexView.Shots.cpp" ^
  "%FIX%\memwb_ui_tests.HexView.Hosts.cpp" "%FIX%\memwb_ui_tests.Segmented.cpp" "%FIX%\memwb_ui_tests.CachedRange.cpp" "%FIX%\memwb_ui_tests.IconAliases.cpp" "%FIX%\memwb_ui_tests.RowFit.cpp" "%APP%\UI\SmoothScrollSupport.cpp" ^
  "%FIX%\memwb_ui_tests.IoMapping.cpp" "%APP%\MemoryDock\WorkbenchIoMapping.cpp" ^
  "%FIX%\memwb_ui_tests.CompareContracts.cpp" "%UI%\WorkbenchCompareView.cpp" "%APP%\Internationalization\LanguageManager.cpp" "%MOC%\moc_WorkbenchCompareView.cpp" ^
  "%UI%\HexCanvas.cpp" "%UI%\HexCanvas.Scroll.cpp" "%UI%\HexCanvas.Layout.cpp" "%UI%\HexCanvas.Paint.cpp" "%UI%\HexCanvas.Input.cpp" "%UI%\HexCanvas.Edit.cpp" "%UI%\HexCanvas.Menu.cpp" "%UI%\HexCanvasFormat.cpp" ^
  "%UI%\HexInspectorPanel.cpp" "%UI%\HexInspectorPanel.Rows.cpp" "%UI%\HexInspectorPanel.Edit.cpp" "%UI%\HexInspectorPanel.Menu.cpp" "%UI%\HexInspectorRowView.cpp" "%UI%\HexInspectorRowView.Paint.cpp" "%UI%\HexInspectorWidgets.cpp" ^
  "%UI%\HexView.cpp" "%UI%\HexView.Toolbar.cpp" "%UI%\HexView.Compat.cpp" "%UI%\HexView.Panels.cpp" "%UI%\HexViewWidgets.cpp" "%UI%\HexViewWidgets.Text.cpp" "%UI%\HexViewFormat.cpp" "%UI%\HexViewSettings.cpp" "%UI%\HexFindBar.cpp" "%UI%\HexFindSearch.cpp" "%UI%\HexGotoBar.cpp" "%UI%\HexExport.cpp" ^
  "%MOC%\moc_HexCanvas.cpp" "%MOC%\moc_HexInspectorPanel.cpp" "%MOC%\moc_HexInspectorRowView.cpp" "%MOC%\moc_HexView.cpp" "%MOC%\moc_HexFindBar.cpp" "%MOC%\moc_HexGotoBar.cpp" "%MOC%\moc_HexViewWidgets.cpp" "%MOC%\qrc_memwb_ui_icons.cpp" ^
  "%CORE%\HexViewport.cpp" "%CORE%\HexViewport.Cache.cpp" "%CORE%\HexViewport.Selection.cpp" "%CORE%\MemoryDiffOverlay.cpp" "%CORE%\MemoryDiffOverlay.Patches.cpp" "%CORE%\MemoryTargetSession.cpp" "%CORE%\MemoryValueDecode.cpp" "%CORE%\MemoryAddressExpr.cpp" "%CORE%\MemoryByteSearch.cpp" ^
  /Fo"%OBJ%\\" /Fe"%OUT%\memwb_ui_tests.exe" ^
  /link /OPT:REF /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Test.lib user32.lib advapi32.lib
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

rem ---- 运行 ----
set "PATH=%OUT%;%QT%\bin;%PATH%"
set "QT_PLUGIN_PATH=%OUT%\plugins"
set "QT_QPA_PLATFORM=offscreen"
"%OUT%\memwb_ui_tests.exe" --shots "%OUT%\shots" --bench "%OUT%\bench.txt" %*
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%
