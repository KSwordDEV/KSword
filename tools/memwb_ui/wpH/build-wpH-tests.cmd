@echo off
chcp 65001 >nul
rem ============================================================
rem build-wpH-tests.cmd
rem 作用：构建并运行 WP-H（反汇编/文本/对比）离屏验证夹具。仿
rem       tools\memwb_ui\build-memwb-ui-tests.cmd，但只链接本包需要的源文件，
rem       与其它工作包的夹具完全隔离（独立产物目录、独立变量，不共享环境变量）。
rem 用法：在任意目录执行 tools\memwb_ui\wpH\build-wpH-tests.cmd [--skip-run] [额外参数传给 exe]
rem 产物：.codex-tmp\memwb-wpH\（已被仓库 .codex-tmp 规则忽略）。
rem 说明：
rem  - CodeEditorWidget 这一条依赖链（CodeEditorWidget.cpp/TypedSyntaxDocument.cpp/
rem    LanguageManager.cpp/MemoryAssembly*.cpp）不是本包新写的代码，主程序用
rem    WarningLevel=Level3（非 Level4/WX）编译它们，所以单独一次 cl 调用用 /W3（不开 /WX）
rem    编译成 .obj，不让别人代码里的既有警告挡住本包自己代码的强校验；本包新代码仍然是
rem    完整的 /std:c++latest /W4 /WX。
rem  - third_party\zydis\Zydis.c 是 C 源文件，用 /DZYDIS_STATIC_BUILD 与主程序 vcxproj 保持一致，
rem    单独一次 cl /c 编译。
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
set "FIX=tools\memwb_ui\wpH"
set "ZYDIS=third_party\zydis"
if not defined MEMWB_OUT set "MEMWB_OUT=.codex-tmp\memwb-wpH"
set "OUT=%MEMWB_OUT%"
set "OBJ=%OUT%\obj"
set "OBJ2=%OUT%\obj2"
set "MOC=%OUT%\moc"
if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%OBJ2%" mkdir "%OBJ2%"
if not exist "%MOC%" mkdir "%MOC%"
if not exist "%OUT%\shots" mkdir "%OUT%\shots"

rem ---- moc：共享行画布、子页与 CodeEditorWidget ----
"%QT%\bin\moc.exe" "%UI%\MemoryRowCanvas.h" -o "%MOC%\moc_MemoryRowCanvas.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\WorkbenchDisasmView.h" -o "%MOC%\moc_WorkbenchDisasmView.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\WorkbenchTextView.h" -o "%MOC%\moc_WorkbenchTextView.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\WorkbenchCompareView.h" -o "%MOC%\moc_WorkbenchCompareView.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexViewWidgets.h" -o "%MOC%\moc_HexViewWidgets.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%APP%\UI\CodeEditorWidget.h" -o "%MOC%\moc_CodeEditorWidget.cpp"
if errorlevel 1 exit /b 1
"%QT%\bin\moc.exe" "%APP%\UI\StructuredFieldView.h" -o "%MOC%\moc_StructuredFieldView.cpp"
if errorlevel 1 exit /b %errorlevel%

rem ---- rcc：复用已有的精简图标 qrc（不复制、不修改，与它的宿主夹具共享同一份资源） ----
"%QT%\bin\rcc.exe" "tools\memwb_ui\memwb_ui_icons.qrc" -name memwb_ui_icons -o "%MOC%\qrc_memwb_ui_icons.cpp"
if errorlevel 1 exit /b %errorlevel%

rem ---- Zydis（C 源文件，单独一次 /c 编译，与主程序 vcxproj 同一个宏） ----
cl /nologo /std:c11 /MD /O2 /DZYDIS_STATIC_BUILD /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I"%ZYDIS%" /c "%ZYDIS%\Zydis.c" /Fo"%OBJ2%\Zydis.obj"
if errorlevel 1 exit /b %errorlevel%

rem ---- 第二遍：CodeEditorWidget 依赖链，/W3 不开 /WX（别人代码，别人的既有警告不该挡住本包） ----
cl /nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W3 /O2 /DWIN32_LEAN_AND_MEAN /external:W0 /DNOMINMAX /DUNICODE /D_UNICODE /DZYDIS_STATIC_BUILD /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB ^
  /I"%ZYDIS%" /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /external:I"%QT%\include\QtSvg" ^
  /c "%APP%\UI\CodeEditorWidget.cpp" "%APP%\UI\CodeTextEdit.cpp" "%APP%\UI\CodeEditorFileSession.cpp" "%APP%\UI\StructuredFieldView.cpp" "%APP%\UI\TypedSyntaxDocument.cpp" "%APP%\UI\FlatButtonTheme.cpp" "%APP%\UI\ThemeBinding.cpp" "%APP%\UI\ThemeAccentIcon.cpp" "%APP%\Internationalization\LanguageManager.cpp" "%APP%\UI\MemoryAssembly.cpp" "%APP%\UI\MemoryAssembly.Core.cpp" "%APP%\UI\ThemeStatusRole.cpp" "%MOC%\moc_CodeEditorWidget.cpp" "%MOC%\moc_StructuredFieldView.cpp" ^
  /Fo"%OBJ2%\\"
if errorlevel 1 exit /b %errorlevel%

rem ---- 第一遍：本包新代码 + 复用的既测文件，/W4 /WX 干净 ----
cl /nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /O2 /Gy /DWIN32_LEAN_AND_MEAN /external:W0 /DNOMINMAX /DUNICODE /D_UNICODE /DZYDIS_STATIC_BUILD /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DQT_TESTLIB_LIB ^
  /I"%ZYDIS%" /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /external:I"%QT%\include\QtTest" /external:I"%QT%\include\QtSvg" ^
  "%FIX%\wpH_main.cpp" "%FIX%\wpH_common.cpp" "%FIX%\wpH_tests.Disasm.cpp" "%FIX%\wpH_tests.Text.cpp" "%FIX%\wpH_tests.Compare.cpp" ^
  "%FIX%\wpH_tests.DisasmRegression.cpp" "%FIX%\wpH_tests.TextRegression.cpp" "%FIX%\wpH_tests.CompareRegression.cpp" ^
  "%FIX%\wpH_tests.DisasmRegression2.cpp" "%FIX%\wpH_tests.DisasmRegression3.cpp" "%FIX%\wpH_tests.TextRegression2.cpp" "%FIX%\wpH_tests.CompareRegression2.cpp" "%FIX%\wpH_tests.SExtra.cpp" ^
  "%UI%\WorkbenchDisasmView.cpp" "%UI%\WorkbenchDisasmView.Edit.cpp" "%UI%\AssemblyPreviewDialog.cpp" "%UI%\WorkbenchDisasmView.Canvas.cpp" "%UI%\MemoryRowCanvas.cpp" "%UI%\WorkbenchTextView.cpp" "%UI%\WorkbenchCompareView.cpp" ^
  "%APP%\UI\FlowLayout.cpp" "%UI%\HexCanvasFormat.cpp" "%UI%\HexViewWidgets.cpp" "%UI%\HexViewWidgets.Text.cpp" "%UI%\HexViewFormat.cpp" ^
  "%CORE%\MemoryTextDecode.cpp" "%CORE%\MemoryDiffOverlay.cpp" "%CORE%\MemoryDiffOverlay.Patches.cpp" ^
  "%MOC%\moc_MemoryRowCanvas.cpp" "%MOC%\moc_WorkbenchDisasmView.cpp" "%MOC%\moc_WorkbenchTextView.cpp" "%MOC%\moc_WorkbenchCompareView.cpp" "%MOC%\moc_HexViewWidgets.cpp" "%MOC%\qrc_memwb_ui_icons.cpp" ^
  /Fo"%OBJ%\\" /Fe"%OUT%\wpH_tests.exe" ^
  /link /OPT:REF /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Test.lib Qt6Svg.lib user32.lib advapi32.lib ^
  "%OBJ2%\CodeEditorWidget.obj" "%OBJ2%\CodeTextEdit.obj" "%OBJ2%\CodeEditorFileSession.obj" "%OBJ2%\StructuredFieldView.obj" "%OBJ2%\TypedSyntaxDocument.obj" "%OBJ2%\FlatButtonTheme.obj" "%OBJ2%\ThemeBinding.obj" "%OBJ2%\ThemeAccentIcon.obj" "%OBJ2%\LanguageManager.obj" "%OBJ2%\MemoryAssembly.obj" "%OBJ2%\MemoryAssembly.Core.obj" "%OBJ2%\ThemeStatusRole.obj" "%OBJ2%\moc_CodeEditorWidget.obj" "%OBJ2%\moc_StructuredFieldView.obj" "%OBJ2%\Zydis.obj"
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
"%OUT%\wpH_tests.exe" --shots "%OUT%\shots" %*
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%
