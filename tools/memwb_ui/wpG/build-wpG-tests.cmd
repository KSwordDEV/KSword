@echo off
chcp 65001 >nul
rem ============================================================
rem build-wpG-tests.cmd
rem 作用：构建并运行 WP-G（会话条/写入模式/状态条/确认框/动作/设置/消息/字符串
rem       写入）离屏验证夹具。仿 tools\memwb_ui\build-memwb-ui-tests.cmd，但只
rem       链接 WP-G 实际用到的源文件，与其它工作包的夹具互不干扰。
rem 用法：tools\memwb_ui\wpG\build-wpG-tests.cmd [--skip-bench] ...
rem       额外参数原样传给 wpG_tests.exe。
rem 产物：.codex-tmp\memwb-wpG\（已被 gitignore；MEMWB_OUT 可覆盖默认目录）。
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
set "FIX=tools\memwb_ui\wpG"
rem MEMWB_OUT 可由调用方预先设置（写进命令行 set，不共享环境变量），默认 .codex-tmp\memwb-wpG。
if not defined MEMWB_OUT set "MEMWB_OUT=.codex-tmp\memwb-wpG"
set "OUT=%MEMWB_OUT%"
set "OBJ=%OUT%\obj"
set "MOC=%OUT%\moc"
if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%MOC%" mkdir "%MOC%"
if not exist "%OUT%\shots" mkdir "%OUT%\shots"

rem ---- moc：四个新增 Q_OBJECT 控件 + 复用的 HexViewWidgets（HexViewSegmented）----
"%QT%\bin\moc.exe" "%UI%\WorkbenchSessionBar.h" -o "%MOC%\moc_WorkbenchSessionBar.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\WriteModeSwitch.h" -o "%MOC%\moc_WriteModeSwitch.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\WorkbenchStatusBar.h" -o "%MOC%\moc_WorkbenchStatusBar.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%APP%\UI\StructuredFieldView.h" -o "%MOC%\moc_StructuredFieldView.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\WorkbenchStringWriteDialog.h" -o "%MOC%\moc_WorkbenchStringWriteDialog.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\moc.exe" "%UI%\HexViewWidgets.h" -o "%MOC%\moc_HexViewWidgets.cpp"
if errorlevel 1 exit /b %errorlevel%
"%QT%\bin\rcc.exe" "%FIX%\wpG_icons.qrc" -name wpG_icons -o "%MOC%\qrc_wpG_icons.cpp"
if errorlevel 1 exit /b %errorlevel%

rem ---- 编译并链接 ----
rem N2（第二轮修复）：WorkbenchMessages/WorkbenchStatusBar 现在调用 ks::i18n::sourceText，
rem 源文件列表里加了 Internationalization\LanguageManager.cpp 才能解析到符号；它只依赖
rem Qt（不含 Framework.h），审核者的探针 bp.cmd（LM 选项）已验证过同样的链接方式可行。
if not defined CL set "CL=/MP"
cl /nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /O2 /Gy /DWIN32_LEAN_AND_MEAN /external:W0 /DNOMINMAX /DUNICODE /D_UNICODE /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" ^
  "%FIX%\wpG_tests.cpp" "%FIX%\wpG_common.cpp" "%FIX%\wpG_tests.SessionBar.cpp" "%FIX%\wpG_tests.StatusBar.cpp" "%FIX%\wpG_tests.Confirmations.cpp" "%FIX%\wpG_tests.Shots.cpp" "%FIX%\wpG_tests.Gaps.cpp" "%FIX%\wpG_tests.Gaps2.cpp" "%FIX%\wpG_tests.Review2.cpp" ^
  "%UI%\WorkbenchMessages.cpp" "%UI%\WorkbenchSettings.cpp" "%UI%\WorkbenchActions.cpp" "%UI%\WriteModeSwitch.cpp" "%UI%\WorkbenchSessionBar.cpp" "%UI%\WorkbenchStatusBar.cpp" "%UI%\WorkbenchConfirmations.cpp" "%UI%\WorkbenchStringWriteDialog.cpp" ^
  "%UI%\HexViewWidgets.cpp" "%UI%\HexViewWidgets.Text.cpp" "%UI%\HexViewFormat.cpp" "%APP%\UI\FlowLayout.cpp" "%APP%\UI\ThemeStatusRole.cpp" ^
  "%APP%\Internationalization\LanguageManager.cpp" ^
  "%APP%\UI\StructuredFieldView.cpp" "%MOC%\moc_StructuredFieldView.cpp" ^
  "%MOC%\moc_WorkbenchSessionBar.cpp" "%MOC%\moc_WriteModeSwitch.cpp" "%MOC%\moc_WorkbenchStatusBar.cpp" "%MOC%\moc_WorkbenchStringWriteDialog.cpp" "%MOC%\moc_HexViewWidgets.cpp" "%MOC%\qrc_wpG_icons.cpp" ^
  "%CORE%\MemoryTargetSession.cpp" "%CORE%\MemoryChannelGate.cpp" "%CORE%\MemoryWritePolicy.cpp" "%CORE%\MemoryDiffOverlay.cpp" "%CORE%\MemoryDiffOverlay.Patches.cpp" "%CORE%\MemoryWriteTransaction.cpp" "%CORE%\MemoryWriteTransaction.Commit.cpp" ^
  /Fo"%OBJ%\\" /Fe"%OUT%\wpG_tests.exe" ^
  /link /OPT:REF /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib user32.lib advapi32.lib
if errorlevel 1 exit /b %errorlevel%

rem ---- 部署 DLL 与插件（离屏平台、SVG 图标引擎与图片格式） ----
for %%D in (Qt6Core Qt6Gui Qt6Widgets Qt6Svg) do copy /y "%QT%\bin\%%D.dll" "%OUT%\" >nul
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
"%OUT%\wpG_tests.exe" --shots "%OUT%\shots" %*
set "RESULT=%errorlevel%"
if not "%RESULT%"=="0" goto :afterGbk

rem ---- GBK 往返校验独立可执行文件（第二轮修复新增）----
rem 作用：wpG_tests.exe 跑在本机真实 ANSI 代码页下（实测是 UTF-8），B1 的"有损"
rem 分支在本机几乎测不到常见汉字触发的真实路径。这里单独编译一个进程，链接参数
rem /MANIFEST:EMBED /MANIFESTINPUT:wpG_gbk.manifest 给它嵌入 activeCodePage=zh-CN
rem 清单，让这一个进程的 GetACP() 报告 936（GBK），不改系统设置、不影响
rem wpG_tests.exe 或其它任何进程。只链接 WorkbenchStringWriteDialog 实际用到的
rem 源文件，复用上面已经生成的 moc_WorkbenchStringWriteDialog.cpp。
cl /nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /O2 /Gy /DWIN32_LEAN_AND_MEAN /external:W0 /DNOMINMAX /DUNICODE /D_UNICODE /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" ^
  "%FIX%\wpG_gbk_tests.cpp" ^
  "%UI%\WorkbenchMessages.cpp" "%UI%\WorkbenchStringWriteDialog.cpp" "%APP%\UI\ThemeStatusRole.cpp" "%APP%\Internationalization\LanguageManager.cpp" ^
  "%MOC%\moc_WorkbenchStringWriteDialog.cpp" ^
  /Fo"%OBJ%\\" /Fe"%OUT%\wpG_gbk_tests.exe" ^
  /link /OPT:REF /MANIFEST:EMBED /MANIFESTINPUT:"%FIX%\wpG_gbk.manifest" /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib user32.lib advapi32.lib
if errorlevel 1 (
    set "RESULT=%errorlevel%"
    goto :afterGbk
)
"%OUT%\wpG_gbk_tests.exe"
set "RESULT=%errorlevel%"

:afterGbk
popd
exit /b %RESULT%
