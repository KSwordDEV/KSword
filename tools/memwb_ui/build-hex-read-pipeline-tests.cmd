@echo off
setlocal
set "REPO=%~dp0..\.."
pushd "%REPO%"
if errorlevel 1 exit /b 2
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul
if errorlevel 1 exit /b %errorlevel%
set "QT=%CD%\.deps\Qt\6.9.3\msvc2022_64"
if not exist "%QT%\lib\Qt6Widgets.lib" set "QT=D:\Software\Qt\6.9.3\msvc2022_64"
set "APP=%CD%\Ksword5.1\Ksword5.1"
set "UI=%APP%\UI\MemoryWorkbench"
set "CORE=%CD%\shared\evidence\memory_workbench"
rem Optional frozen scroll implementation for a controlled negative regression.
if not defined HEX_SCROLL_SOURCE set "HEX_SCROLL_SOURCE=%UI%\HexCanvas.Scroll.cpp"
set "OUT=%CD%\.codex-tmp\hex-read-pipeline"
if not exist "%OUT%" mkdir "%OUT%"
for %%H in (HexCanvas WorkbenchTarget WorkbenchPageProvider) do (
  "%QT%\bin\moc.exe" "%UI%\%%H.h" -o "%OUT%\moc_%%H.cpp"
  if errorlevel 1 exit /b 2
)
cl /MP4 /nologo /std:c++20 /Zc:__cplusplus /utf-8 /EHsc /MD /W4 /WX /O2 /Gy /DUNICODE /D_UNICODE /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /external:W0 /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /I"%UI%" ^
  tools\tests\hex_navigation_read_pipeline_tests.cpp "%OUT%\moc_HexCanvas.cpp" "%OUT%\moc_WorkbenchTarget.cpp" "%OUT%\moc_WorkbenchPageProvider.cpp" ^
  "%UI%\HexCanvas.cpp" "%HEX_SCROLL_SOURCE%" "%UI%\HexCanvas.Layout.cpp" "%UI%\HexCanvas.Paint.cpp" "%UI%\HexCanvas.Input.cpp" "%UI%\HexCanvas.Edit.cpp" "%UI%\HexCanvas.Menu.cpp" "%UI%\HexCanvasFormat.cpp" ^
  "%UI%\WorkbenchPageProvider.cpp" "%UI%\WorkbenchPageProvider.Pool.cpp" "%UI%\WorkbenchTarget.cpp" "%UI%\WorkbenchTarget.Anchor.cpp" "%UI%\WorkbenchTarget.Modules.cpp" ^
  "%APP%\Internationalization\LanguageManager.cpp" ^
  "%APP%\MemoryDock\WorkbenchUserModeRead.cpp" ^
  "%CORE%\HexViewport.cpp" "%CORE%\HexViewport.Cache.cpp" "%CORE%\HexViewport.Selection.cpp" "%CORE%\MemoryDiffOverlay.cpp" "%CORE%\MemoryDiffOverlay.Patches.cpp" ^
  "%CORE%\MemoryTargetSession.cpp" "%CORE%\MemoryTargetTracker.cpp" "%CORE%\MemoryModuleDirectory.cpp" "%CORE%\MemoryProcessMatch.cpp" "%CORE%\MemoryAddressExpr.cpp" "%CORE%\SessionAddressResolver.cpp" "%CORE%\MemoryChannelGate.cpp" "%CORE%\MemoryPageReader.cpp" ^
  /Fo"%OUT%\\" /Fe"%OUT%\hex-read-pipeline-tests.exe" /link /OPT:REF /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib user32.lib advapi32.lib
if errorlevel 1 exit /b %errorlevel%
set "PATH=%QT%\bin;%PATH%"
set "QT_QPA_PLATFORM=offscreen"
set "QT_PLUGIN_PATH=%QT%\plugins"
"%OUT%\hex-read-pipeline-tests.exe"
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%
