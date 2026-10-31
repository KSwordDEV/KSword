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
set "ACTUAL=%CD%\Ksword5.1\Ksword5.1\UI\MemoryWorkbench"
rem Baseline mode requires an explicit frozen source tree, e.g. commit 9a33349d.
if /I "%1"=="baseline" if not defined HEX_SOURCE_ROOT exit /b 2
if not defined HEX_SOURCE_ROOT set "HEX_SOURCE_ROOT=%CD%"
if not defined HEX_TEST_OUT set "HEX_TEST_OUT=%CD%\.codex-tmp\hex-navigation"
set "OUT=%HEX_TEST_OUT%"
set "UI=%HEX_SOURCE_ROOT%\Ksword5.1\Ksword5.1\UI\MemoryWorkbench"
set "CORE=%HEX_SOURCE_ROOT%\shared\evidence\memory_workbench"
if not exist "%OUT%" mkdir "%OUT%"
set "FEATURES=/DHEX_VIEW_FEATURES"
set "FEATURE_SOURCES="
if /I "%1"=="baseline" goto moc_canvas
"%QT%\bin\moc.exe" "%ACTUAL%\WorkbenchStatusBar.h" -o "%OUT%\moc_WorkbenchStatusBar.cpp"
if errorlevel 1 exit /b %errorlevel%
set FEATURE_SOURCES="%ACTUAL%\WorkbenchStatusBar.cpp" "%ACTUAL%\WorkbenchMessages.cpp" "%ACTUAL%\..\FlowLayout.cpp" "%ACTUAL%\..\ThemeStatusRole.cpp" "%ACTUAL%\..\ThemeBinding.cpp" "%ACTUAL%\..\FlatButtonTheme.cpp" "%ACTUAL%\..\MainSurfaceStyle.cpp" "%ACTUAL%\..\PrimaryPageStyle.cpp" "%ACTUAL%\..\ThemeControlGlyphs.cpp" "%OUT%\moc_WorkbenchStatusBar.cpp"
:moc_canvas
if /I "%1"=="baseline" set "FEATURES="
"%QT%\bin\moc.exe" "%UI%\HexCanvas.h" -o "%OUT%\moc_HexCanvas.cpp"
if errorlevel 1 exit /b %errorlevel%
cl /MP4 /nologo /std:c++20 /Zc:__cplusplus /utf-8 /EHsc /MD /W4 /WX /O2 /Gy /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DQT_TESTLIB_LIB %FEATURES% /external:W0 /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /external:I"%QT%\include\QtTest" /I"%UI%" /I"%ACTUAL%" /I"%CD%\shared\evidence\memory_workbench" ^
  tools\tests\hex_navigation_tests.cpp "%OUT%\moc_HexCanvas.cpp" %FEATURE_SOURCES% ^
  "%UI%\HexCanvas.cpp" "%UI%\HexCanvas.Scroll.cpp" "%UI%\HexCanvas.Layout.cpp" "%UI%\HexCanvas.Paint.cpp" "%UI%\HexCanvas.Input.cpp" "%UI%\HexCanvas.Edit.cpp" "%UI%\HexCanvas.Menu.cpp" "%UI%\HexCanvasFormat.cpp" ^
  "%CORE%\HexViewport.cpp" "%CORE%\HexViewport.Cache.cpp" "%CORE%\HexViewport.Selection.cpp" "%CORE%\MemoryDiffOverlay.cpp" "%CORE%\MemoryDiffOverlay.Patches.cpp" ^
  Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp ^
  /Fo"%OUT%\\" /Fe"%OUT%\hex-navigation-tests.exe" /link /OPT:REF /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Test.lib user32.lib advapi32.lib
if errorlevel 1 exit /b %errorlevel%
set "PATH=%QT%\bin;%PATH%"
set "QT_QPA_PLATFORM=offscreen"
set "QT_PLUGIN_PATH=%QT%\plugins"
"%OUT%\hex-navigation-tests.exe" %2
set "RESULT=%errorlevel%"
if not "%RESULT%"=="0" exit /b %RESULT%
if /I "%1"=="baseline" goto done
cl /MP3 /nologo /std:c++20 /Zc:__cplusplus /utf-8 /EHsc /MD /W4 /WX /O2 tools\tests\hex_folding_tests.cpp KswordARKLightTests\HexViewportTests.cpp KswordARKLightTests\HexViewportCacheTests.cpp "%CORE%\HexViewport.cpp" "%CORE%\HexViewport.Cache.cpp" "%CORE%\HexViewport.Selection.cpp" /Fo"%OUT%\\" /Fe"%OUT%\hex-folding-tests.exe"
if errorlevel 1 exit /b %errorlevel%
"%OUT%\hex-folding-tests.exe"
set "RESULT=%errorlevel%"
:done
popd
exit /b %RESULT%
