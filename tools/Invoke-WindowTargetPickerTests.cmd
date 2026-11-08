@echo off
setlocal
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" exit /b 2
call "%VCVARS%" >nul
if errorlevel 1 exit /b %errorlevel%
set "QT=%CD%\.deps\Qt\6.9.3\msvc2022_64"
if not exist "%QT%\lib\Qt6Widgets.lib" set "QT=D:\Software\Qt\6.9.3\msvc2022_64"
set "OUT=%CD%\.codex-build-logs\window-target-picker-tests"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /DNOMINMAX /DUNICODE /D_UNICODE /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB /external:W0 /external:I"%QT%\include" /external:I"%QT%\include\QtCore" /external:I"%QT%\include\QtGui" /external:I"%QT%\include\QtWidgets" /external:I"%QT%\include\QtTest" tools\window_target_picker_tests.cpp Ksword5.1\Ksword5.1\UI\AsyncOperation.cpp Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp /Fo"%OUT%\\" /Fe"%OUT%\window_target_picker_tests.exe" /link /LIBPATH:"%QT%\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Test.lib user32.lib
if errorlevel 1 exit /b %errorlevel%
set "PATH=%QT%\bin;%PATH%"
set "QT_PLUGIN_PATH=%QT%\plugins"
set "QT_QPA_PLATFORM=windows"
"%OUT%\window_target_picker_tests.exe"
if errorlevel 1 exit /b %errorlevel%
if /i "%~1"=="--dpi-matrix" (
    for %%S in (1.25 1.5 2) do (
        set "QT_SCALE_FACTOR=%%S"
        "%OUT%\window_target_picker_tests.exe"
        if errorlevel 1 exit /b 1
    )
)
exit /b %errorlevel%
