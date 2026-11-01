@echo off
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
if not exist "%QT%\lib\Qt6Core.lib" set "QT=D:\Software\Qt\6.9.3\msvc2022_64"
if not exist "%QT%\lib\Qt6Core.lib" exit /b 2
set "OUT=%CD%\.codex-tmp\hex-find-ansi"
if not exist "%OUT%" mkdir "%OUT%"
set "UI=Ksword5.1\Ksword5.1\UI\MemoryWorkbench"
cl /nologo /std:c++20 /Zc:__cplusplus /utf-8 /EHsc /MD /W4 /WX /O2 /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DQT_CORE_LIB /external:W0 /external:I"%QT%\include" /external:I"%QT%\include\QtCore" ^
  tools\tests\hex_find_ansi_tests.cpp "%UI%\HexFindSearch.cpp" "%UI%\HexViewFormat.cpp" shared\evidence\memory_workbench\MemoryByteSearch.cpp ^
  /Fo"%OUT%\\" /Fe"%OUT%\hex-find-ansi-tests.exe" /link /LIBPATH:"%QT%\lib" Qt6Core.lib
if errorlevel 1 exit /b %errorlevel%
set "PATH=%QT%\bin;%PATH%"
"%OUT%\hex-find-ansi-tests.exe"
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%
