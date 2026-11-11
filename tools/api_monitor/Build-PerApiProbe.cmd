@echo off
setlocal
pushd "%~dp0\..\.."
if not exist ".codex-build-logs" mkdir ".codex-build-logs"
set "probeVsSetup=%KSWORD_VSDEVCMD%"
if not defined probeVsSetup set "probeVsSetup=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
if not exist "%probeVsSetup%" set "probeVsSetup=D:\Software\VS\Common7\Tools\VsDevCmd.bat"
if not exist "%probeVsSetup%" exit /b 2
call "%probeVsSetup%" -no_logo -host_arch=x64 -arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /std:c++17 /EHsc /MT /W4 /WX /utf-8 tools\api_monitor\runtime_probe_fixture.cpp /Fo.codex-build-logs\RuntimeProbe64.obj /Fe.codex-build-logs\RuntimeProbe64.exe /link user32.lib gdi32.lib ole32.lib advapi32.lib bcrypt.lib uuid.lib psapi.lib
if errorlevel 1 exit /b %errorlevel%
call "%probeVsSetup%" -no_logo -host_arch=x64 -arch=x86 >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /std:c++17 /EHsc /MT /W4 /WX /utf-8 tools\api_monitor\runtime_probe_fixture.cpp /Fo.codex-build-logs\RuntimeProbe32.obj /Fe.codex-build-logs\RuntimeProbe32.exe /link user32.lib gdi32.lib ole32.lib advapi32.lib bcrypt.lib uuid.lib psapi.lib
if errorlevel 1 exit /b %errorlevel%
popd
endlocal
