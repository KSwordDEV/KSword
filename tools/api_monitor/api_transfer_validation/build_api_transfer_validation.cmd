@echo off
rem API transfer-parameter producer validation build script.
rem Fixture + Helper (x64/x86) and both Agents (Release). BelowNormal priority,
rem 64-bit MSBuild, HostX64 tools. All steps are run via "start /b /belownormal".
setlocal EnableExtensions
cd /d "%~dp0..\..\.." || exit /b 1

set "MSBUILD=D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe"
if not exist "%MSBUILD%" set "MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"
if not exist "%MSBUILD%" (
  echo ERROR: 64-bit MSBuild not found.
  exit /b 2
)
echo HostX64 MSBuild = %MSBUILD%

set "LOGDIR=%~dp0..\..\..\.codex-build-logs\api-transfer-producer"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

echo Fixture IntDir  = E:\Projects\Ksword5.1\tools\api_monitor\api_transfer_validation\obj\{Win32^|x64}\Release\
echo Fixture OutDir  = E:\Projects\Ksword5.1\Ksword5.1\x64\Release\ [ApiTransferValidationFixture64.exe^|ApiTransferValidationFixture32.exe]
echo Agent x64 IntDir= E:\Projects\Ksword5.1\APIMonitor_x64\x64\Release\
echo Agent x86 IntDir= E:\Projects\Ksword5.1\APIMonitor_x86\obj\Release\
echo Agent OutDir    = E:\Projects\Ksword5.1\Ksword5.1\x64\Release\

set "TOOLS=/p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64"

set STEP=%1
if "%STEP%"=="" set STEP=all

goto :%STEP% 2>nul || (echo ERROR: unknown step "%STEP%" & exit /b 3)

:fixture
echo === [fixture x64] ===
start "fixture-x64" /b /wait /belownormal "%MSBUILD%" "tools\api_monitor\api_transfer_validation\ApiTransferValidationFixture.vcxproj" /t:Build /p:Configuration=Release /p:Platform=x64 %TOOLS% /m:1 /v:minimal /nologo > "%LOGDIR%\fixture-x64-build.log" 2>&1
set RC1=%ERRORLEVEL%
findstr /i /c:"error" /c:"warning" "%LOGDIR%\fixture-x64-build.log"
echo FIXTURE_X64_EXIT=%RC1%
echo === [fixture x86] ===
start "fixture-x86" /b /wait /belownormal "%MSBUILD%" "tools\api_monitor\api_transfer_validation\ApiTransferValidationFixture.vcxproj" /t:Build /p:Configuration=Release /p:Platform=Win32 %TOOLS% /m:1 /v:minimal /nologo > "%LOGDIR%\fixture-x86-build.log" 2>&1
set RC2=%ERRORLEVEL%
findstr /i /c:"error" /c:"warning" "%LOGDIR%\fixture-x86-build.log"
echo FIXTURE_X86_EXIT=%RC2%
if "%RC1%" NEQ "0" exit /b %RC1%
if "%RC2%" NEQ "0" exit /b %RC2%
goto :eof

:helper
echo === [helper x64] ===
start "helper-x64" /b /wait /belownormal "%MSBUILD%" "tools\api_monitor\api_transfer_validation\ApiTransferValidationHelper.vcxproj" /t:Build /p:Configuration=Release /p:Platform=x64 %TOOLS% /m:1 /v:minimal /nologo > "%LOGDIR%\helper-x64-build.log" 2>&1
set RC3=%ERRORLEVEL%
findstr /i /c:"error" /c:"warning" "%LOGDIR%\helper-x64-build.log"
echo HELPER_X64_EXIT=%RC3%
echo === [helper x86] ===
start "helper-x86" /b /wait /belownormal "%MSBUILD%" "tools\api_monitor\api_transfer_validation\ApiTransferValidationHelper.vcxproj" /t:Build /p:Configuration=Release /p:Platform=Win32 %TOOLS% /m:1 /v:minimal /nologo > "%LOGDIR%\helper-x86-build.log" 2>&1
set RC4=%ERRORLEVEL%
findstr /i /c:"error" /c:"warning" "%LOGDIR%\helper-x86-build.log"
echo HELPER_X86_EXIT=%RC4%
if "%RC3%" NEQ "0" exit /b %RC3%
if "%RC4%" NEQ "0" exit /b %RC4%
goto :eof

:agents
echo === [agent x64] ===
start "agent-x64" /b /wait /belownormal "%MSBUILD%" "APIMonitor_x64\APIMonitor_x64.vcxproj" /t:Build /p:Configuration=Release /p:Platform=x64 %TOOLS% /m:1 /v:minimal /nologo > "%LOGDIR%\agent-x64-build.log" 2>&1
set RC5=%ERRORLEVEL%
findstr /i /c:"error" /c:"warning" "%LOGDIR%\agent-x64-build.log"
echo AGENT_X64_EXIT=%RC5%
echo === [agent x86] ===
start "agent-x86" /b /wait /belownormal "%MSBUILD%" "APIMonitor_x86\APIMonitor_x86.vcxproj" /t:Build /p:Configuration=Release /p:Platform=Win32 %TOOLS% /m:1 /v:minimal /nologo > "%LOGDIR%\agent-x86-build.log" 2>&1
set RC6=%ERRORLEVEL%
findstr /i /c:"error" /c:"warning" "%LOGDIR%\agent-x86-build.log"
echo AGENT_X86_EXIT=%RC6%
if "%RC5%" NEQ "0" exit /b %RC5%
if "%RC6%" NEQ "0" exit /b %RC6%
goto :eof

:all
call :fixture || exit /b %ERRORLEVEL%
call :helper || exit /b %ERRORLEVEL%
call :agents || exit /b %ERRORLEVEL%
echo ALL_STEPS_DONE
goto :eof
