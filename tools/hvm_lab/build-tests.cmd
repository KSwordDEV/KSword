@echo off
setlocal
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" exit /b 2
call "%VCVARS%" >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_unit_tests.c /Fe:tools\hvm_lab\svm_unit_tests.exe /Fo:tools\hvm_lab\svm_unit_tests.obj
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_unit_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mmu.c KswordARKDriver\src\features\hvm\hvm_svm_nested_shadow.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c /Fe:tools\hvm_lab\svm_nested_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_permissions_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c /Fe:tools\hvm_lab\svm_nested_permissions_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_permissions_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_operand_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_operand.c /Fe:tools\hvm_lab\svm_nested_operand_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_operand_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_entry_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_entry.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c /Fe:tools\hvm_lab\svm_nested_entry_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_entry_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_writeback_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_writeback.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c /Fe:tools\hvm_lab\svm_nested_writeback_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_writeback_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_session_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_session.c KswordARKDriver\src\features\hvm\hvm_svm_nested_entry.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c KswordARKDriver\src\features\hvm\hvm_svm_nested_operand.c KswordARKDriver\src\features\hvm\hvm_svm_nested_writeback.c KswordARKDriver\src\features\hvm\hvm_svm_nested_shadow.c /Fe:tools\hvm_lab\svm_nested_session_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_session_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_route_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_route.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c /Fe:tools\hvm_lab\svm_nested_route_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_route_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 /DKSW_SVM_NESTED_HOST_TEST /Itools\hvm_lab tools\hvm_lab\svm_nested_probe_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_probe.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mmu.c KswordARKDriver\src\features\hvm\hvm_svm_nested_shadow.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c KswordARKDriver\src\features\hvm\hvm_svm_nested_operand.c KswordARKDriver\src\features\hvm\hvm_svm_nested_entry.c KswordARKDriver\src\features\hvm\hvm_svm_nested_writeback.c KswordARKDriver\src\features\hvm\hvm_svm_nested_session.c KswordARKDriver\src\features\hvm\hvm_svm_nested_route.c KswordARKDriver\src\features\hvm\hvm_svm_xstate.c /Fe:tools\hvm_lab\svm_nested_probe_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_probe_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_xstate_tests.c KswordARKDriver\src\features\hvm\hvm_svm_xstate.c /Fe:tools\hvm_lab\svm_xstate_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_xstate_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_event_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_event.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c /Fe:tools\hvm_lab\svm_nested_event_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\svm_nested_event_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_unit_tests\hvm_unit_tests.c /Fe:tools\hvm_lab\vmx_unit_tests.exe /Fo:tools\hvm_lab\vmx_unit_tests.obj
if errorlevel 1 exit /b %errorlevel%
tools\hvm_lab\vmx_unit_tests.exe
exit /b %errorlevel%
