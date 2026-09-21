@echo off
setlocal
set "KSW_RUN_TESTS=1"
if not "%~2"=="" exit /b 2
if not "%~1"=="" if /i not "%~1"=="--build-only" exit /b 2
if /i "%~1"=="--build-only" set "KSW_RUN_TESTS=0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" exit /b 2
call "%VCVARS%" >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_unit_tests.c /Fe:tools\hvm_lab\svm_unit_tests.exe /Fo:tools\hvm_lab\svm_unit_tests.obj
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_unit_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mmu.c KswordARKDriver\src\features\hvm\hvm_svm_nested_shadow.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c /Fe:tools\hvm_lab\svm_nested_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_permissions_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c /Fe:tools\hvm_lab\svm_nested_permissions_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_permissions_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_operand_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_operand.c /Fe:tools\hvm_lab\svm_nested_operand_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_operand_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_entry_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_entry.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c /Fe:tools\hvm_lab\svm_nested_entry_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_entry_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_writeback_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_writeback.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c /Fe:tools\hvm_lab\svm_nested_writeback_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_writeback_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_session_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_session.c KswordARKDriver\src\features\hvm\hvm_svm_nested_tlb.c KswordARKDriver\src\features\hvm\hvm_svm_nested_transfer.c KswordARKDriver\src\features\hvm\hvm_svm_nested_owner.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mailbox.c KswordARKDriver\src\features\hvm\hvm_svm_nested_entry.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c KswordARKDriver\src\features\hvm\hvm_svm_nested_operand.c KswordARKDriver\src\features\hvm\hvm_svm_nested_writeback.c KswordARKDriver\src\features\hvm\hvm_svm_nested_shadow.c KswordARKDriver\src\features\hvm\hvm_svm_nested_pending.c /Fe:tools\hvm_lab\svm_nested_session_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_session_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_route_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_route.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c /Fe:tools\hvm_lab\svm_nested_route_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_route_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 /DKSW_SVM_NESTED_HOST_TEST /Itools\hvm_lab tools\hvm_lab\svm_nested_probe_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_probe.c KswordARKDriver\src\features\hvm\hvm_svm_nested_register.c KswordARKDriver\src\features\hvm\hvm_svm_nested_cpuid.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mmu.c KswordARKDriver\src\features\hvm\hvm_svm_nested_shadow.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c KswordARKDriver\src\features\hvm\hvm_svm_nested_operand.c KswordARKDriver\src\features\hvm\hvm_svm_nested_entry.c KswordARKDriver\src\features\hvm\hvm_svm_nested_writeback.c KswordARKDriver\src\features\hvm\hvm_svm_nested_session.c KswordARKDriver\src\features\hvm\hvm_svm_nested_tlb.c KswordARKDriver\src\features\hvm\hvm_svm_nested_transfer.c KswordARKDriver\src\features\hvm\hvm_svm_nested_owner.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mailbox.c KswordARKDriver\src\features\hvm\hvm_svm_nested_route.c KswordARKDriver\src\features\hvm\hvm_svm_xstate.c KswordARKDriver\src\features\hvm\hvm_svm_nested_pending.c /Fe:tools\hvm_lab\svm_nested_probe_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_probe_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_xstate_tests.c KswordARKDriver\src\features\hvm\hvm_svm_xstate.c /Fe:tools\hvm_lab\svm_xstate_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_xstate_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_event_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_event.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c /Fe:tools\hvm_lab\svm_nested_event_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_event_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_owner_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_owner.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mailbox.c KswordARKDriver\src\features\hvm\hvm_svm_nested_pending.c /Fe:tools\hvm_lab\svm_nested_owner_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_owner_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_unit_tests\hvm_unit_tests.c /Fe:tools\hvm_lab\vmx_unit_tests.exe /Fo:tools\hvm_lab\vmx_unit_tests.obj
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\vmx_unit_tests.exe
if errorlevel 1 exit /b %errorlevel%

cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_pending_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_pending.c /Fe:tools\hvm_lab\svm_nested_pending_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_pending_tests.exe
if errorlevel 1 exit /b %errorlevel%

cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_interrupt_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_interrupt.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c /Fe:tools\hvm_lab\svm_nested_interrupt_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_interrupt_tests.exe
if errorlevel 1 exit /b %errorlevel%

cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_fetch_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_fetch.c /Fe:tools\hvm_lab\svm_nested_fetch_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_fetch_tests.exe
if errorlevel 1 exit /b %errorlevel%

cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_window_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_window.c /Fe:tools\hvm_lab\svm_nested_window_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_window_tests.exe
if errorlevel 1 exit /b %errorlevel%

cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_reflect_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_reflect.c KswordARKDriver\src\features\hvm\hvm_svm_nested_pending.c /Fe:tools\hvm_lab\svm_nested_reflect_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_reflect_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_machine_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_iret.c KswordARKDriver\src\features\hvm\hvm_svm_nested_machine.c KswordARKDriver\src\features\hvm\hvm_svm_nested_execute.c KswordARKDriver\src\features\hvm\hvm_svm_nested_reflect.c KswordARKDriver\src\features\hvm\hvm_svm_nested_interrupt.c KswordARKDriver\src\features\hvm\hvm_svm_nested_window.c KswordARKDriver\src\features\hvm\hvm_svm_nested_pending.c KswordARKDriver\src\features\hvm\hvm_svm_nested_fetch.c KswordARKDriver\src\features\hvm\hvm_svm_nested_register.c KswordARKDriver\src\features\hvm\hvm_svm_nested_cpuid.c KswordARKDriver\src\features\hvm\hvm_svm_nested_event.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mmu.c KswordARKDriver\src\features\hvm\hvm_svm_nested_shadow.c KswordARKDriver\src\features\hvm\hvm_svm_nested_session.c KswordARKDriver\src\features\hvm\hvm_svm_nested_tlb.c KswordARKDriver\src\features\hvm\hvm_svm_nested_transfer.c KswordARKDriver\src\features\hvm\hvm_svm_nested_owner.c KswordARKDriver\src\features\hvm\hvm_svm_nested_mailbox.c KswordARKDriver\src\features\hvm\hvm_svm_nested_entry.c KswordARKDriver\src\features\hvm\hvm_svm_nested_state.c KswordARKDriver\src\features\hvm\hvm_svm_nested_permissions.c KswordARKDriver\src\features\hvm\hvm_svm_nested_operand.c KswordARKDriver\src\features\hvm\hvm_svm_nested_writeback.c KswordARKDriver\src\features\hvm\hvm_svm_nested_route.c KswordARKDriver\src\features\hvm\hvm_svm_xstate.c /Fe:tools\hvm_lab\svm_nested_machine_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_machine_tests.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /W4 /WX /O2 tools\hvm_lab\svm_nested_iret_tests.c KswordARKDriver\src\features\hvm\hvm_svm_nested_iret.c /Fe:tools\hvm_lab\svm_nested_iret_tests.exe /Fo:tools\hvm_lab\
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="1" tools\hvm_lab\svm_nested_iret_tests.exe
if errorlevel 1 exit /b %errorlevel%
if "%KSW_RUN_TESTS%"=="0" echo TEST_EXECUTION=NOT_RUN
exit /b 0
