"""Compile native policy validation/codec tests and parse the fixed PowerShell program."""
from pathlib import Path
import base64
import os
import subprocess
from native_msvc_test_support import find_msvc_developer_environment

ROOT=Path(__file__).resolve().parents[1]

def main():
    work=ROOT/'.codex-build-logs/network-policy-tests'
    work.mkdir(parents=True,exist_ok=True)
    developer=find_msvc_developer_environment()
    executable=work/'network_policy_tests.exe'
    command=['cl','/nologo','/std:c++20','/W4','/WX','/utf-8','/EHsc','/MT','/permissive-',
             '/DWIN32_LEAN_AND_MEAN','/DNOMINMAX','/DUNICODE','/D_UNICODE','/I'+str(ROOT),
             str(ROOT/'tools/network_policy_tests.cpp'),
             str(ROOT/'shared/usermode/backend/network/Firewall.cpp'),
             str(ROOT/'shared/usermode/backend/network/NetworkSupport.cpp'),
             '/Fe:'+str(executable),'/Fo:'+str(work)+'\\']
    build=work/'build.cmd'
    build.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\nif errorlevel 1 exit /b 1\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
    subprocess.run(['cmd','/d','/c',str(build)],cwd=work,check=True)
    subprocess.run([str(executable)],cwd=work,check=True)
    driver_executable=work/'network_policy_driver_tests.exe'
    driver_command=[argument.replace(str(ROOT/'tools/network_policy_tests.cpp'),str(ROOT/'tools/network_policy_driver_tests.cpp'))
                    .replace('/Fe:'+str(executable),'/Fe:'+str(driver_executable)) for argument in command]
    driver_command.insert(-2,str(ROOT/'shared/usermode/backend/network/NetworkPolicy.cpp'))
    build.write_text('@echo off\ncall "'+str(developer)+'" -arch=x64 -host_arch=x64 >nul\nif errorlevel 1 exit /b 1\n'+subprocess.list2cmdline(driver_command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
    subprocess.run(['cmd','/d','/c',str(build)],cwd=work,check=True)
    subprocess.run([str(driver_executable)],cwd=work,check=True)
    source=(ROOT/'shared/usermode/backend/network/NetworkPolicy.cpp').read_text(encoding='utf-8')
    program=source.split('constexpr wchar_t qosProgram[]=LR"PS(',1)[1].split(')PS";',1)[0]
    script=work/'fixed-qos-program.ps1'
    script.write_text(program,encoding='utf-8-sig')
    environment=dict(os.environ,KSWORD_QOS_PROGRAM=str(script))
    validation="""$ProgressPreference='SilentlyContinue';$errors=$null;$tokens=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:KSWORD_QOS_PROGRAM,[ref]$tokens,[ref]$errors);if($errors.Count){$errors|ForEach-Object {$_.Message};exit 1};Write-Output 'QOS_FIXED_PROGRAM_AST=PASS provider_mutations=0'"""
    encoded=base64.b64encode(validation.encode('utf-16-le')).decode('ascii')
    powershell=Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    subprocess.run([str(powershell),'-NoProfile','-NonInteractive','-EncodedCommand',encoded],env=environment,cwd=work,check=True,timeout=30)
    subprocess.run([str(powershell),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(ROOT/'tools/test_qos_parameter_builder.ps1')],env=environment,cwd=work,check=True,timeout=30)

if __name__=='__main__':
    main()
