"""Native rate arithmetic and fake-ETW lifecycle/decoding contracts."""
from pathlib import Path
import subprocess
from native_msvc_test_support import find_msvc_developer_environment

ROOT = Path(__file__).resolve().parents[1]


def main():
    work = ROOT / '.codex-build-logs/process-network-contracts'
    work.mkdir(parents=True, exist_ok=True)
    developer = find_msvc_developer_environment()
    cases = [
        ('rate', [ROOT / 'tools/process_network_rate_tests.cpp'], []),
        ('lifecycle', [ROOT / 'tools/performance/process_etw_lifecycle_tests.cpp'], []),
        ('decoder', [ROOT / 'Ksword5.1/Ksword5.1/ksword/network/network_process_etw_monitor.cpp',
                     ROOT / 'tools/native_process_network_etw_tests.cpp'],
         ['/FI' + str(ROOT / 'tools/native_process_network_etw_fake_api.h')]),
    ]
    for name, sources, extra in cases:
        output = work / (name + '.exe')
        command = ['cl', '/nologo', '/std:c++20', '/permissive-', '/EHsc', '/W4', '/WX', '/utf-8', '/MT',
                   '/DWIN32_LEAN_AND_MEAN', '/DNOMINMAX', '/I' + str(ROOT), *extra,
                   *(str(source) for source in sources), '/Fo:' + str(work) + '\\', '/Fe:' + str(output),
                   '/link', 'Advapi32.lib']
        script = work / (name + '.cmd')
        script.write_text('@echo off\ncall "' + str(developer) + '" -arch=x64 -host_arch=x64 >nul\n'
                          + 'if errorlevel 1 exit /b 1\n' + subprocess.list2cmdline(command)
                          + '\nexit /b %errorlevel%\n', encoding='utf-8')
        subprocess.run(['cmd', '/d', '/c', str(script)], cwd=work, check=True, timeout=120)
        subprocess.run([str(output)], cwd=work, check=True, timeout=30)
    print('PROCESS_NETWORK_CONTRACTS=PASS REAL_PROVIDER_OR_POLICY_IO=0')


if __name__ == '__main__':
    main()
