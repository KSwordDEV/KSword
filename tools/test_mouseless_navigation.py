"""Compile/run production gesture and focus-cycle logic without creating any GUI.

Also compile the actual Qt navigation translation unit, without linking or running it.
"""
from pathlib import Path
import subprocess
from native_msvc_test_support import find_msvc_developer_environment, qt_root

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'Ksword5.1/Ksword5.1'


def main():
    work = ROOT / 'output/mouseless-navigation-tests'
    work.mkdir(parents=True, exist_ok=True)
    qt = qt_root()
    env = find_msvc_developer_environment()
    script = work / 'build.cmd'
    common = '/nologo /std:c++17 /EHsc /MD /utf-8 /permissive- /Zc:__cplusplus /D NOMINMAX'
    includes = ' '.join(f'/I"{qt / "include" / x}"' for x in ['', 'QtCore', 'QtGui', 'QtWidgets'])
    script.write_text(
        f'@echo off\ncall "{env}" -arch=x64 -host_arch=x64 >nul\n'
        f'cl {common} /W4 /WX "{ROOT / "tools/mouseless_navigation_state_tests.cpp"}" /Fe:state-tests.exe /Fo:state-tests.obj\n'
        'if errorlevel 1 exit /b 1\nstate-tests.exe\nif errorlevel 1 exit /b 1\n'
        f'cl {common} /c {includes} /I"{APP / "include/ads"}" "{APP / "UI/MouselessNavigation.cpp"}" /Fo:navigation.obj\n'
        'exit /b %errorlevel%\n', encoding='utf-8')
    result = subprocess.run(['cmd', '/d', '/c', str(script)], cwd=work,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    print(result.stdout.decode('utf-8', errors='replace'))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
