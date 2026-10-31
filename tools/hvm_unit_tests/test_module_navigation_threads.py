"""Run complete production navigation/attach methods and thread attribution with endpoint substitutes.

Uses real QtCore QPointer lifetime handling, without GUI, driver IOCTLs, or process attachment.
"""
from pathlib import Path
import os
import subprocess
import sys

sys.dont_write_bytecode = True
from test_memory_bookmarks import extract_method

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / '.codex-tmp/module-navigation-tests'
OUTPUT.mkdir(parents=True, exist_ok=True)
APP = ROOT / 'Ksword5.1/Ksword5.1'
region = (APP / 'MemoryDock/MemoryDock.ProcessRegion.cpp').read_text(encoding='utf-8-sig')
entry = (APP / 'MemoryDock/MemoryDock.WorkbenchEntry.cpp').read_text(encoding='utf-8-sig')
process = (APP / 'ksword/process/process.cpp').read_text(encoding='utf-8-sig')
start = process.index('    struct ModuleThreadStart\n')
end = process.index('    };', start) + len('    };')
production = '\n'.join((
    extract_method(entry, 'MemoryDock::jumpToModuleBase'),
    extract_method(entry, 'MemoryDock::probeModuleDriverJump'),
    extract_method(region, 'MemoryDock::attachToProcess'),
    extract_method(region, 'MemoryDock::attachToProcessAfterLeave'),
    process[start:end],
    extract_method(process, 'BuildThreadIdSummaryText'),
    extract_method(process, 'AssignModuleThreads'),
))
(OUTPUT / 'module_navigation_production.inc').write_text(production, encoding='utf-8')
qt = ROOT / '.deps/Qt/6.9.3/msvc2022_64'
if not (qt / 'lib/Qt6Core.lib').exists():
    qt = Path('D:/Software/Qt/6.9.3/msvc2022_64')
vcvars = Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Auxiliary/Build/vcvars64.bat')
if not vcvars.exists():
    vcvars = Path('D:/Software/VS/VC/Auxiliary/Build/vcvars64.bat')
exe = OUTPUT / 'module-navigation-tests.exe'
command = ['cl', '/nologo', '/std:c++20', '/Zc:__cplusplus', '/utf-8', '/EHsc', '/MD', '/W4', '/WX',
           '/DQT_CORE_LIB', '/DNOMINMAX', '/external:W0', f'/external:I{qt / "include"}',
           f'/external:I{qt / "include/QtCore"}', f'/I{OUTPUT}',
           str(ROOT / 'tools/tests/module_navigation_threads_tests.cpp'), f'/Fo{OUTPUT}{os.sep}',
           f'/Fe{exe}', '/link', f'/LIBPATH:{qt / "lib"}', 'Qt6Core.lib']
batch = OUTPUT / 'build.cmd'
batch.write_text('@echo off\ncall ' + subprocess.list2cmdline([str(vcvars)]) + ' >nul\n'
                 'if errorlevel 1 exit /b %errorlevel%\n' + subprocess.list2cmdline(command)
                 + '\nexit /b %errorlevel%\n', encoding='utf-8')
subprocess.run(['cmd', '/c', str(batch)], cwd=ROOT, check=True)
env = os.environ.copy()
env['PATH'] = str(qt / 'bin') + os.pathsep + env['PATH']
subprocess.run([str(exe)], cwd=ROOT, env=env, check=True)
