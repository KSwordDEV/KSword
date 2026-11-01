"""Exercise production module/volume treemap projections with committed value snapshots.

Only the host windows, translation service and source-table facade are adapters;
the production projection methods and raw metric-node type are compiled unchanged.
This does not sample devices, invoke process actions, or validate MainWindow visuals.
"""
from pathlib import Path
import argparse
import os
import subprocess
from process_activity_tree_tests import declaration


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--qt', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    app = root / 'Ksword5.1/Ksword5.1'
    work = root / '.codex-build-logs/metric-area-adapters-tests'
    work.mkdir(parents=True, exist_ok=True)
    module = (app / 'ProcessDock/ProcessDetailWindow.Module.cpp').read_text(encoding='utf-8-sig')
    volume = (app / 'HardwareDock/DiskMonitorStoragePanel.cpp').read_text(encoding='utf-8-sig')
    fixture = (root / 'tools/metric_area_adapters_tests.cpp').read_text(encoding='utf-8')
    fixture = fixture.replace('__MODULE_PROJECTION__', declaration(module, 'void ProcessDetailWindow::refreshModuleAreaWindow()'))
    fixture = fixture.replace('__VOLUME_PROJECTION__', declaration(volume, 'void DiskMonitorStoragePanel::refreshAreaWindow()'))
    fixture = fixture.replace('__FORMAT_BYTES__', declaration(volume, 'QString DiskMonitorStoragePanel::formatBytes('))
    fixture = fixture.replace('__FORMAT_RATE__', declaration(volume, 'QString DiskMonitorStoragePanel::formatRate('))
    (work / 'fixture.cpp').write_text(fixture, encoding='utf-8')
    qt = args.qt.resolve()
    developer = Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/VsDevCmd.bat')
    if not developer.exists():
        developer = Path('D:/Software/VS/Common7/Tools/VsDevCmd.bat')
    command = ['cl', '/nologo', '/std:c++20', '/Zc:__cplusplus', '/permissive-', '/utf-8', '/EHsc', '/MD', '/W4', '/WX', '/DNOMINMAX',
               '/I' + str(app / 'UI'), *('/external:I' + str(qt / 'include' / module) for module in ('', 'QtCore', 'QtGui', 'QtWidgets')),
               '/external:W0', str(work / 'fixture.cpp'), '/Fe:' + str(work / 'test.exe'), '/Fo:' + str(work) + '\\',
               '/link', '/LIBPATH:' + str(qt / 'lib'), 'Qt6Core.lib', 'Qt6Gui.lib', 'Qt6Widgets.lib']
    build = work / 'build.cmd'
    build.write_text('@echo off\ncall "' + str(developer) + '" -arch=x64 -host_arch=x64 >nul\n'
                     + subprocess.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding='utf-8')
    subprocess.run(['cmd', '/d', '/c', str(build)], cwd=work, check=True)
    environment = dict(os.environ)
    environment['PATH'] = str(qt / 'bin') + os.pathsep + environment.get('PATH', '')
    subprocess.run([str(work / 'test.exe')], cwd=work, env=environment, check=True)


if __name__ == '__main__':
    main()
