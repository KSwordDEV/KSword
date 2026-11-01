"""Exercise production process selection tracking/restoration with real Qt views and model updates."""
from pathlib import Path
import argparse
import os
import subprocess
from process_activity_tree_tests import declaration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qt', type=Path, default=Path('D:/Software/Qt/6.9.3/msvc2022_64'))
    parser.add_argument('--source-ref', help='Run the same test against an earlier ProcessDock.cpp')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = root / '.codex-build-logs' / ('process-selection-before' if args.source_ref else 'process-selection-tests')
    output.mkdir(parents=True, exist_ok=True)
    relative = 'Ksword5.1/Ksword5.1/ProcessDock/ProcessDock.cpp'
    source = (subprocess.check_output(['git', 'show', f'{args.source_ref}:{relative}'], cwd=root).decode('utf-8-sig')
              if args.source_ref else (root / relative).read_text(encoding='utf-8-sig'))
    signatures = ['const ProcessDock::ProcessTableRow* ProcessDock::processTableRowForViewIndex(',
                  'QModelIndex ProcessDock::processTableViewIndexForIdentityKey(',
                  'std::vector<QModelIndex> ProcessDock::selectedProcessTableRowIndexes(',
                  'void ProcessDock::syncTrackedSelectionFromTable(',
                  'std::string ProcessDock::selectedIdentityKey(',
                  'std::vector<std::string> ProcessDock::currentProcessActivitySelectionKeys(']
    if 'std::string ProcessDock::processTableSelectionKey(' in source:
        signatures.insert(0, 'std::string ProcessDock::processTableSelectionKey(')
    methods = '\n'.join(('static ' if '::processTableSelectionKey(' in signature else '')
                        + declaration(source, signature).replace('ProcessDock::', '') for signature in signatures)
    capture = source[source.index('    const std::string trackedIdentityKeyBeforeRebuild ='):
                     source.index('    // 滚动位置快照：', source.index('void ProcessDock::rebuildTable()'))]
    restore = source[source.index('    bool restoredAnySelection = false;', source.index('void ProcessDock::rebuildTable()')):
                     source.index('    // 根据本轮数据刷新标题栏', source.index('void ProcessDock::rebuildTable()'))]
    fixture = (root / 'tools/process_selection_tests.cpp').read_text(encoding='utf-8')
    fixture = fixture.replace('__METHODS__', methods).replace('__CAPTURE__', capture).replace('__RESTORE__', restore)
    cpp = output / 'fixture.cpp'
    cpp.write_text(fixture, encoding='utf-8')
    developer = next(path for path in [Path('D:/Software/VS/Common7/Tools/VsDevCmd.bat'),
        Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/VsDevCmd.bat')] if path.exists())
    command = ['cl.exe', '/nologo', '/std:c++20', '/Zc:__cplusplus', '/permissive-', '/utf-8', '/EHsc', '/MD',
               '/W4', '/WX', '/O2', '/DNOMINMAX', '/DWIN32_LEAN_AND_MEAN', '/external:W0',
               '/DQT_WIDGETS_LIB', '/DQT_GUI_LIB', '/DQT_CORE_LIB', '/DQT_TESTLIB_LIB',
               '/I' + str(root / 'Ksword5.1/Ksword5.1/UI')]
    command += ['/external:I' + str(args.qt / 'include' / part) for part in ['', 'QtCore', 'QtGui', 'QtWidgets', 'QtTest']]
    command += [str(cpp), str(root / 'Ksword5.1/Ksword5.1/Internationalization/LanguageManager.cpp'),
                '/Fo' + str(output) + '\\', '/Fe' + str(output / 'test.exe'), '/link',
                '/LIBPATH:' + str(args.qt / 'lib'), 'Qt6Widgets.lib', 'Qt6Gui.lib', 'Qt6Core.lib',
                'Qt6Test.lib', 'user32.lib', 'advapi32.lib']
    build = output / 'build.cmd'
    build.write_text('@echo off\ncall "' + str(developer) + '" -arch=x64 -host_arch=x64 >nul\n'
                     + subprocess.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding='utf-8')
    subprocess.run(['cmd.exe', '/d', '/c', str(build)], cwd=output, check=True)
    environment = dict(os.environ, QT_QPA_PLATFORM='offscreen', QT_PLUGIN_PATH=str(args.qt / 'plugins'))
    environment['PATH'] = str(args.qt / 'bin') + os.pathsep + environment.get('PATH', '')
    subprocess.run([str(output / 'test.exe')], env=environment, check=True)


if __name__ == '__main__':
    main()
