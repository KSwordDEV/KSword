#!/usr/bin/env python3
"""Compile the actual Windows Qt pages; optional offline mode performs no account/device I/O."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main() -> None:
    # 输出位置由调用者指定；复用模式拒绝悄悄创建新的构建目录。
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qt-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--compiler', default='g++')
    parser.add_argument('--incremental', action='store_true')
    parser.add_argument('--force-source', action='append', default=[])
    parser.add_argument('--reuse-output', action='store_true')
    parser.add_argument('--offline-only', action='store_true')
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = arguments.output_dir.resolve()
    if arguments.reuse_output:
        if not output.is_dir():
            raise RuntimeError('The requested existing output directory is unavailable')
    else:
        output.mkdir(parents=True, exist_ok=True)
    qt = arguments.qt_dir.resolve()
    source = root / 'Ksword5.1/Ksword5.1'

    # 拆出的后台与报告必须实际参与链接，编辑器也使用生产实现和真实 moc。
    files = [root / 'tools/privilege_workbench_tests.cpp']
    files += [source / 'PrivilegeDock' / name for name in
        ('PrivilegeAccountPages.cpp', 'PrivilegeTokenPages.cpp', 'PrivilegeAccessPage.cpp',
         'PrivilegeAccessBackend.cpp', 'PrivilegeAccessReport.cpp',
         'PrivilegeSnapshotPage.cpp', 'PrivilegeSnapshotModel.cpp')]
    files += [source / name for name in ('Internationalization/LanguageManager.cpp',
        'UI/ThemeStatusRole.cpp', 'UI/ThemeControlGlyphs.cpp', 'UI/CodeEditorWidget.cpp',
        'UI/CodeTextEdit.cpp', 'UI/CodeEditorFileSession.cpp',
        'UI/ReportStructuredView.cpp', 'ksword/process/process_run_as.cpp',
        'MiscDock/DiskEditor/StorageControllerResearchDialog.cpp',
        'ArkDriverClient/ArkStorageControllerClient.cpp')]
    generated = output / 'privilege-review-moc_CodeEditorWidget.cpp'
    subprocess.run([str(qt / 'bin/moc.exe'), str(source / 'UI/CodeEditorWidget.h'),
        '-o', str(generated)], check=True, timeout=60)
    files.append(generated)

    compiler = shutil.which(arguments.compiler) or arguments.compiler
    msvc = Path(compiler).stem.lower() == 'cl'
    includes = [qt / part for part in
        ('include', 'include/QtCore', 'include/QtGui', 'include/QtWidgets', 'include/QtSvg')]
    if msvc:
        # 仅接受明确的 HostX64/x64 编译器和三项宿主架构设置。
        host_path = str(Path(compiler).resolve()).replace('\\', '/').lower()
        if '/hostx64/x64/' not in host_path or any(
            os.environ.get(key, '').upper() != value for key, value in
            (('PreferredToolArchitecture', 'X64'), ('PROCESSOR_ARCHITECTURE', 'AMD64'))):
            raise RuntimeError('MSVC requires HostX64/x64 and explicit x64 architecture settings')
        flags = ['/nologo', '/std:c++latest', '/Zc:__cplusplus', '/permissive-', '/utf-8',
            '/EHsc', '/MD', '/W4', '/WX', '/O1', '/external:W0', '/DNOMINMAX',
            '/DUNICODE', '/D_UNICODE', '/DQT_CORE_LIB', '/DQT_GUI_LIB', '/DQT_WIDGETS_LIB']
        flags += ['/external:I' + str(include) for include in includes]
    else:
        flags = ['-std=c++23', '-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas',
            '-DNOMINMAX', '-DUNICODE', '-D_UNICODE', '-O1']
        for include in includes:
            flags += ['-isystem', str(include)]
    build_environment = dict(os.environ)
    if msvc:
        # 给编译/链接子进程显式设置三项；64 位 Python 启动时可能移除 ARCHITEW6432。
        build_environment.update(PreferredToolArchitecture='x64',
            PROCESSOR_ARCHITECTURE='AMD64', PROCESSOR_ARCHITEW6432='AMD64')
    # 增量模式也观察本包头文件，避免只改类型或断言时复用过期对象。
    headers = list((source / 'PrivilegeDock').glob('PrivilegeAccess*.h'))
    headers += list((source / 'MiscDock/DiskEditor').glob('StorageControllerResearchDialog*.h'))
    headers += [root / 'tools/privilege_access_page_tests.h',
        root / 'tools/privilege_token_pages_tests.h', source / 'UI/CodeEditorWidget.h',
        source / 'UI/CodeTextEdit.h', source / 'UI/CodeEditorFileSession.h']
    latest_header = max(header.stat().st_mtime for header in headers)
    objects = []
    for file in files:
        obj = output / ('privilege-review-' + file.stem + ('.obj' if msvc else '.o'))
        if (not arguments.incremental or file.name in arguments.force_source
                or not obj.exists() or obj.stat().st_mtime < max(file.stat().st_mtime, latest_header)):
            compile_flags = list(flags)
            if msvc and file.name in ('CodeEditorWidget.cpp', 'CodeTextEdit.cpp', 'CodeEditorFileSession.cpp', 'ReportStructuredView.cpp',
                                      'LanguageManager.cpp', 'ThemeControlGlyphs.cpp', 'PrivilegeSnapshotPage.cpp'):
                # 既有公共组件沿用生产 /W3；本次拆分与页面保持 /W4 /WX。
                compile_flags = [flag for flag in compile_flags if flag not in ('/W4', '/WX')]
                compile_flags += ['/W3']
            command = ([compiler, *compile_flags, '/c', str(file), '/Fo' + str(obj)] if msvc
                else [compiler, *compile_flags, '-c', str(file), '-o', str(obj)])
            subprocess.run(command, check=True, timeout=120, env=build_environment)
        objects.append(str(obj))
    executable = output / 'privilege_review_workbench_tests.exe'
    if msvc:
        subprocess.run(['link', '/NOLOGO', *objects, '/OUT:' + str(executable),
            '/LIBPATH:' + str(qt / 'lib'), 'Qt6Widgets.lib', 'Qt6Gui.lib', 'Qt6Core.lib',
            'Qt6Svg.lib', 'advapi32.lib', 'netapi32.lib', 'secur32.lib', 'shell32.lib',
            'userenv.lib', 'authz.lib', 'SetupAPI.lib', 'user32.lib', 'gdi32.lib'],
            check=True, timeout=120, env=build_environment)
    else:
        subprocess.run([compiler, *objects, '-L' + str(qt / 'lib'), '-o', str(executable),
            '-lQt6Widgets', '-lQt6Gui', '-lQt6Core', '-lQt6Svg', '-ladvapi32', '-lnetapi32',
            '-lsecur32', '-lshell32', '-luserenv', '-lauthz', '-lsetupapi'], check=True, timeout=120)

    # 复用模式从仓库既有语言包查找，不新建资源或截图目录。
    screenshots = output
    if not arguments.reuse_output:
        language_dir = output / 'languages'
        language_dir.mkdir(exist_ok=True)
        for language in ('en-US', 'zh-CN'):
            shutil.copy2(source / 'languages' / (language + '.json'), language_dir)
        screenshots = output / 'screenshots'
        screenshots.mkdir(exist_ok=True)
    environment = dict(os.environ, QT_QPA_PLATFORM='offscreen', QT_PLUGIN_PATH=str(qt / 'plugins'))
    environment['PATH'] = str(qt / 'bin') + os.pathsep + environment['PATH']
    command = [str(executable), str(screenshots)]
    if arguments.offline_only:
        command.append('--offline-only')
    subprocess.run(command, check=True, timeout=120, env=environment, cwd=root)


if __name__ == '__main__':
    main()
