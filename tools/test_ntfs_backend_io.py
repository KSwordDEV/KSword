#!/usr/bin/env python3
"""Run the complete production NTFS backend with deterministic volume I/O.

Only the two Windows I/O includes are replaced by the fixture's API adapters.
The production build, mapping, scan, parser, journal and snapshot paths are whole
translation units. --source-ref HEAD is an old-backend negative control. Native
NTFS behavior is covered separately by test_native_ntfs_index.py on Windows.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from test_theme_first_frame_ui import qt_include

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'Ksword5.1/Ksword5.1/FileDock'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qt-root', type=Path, default=Path('/usr'))
    parser.add_argument('--cxx', default=shutil.which('cl' if os.name == 'nt' else 'c++'))
    parser.add_argument('--source-ref')
    parser.add_argument('--record-source-ref', help='Old record parser for the fixed-up cache-tail negative control')
    parser.add_argument('--scenario', choices=('all', 'metadata', 'attribute-list', 'record-recovery', 'continuation'), default='all')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if not args.cxx:
        parser.error('Native C++ compiler required')
    include = qt_include(args.qt_root)
    relative = 'Ksword5.1/Ksword5.1/FileDock/NtfsFastIndex.cpp'
    production = (subprocess.check_output(['git', 'show', f'{args.source_ref}:{relative}'], cwd=ROOT).decode('utf-8-sig')
                  if args.source_ref else (ROOT / relative).read_text(encoding='utf-8-sig'))
    for marker in ('#include <Windows.h>', '#include <winioctl.h>'):
        if production.count(marker) != 1:
            raise SystemExit('Expected one Windows I/O include: ' + marker)
        production = production.replace(marker, '')
    fixture = (ROOT / 'tools/ntfs_backend_io_test.cpp').read_text(encoding='utf-8')
    marker = '// KSWORD_WHOLE_PRODUCTION_BACKEND'
    if fixture.count(marker) != 1:
        raise SystemExit('Expected one whole-backend marker')
    with tempfile.TemporaryDirectory(prefix='ksword-ntfs-backend-') as temporary:
        work = Path(temporary)
        source = work / 'test.cpp'
        source.write_text(fixture.replace(marker, production), encoding='utf-8')
        binary = work / ('ntfs_backend.exe' if os.name == 'nt' else 'ntfs_backend')
        record_source = APP / 'NtfsIndexRecord.cpp'
        if args.record_source_ref:
            record_source = work / 'NtfsIndexRecord.cpp'
            record_source.write_bytes(subprocess.check_output(['git', 'show',
                f'{args.record_source_ref}:Ksword5.1/Ksword5.1/FileDock/NtfsIndexRecord.cpp'], cwd=ROOT))
        paths = [APP, include, include / 'QtCore']
        if os.name == 'nt':
            if args.sanitize:
                parser.error('--sanitize requires GNU/Clang')
            command = [args.cxx, '/nologo', '/std:c++20', '/permissive-', '/Zc:__cplusplus', '/utf-8', '/EHsc', '/MD', '/DNOMINMAX',
                       *('/I' + str(p) for p in paths), str(source), str(record_source), '/Fe:' + str(binary),
                       '/link', '/LIBPATH:' + str(args.qt_root / 'lib'), 'Qt6Core.lib']
        else:
            libraries = [args.qt_root / 'lib', *sorted((args.qt_root / 'lib').glob('*-linux-gnu'))]
            command = [args.cxx, '-std=c++20', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC',
                       *('-I' + str(p) for p in paths), *('-L' + str(p) for p in libraries if p.is_dir()),
                       str(source), str(record_source), '-l:libQt6Core.so.6', '-o', str(binary)]
            if args.sanitize:
                command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, cwd=work, check=True, timeout=120)
        environment = dict(os.environ)
        if os.name == 'nt':
            environment['PATH'] = str(args.qt_root / 'bin') + os.pathsep + environment.get('PATH', '')
        else:
            environment['LD_LIBRARY_PATH'] = os.pathsep.join(str(p) for p in libraries if p.is_dir()) + os.pathsep + environment.get('LD_LIBRARY_PATH', '')
            if args.sanitize:
                environment['ASAN_OPTIONS'] = 'detect_leaks=0'
        subprocess.run([str(binary), args.scenario], check=True, env=environment, timeout=30)


if __name__ == '__main__':
    main()
