"""Verify curated reference prototypes against the installed Windows SDK.

Each exact function-pointer type is compiled for both x86 and x64 using MSVC.
Only after both compiles pass is a new, separate catalog file written. These
assertions validate the declaration ABI, not capture direction or semantics.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

SDK_VERSION = '10.0.26100.0'
PROTOTYPES = {
    'ClientToScreen': ('BOOL', ['HWND', 'LPPOINT']),
    'DestroyWindow': ('BOOL', ['HWND']),
    'DispatchMessageA': ('LRESULT', ['const MSG*']),
    'DispatchMessageW': ('LRESULT', ['const MSG*']),
    'EnableWindow': ('BOOL', ['HWND', 'BOOL']),
    'GetActiveWindow': ('HWND', []),
    'GetAsyncKeyState': ('SHORT', ['int']),
    'GetCapture': ('HWND', []),
    'GetClassNameA': ('int', ['HWND', 'LPSTR', 'int']),
    'GetClassNameW': ('int', ['HWND', 'LPWSTR', 'int']),
    'GetClientRect': ('BOOL', ['HWND', 'LPRECT']),
    'GetCursorPos': ('BOOL', ['LPPOINT']),
    'GetDesktopWindow': ('HWND', []),
    'GetDlgCtrlID': ('int', ['HWND']),
    'GetDoubleClickTime': ('UINT', []),
    'GetFocus': ('HWND', []),
    'GetKeyboardState': ('BOOL', ['PBYTE']),
    'GetMessageA': ('BOOL', ['LPMSG', 'HWND', 'UINT', 'UINT']),
    'GetMessagePos': ('DWORD', []),
    'GetMessageTime': ('LONG', []),
    'GetMessageW': ('BOOL', ['LPMSG', 'HWND', 'UINT', 'UINT']),
    'GetParent': ('HWND', ['HWND']),
    'GetSystemMetrics': ('int', ['int']),
    'GetWindow': ('HWND', ['HWND', 'UINT']),
    'GetWindowRect': ('BOOL', ['HWND', 'LPRECT']),
    'GetWindowTextA': ('int', ['HWND', 'LPSTR', 'int']),
    'GetWindowTextW': ('int', ['HWND', 'LPWSTR', 'int']),
    'InvalidateRect': ('BOOL', ['HWND', 'const RECT*', 'BOOL']),
    'IsChild': ('BOOL', ['HWND', 'HWND']),
    'IsIconic': ('BOOL', ['HWND']),
    'IsWindow': ('BOOL', ['HWND']),
    'IsWindowUnicode': ('BOOL', ['HWND']),
    'IsWindowVisible': ('BOOL', ['HWND']),
    'IsZoomed': ('BOOL', ['HWND']),
    'MapWindowPoints': ('int', ['HWND', 'HWND', 'LPPOINT', 'UINT']),
    'PeekMessageA': ('BOOL', ['LPMSG', 'HWND', 'UINT', 'UINT', 'UINT']),
    'PeekMessageW': ('BOOL', ['LPMSG', 'HWND', 'UINT', 'UINT', 'UINT']),
    'PostMessageA': ('BOOL', ['HWND', 'UINT', 'WPARAM', 'LPARAM']),
    'PostMessageW': ('BOOL', ['HWND', 'UINT', 'WPARAM', 'LPARAM']),
    'ReleaseCapture': ('BOOL', []),
    'ScreenToClient': ('BOOL', ['HWND', 'LPPOINT']),
    'SendMessageA': ('LRESULT', ['HWND', 'UINT', 'WPARAM', 'LPARAM']),
    'SendMessageW': ('LRESULT', ['HWND', 'UINT', 'WPARAM', 'LPARAM']),
    'SetActiveWindow': ('HWND', ['HWND']),
    'SetCapture': ('HWND', ['HWND']),
    'SetCursorPos': ('BOOL', ['int', 'int']),
    'SetFocus': ('HWND', ['HWND']),
    'SetWindowTextA': ('BOOL', ['HWND', 'LPCSTR']),
    'SetWindowTextW': ('BOOL', ['HWND', 'LPCWSTR']),
    'ShowWindow': ('BOOL', ['HWND', 'int']),
    'TranslateMessage': ('BOOL', ['const MSG*']),
    'UpdateWindow': ('BOOL', ['HWND']),
    'ValidateRect': ('BOOL', ['HWND', 'const RECT*']),
}


def source_text():
    lines = ['#include <windows.h>', '#include <type_traits>']
    for name, (ret, params) in sorted(PROTOTYPES.items()):
        lines.append(f'static_assert(std::is_same_v<decltype(&::{name}), {ret} (WINAPI*)({", ".join(params)})>, "{name}");')
    return '\n'.join(lines) + '\n'


def verify(devcmd, sdk_header):
    if not devcmd.is_file() or not sdk_header.is_file():
        raise ValueError('VS developer command or SDK winuser.h not found')
    with tempfile.TemporaryDirectory(prefix='ksword_api_sdk_abi_') as temp:
        source = Path(temp) / 'verify.cpp'
        source.write_text(source_text(), encoding='utf-8')
        for arch in ('x86', 'x64'):
            command = (f'call "{devcmd}" -arch={arch} -host_arch=x64 -winsdk={SDK_VERSION} >nul '
                       f'&& cl /nologo /std:c++20 /EHsc /Zs "{source}"')
            subprocess.run('cmd /d /s /c "' + command + '"', check=True)
    return hashlib.sha256(sdk_header.read_bytes()).hexdigest()


def apply_verified(catalog, header_hash):
    refs = catalog['reference_signatures']
    if refs['status'] != 'unverified':
        raise ValueError('invalid reference status')
    rows = {(r[0].casefold(), r[1]): r for r in refs['entries']}
    entries = []
    for name, (ret, params) in sorted(PROTOTYPES.items()):
        row = rows.get(('user32.dll', name))
        if row is None or len(row[4]) != len(params):
            raise ValueError('missing or incompatible source identity: ' + name)
        entries.append(['User32.dll', name, ret, 'WINAPI', params])
    refs['verified_abis'] = {'sdk': SDK_VERSION, 'header': 'um/winuser.h',
                              'header_sha256': header_hash,
                              'architectures': ['x86', 'x64'], 'entries': entries}
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--devcmd', type=Path, required=True)
    parser.add_argument('--sdk-include', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('output must be a new file')
    digest = verify(args.devcmd, args.sdk_include / 'um/winuser.h')
    catalog = apply_verified(json.loads(args.catalog.read_text(encoding='utf-8-sig')), digest)
    refs = catalog.pop('reference_signatures')
    base = json.dumps(catalog, ensure_ascii=False, indent=2)
    data = base[:-2] + ',\n  "reference_signatures": ' + json.dumps(refs, ensure_ascii=False, separators=(',', ':')) + '\n}\n'
    with args.output.open('x', encoding='utf-8', newline='\n') as out:
        out.write(data)
    print(f'SDK {SDK_VERSION} winuser.h sha256={digest}; x86/x64 verified={len(PROTOTYPES)}')


if __name__ == '__main__':
    main()
