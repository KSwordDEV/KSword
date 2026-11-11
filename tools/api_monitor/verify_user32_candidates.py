"""Compile-check safe User32 reference prototypes against a pinned Windows SDK.

The source catalog is never modified. A candidate is accepted only when the
exact reference prototype compiles against the SDK on both x86 and x64.
Unrecognized types, macros without real declarations, and failures remain
unverified. This establishes types and calling convention, not direction,
buffer semantics, API availability or permission to redistribute data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SDK_VERSION = '10.0.26100.0'
# Each type has a known direct return and/or x86 parameter footprint in
# WinAPISignatureCatalog; do not infer aliases or structure layouts.
SAFE = frozenset('BOOL BOOLEAN BYTE WORD SHORT WPARAM LPMSG LPPOINT LPRECT DWORD LONG ULONG USHORT UCHAR INT UINT int long SIZE_T DWORD_PTR ULONG_PTR LPARAM HANDLE HMODULE HKEY HWND HINSTANCE LPVOID LPCVOID LPSTR LPCSTR LPWSTR LPCWSTR LPDWORD LPBYTE PVOID PULONG LRESULT HRESULT VOID void'.split())
IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z_0-9]*$')


def choose(catalog):
    refs = catalog['reference_signatures']
    if refs.get('schema_version') != 1 or refs.get('status') != 'unverified':
        raise ValueError('unsupported reference catalog')
    verified = refs['verified_abis']
    if verified.get('sdk') != SDK_VERSION or verified.get('architectures') != ['x86', 'x64']:
        raise ValueError('existing verified SDK/architectures mismatch')
    existing = {(row[0].casefold(), row[1]) for row in verified['entries']}
    seen, chosen = set(), []
    for row in refs['entries']:
        if not isinstance(row, list) or len(row) != 6:
            raise ValueError('invalid reference row')
        module, name, convention, ret, params, _ = row
        if not isinstance(module, str) or not isinstance(name, str) or not isinstance(params, list):
            raise ValueError('invalid reference identity')
        key = (module.casefold(), name)
        if key in seen:
            raise ValueError('duplicate reference identity')
        seen.add(key)
        if (key in existing or key[0] != 'user32.dll' or not IDENTIFIER.fullmatch(name)
                or convention != 'STDCALL' or ret not in SAFE or len(params) > 8):
            continue
        if any(not isinstance(p, list) or len(p) != 2 or p[1] not in SAFE for p in params):
            continue
        chosen.append((name, ret, tuple(p[1] for p in params)))
    return sorted(chosen)


def source(rows):
    lines = ['#include <windows.h>', '#include <type_traits>']
    for name, ret, params in rows:
        # Suppress generic A/W aliases; only an actual exact SDK name proves a
        # declaration with this name, never a preprocessor substitution.
        lines += [f'#ifdef {name}', f'#undef {name}', '#endif',
                  f'static_assert(std::is_same_v<decltype(&::{name}), {ret} (WINAPI*)({", ".join(params)})>, "{name}");']
    return '\n'.join(lines) + '\n'


def developer_environment(devcmd, arch):
    cmd = f'call "{devcmd}" -arch={arch} -host_arch=x64 -winsdk={SDK_VERSION} >nul && set'
    result = subprocess.run('cmd.exe /d /s /c "' + cmd + '"', text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    env = os.environ.copy()
    for line in result.stdout.splitlines():
        if '=' in line and not line.startswith('='):
            key, value = line.split('=', 1)
            env[key.upper()] = value
    if (not env.get('VCTOOLSINSTALLDIR') or env.get('VSCMD_ARG_TGT_ARCH') != arch
            or not env.get('WINDOWSSDKVERSION', '').rstrip('\\').endswith(SDK_VERSION)):
        raise ValueError('developer environment did not select requested architecture and SDK')
    return env


def compile_group(rows, env, path):
    path.write_text(source(rows), encoding='utf-8')
    compiler = shutil.which('cl.exe', path=env.get('PATH', ''))
    if not compiler or 'hostx64' not in compiler.casefold():
        raise ValueError('HostX64 MSVC compiler not found')
    result = subprocess.run([compiler, '/nologo', '/std:c++20', '/EHsc', '/Zs', str(path)],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace')
    return result.returncode == 0


def verify_arch(rows, env, path):
    accepted, rejected = [], []
    def visit(group):
        if not group:
            return
        if compile_group(group, env, path):
            accepted.extend(group)
        elif len(group) == 1:
            rejected.extend(group)
        else:
            middle = len(group) // 2
            visit(group[:middle]); visit(group[middle:])
    # Small groups bound compiler memory and diagnostics on older SDKs.
    for i in range(0, len(rows), 16):
        visit(rows[i:i+16])
    return accepted, rejected


def merge(catalog, approved, digest):
    verified = catalog['reference_signatures']['verified_abis']
    if verified.get('header_sha256', '').casefold() != digest.casefold():
        raise ValueError('SDK header hash differs from existing verified ABI evidence')
    entries = verified['entries']
    keys = {(row[0].casefold(), row[1]) for row in entries}
    for name, ret, params in approved:
        if ('user32.dll', name) in keys:
            raise ValueError('duplicate verified identity')
        entries.append(['User32.dll', name, ret, 'WINAPI', list(params)])
    entries.sort(key=lambda x: (x[0].casefold(), x[1]))
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--devcmd', required=True, type=Path)
    parser.add_argument('--sdk-include', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.report.exists() or args.output.resolve() == args.catalog.resolve():
        raise ValueError('output and report must be new files')
    header = args.sdk_include / 'um/winuser.h'
    digest = hashlib.sha256(header.read_bytes()).hexdigest()
    catalog = json.loads(args.catalog.read_text(encoding='utf-8-sig'))
    rows = choose(catalog)
    if catalog['reference_signatures']['verified_abis']['header_sha256'].casefold() != digest:
        raise ValueError('SDK header does not match existing evidence')
    with tempfile.TemporaryDirectory(prefix='ksword_sdk_user32_') as temporary:
        path = Path(temporary) / 'probe.cpp'
        env32 = developer_environment(args.devcmd, 'x86')
        env64 = developer_environment(args.devcmd, 'x64')
        for arch, env in [('x86', env32), ('x64', env64)]:
            if not compile_group([('GetSystemMetrics', 'int', ('int',))], env, path):
                raise RuntimeError(f'{arch} SDK compiler preflight failed')
        accepted32, rejected32 = verify_arch(rows, env32, path)
        accepted64, rejected64 = verify_arch(rows, env64, path)
    approved = sorted(set(accepted32) & set(accepted64))
    merged = merge(catalog, approved, digest)
    # Preserve schema and compact the existing reference data as before.
    refs = merged.pop('reference_signatures')
    base = json.dumps(merged, ensure_ascii=False, indent=2)
    encoded = base[:-2] + ',\n  "reference_signatures": ' + json.dumps(refs, ensure_ascii=False, separators=(',', ':')) + '\n}\n'
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(encoded)
    report = {'sdk': SDK_VERSION, 'header_sha256': digest, 'candidate_count': len(rows),
              'verified_both': [row[0] for row in approved],
              'rejected_x86': [row[0] for row in rejected32], 'rejected_x64': [row[0] for row in rejected64]}
    with args.report.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'candidates': len(rows), 'verified_both': len(approved),
                      'rejected_x86': len(rejected32), 'rejected_x64': len(rejected64)}))


if __name__ == '__main__':
    main()
