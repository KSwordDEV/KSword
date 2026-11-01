"""Compile managed-policy matching and control functions with bounded NT/WFP adapters."""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile
from process_activity_tree_tests import declaration
from native_msvc_test_support import find_msvc_developer_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default='cl')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / 'KswordARKDriver/src/features/network/network_managed.c').read_text(encoding='utf-8')
    functions = ['ManagedIdEmpty', 'ManagedPrefixValid', 'ManagedPolicyValid', 'ManagedPolicyMatches',
                 'ManagedReauthorize', 'ManagedRefreshExited', 'ManagedCapabilities', 'ManagedControlHeader',
                 'ManagedReferenceProcess', 'ManagedApply', 'ManagedProcessNotify', 'ManagedClassify']
    pieces = []
    for name in functions:
        position = source.index(name + '(')
        signature = source.rfind('static ', 0, position)
        pieces.append(declaration(source, source[signature:position + len(name) + 1]))
    assert 'FWP_ACTION_CALLOUT_UNKNOWN' in declaration(source, 'static NTSTATUS ManagedAddFilters(')
    fixture = (root / 'tools/managed_network_core_tests.cpp').read_text(encoding='utf-8').replace('__PRODUCTION_CORE__', '\n'.join(pieces))
    developer = find_msvc_developer_environment()
    (root / 'output').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='managed-network-', dir=root / 'output') as folder:
        work = Path(folder); cpp = work / 'fixture.cpp'; cpp.write_text(fixture, encoding='utf-8')
        executable = work / 'test.exe'
        command = [args.compiler, '/nologo', '/std:c++20', '/Zc:__cplusplus', '/permissive-', '/utf-8', '/EHsc', '/W4', '/WX', '/DNOMINMAX',
                   '/I' + str(root), str(cpp), '/Fe:' + str(executable), '/Fo:' + str(work) + '\\']
        script = work / 'build.cmd'
        script.write_text('@echo off\ncall "' + str(developer) + '" -arch=x64 -host_arch=x64 >nul\n' + subprocess.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding='utf-8')
        subprocess.run(['cmd', '/d', '/c', str(script)], cwd=work, check=True)
        subprocess.run([str(executable)], cwd=work, check=True, env=dict(os.environ))


if __name__ == '__main__': main()
