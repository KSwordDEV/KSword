"""Compile actual candidate hook bodies against deterministic failure stubs.

Run from either HostX64 developer prompt, once targeting x64 and once x86.
The fixtures do not access the system clipboard or attach to another process.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).with_name('fixtures')
HOOKS = ROOT / 'APIMonitor_x64/hook'


def extract(text, name, indent):
    pattern = '^' + indent + r'[^\n]*\b' + name + r'\([^\n]*\)\n' + indent + r'\{.*?\n' + indent + r'\}'
    matches = list(re.finditer(pattern, text, re.M | re.S))
    if len(matches) != 1:
        raise ValueError(f'{name}: expected one definition, got {len(matches)}')
    return matches[0]


clipboard = (HOOKS / 'ClipboardGuardHook.cpp').read_text(encoding='utf-8')
targets = (HOOKS / 'HookTargets.cpp').read_text(encoding='utf-8')
async_source = (HOOKS / 'AsyncIoHandlers.inc').read_text(encoding='utf-8')
cases = [
    ('clipboard-status-fixture.cpp', clipboard, '    ',
     ['HookedOpenClipboard', 'HookedEnumClipboardFormats', 'HookedIsClipboardFormatAvailable', 'HookedOleGetClipboard']),
    ('winsock-status-fixture.cpp', targets, '        ', ['HookedSend']),
    ('wsa-output-sentinel.cpp', targets, '        ', ['HookedWSARecv']),
    ('couninitialize-fixture.cpp', targets, '        ', ['HookedCoUninitialize']),
]

with tempfile.TemporaryDirectory(prefix='ksword_special_status_') as tmp:
    directory = Path(tmp)
    for filename, source, indent, names in cases:
        text = (FIXTURES / filename).read_text(encoding='utf-8')
        # Replace one function at a time using fresh offsets; never splice a
        # previously captured list of offsets after the text has changed.
        for name in names:
            actual = extract(source, name, indent).group()
            existing = extract(text, name, indent)
            text = text[:existing.start()] + actual + text[existing.end():]
        cpp = directory / filename
        cpp.write_text(text, encoding='utf-8')
        exe = directory / (cpp.stem + '.exe')
        command = ['cl', '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/utf-8', str(cpp),
                   '/Fo:' + str(directory / (cpp.stem + '.obj')), '/Fe:' + str(exe)]
        if filename in ('winsock-status-fixture.cpp', 'wsa-output-sentinel.cpp'):
            command += ['ws2_32.lib']
        subprocess.run(command, check=True)
        subprocess.run([str(exe)], check=True, timeout=15)

    # Compile the exact checked-read and NTSTATUS confirmation helpers, not a
    # duplicate of their implementation.
    text = (FIXTURES / 'confirmed-failure-fixture.cpp').read_text(encoding='utf-8')
    header = text[:text.index('        template<class T> bool TrySafeIoValue')]
    body = text[text.index('int main()'):]
    start = async_source.index('        template<class T> bool TrySafeIoValue')
    end = async_source.index('        void CaptureDatagramCompletion')
    cpp = directory / 'confirmed-failure.cpp'
    cpp.write_text(header + async_source[start:end] + body, encoding='utf-8')
    exe = directory / 'confirmed-failure.exe'
    subprocess.run(['cl', '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/utf-8', str(cpp),
                    '/Fo:' + str(directory / 'confirmed-failure.obj'), '/Fe:' + str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=15)
print('PASS: clipboard, Winsock, output sentinel, CoUninitialize, and failure confirmation')
