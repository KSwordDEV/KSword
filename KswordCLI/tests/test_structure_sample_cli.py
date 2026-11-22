"""Test live-sampler CLI preflight failures without opening the host driver."""

import ctypes
import json
import os
from pathlib import Path
import subprocess


REPO = Path(__file__).resolve().parents[2]
CLI = REPO / 'Ksword5.1' / 'x64' / 'Release' / 'KswordCLI.exe'


def invoke(arguments, expected):
    """调用正式 CLI 并核验退出码/封套；此文件只覆盖拒绝路径，不计为现场验收。"""
    result = subprocess.run([str(CLI), *arguments, '--json'], capture_output=True,
                            encoding='utf-8', timeout=15)
    assert result.returncode == expected, (arguments, result.returncode, result.stdout, result.stderr)
    packet = json.loads(result.stdout)
    assert packet['schemaVersion'] == 1, packet
    return packet


def check_rejected(arguments, expected):
    """有效拒绝必须保留来源分类，同时没有字段、覆盖率成功或设备访问。"""
    packet = invoke(arguments, expected)
    data = packet['data']
    assert data['source'] == 'live_object_body' and data['atomic'] is False, data
    assert not data['identityVerified'] and not data['coverageExceedsHalf'], data
    assert not data['deviceAccessAttempted'] and not data['requestAttempted'], data
    assert data['fields'] == [] and data['coverageRows'] is None, data
    print('PASS pre-device rejection:', ' '.join(arguments))


def main():
    """检查帮助、参数、未知分片和错误对象代次；不执行任何宿主机 IOCTL。"""
    pid = str(os.getpid())
    tid = str(ctypes.windll.kernel32.GetCurrentThreadId())
    missing = REPO / 'tools' / 'tests' / 'fixtures' / 'structure-sample-missing-profile'
    assert not missing.exists(), 'The missing-profile fixture must remain nonexistent.'
    for prefix in (['process', 'layout', 'sample'], ['process', 'thread', 'layout', 'sample']):
        help_result = subprocess.run([str(CLI), 'help', *prefix], capture_output=True,
                                     encoding='utf-8', timeout=10)
        assert help_result.returncode == 0 and 'coverageRows' in help_result.stdout, help_result
        required = ['--pid', pid] + (['--tid', tid] if 'thread' in prefix else [])
        check_rejected([*prefix, *required, '--profiles', str(missing)], 5)
        check_rejected([*prefix, *required, '--creation-time', '1'], 3)
        invoke([*prefix, *required, '--backend', 'r3'], 1)
        invoke([*prefix, *required, '--creation-time', '0'], 1)
        invoke([*prefix, *required, '--kernel', str(CLI)], 1)
    check_rejected(['process', 'thread', 'layout', 'sample', '--pid', pid, '--tid', tid,
                    '--thread-creation-time', '1'], 3)
    print('Live-sampler preflight checks passed; no live driver sampling was performed.')


if __name__ == '__main__':
    main()
