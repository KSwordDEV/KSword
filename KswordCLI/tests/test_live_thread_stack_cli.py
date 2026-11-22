"""Preflight-only checks: never open the host kernel driver or queue an APC."""

import ctypes
import json
import os
from pathlib import Path
import subprocess


CLI = Path(__file__).resolve().parents[2] / 'Ksword5.1/x64/Release/KswordCLI.exe'


def main():
    """用真实进程/线程号配错误创建时间，验证帮助、参数与设备访问前拒绝。"""
    prefix = ['process', 'thread', 'stack', 'capture']
    help_result = subprocess.run([str(CLI), 'help', *prefix], capture_output=True, encoding='utf-8', timeout=10)
    assert help_result.returncode == 0 and all(text in help_result.stdout for text in (
        '--method auto|saved|apc', 'completion exits 0', 'partial exits 6')), help_result
    arguments = [*prefix, '--pid', str(os.getpid()), '--tid', str(ctypes.windll.kernel32.GetCurrentThreadId()),
                 '--creation-time', '1', '--thread-creation-time', '1']
    cases = [(arguments, 3)]
    cases.extend(([*arguments, '--method', method], 3) for method in ('auto', 'saved', 'apc'))
    for option, value in (('--limit', '0'), ('--limit', '65'), ('--timeout-ms', '0'),
                          ('--timeout-ms', '5001'), ('--backend', 'r3'), ('--method', 'guess')):
        cases.append(([*arguments, option, value], 1))
    for command, expected in cases:
        result = subprocess.run([str(CLI), *command, '--json'], capture_output=True, encoding='utf-8', timeout=15)
        assert result.returncode == expected, (command, result.returncode, result.stdout, result.stderr)
        packet = json.loads(result.stdout)
        if '--backend' not in command:
            assert packet['backend'] == 'r0', packet
        if expected == 3:
            assert packet['data']['deviceAccessAttempted'] is False and packet['data']['frames'] == [], packet
        print('PASS pre-device live-stack rejection:', ' '.join(command))
    print('PREFLIGHT_ONLY=PASS; no driver access or target APC was performed.')


if __name__ == '__main__':
    main()
