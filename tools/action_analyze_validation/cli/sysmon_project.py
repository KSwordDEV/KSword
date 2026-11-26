"""用正式 CLI 验证本机缺少 Sysmon 通道时不创建采样。"""

import hashlib
import json
from pathlib import Path
import subprocess

from project_v1 import owned_project_path
from smoke import EXE, TIMEOUT


def main():
    """只读查询一个自有验证 GUID；不安装提供者，不修改日志。"""
    with owned_project_path() as project:
        # 使用正式项目入口创建一次性空项目，路径与后续查询保持相同。
        greeting = f'project create "{project}" "Sysmon project negative control"\nquit\n'
        subprocess.run([EXE, 'analyze', 'session'], input=greeting.encode(),
                       capture_output=True, timeout=TIMEOUT, check=True)
        samples = project / 'samples'  # 比较正式项目目录实际采样数。
        assert samples.is_dir() and not list(samples.iterdir())
        target = '11bbaaa0-4ed5-4bd3-a0a8-ba9271a493b1'  # 不从 PID 或其他进程推导身份。
        result = subprocess.run([EXE, 'analyze', 'sysmon-thread-create', 'archive',
                                 '--project', str(project), '--target-guid', target, '--json'],
                                capture_output=True, timeout=TIMEOUT)
        report = json.loads(result.stdout)['data']  # 单文档 CLI 的业务回执。
        print(json.dumps({'commandExit': result.returncode, 'receipt': report,
                          'cliSha256': hashlib.sha256(Path(EXE).read_bytes()).hexdigest()}), flush=True)
        assert (result.returncode, report['readState'], report['win32Error']) == (5, 'channel-unavailable', 15007), report
        assert report['sampleId'] is None and not report['archiveVerified'] and not list(samples.iterdir()), report
        print('AA10_SYSMON_CHANNEL_UNAVAILABLE=PASS PROJECT_SAMPLE_COUNT=0', flush=True)


if __name__ == '__main__':
    main()
