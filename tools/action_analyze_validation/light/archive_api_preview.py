"""用同一份合成项目验收正式 Light 的 API 归档回放。"""

import subprocess
import sys

from archive_etw_preview import preview
from api_evidence import EXE, TIMEOUT, archive_line, cli, import_fixture, packet
from project_v1 import owned_project_path


def import_large_fixture(project, count):
    """导入可跨过显示上限的合成原包，返回可打开的唯一 raw 段。"""
    subprocess.run([EXE, 'analyze', 'session'], input=f'project create "{project}" Window\nquit\n'.encode(),
                   capture_output=True, timeout=TIMEOUT, check=True)
    wire = packet('ntdll', 'NtMapViewOfSection', 8)  # 仅离线数据，无实际调用。
    archive = project.parent / 'events.jsonl'  # 固定目录内的合成输入。
    with archive.open('xb') as file:
        for sequence in range(1, count + 1):
            file.write(archive_line(sequence, wire))
    receipt = cli('import', '--archive', archive, '--project', project, '--title', 'Recent window')
    assert receipt['status'] == 'readback-verified' and int(receipt['clueRows']) == count, receipt
    return project / 'samples' / receipt['sampleId'] / 'raw/00000000000000000001.ksaseg'


def main():
    """复用 CLI 和 Qt 的归档夹具，验证 Light 从项目打开和原位重读。"""
    with owned_project_path() as project:
        if sys.argv[1:] == ['--large']:
            count = 22000  # 近输入上限，全匹配用于证据窗口压力回归。
            preview(import_large_fixture(project, count), api_window_total=count)
        elif not sys.argv[1:]:
            _, segment, rows = import_fixture(project, 'Light API archive validation')
            preview(segment, api_rows=rows)
        else:
            raise SystemExit('Usage: archive_api_preview.py [--large]')


if __name__ == '__main__':
    main()
