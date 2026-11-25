"""用同一份合成项目验收正式 Light 的 API 归档回放。"""

import argparse
from pathlib import Path
import subprocess
import uuid

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


def preview_authorized(manifest, sample):
    """只读核验用户指定的离线采样，按 Light 的最近预览范围准备断言。"""
    project = manifest.resolve(strict=True)
    if project.is_dir():
        project = project / 'project.ksaproj'
    if project.name.casefold() != 'project.ksaproj' or not project.is_file():
        raise SystemExit('--project must identify an existing project.ksaproj or its directory')
    first = cli('replay', '--project', project, '--sample', sample, '--limit', '100')
    assert first['status'] == 'readback-verified' and first['sampleId'] == sample
    total = int(first['clueRows'])
    if not total:
        raise SystemExit('The selected sample has no verified API evidence')
    start = max(0, total - 4096)
    after, rows = start, []
    while after < total:
        replay = first if after == 0 else cli('replay', '--project', project, '--sample', sample,
                                              '--after', str(after), '--limit', '100')
        assert replay['sampleId'] == sample and int(replay['clueRows']) == total
        batch = replay['rows']
        assert batch and [int(row['rawSequence']) for row in batch] == list(range(after + 1, after + 1 + len(batch)))
        rows.extend(batch)
        after = int(batch[-1]['rawSequence'])
    segment = project.parent / 'samples' / sample / 'raw/00000000000000000001.ksaseg'
    preview(segment, api_rows=rows, api_read_only=True)


def main():
    """复用 CLI 和 Qt 的归档夹具，验证 Light 从项目打开和原位重读。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--large', action='store_true')
    parser.add_argument('--project', type=Path, help='existing authorized project directory or project.ksaproj')
    parser.add_argument('--sample', type=uuid.UUID, help='sample UUID for read-only replay of --project')
    options = parser.parse_args()
    if (options.project is None) != (options.sample is None) or (options.project and options.large):
        parser.error('use --project and --sample together, or --large alone')
    if options.project:
        preview_authorized(options.project, str(options.sample))
        return
    with owned_project_path() as project:
        if options.large:
            count = 22000  # 近输入上限，全匹配用于证据窗口压力回归。
            preview(import_large_fixture(project, count), api_window_total=count)
        else:
            _, segment, rows = import_fixture(project, 'Light API archive validation')
            preview(segment, api_rows=rows)


if __name__ == '__main__':
    main()
