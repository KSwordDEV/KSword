"""通过独立非输入桌面验收三端拒绝旧合成 Sysmon 档案，不调用任何采集命令。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from archive_etw_preview import con, gui, preview, require_isolated_desktop, text, wait_for
from continuous_etw import regular_identity
from live_etw import decode_raw
from smoke import EXE, SESSION, invoke, line, request

# Light 和 Qt 有同名夹具；先加载上面的 Light helper，再导入 Qt 专用入口。
VALIDATION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(VALIDATION / 'qt'))
from archive_api_preview import open_project_sample, read_table, test_window
from live_preview import until, unique


FIXTURE = VALIDATION / 'project/x64/Release/sysmon-project-fixture'  # 原生夹具默认保留位置。
SAMPLE_SIZES = {  # 标题和原始记录数区分有一条观察、没有任何观察的两个旧采样。
    'Synthetic Sysmon Event 8': 3,
    'Synthetic Sysmon exhausted without a match': 2,
}
UNSUPPORTED = re.compile(r'不受支持|不支持|unsupported|not supported', re.IGNORECASE)


def read_fixture(root):
    """输入固定或显式指定的根目录；校验合成数据后返回清单、项目 ID 和采样元组。"""
    manifest = root / 'project.ksaproj'  # 三端使用同一个项目清单。
    project = json.loads(manifest.read_bytes())
    assert project['title'] == 'Synthetic Sysmon storage fixture', manifest
    project_id = project['projectId']
    samples = []  # 每项保留目录中的 UUID、标题和用于对账的原始段。
    for directory in sorted((root / 'samples').iterdir()):
        description = (directory / 'sample.json').read_bytes()
        sample = json.loads(description)
        sample_id, title = sample['sampleId'], sample['title']
        assert (sample_id, sample['projectId']) == (directory.name, project_id), sample
        segment = directory / 'raw/00000000000000000001.ksaseg'
        marker = json.loads((directory / 'checkpoints/sysmon-retained-1.json').read_bytes())

        # 查看实际 Stored 记录，确保有数据的采样不是空壳，两份旧档均完整。
        rows, digest = decode_raw(segment)
        expected_kinds = ['sysmon-retained-plan-v1']
        if SAMPLE_SIZES[title] == 3:
            expected_kinds.append('sysmon-event8-v2-observation')
            assert rows[1][0]['computer'] == 'synthetic-fixture.invalid', segment
            assert rows[1][0]['eventRecordId'] == '73', segment
        expected_kinds.append('sysmon-retained-end-v1')
        assert [metadata['kind'] for metadata, _ in rows] == expected_kinds, segment
        assert marker['kind'] == 'sysmon-retained-checkpoint-v1', marker
        assert (marker['sampleId'], marker['projectId'], marker['descriptionHash']) == (
            sample_id, project_id, hashlib.sha256(description).hexdigest()), marker
        assert (marker['sha256'], marker['endOffset'], marker['lastSequence']) == (
            digest, str(segment.stat().st_size), str(len(rows))), marker
        samples.append((sample_id, title, segment))
    assert sorted(title for _, title, _ in samples) == sorted(SAMPLE_SIZES), samples
    return manifest, project_id, samples


def fixture_snapshot(root):
    """只读记录目录结构与文件摘要，供结束时比较；不跟随夹具内部的重解析点。"""
    entries = {}  # 相对路径映射到目录占位或文件摘要。
    for parent, directories, files in os.walk(root):
        for name in directories + files:
            path = Path(parent) / name
            regular_identity(path)  # 先检查对象，再读文件或由 os.walk 进入子目录。
            entries[path.relative_to(root)] = None if name in directories else hashlib.sha256(path.read_bytes()).hexdigest()
    return entries


def verify_cli(manifest, project_id, samples):
    """对固定 Release CLI 仅读帮助并发起 offline 图查询；失败响应必须不含证据。"""
    # 只检查正常帮助入口，绝不把已移除的子命令作为执行参数。
    for args in (('help', 'analyze'), ('help', 'analyze', 'session')):
        stdout, _ = invoke(args)
        help_text = stdout.lower()
        assert b'analyze session' in help_text and b'sysmon' not in help_text, stdout
    print('CLI_SYSMON_HELP_ABSENT=PASS', flush=True)

    commands = [request('open', 'project.open', {'path': str(manifest), 'access': 'read-only'})]
    for sample_id, _, _ in samples:
        params = {'projectId': project_id, 'sampleId': sample_id, 'stream': 'raw', 'ordinal': '1', 'view': 'graph'}
        commands.append(request(sample_id, 'archive.inspect', params))
    commands.append(request('shutdown', 'controller.shutdown'))
    # 所有请求随同一个离线会话提交，不打开任何实时后端。
    stdout, _ = invoke(SESSION, b''.join(map(line, commands)))
    frames = [json.loads(raw) for raw in stdout.splitlines()]
    assert frames[0]['type'] == 'hello' and frames[0]['capabilities']['backend'] == 'offline', frames[0]
    assert frames[0]['capabilities']['nativeCapture'] is False, frames[0]
    replies = [frame for frame in frames if frame['type'] == 'response']
    assert [reply['requestId'] for reply in replies] == [command['requestId'] for command in commands], replies
    opened = replies[0]  # 项目本身支持打开，不能把路径或权限报错误算为拒绝来源。
    assert opened['error'] is None and opened['result']['projectId'] == project_id, opened
    assert opened['result']['access'] == 'read-only', opened
    for reply in replies[1:-1]:
        assert reply['result'] is None and reply['error']['errorId'] == 'project-unsupported', reply
        assert reply['error']['message'] == 'graphArchiveSource', reply
        print(f"CLI_SYSMON_GRAPH_REJECTED=PASS SAMPLE={reply['requestId']} ROWS=0", flush=True)

    # 记录正常退出，确保没有漏读最后一个采样的协议回执。
    assert replies[-1]['error'] is None and replies[-1]['result'] == {'shutdown': True}, replies[-1]
    summary = frames[-1]
    assert (summary['type'], summary['reason'], summary['clean'], summary['exitCode']) == ('summary', 'shutdown', True, 0), summary
    print(f'CLI_SHA256={hashlib.sha256(EXE.read_bytes()).hexdigest()}', flush=True)


def verify_qt(manifest, sample_id, title):
    """从 Qt 项目目录打开指定采样；要求可见拒绝回执及实际记录模型零行。"""
    with test_window() as client:
        nodes = open_project_sample(client, manifest, sample_id, title=title)  # 真实目录按 UUID 选择。

        def visible_nodes():
            """回读当前 Qt 桥快照，不读取隐藏页的状态。"""
            return [node for node in nodes() if node['visible']]

        def rejection_report():
            """取含本次采样身份的可见标签；外层等待将最后一次回执留给失败诊断。"""
            return [node['name'] for node in visible_nodes() if sample_id in node['name']]

        report = until(rejection_report, lambda names: any(UNSUPPORTED.search(name) for name in names))
        # 用既有归档表头定位记录模型，不把项目目录、证据分组表当作归档记录表。
        table = unique(visible_nodes(), lambda node: node['class'] == 'QTableView'
                       and {'PID', 'TID', '事件'} <= set(read_table(client, node)['headers']))
        model = read_table(client, table)
        assert model['row_total'] == 0 and not model['rows'], (report, model)
        print(f'QT_SYSMON_REJECTED=PASS SAMPLE={sample_id} ROWS=0 DIAGNOSTIC={report!r}', flush=True)


def verify_light(segment, sample_id):
    """从 Light 正式项目导航检查自动预览与显式回放，均不得发布原始记录。"""
    def check(_process, _page, _records, _detail, status, _api, replay, _retry, count):
        """使用 Light helper 交付的状态标签、回放按钮和记录计数，无返回值。"""
        def rejected():
            """返回关联本采样的不支持诊断；忽略上一个请求或正在处理的状态。"""
            report = text(status)
            return report if gui.IsWindowVisible(status) and sample_id in report and UNSUPPORTED.search(report) else ''

        selection = wait_for(f'Light selection must reject {sample_id}', rejected)
        assert count() == 0, selection
        assert gui.IsWindowVisible(replay) and gui.IsWindowEnabled(replay), selection
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)

        # 显式回放必须产生独立回执，不能把自动预览的结果重复计为通过。
        def replay_rejected():
            """返回显式回放的不支持回执，忽略尚未更新的选择预览。"""
            report = rejected()
            return report if report and report != selection else ''

        report = wait_for(f'Light replay must reject {sample_id}', replay_rejected)
        assert count() == 0, report
        print(f'LIGHT_SYSMON_REJECTED=PASS SAMPLE={sample_id} ROWS=0 DIAGNOSTIC={report!r}', flush=True)

    preview(segment, check_project_replay=check)  # 专用回调提前返回，不执行 helper 的故障注入。


def main():
    """解析可选夹具目录，在隔离桌面执行三端验收；不清理夹具。"""
    require_isolated_desktop()
    if sys.flags.optimize:
        raise RuntimeError('请使用未禁用断言的 Python 执行验收')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project_root', nargs='?', type=Path, default=FIXTURE)
    root = parser.parse_args().project_root.resolve(strict=True)
    before = fixture_snapshot(root)  # 夹具无论通过还是失败均只读、保留。
    manifest, project_id, samples = read_fixture(root)
    try:
        verify_cli(manifest, project_id, samples)
        for sample_id, title, segment in samples:
            verify_qt(manifest, sample_id, title)
            verify_light(segment, sample_id)
    finally:
        assert fixture_snapshot(root) == before, f'夹具目录或内容变化：{root}'
        print(f'SYSMON_FIXTURE_UNCHANGED=True ROOT={root}', flush=True)
    print('SYSMON_SOURCE_REJECTION=PASS SAMPLES=2 CLIENTS=3', flush=True)


if __name__ == '__main__':
    main()
