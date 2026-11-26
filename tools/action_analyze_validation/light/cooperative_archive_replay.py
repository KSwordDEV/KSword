"""经 isolated_desktop.py 采集自有目标，再让正式 Qt 与 Light 只读回放同一原包。"""

import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from uuid import UUID

from api_rule_profile import behavior_rule, display_summary
from isolated_desktop import require_isolated_desktop


VALIDATION = Path(__file__).resolve().parents[1]  # 隔离桌面及 CLI、Qt、Light 助手的共同目录。
RELEASE = VALIDATION.parents[1] / 'Ksword5.1/x64/Release'  # 唯一正式产物目录。
OPT_IN = 'KSWORD_APIMON_COOPERATIVE_SESSION_V1\0'.encode('utf-16-le')  # 两个镜像必须认识同一 opt-in。
TITLE = 'AA-03 self writes'  # 合作夹具的正例采样标题，不选负控样本。
API_NAME = 'WriteProcessMemory'  # 只对账合作目标的一条自写记录。
ARCHIVE_SOURCE = 'cooperative-pipe'  # 合作档尾记与三个正式读端使用的共同来源值。
BEHAVIOR_ID = 'ksword.behavior.memory-write-access-denied-return.v1'  # 自有目标拒绝样本的预期规则。


def expected_behavior_lines():
    """返回 Light 合作回放详情中的规则 ID、证据级别和源码释义。"""
    return {f'行为规则 ID：{BEHAVIOR_ID}', '证据级别：reported-api-return',
            display_summary(behavior_rule(BEHAVIOR_ID))}


def check_images():
    """导入合作助手前检查当前解释器架构和正式镜像标记；无返回值。"""
    with Path(sys.executable).open('rb') as image:
        dos = image.read(64)  # DOS 头给出 PE 头的位置。
        assert dos[:2] == b'MZ', sys.executable
        image.seek(struct.unpack_from('<I', dos, 60)[0])
        assert struct.unpack('<4sH', image.read(6)) == (b'PE\0\0', 0x8664), '需要 AMD64 Python'

    for name in ('KswordCLI.exe', 'APIMonitor_x64.dll'):
        binary = (RELEASE / name).read_bytes()  # 旧镜像会忽略 opt-in，可能触及共享会话 ACL。
        assert OPT_IN in binary, f'正式镜像缺少合作传输标记：{RELEASE / name}'
        print(f'{name}_SHA256={hashlib.sha256(binary).hexdigest()}', flush=True)


def read_cooperative_archive(sample_dir, decode_raw):
    """从采样目录读取已发布段链，返回每段摘要、普通包与末记录序号。"""
    digests = {}  # 按段号保存路径和字节摘要，供回放后再次核对。
    packets = []  # 只统计普通包，保留全局 Stored 序号和元数据。
    next_raw = 1  # 每个段首计划也占一个序号。
    previous_digest = None  # 首段没有前驱，其余段必须与上一段摘要相连。
    for ordinal, marker_path in enumerate(sorted((sample_dir / 'checkpoints').glob('*.json')), 1):
        assert marker_path.stem == f'{ordinal:020d}', marker_path
        segment = sample_dir / 'raw' / f'{ordinal:020d}.ksaseg'
        rows, digest = decode_raw(segment, next_raw)
        marker = json.loads(marker_path.read_bytes())
        assert marker['raw']['sha256'] == digest and marker['previousRawSha256'] == previous_digest, marker
        assert rows[0][0]['kind'] == 'api-archive-follow-plan-v1' and not rows[0][1], rows[0]
        assert rows[0][0]['archiveSource'] == ARCHIVE_SOURCE, rows[0][0]
        final = marker['finalSegment']
        for raw, (metadata, wire) in enumerate(rows[1:-1] if final else rows[1:], next_raw + 1):
            assert metadata['kind'] == 'api-archive-packet-v1' and len(wire) == 1000, metadata
            assert metadata['sourceSequence'] == str(len(packets) + 1), metadata
            packets.append((ordinal, raw, metadata, wire))
        assert marker['lastSourceSequence'] == str(len(packets)), marker
        digests[segment] = digest
        previous_digest = digest
        next_raw += len(rows)
        if final:
            end, wire = rows[-1]
            assert not wire and end['kind'] == 'api-archive-follow-end-v1', end
            assert end['source']['kind'] == ARCHIVE_SOURCE and end['source']['validatedRows'] == str(len(packets)), end
            return digests, packets, next_raw - 1
    raise AssertionError(f'No published cooperative terminal segment in {sample_dir}')


def replay_witness(invoke, project, sample, witness, digests, packets):
    """使用同一个原包与 CLI 对账，返回线索、从零开始的求值偏移和累计线索数。"""
    ordinal, raw, metadata, packet = witness
    report = invoke('analyze', 'api-evidence', 'replay', '--project', project, '--sample', sample,
                    '--packet', '1', '--after', str(raw - 1), '--limit', '1')
    assert (report['status'], report['sampleId'], report['archiveSource']) == ('readback-verified', sample, ARCHIVE_SOURCE), report
    assert report['finalSegment'] and int(report['committedSegments']) == len(digests), report
    assert int(report['sourceRows']) == len(packets) >= int(report['clueRows']), report
    row, = report['rows']
    assert (row['api'], row['rawSegment'], row['rawSequence'], row['sourceSequence'], row['packet']) == (
        API_NAME, str(ordinal), str(raw), metadata['sourceSequence'], packet.hex()), row
    after = offset = 0  # CLI 证据页游标为 Stored 序号，规则页偏移只计线索。
    while True:
        page = invoke('analyze', 'api-evidence', 'replay', '--project', project, '--sample', sample,
                      '--after', str(after), '--limit', '100')
        for index, clue in enumerate(page['rows'], offset):
            if clue['rawSequence'] == row['rawSequence']:
                return row, index, int(report['clueRows'])
        assert page['nextAfter'] and int(page['nextAfter']) > after, page
        after = int(page['nextAfter'])
        offset += len(page['rows'])


def read_witness(project, invoke, decode_raw, denied=False):
    """读取本轮项目的唯一采样，从真实 Stored 段选一条自写原包，再与正式 CLI 对账。"""
    description, = (project / 'samples').glob('*/sample.json')
    sample = json.loads(description.read_bytes())  # CLI 创建的采样描述，确保路径与采样 ID 一致。
    sample_id = sample['sampleId']
    assert sample_id == description.parent.name == str(UUID(sample_id)) and sample['title'] == TITLE, sample
    digests, packets, last_raw = read_cooperative_archive(description.parent, decode_raw)

    # 从尾部选最新自写项，使它留在两个客户端有上限的最近记录窗口内。
    for witness in reversed(packets):
        _, raw, _, packet = witness
        name = packet[96:224].decode('utf-16-le').split('\0', 1)[0]
        if name != API_NAME:
            continue
        detail = packet[224:864].decode('utf-16-le').split('\0', 1)[0].casefold().split()
        status, = struct.unpack_from('<i', packet, 28)
        if denied and status == 5 and {'size=1', 'written=0'}.issubset(detail):
            break  # 同轮 CLI 夹具另核对查询句柄及自有缓冲区地址。
        if not denied and status == 0 and {'process=0xffffffffffffffff', 'size=1', 'written=1'}.issubset(detail):
            break
    else:
        raise AssertionError('合作采样中没有自写 WriteProcessMemory 原包')

    row, offset, clues = replay_witness(invoke, project, sample_id, witness, digests, packets)
    return digests, row, last_raw - raw, offset, clues


def verify_cli_behavior(invoke, project, sample, row, offset, denied):
    """按 Light 将选中的同一原始坐标回读正式 CLI 的规则结果。"""
    report = invoke('analyze', 'replay-api-rules', '--project', project, '--sample', sample,
                    '--profile', 'by-category', '--offset', str(offset), '--limit', '1')
    match, = report['matches']
    assert report['archiveSource'] == ARCHIVE_SOURCE, report
    assert (report['status'], report['sampleId'], match['raw']['segment'], match['raw']['sequence'], match['sourceSequence']) == (
        'readback-verified', sample, row['rawSegment'], row['rawSequence'], row['sourceSequence']), match
    if denied:
        definition = behavior_rule(BEHAVIOR_ID)  # 同一见证同时核对 CLI 提供的两种释义。
        assert match['behavior'] == {'ruleId': BEHAVIOR_ID, 'evidence': 'reported-api-return',
                                     'summary': definition['summary'], 'summaryZh': definition.get('summaryZh')}, match
    else:
        assert 'behavior' not in match, match


def verify_qt_project_rules(client, nodes, sample, row, distance, terminal):
    """在已打开的 Qt 项目中回放同一选中采样，核对报告中的原包坐标；无返回值。"""
    from archive_api_preview import until
    from live_passive_api import press, select_tab, subtree, wait_visible

    select_tab(client, nodes, '项目与采样')  # 沿用已按采样 UUID 选定的目录行。
    button = wait_visible(nodes, 'action_analyze_sample_rule_replay', lambda item: item['enabled'])
    press(client, button)
    wrapper = wait_visible(nodes, 'ks_behavior_rule_receipt')  # 项目动作切到正式规则页。
    editor = wait_visible(lambda: subtree(client, wrapper, depth=4, max_nodes=120), 'code_editor_text')
    assert editor['read_only'], editor

    def read_report(offset, length):
        """按 UTF-16 坐标读取当前只读规则报告的指定片段和总长度。"""
        return client.call('read_text', {'object_id': editor['id'], 'offset': offset, 'length': length})['data']

    # 先等同一采样的项目回执发布，再读档尾见证，避免把 8192 字符当作整份报告上限。
    header = until(lambda: read_report(0, 512), lambda part: sample in part['text']
                   and f'已核验采样归档至终段 raw/{terminal}。' in part['text'])
    tail_length = min(65536, max(8192, 512 * (distance + 2)))  # 覆盖见证之后的命中及一行余量。
    tail = read_report(max(0, header['total_length'] - tail_length), tail_length)
    hits = [line for line in tail['text'].splitlines() if line.startswith('raw/')]  # 报告中的独立命中行。
    expected = (f"raw/{row['rawSegment']} #{row['rawSequence']} · 合作流水号 {row['sourceSequence']} · {API_NAME} · "
                'ksword.api.memory-operation-observed.v1 · ksword.api.memory-write-observed.v1')
    assert len(hits) > distance and hits[-1 - distance] == expected, (expected, hits[-1 - distance:])


def verify_qt(client, segment, row, distance, clue_distance, terminal):
    """在正式 Qt 项目中核对同一采样的 64 字节详情前缀和规则命中；无返回值。"""
    from archive_api_preview import PREVIEW, dispatch, open_project_sample, read_table, unique, until

    sample = segment.parents[1].name  # 两端都从 CLI 写入的清单选此 UUID。
    nodes = open_project_sample(client, segment.parents[3] / 'project.ksaproj', sample, title=TITLE)
    visible = until(nodes, lambda items: any(node['visible'] and '条源归档记录。覆盖范围未知。' in node['name']
                                            for node in items))
    table = unique(visible, lambda node: node['visible'] and node['object_name'] == 'aa_archive_event_table')
    target = read_table(client, table)['row_total'] - 1 - distance  # UI 显示窗口可能截去更早的记录。
    assert target >= 0, target
    model = client.call('read_table', {'object_id': table['id'], 'row_start': target, 'row_count': 1})['data']
    cells, = model['rows']  # 核对真实表格；详情只会随正式选行入口更新。
    assert cells[model['headers'].index('事件')] == API_NAME, model
    dispatch(client, 'select_row', object_id=table['id'], row=target, revision=model['revision'], confirmed=True)

    def details():
        """读取已显示的详情字段，兼容平铺和树形分组；未就绪时返回空映射。"""
        shown = [node for node in nodes() if node['visible']]
        hosts = {node['id'] for node in shown if node['object_name'] == 'aa_archive_event_details'}
        for view in shown:
            if view['type'] != 'item_view' or view['parent_id'] not in hosts:
                continue
            fields = read_table(client, view)['rows']  # 单组详情可能直接出现在根下。
            for index, field in enumerate(fields):
                if field and field[0] == '归档 API 线索':
                    fields = read_table(client, view, [index])['rows']
                    break
            return {str(field[0]): str(field[1]) for field in fields if len(field) >= 2}
        return {}

    shown = until(details, lambda fields: fields.get('记录序号') == row['rawSequence'])
    # 归档记录序号仍用于定位，合作流水号在独立字段中显示，不再标成文件行号。
    assert (shown['采样 ID'], shown['归档段号'], shown['记录序号'], shown[PREVIEW]) == (
        sample, row['rawSegment'], row['rawSequence'], bytes.fromhex(row['packet'])[:64].hex(' '),
    ), shown
    assert shown['归档输入类型（尾记声明）'] == ARCHIVE_SOURCE, shown
    assert shown['合作流水号（非 JSONL 行号）'] == row['sourceSequence'], shown
    assert '源归档行号' not in shown, shown
    verify_qt_project_rules(client, nodes, sample, row, clue_distance, terminal)


def verify_light(light, segment, row, distance, denied_witness=None, *, denied_only=False):
    """复用 Light 正式项目选择，显式回放并核对同一条线索的 128 字节原包前缀。"""
    sample = segment.parents[1].name  # 助手按这一个 UUID 从清单选择采样。
    original_state = light.workspace_state()  # 只回读配置，由现有助手负责恢复。
    con, gui = light.con, light.gui  # 使用 Light 助手的原生消息和窗体访问函数。

    def check(_process, _page, records, detail, status, _api, replay, _retry, item_count):
        """在助手提供的本轮窗口控件内提交回放、选行并断言详情，不修改归档。"""
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)

        def committed():
            """仅接受已提交的回放状态，不把目录快速预览算作通过。"""
            report = light.text(status)
            return ('当前归档' in report and '正在读取' not in report and '读取失败' not in report
                    and item_count() > 0)

        light.wait_for('Light 已提交合作样本回放', committed)
        # 先选拒绝正例，再选成功负例，检查切换不会残留旧行为证据。
        selected = [(row, distance, denied_only)]
        if denied_witness:
            selected.insert(0, (*denied_witness, True))
        behavior_lines = expected_behavior_lines() if denied_witness or denied_only else None
        for packet, from_end, denied in selected:
            target = item_count() - 1 - from_end  # 未筛选表格保留普通包及计划和尾记。
            assert target >= 0, target
            gui.SendMessage(records, con.WM_KEYDOWN, con.VK_END, 0)
            for _ in range(from_end):
                gui.SendMessage(records, con.WM_KEYDOWN, con.VK_UP, 0)
            assert gui.SendMessage(records, 0x100C, -1, 0x0002) == target  # LVM_GETNEXTITEM / LVNI_SELECTED。

            shown = light.text(detail).splitlines()  # 精确匹配坐标及 128 B 的预览。
            assert f'当前归档 · 采样：{sample}' in shown and API_NAME in shown, shown
            assert any(line.startswith(f"归档记录序号：{packet['rawSequence']} ") and f"所属段号：{packet['rawSegment']} " in line
                       for line in shown), shown
            assert f'归档输入类型（尾记声明）：{ARCHIVE_SOURCE}' in shown, shown
            assert f"合作流水号（非 JSONL 行号）：{packet['sourceSequence']}" in shown, shown
            assert not any(line.startswith('源归档行号：') for line in shown), shown
            assert shown[-1] == bytes.fromhex(packet['packet'])[:128].hex(' ') + ' … [字节预览截断]', shown
            if behavior_lines is not None:
                assert (behavior_lines & set(shown)) == (behavior_lines if denied else set()), shown

    light.preview(segment, check_project_replay=check)
    assert light.workspace_state() == original_state, 'Light 工作区配置未恢复'


def main():
    """默认三端对账；Qt 忙时可单独对账真实行为样本的 CLI 和 Light。"""
    require_isolated_desktop()
    if os.name != 'nt' or struct.calcsize('P') != 8 or not __debug__ or sys.argv[1:] not in ([], ['--light-behavior']):
        raise RuntimeError('需要 Windows AMD64 Python、启用断言；唯一可选参数为 --light-behavior')
    light_behavior = sys.argv[1:] == ['--light-behavior']
    check_images()

    # 镜像门禁之后才引入合作脚本。先加载 Light 同名助手，再加入 Qt 搜索路径。
    sys.path.insert(0, str(VALIDATION / 'cli'))
    import archive_etw_preview as light
    from cooperative_api_capture import create_session_directory, invoke, run
    from live_etw import decode_raw
    from project_v1 import owned_project_path, regular_identity
    sys.path.insert(0, str(VALIDATION / 'qt'))
    from archive_api_preview import test_window

    with owned_project_path() as project:
        directory = project.parent / 'KswordApiMonCooperative'  # 既有受保护 DACL 的合作会话目录。
        create_session_directory(directory)
        identity = regular_identity(directory)  # 只允许移除本次创建且已由 CLI 助手清空的目录。
        run(project, directory, behavior=light_behavior)
        assert regular_identity(directory) == identity and not any(directory.iterdir()), directory
        directory.rmdir()
        assert not os.path.lexists(directory), directory
        print('COOPERATIVE_SESSION_DIRECTORY_REMOVED=True', flush=True)

        digests, row, distance, offset, clues = read_witness(project, invoke, decode_raw)
        segment = next(iter(digests))  # 目录入口仍以首段定位采样。
        sample = segment.parents[1].name  # 清理之后仍可用来记录本轮的实际坐标。
        if light_behavior:
            _, denied, denied_distance, denied_offset, _ = read_witness(project, invoke, decode_raw, denied=True)
            verify_cli_behavior(invoke, project, sample, denied, denied_offset, denied=True)
            verify_cli_behavior(invoke, project, sample, row, offset, denied=False)
            verify_light(light, segment, row, distance, (denied, denied_distance))
        else:
            with test_window() as client:  # Qt 助手关闭本轮窗口，核对外观和布局恢复。
                verify_qt(client, segment, row, distance, clues - 1 - offset, len(digests))
            verify_light(light, segment, row, distance)
        assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in digests.items())

    if light_behavior:
        print(f'LIGHT_COOPERATIVE_BEHAVIOR_REPLAY=PASS SAMPLE={sample} '
              f'POSITIVE={denied["rawSegment"]}#{denied["rawSequence"]}:{denied["sourceSequence"]} '
              f'NEGATIVE={row["rawSegment"]}#{row["rawSequence"]}:{row["sourceSequence"]} CLIENTS=CLI,Light', flush=True)
    else:
        print(f'COOPERATIVE_ARCHIVE_REPLAY=PASS SAMPLE={sample} RAW={row["rawSegment"]}#{row["rawSequence"]} '
              f'SOURCE={row["sourceSequence"]} CLIENTS=CLI,Qt,Light', flush=True)


if __name__ == '__main__':
    main()
