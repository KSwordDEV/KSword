"""在独立非输入桌面只读验收 Qt 和 Light 的 KSword 自有回调归档。"""

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
from uuid import UUID

# 先加载 Light 助手，再引入 Qt 路径；两个目录有同名模块。
from archive_etw_preview import RELEASE, con, control, gui, preview, require_isolated_desktop, text, windows
from live_etw import decode_raw
from project_v1 import raise_walk_error, regular_identity

VALIDATION = Path(__file__).resolve().parents[1]  # 两端及原生夹具的公共目录。
sys.path.insert(0, str(VALIDATION / 'qt'))
from archive_api_preview import open_project, read_table, test_window
from live_preview import dispatch, unique, until


FIXTURE = VALIDATION / 'project/x64/Release/callback-project-fixture'  # CLI 已验证的现有合成项目。
SEGMENT = 'raw/00000000000000000001.ksaseg'  # 三个采样都只有第一个原始段。
POSITIVE = 'Synthetic thread creation'
EMPTY = 'Complete empty callback batch'
CONFLICT = 'Conflicting callback counts'
ROW_LABEL = 'KSwordARK 线程创建回调'  # Qt 事件名，也是选中观察的详情分组名。
BATCH_LABEL = 'KSwordARK 回调批次'  # Qt 整批详情分组名，空批也应显示。
SOURCE = 'kswordark.callback'
EPOCH = '11111111-1111-4111-8111-111111111111'
QT_OK = '已核验 KSwordARK 回调批次。采集覆盖未知。'
QT_EMPTY = '已核验 KSwordARK 回调空批次。采集覆盖未知。'
LIGHT_OK = 'KSword 回调批次已核验 · 采集覆盖未知'
LIGHT_EMPTY = '空批次已核验 · 没有线程创建观测'


def snapshot_fixture():
    """只读固定项目，返回目录身份及文件摘要；拒绝夹具路径上的重解析点。"""
    for ancestor in (*reversed(FIXTURE.parents), FIXTURE):
        regular_identity(ancestor)
    assert FIXTURE.resolve(strict=True) == FIXTURE, FIXTURE
    entries = {}  # 将目录结构、文件身份和字节一起纳入运行前后比较。
    for parent, directories, files in os.walk(FIXTURE, followlinks=False, onerror=raise_walk_error):
        for name in directories + files:
            path = Path(parent) / name
            identity = regular_identity(path)
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if name in files else None
            entries[path.relative_to(FIXTURE)] = (identity, digest)
    return entries


def load_fixture():
    """检查既有合成清单和 Stored 帧，返回清单、项目 ID 和按标题索引的采样。"""
    manifest = FIXTURE / 'project.ksaproj'
    project = json.loads(manifest.read_bytes())
    assert (project['kind'], project['title']) == ('action-analyze-project', 'Synthetic callback archive'), project
    project_id = project['projectId']
    samples = {}
    counts = {POSITIVE: ('1', '3'), EMPTY: ('0', '0'), CONFLICT: ('1', '4')}  # 观察数与源返回数不同。
    base = 'kswordark-callback-thread-create-'  # Stored 元数据类型的精确前缀。
    for description in (FIXTURE / 'samples').glob('*/sample.json'):
        sample = json.loads(description.read_bytes())
        title, sample_id = sample['title'], sample['sampleId']
        assert (sample_id, sample['projectId']) == (description.parent.name, project_id), sample
        assert title in counts and title not in samples, sample
        segment = description.parent / SEGMENT
        rows, digest = decode_raw(segment)
        data = segment.read_bytes()  # 从真实段头核对 UI 即将打开的项目、采样和段号。
        assert (UUID(bytes=data[32:48]), UUID(bytes=data[48:64])) == (UUID(project_id), UUID(sample_id)), segment
        assert struct.unpack_from('<Q', data, 24) == (1,), segment
        kinds = ['plan-v1', 'end-v1'] if title == EMPTY else ['plan-v1', 'observation-v1', 'end-v1']
        assert [meta['kind'] for meta, _ in rows] == [base + kind for kind in kinds], rows
        end = rows[-1][0]
        assert (end['observationCount'], end['returnedCount']) == counts[title], end
        samples[title] = (sample_id, segment, digest)
    assert set(samples) == set(counts), samples
    return manifest, project_id, samples


def verify_coordinates(segment, record_offset, inline_offset, inline_bytes):
    """按界面报告的位置读取指定原始段，核对第二条 Stored 记录及完整合成回调包。"""
    data = segment.read_bytes()
    first = 96 + 80  # Stored v1 段头及未压缩块头；首条记录是批次计划。
    first_length, = struct.unpack_from('<I', data, first)
    assert record_offset == first + first_length, (segment, record_offset)
    length, kind, schema, _, body_size, sequence = struct.unpack_from('<IHHIIQ', data, record_offset)
    assert (kind, schema, sequence, length) == (3, 1, 2, body_size + 32), segment
    meta_size, = struct.unpack_from('<I', data, record_offset + 32)
    meta_start = record_offset + 36  # 记录头之后是 4 字节元数据大小及 JSON 元数据。
    assert json.loads(data[meta_start:meta_start + meta_size]) == {
        'kind': 'kswordark-callback-thread-create-observation-v1',
    }, segment
    assert (inline_offset, inline_bytes) == (meta_start + meta_size, body_size - 4 - meta_size), segment
    packet = data[inline_offset:inline_offset + inline_bytes]
    # 对照原生夹具的 Windows ABI 布局：96 字节固定字段，之后是 64+520 个 UTF-16 字符。
    assert len(packet) == inline_bytes == 96 + 2 * (64 + 520), segment
    assert struct.unpack_from('<IIQqIIIIIIII', packet) == (
        1, inline_bytes, 107, 133000000000000123, 2, 1, 1, 0, 4101, 4102, 4201, 4202,
    ), segment
    assert packet[56:] == bytes(40) + 'X中'.encode('utf-16-le') + bytes(2 * (64 + 520) - 4), segment


def qt_detail_rows(client, nodes):
    """读取当前可见归档详情的根和回调分组字段；详情准备中返回空列表。"""
    visible = [node for node in nodes() if node['visible']]
    host_ids = {node['id'] for node in visible if node['object_name'] == 'aa_archive_event_details'}
    for node in visible:  # 只选归档详情宿主的字段模型，不读取项目目录或其它对象详情。
        if node['type'] != 'item_view' or node['parent_id'] not in host_ids:
            continue
        root = read_table(client, node)['rows']
        rows = list(root)
        for index, row in enumerate(root):
            if row and row[0] in {ROW_LABEL, BATCH_LABEL}:
                rows.extend(read_table(client, node, [index])['rows'])
        return rows
    return []


def qt_fields(rows):
    """将桥接详情行转换为字段值映射，供等待异步投影和最终断言使用。"""
    return {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}


def verify_qt(manifest, project_id, samples):
    """在同一个正式 Qt 窗口验证三种回执，返回实际显示的三个原包坐标。"""
    with test_window() as client:
        nodes = open_project(client, manifest)

        def select_sample(title):
            """在真实目录以标题+UUID 选择采样，再显式转到总览，只返回目标 UUID。"""
            sample_id = samples[title][0]
            tabs = unique(nodes(), lambda node: node['object_name'] == 'action_analyze_tabs')
            dispatch(client, 'set_field', object_id=tabs['id'], value=tabs['tabs'].index('项目与采样'), confirmed=True)
            catalog = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QTableView'
                             and '采样名称' in read_table(client, node)['headers'])
            model = until(lambda: read_table(client, catalog),
                          lambda data: any(sample_id in row and title in row for row in data['rows']))
            row_index, = (index for index, row in enumerate(model['rows']) if sample_id in row and title in row)
            dispatch(client, 'select_row', object_id=catalog['id'], row=row_index, revision=model['revision'], confirmed=True)
            action = until(lambda: unique(nodes(), lambda node: node['object_name'] == 'action_analyze_sample_archive'),
                           lambda node: node['visible'] and node['enabled'])
            dispatch(client, 'action', object_id=action['id'], action='press', confirmed=True)
            return sample_id

        def status():
            """回读当前可见的正式读取状态，不使用详情、目录或隐藏页文案代替。"""
            return next((node['name'] for node in nodes() if node['visible']
                         and node['object_name'] == 'aa_archive_read_status'), '')

        def event_table():
            """定位实际事件表控件，调用者读取当前行数或提交选区请求。"""
            return unique(nodes(), lambda node: node['visible'] and node['object_name'] == 'aa_archive_event_table')

        def check_identity(sample_id):
            """确认总览的已发布归档同时绑定当前窗口所选项目、采样和 raw/1。"""
            labels = [node['name'] for node in nodes() if node['visible']]
            assert any(f'项目 {project_id} · 采样 {sample_id} · 流 1 · 段 1' in label for label in labels), labels
            assert '归档项目和采样 ID 均匹配。' in labels, labels

        # 先读正例并通过正式表格选行；坐标必须可定位到实际原包。
        positive = select_sample(POSITIVE)
        segment = samples[POSITIVE][1]
        size = segment.stat().st_size
        until(status, lambda report: QT_OK in report and f'已校验前缀 {size} / {size} 字节。' in report)
        check_identity(positive)
        table = event_table()
        model = read_table(client, table)
        assert model['row_total'] == len(model['rows']) == 1 and model['row_hidden'] == [False], model
        columns = [model['headers'].index(name) for name in ('事件', '目标 PID 提示', '目标 TID 提示')]
        assert [str(model['rows'][0][column]) for column in columns] == [ROW_LABEL, '4201', '4202'], model
        dispatch(client, 'select_row', object_id=table['id'], row=0, revision=model['revision'], confirmed=True)
        expected = {
            '采样 ID': positive, '归档段号': '1', '记录序号': '2', '原始回调序号': '107',
            'FILETIME': '133000000000000123', '回调上下文 PID 提示': '4101', '回调上下文 TID 提示': '4102',
            '目标 PID 提示': '4201', '目标 TID 提示': '4202', '事件来源': SOURCE, '来源代次': EPOCH,
            '采集覆盖': '未知', '回调批次游标状态': '已读至本次源快照末尾',
            '请求游标（不含）': '101', '响应游标': '108', '源快照最新序号': '108',
            '源返回记录数': '3', '游标前缀覆盖数': '4', '回调环累计丢弃数': '17', '归档块号': '1',
        }
        detail = until(lambda: qt_detail_rows(client, nodes), lambda rows: bool(rows)
                       and expected.items() <= qt_fields(rows).items())
        fields = qt_fields(detail)
        assert any('进程和线程实例、实际写入、执行及跨进程归因均未知。' in row for row in detail), detail
        offsets = tuple(int(fields[key]) for key in ('文件偏移（字节）', '原包起点（字节）', '原包长度（字节）'))
        verify_coordinates(segment, *offsets)

        # 冲突段有原包但语义校验失败，必须保留原正例，而不是提交空批或冲突原包。
        conflict = select_sample(CONFLICT)
        report = until(status, lambda value: conflict in value and 'KSwordARK 回调归档读取或核验失败。' in value
                       and '第 1 段校验失败。' in value)
        assert '仍显示上次提交的结果。' in report and QT_EMPTY not in report, report
        retained = read_table(client, event_table())
        assert (retained['row_total'], retained['rows']) == (1, model['rows']), retained
        assert qt_fields(qt_detail_rows(client, nodes)) == fields, report

        # 空批必须替换旧结果，显示真正的零观察、独立采样身份及零／未知回执。
        empty = select_sample(EMPTY)
        size = samples[EMPTY][1].stat().st_size
        until(status, lambda value: QT_EMPTY in value and f'已校验前缀 {size} / {size} 字节。' in value)
        check_identity(empty)
        empty_model = read_table(client, event_table())
        assert empty_model['row_total'] == 0 and not empty_model['rows'], empty_model
        assert {'事件', '目标 PID 提示', '目标 TID 提示'} <= set(empty_model['headers']), empty_model
        assert any(node['visible'] and node['name'] == '归档线程创建观测数：0。' for node in nodes())
        batch = until(lambda: qt_fields(qt_detail_rows(client, nodes)), lambda values: values.get('源返回记录数') == '0')
        assert (batch['响应游标'], batch['游标前缀覆盖数'], batch['回调环累计丢弃数'], batch['采集覆盖']) == (
            '101', '0', '未知', '未知',
        ), batch
        assert '原始回调序号' not in batch, batch
    print(f'QT_CALLBACK_ARCHIVE=PASS POSITIVE={positive} CONFLICT={conflict} EMPTY={empty} RAW=1#2 SOURCE=107 '
          f'RECORD_OFFSET={offsets[0]} INLINE_OFFSET={offsets[1]} INLINE_BYTES={offsets[2]}', flush=True)
    return offsets


def verify_light(project_id, samples):
    """用一次 Light 工程选择验证三种预览及回放，恢复工作区后返回实测坐标。"""
    positive, segment, digest = samples[POSITIVE]
    conflict = samples[CONFLICT][0]
    empty, empty_segment, empty_digest = samples[EMPTY]
    offsets = []  # 助手不转发回调返回值；这里保存正式详情读出的三个坐标。

    def check(_process, page, records, detail, status, _api, replay, _retry, count):
        """接收正式页面控件及实际行数读取函数，在同一目录中切换采样。"""
        chooser = control(page, 58310)  # 同一正式目录的采样下拉框。
        assert all(gui.IsWindowVisible(hwnd) for hwnd in (chooser, records, detail, status, replay))
        total = gui.SendMessage(chooser, con.CB_GETCOUNT, 0, 0)
        items = [text(chooser, con.CB_GETLBTEXT, index) for index in range(total)]
        assert sorted(items) == sorted(f'{sample_id} · {title}' for title, (sample_id, _, _) in samples.items()), items

        def select_sample(title):
            """按真实下拉项目选择采样并发送原生选择通知，不直接写入业务状态。"""
            index = items.index(f'{samples[title][0]} · {title}')
            assert gui.SendMessage(chooser, con.CB_SETCURSEL, index, 0) == index
            gui.SendMessage(page, con.WM_COMMAND, 58310 | (con.CBN_SELCHANGE << 16), chooser)
            assert gui.SendMessage(chooser, con.CB_GETCURSEL, 0, 0) == index and gui.IsWindowEnabled(replay)

        def good_status(sample_id, *, live_preview):
            """等待本次 UUID 上的核验通过，区分选中预览和已经提交的回放。"""
            marker = f'快速预览 · {sample_id} · {LIGHT_OK}' if live_preview else f'{LIGHT_OK} · #1 · {sample_id}'
            return until(lambda: text(status), lambda report: marker in report and '读取失败：' not in report)

        # 助手已选择正例；先证明预览，然后选中唯一的真实列表行。
        good_status(positive, live_preview=True)
        assert count() == 1
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
        until(lambda: text(detail), lambda value: f'选中采样预览 · 采样：{positive}' in value
              and '归档记录序号：2 ' in value)
        assert gui.SendMessage(records, 0x100C, -1, 0x0002) == 0  # LVM_GETNEXTITEM / LVNI_SELECTED。
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        report = good_status(positive, live_preview=False)
        shown = until(lambda: text(detail).replace('\r\n', '\n'),
                      lambda value: f'当前归档 · 采样：{positive}' in value and '归档记录序号：2 ' in value)
        assert count() == 1 and gui.SendMessage(records, 0x100C, -1, 0x0002) == 0, report
        size = segment.stat().st_size  # 计划、原包、尾记三帧，只显示一个观测。
        assert '帧记录 3' in report and f'帧前缀 {size} / {size} B' in report, report
        for expected in (
            f'当前归档 · 采样：{positive}', f'项目：{project_id}', f'来源（归档声明）：{SOURCE}', f'来源代次：{EPOCH}',
            '线程创建回调 · 源序号 107', '来源上下文 · KSword 回调 · raw/1 #2',
            '回调上下文 PID/TID 提示：4101 / 4102', '目标 PID/TID 提示：4201 / 4202',
            '来源时间（FILETIME）：133000000000000123', '原生返回 / 请求上限：3 / 8',
            '来源游标（请求后 / 下次 / 快照上界）：101 / 108 / 108 · 已到本次快照上界',
            '环覆盖丢失：4    环累计丢弃：17', f'raw 段 SHA-256：{digest}',
            '采集覆盖：未知。PID/TID 仅是提示；进程、线程实例以及写入、执行和跨进程归因均未核验。',
        ):
            assert expected in shown, shown
        record = re.search(r'^归档记录序号：2 +所属段号：1 +块号：1 +文件字节偏移：(\d+)$', shown, re.MULTILINE)
        packet = re.search(r'^内联原包字节偏移：(\d+) +原包长度：(\d+) B$', shown, re.MULTILINE)
        assert record and packet, shown
        offsets.extend(map(int, (record[1], packet[1], packet[2])))
        verify_coordinates(segment, *offsets)

        # 拒绝冲突采样时，预览和显式回放都要给出本次诊断，已提交行仍属正例。
        select_sample(CONFLICT)
        until(lambda: text(status), lambda value: f'无法预览采样 {conflict}' in value and 'corrupt/callbackRawBatch' in value)
        assert count() == 1 and text(detail).replace('\r\n', '\n') == shown
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        failure = until(lambda: text(status), lambda value: value.startswith('读取失败：corrupt/callbackRawBatch')
                        and conflict in value)
        assert '保留当前归档' in failure and count() == 1, failure
        assert text(detail).replace('\r\n', '\n') == shown, failure

        # 空批预览和回放都必须发布新的零行模型和可见空态，而非沿用失败或正例的详情。
        select_sample(EMPTY)
        for live_preview in (True, False):
            if not live_preview:
                gui.SendMessage(replay, con.BM_CLICK, 0, 0)
            empty_status = good_status(empty, live_preview=live_preview)
            source = '选中采样预览' if live_preview else '当前归档'
            current = until(lambda: text(detail), lambda value: f'{source} · 采样：{empty}' in value)
            size = empty_segment.stat().st_size
            assert count() == 0 and '帧记录 2' in empty_status and f'帧前缀 {size} / {size} B' in empty_status, empty_status
            assert any(gui.IsWindowVisible(hwnd) and gui.GetClassName(hwnd).casefold() == 'static' and text(hwnd) == LIGHT_EMPTY
                       for hwnd in windows(page)), empty_status
            assert f'项目：{project_id}' in current, current
            assert f'raw 段 SHA-256：{empty_digest}' in current and '归档记录序号：' not in current, current
            assert '环覆盖丢失：0    环累计丢弃：未知' in current and '采集覆盖：未知。' in current, current

    # 专用验证回调直接返回，跳过通用帮助中的修改归档、故障注入和其他来源测试。
    preview(segment, check_project_replay=check)
    light_sha = hashlib.sha256((RELEASE / 'KswordARKLight.exe').read_bytes()).hexdigest()
    print(f'LIGHT_CALLBACK_ARCHIVE=PASS POSITIVE={positive} CONFLICT={conflict} EMPTY={empty} RAW=1#2 SOURCE=107 '
          f'RECORD_OFFSET={offsets[0]} INLINE_OFFSET={offsets[1]} INLINE_BYTES={offsets[2]} LIGHT_SHA256={light_sha}', flush=True)
    return tuple(offsets)


def main():
    """只接收隔离桌面启动器调用；两端退出后比较同一固定夹具的原有内容。"""
    require_isolated_desktop()
    if sys.flags.optimize or len(sys.argv) != 1:
        raise RuntimeError('验收需要启用断言、且不接收自定义夹具参数。')
    before = snapshot_fixture()
    try:
        manifest, project_id, samples = load_fixture()
        qt_offsets = verify_qt(manifest, project_id, samples)
        light_offsets = verify_light(project_id, samples)
        assert qt_offsets == light_offsets, (qt_offsets, light_offsets)
    finally:
        assert snapshot_fixture() == before, f'夹具目录或内容变化：{FIXTURE}'
        print(f'CALLBACK_FIXTURE_UNCHANGED=True ROOT={FIXTURE}', flush=True)
    print('CALLBACK_ARCHIVE_GUI=PASS CLIENTS=2 SAMPLES=3', flush=True)


if __name__ == '__main__':
    main()
