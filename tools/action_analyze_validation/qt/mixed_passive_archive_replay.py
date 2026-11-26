"""用正式 Qt 和 Light 只读回放已由 CLI 核验的同一个混采项目。"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from uuid import UUID

from archive_api_preview import (
    RELEASE, check_location, dispatch, open_project_sample, read_table,
    regular_identity, test_window, unique, until,
)
from isolated_desktop import require_isolated_desktop
from live_etw import decode_raw


VALIDATION = Path(__file__).resolve().parents[1]  # Qt 助手已加载，优先导入 Light 的同名 ETW 助手。
sys.path.insert(0, str(VALIDATION / 'light'))
from archive_etw_preview import control, con, gui, preview, text, wait_for


API_EVENT = 'WriteProcessMemory'  # CLI 夹具两条合成包的共同分类事件。
API_COUNT = 2  # 已知混采夹具的 API 线索数。
ETW_COUNT = 12  # 已知混采夹具的真实 ETW 观察数，不含计划和尾记。


def fingerprint(project):
    """输入项目根路径，返回文件/目录清单、身份及文件内容指纹。"""
    entries = {}  # 每项按相对路径记录；不依赖访问时间。
    for path in (project, *sorted(project.rglob('*'))):
        identity = regular_identity(path)  # 拒绝符号链接和其它重解析点。
        key = path.relative_to(project).as_posix()
        if path.is_dir():
            entries[key] = ('directory', identity)
        else:
            with path.open('rb') as source:
                entries[key] = ('file', identity, path.stat().st_mtime_ns,
                                hashlib.file_digest(source, 'sha256').hexdigest())
    return entries


def read_archive(sample, identity, stream, checkpoint_dir, ordinal, first_sequence, kind):
    """输入物理通道及 CLI 检查点坐标，返回只读段路径、检查点和已发布记录。"""
    stem = f'{ordinal:020d}'  # Stored 段和检查点使用相同的固定宽度编号。
    segment = sample / stream / f'{stem}.ksaseg'
    checkpoint = json.loads((sample / checkpoint_dir / f'{stem}.json').read_bytes())
    description_hash = hashlib.sha256((sample / 'sample.json').read_bytes()).hexdigest()
    assert (checkpoint['kind'], checkpoint['generation'], checkpoint['descriptionHash']) == (
        kind, str(ordinal), description_hash), checkpoint
    assert {key: checkpoint[key] for key in identity} == identity, checkpoint
    # 用既有独立 Stored 解码器校验同一采样发布的原始段，期间不启动 CLI。
    rows, digest = decode_raw(segment, first_sequence)
    raw = checkpoint['raw']  # 独立通道的已发布范围。
    assert (raw['sha256'], int(raw['endOffset']), int(raw['lastSequence'])) == (
        digest, segment.stat().st_size, first_sequence + len(rows) - 1), raw
    return segment, checkpoint, rows


def archive_expectations(manifest, sample_id):
    """输入明确清单和 CLI 采样 ID，返回冻结身份、显示标题及两条 #2 的来源。"""
    catalog = json.loads(manifest.read_bytes())  # 不通过新建项目或采集获得回放输入。
    assert catalog['kind'] == 'action-analyze-project' and catalog['producer'] == 'KswordCLI', catalog
    sample = manifest.parent / 'samples' / sample_id
    assert list(sample.parent.iterdir()) == [sample], '此夹具须只包含给定的 CLI 混采采样'
    description = json.loads((sample / 'sample.json').read_bytes())
    identity = {'projectId': catalog['projectId'], 'sampleId': sample_id}
    assert {key: description[key] for key in identity} == identity, description

    # 主通道的第一段有两条包，第二段是实际发布的终段。
    api_kind = 'api-archive-checkpoint-v1'
    api_segment, api_checkpoint, api_rows = read_archive(sample, identity, 'raw', 'checkpoints', 1, 1, api_kind)
    _, api_final, api_end = read_archive(sample, identity, 'raw', 'checkpoints', 2, len(api_rows) + 1, api_kind)
    assert api_checkpoint['finalSegment'] is False and api_final['finalSegment'] is True
    assert api_final['previousRawSha256'] == api_checkpoint['raw']['sha256']
    assert len(api_end) == 2 and api_end[-1][0]['kind'] == 'api-archive-follow-end-v1', api_end
    assert len(api_rows) == API_COUNT + 1
    for index, (metadata, _) in enumerate(api_rows[1:], 1):
        assert metadata['kind'] == 'api-archive-packet-v1' and metadata['sourceSequence'] == str(index), metadata

    # ETW 使用另一枚终态检查点；两侧冻结的是同一 PID 和创建时间，而非实时进程查询。
    etw_segment, _, etw_rows = read_archive(
        sample, identity, 'raw-etw', 'checkpoints-etw', 1, 1, 'etw-terminal-checkpoint-v1',
    )
    api_plan, etw_plan = api_rows[0][0], etw_rows[0][0]
    assert api_plan['mixedEtw'] is True and etw_plan['mixedEtw'] is True
    pid = int(api_plan['readerPid'])  # 历史 PID 只用于核对归档头，不能证明逐事件关联。
    assert (pid, int(api_plan['readerCreation100ns'])) == (
        int(etw_plan['headerPid']), int(etw_plan['processCreationFileTime'])), etw_plan
    assert len(etw_rows) == ETW_COUNT + 2 and etw_rows[-1][0]['kind'] == 'etw-capture-end-v1'
    for metadata, _ in etw_rows[1:-1]:
        assert metadata['kind'] == 'etw-observation-v1' and metadata['headerPid'] == pid, metadata

    # 各通道的 #2 保存不同元数据和原包，即使 UI 错选同序号也不能通过。
    api_meta, api_packet = api_rows[1]
    etw_meta, etw_packet = etw_rows[1]
    assert struct.unpack_from('<I', api_packet, 8)[0] == pid
    lanes = {'raw': (api_segment, api_meta, api_packet), 'raw-etw': (etw_segment, etw_meta, etw_packet)}
    return identity, description['title'], pid, lanes


def verify_selected_offset(lane, offset):
    """把窗口报告的文件偏移作为输入，核对该通道的 #2 记录头、元数据和原包。"""
    segment, expected_metadata, expected_packet = lane
    with segment.open('rb') as source:
        assert 176 <= offset < segment.stat().st_size, (segment, offset)
        source.seek(offset)
        header = source.read(36)  # Stored v1 32 字节记录头及 4 字节元数据长度。
        length, record_type, schema, _, _, sequence = struct.unpack_from('<IHHIIQ', header)
        metadata_size, = struct.unpack_from('<I', header, 32)
        assert (record_type, schema, sequence) == (3, 1, 2), (segment, offset, sequence)
        assert length == len(header) + metadata_size + len(expected_packet), (segment, offset, length)
        assert json.loads(source.read(metadata_size)) == expected_metadata
        assert source.read(len(expected_packet)) == expected_packet


def verify_qt(manifest, identity, title, pid, lanes):
    """传入同一 CLI 采样，用正式 Qt 检查两个独立来源筛选，返回两条选中偏移。"""
    sample_id = identity['sampleId']
    with test_window() as client:
        nodes = open_project_sample(client, manifest, sample_id, title=title)
        # 等待完整回放而不是采样选择触发的单段快速预览。
        until(nodes, lambda values: any(node['visible'] and all(fragment in node['name'] for fragment in (
            'API (raw)', 'ETW (raw-etw)', '已验证至第 2 段。', '已验证至第 1 段。',
        )) and node['name'].count('已核验终段。') == 2 for node in values))
        table = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QTableView'
                       and {'PID', 'TID', '事件'} <= set(read_table(client, node)['headers']))
        full = read_table(client, table)  # 取消筛选后应完整恢复同一窗口。
        assert full['row_total'] >= API_COUNT + ETW_COUNT, full
        api = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QCheckBox' and node['name'] == 'API')
        etw = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QCheckBox' and node['name'] == 'ETW')
        assert api['enabled'] and etw['enabled'], (api, etw)

        def toggle(source, enabled):
            """设置一个正式来源控件；结果另由表模型核对。"""
            dispatch(client, 'set_field', object_id=source['id'], value=enabled, confirmed=True)

        def fields(stream):
            """读取该通道的可见已选详情，兼容共享详情模型的分组与平铺。"""
            for view in nodes():
                if not view['visible'] or view['type'] != 'item_view' or view['id'] == table['id']:
                    continue
                rows = read_table(client, view)['rows']
                for index, row in enumerate(rows):
                    if row and row[0] in ('归档 API 线索', '归档记录'):
                        rows = read_table(client, view, [index])['rows']
                        break
                values = {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}
                if values.get('归档原始通道') == stream:
                    return values
            return {}

        def verify_source(stream, count, event_prefix):
            """核对筛选后所有可见行的事件及 PID，再回读首条的正式选中详情。"""
            model = until(lambda: read_table(client, table), lambda value: value['row_total'] == count)
            event_col, pid_col = (model['headers'].index(key) for key in ('事件', 'PID'))
            assert len(model['rows']) == count and all(
                str(row[event_col]).startswith(event_prefix) and str(row[pid_col]) == str(pid)
                for row in model['rows']), model
            dispatch(client, 'select_row', object_id=table['id'], row=0, revision=model['revision'], confirmed=True)
            selected = until(lambda: fields(stream), lambda value: value.get('记录序号') == '2')
            assert (selected['采样 ID'], selected['归档段号'], selected['来源头 PID']) == (sample_id, '1', str(pid)), selected
            assert selected['事件'] == str(model['rows'][0][event_col]), selected
            _, metadata, packet = lanes[stream]
            if stream == 'raw':
                assert selected['线索类别'] == 'memory-write' and selected['源归档行号'] == metadata['sourceSequence'], selected
                assert selected['API 原包前缀（十六进制）'] == packet[:64].hex(' '), selected
            else:
                assert selected['ETW 来源代次'] == metadata['sourceEpoch'], selected
                assert selected['ETW 字节预览（十六进制）'] == packet.hex(' '), selected
            offset = int(selected['文件偏移（字节）'])  # 用实际选中详情中的文件偏移核对原包。
            verify_selected_offset(lanes[stream], offset)
            return offset

        toggle(api, True)
        api_offset = verify_source('raw', API_COUNT, API_EVENT)
        toggle(etw, True)
        until(lambda: read_table(client, table), lambda value: value['row_total'] == API_COUNT + ETW_COUNT)
        toggle(api, False)
        etw_offset = verify_source('raw-etw', ETW_COUNT, 'ETW 事件 ')
        toggle(etw, False)
        until(lambda: read_table(client, table), lambda value: value['rows'] == full['rows'])
    return {'raw': api_offset, 'raw-etw': etw_offset}


def verify_light(identity, lanes):
    """传入 Qt 同一采样及段，复用正式 Light 打开和恢复配置，返回两条选中偏移。"""
    offsets = {}  # 回调填入界面报告的两个物理通道偏移。
    with (RELEASE / 'KswordARKLight.exe').open('rb') as image:
        print(f'LIGHT_SHA256={hashlib.file_digest(image, "sha256").hexdigest()}', flush=True)

    def verify(_process, page, records, detail, status, api, replay, _retry, item_count):
        """仅执行项目回放和来源筛选，不进入 Light 既有单来源验收分支。"""
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        wait_for('Light terminal checkpoints for both lanes', lambda: (
            f"混采回放 · {identity['sampleId']}" in text(status)
            and '被动 API · raw/2' in text(status) and 'ETW · raw-etw/1' in text(status)
            and text(status).count('终态检查点已验证') == 2))
        full = item_count()
        etw = control(page, 58309)  # Light 的现有 ETW 来源按钮。
        assert full >= API_COUNT + ETW_COUNT and all(gui.IsWindowEnabled(hwnd) for hwnd in (api, etw))

        def toggle(hwnd, checked):
            """按需切换来源按钮，回读原生选中状态。"""
            target = con.BST_CHECKED if checked else con.BST_UNCHECKED
            if gui.SendMessage(hwnd, con.BM_GETCHECK, 0, 0) != target:
                gui.SendMessage(hwnd, con.BM_CLICK, 0, 0)
            assert gui.SendMessage(hwnd, con.BM_GETCHECK, 0, 0) == target

        def verify_source(stream, count):
            """选择筛选后的首行，使用详情的通道、序号、原包和文件偏移对账。"""
            assert item_count() == count, (stream, item_count(), text(status))
            gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
            coordinate = f'归档坐标：{stream}/1 #2\r\n'
            selected = wait_for(coordinate.strip(), lambda: text(detail) if coordinate in text(detail) else '')
            assert gui.SendMessage(records, 0x100C, -1, 0x0002) == 0  # LVM_GETNEXTITEM / LVNI_SELECTED
            assert f"当前归档 · 采样：{identity['sampleId']}\r\n" in selected
            assert f"项目：{identity['projectId']}\r\n" in selected
            _, metadata, packet = lanes[stream]
            if stream == 'raw':
                assert f'\r\n{API_EVENT}\r\n' in selected and '（memory-write）' in selected, selected
                assert f"源归档行号：{metadata['sourceSequence']}\r\n" in selected, selected
            else:
                assert '\r\nETW 事件 ' in selected and metadata['sourceEpoch'] in selected, selected
                assert re.search(r'"headerPid"\s*:\s*' + str(metadata['headerPid']) + r'\b', selected), selected
            assert packet[:128].hex(' ') in selected, selected  # API 原包也包含已冻结的 PID。
            offset = int(selected.split('文件字节偏移：', 1)[1].split('\r\n', 1)[0])
            verify_selected_offset(lanes[stream], offset)
            offsets[stream] = offset

        toggle(etw, False)
        toggle(api, True)
        verify_source('raw', API_COUNT)
        toggle(etw, True)
        assert item_count() == API_COUNT + ETW_COUNT
        toggle(api, False)
        verify_source('raw-etw', ETW_COUNT)
        toggle(etw, False)
        assert item_count() == full

    preview(lanes['raw'][0], check_project_replay=verify)
    return offsets


def main():
    """接收现有 Release 清单和采样 ID；GUI 退出、配置恢复及项目不变后才打印通过。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path, help='现有 CLI 混采项目的 project.ksaproj')
    parser.add_argument('sample_id', type=UUID, help='原 CLI 回执中的唯一采样 ID')
    args = parser.parse_args()
    require_isolated_desktop()
    manifest = args.manifest.absolute()  # 先检查原路径，再拒绝重解析路径和非正式 Release 路径。
    assert manifest.is_relative_to(RELEASE) and manifest.name == 'project.ksaproj', manifest
    check_location(manifest)
    assert manifest.is_file(), f'保留的 CLI 混采项目不存在：{manifest}'

    project = manifest.parent
    before = fingerprint(project)  # 先记录完整项目，包含清单、采样、所有通道和检查点。
    identity, title, pid, lanes = archive_expectations(manifest, str(args.sample_id))
    try:
        qt_offsets = verify_qt(manifest, identity, title, pid, lanes)
        assert fingerprint(project) == before, 'Qt 回放后项目内容或文件身份改变'
        print(f"QT_MIXED_ARCHIVE=PASS SAMPLE={identity['sampleId']} OFFSETS={qt_offsets}", flush=True)
        light_offsets = verify_light(identity, lanes)
        assert qt_offsets == light_offsets, (qt_offsets, light_offsets)
    finally:
        assert fingerprint(project) == before, '回放前后项目内容或文件身份改变'
        print(f'PROJECT_UNCHANGED=True PROJECT_ENTRIES={len(before)}', flush=True)
    print(f"LIGHT_MIXED_ARCHIVE=PASS SAMPLE={identity['sampleId']} OFFSETS={light_offsets}", flush=True)
    print(json.dumps(dict(identity, manifest=str(manifest), archivedPid=pid, apiRows=API_COUNT, etwRows=ETW_COUNT,
                          coordinates={f'{stream}/1 #2': offset for stream, offset in qt_offsets.items()},
                          captureStarted=False, qtAndLightSettingsRestored=True), ensure_ascii=False), flush=True)
    print('QT_LIGHT_MIXED_PASSIVE_ARCHIVE=PASS', flush=True)


if __name__ == '__main__':
    main()
