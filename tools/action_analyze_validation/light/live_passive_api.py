"""Exercise Light's passive file follow on an isolated desktop with synthetic JSONL only."""

import hashlib
import json
import re
import struct
import sys
from uuid import UUID

from live_project_preview import (BINARY, CREATE_TITLE, RELEASE, con, control, gui, light_window,
                                  require_isolated_desktop, set_text, text, wait_for)
from api_rule_profile import behavior_rule, display_summary
from continuous_etw import owned_scratch
from live_etw import decode_raw
from passive_api_session import CREATION, SESSION_ID, make_rows


SCRATCH = RELEASE / 'ActionAnalyzeLightPassiveApiValidation'
BROWSE_TITLE = '选择已授权的本地 API JSONL'
API_CONTROLS = {'mode': 58326, 'api_pid': 58327, 'session': 58328, 'creation': 58329,
                'browse_api': 58330, 'api_path': 58331, 'replay_current': 58321, 'api_only': 58313}
PRESET = 'ksword.api.behavior-presets.v1'
RULE = 'ksword.api.memory-write-observed.v1'
COORDINATES = ((1, 2), (1, 3), (2, 5), (2, 6))


def read_archive(manifest, sample_id, packets, input_bytes):
    """Check the committed chain, frozen source identity, all original packets and the terminal cutoff."""
    project = json.loads(manifest.read_bytes())
    sample = manifest.parent / 'samples' / sample_id
    description_hash = hashlib.sha256((sample / 'sample.json').read_bytes()).hexdigest()
    assert {path.name for path in sample.parent.iterdir()} == {sample_id}
    segments = sorted((sample / 'raw').glob('*.ksaseg'))
    markers = sorted((sample / 'checkpoints').glob('*.json'))
    assert len(segments) == len(markers) == 3, (segments, markers)

    recorded, hashes = [], []
    plan = None
    sequence = 1
    previous_source = 0
    for ordinal, (segment, marker_path) in enumerate(zip(segments, markers), 1):
        assert segment.stem == marker_path.stem == f'{ordinal:020d}'
        marker = json.loads(marker_path.read_bytes())
        decoded, digest = decode_raw(segment, sequence)
        final = ordinal == 3
        assert len(decoded) == (2 if final else 3), decoded
        assert (marker['kind'], marker['projectId'], marker['sampleId'], marker['descriptionHash']) == (
            'api-archive-checkpoint-v1', project['projectId'], sample_id, description_hash), marker
        assert (marker['generation'], marker['planRawSequence'], marker['previousRawSha256'],
                marker['previousSourceSequence'], marker['lastSourceSequence'], marker['finalSegment']) == (
            str(ordinal), str(sequence), hashes[-1] if hashes else None,
            str(previous_source), str(min(2 * ordinal, 4)), final), marker
        assert marker['raw'] == {'block': '1', 'endOffset': str(segment.stat().st_size),
                                 'lastSequence': str(sequence + len(decoded) - 1), 'sha256': digest}, marker
        hashes.append(digest)

        if plan is None:
            plan = decoded[0][0]
            assert plan['kind'] == 'api-archive-follow-plan-v1' and plan['session']['id'] == sample_id, plan
            assert plan['projectId'] == project['projectId'] and plan['revisionId'] == project['currentRevisionId'], plan
            assert (plan['readerPid'], plan['readerCreation100ns'], plan['sessionIdentity'],
                    plan['checkpointRequired'], plan['rulePresetSet']) == (42, CREATION, str(SESSION_ID), True, PRESET), plan
        assert decoded[0] == (plan, b'')

        for raw_sequence, (metadata, wire) in enumerate(decoded[1:], sequence + 1):
            if final:
                assert not wire, decoded
                assert (metadata['kind'], metadata['stopReason']) == ('api-archive-follow-end-v1', 'requested'), metadata
                source = metadata['source']
                assert (source['state'], source['cutoffReached'], source['cutoffBytes'], source['validatedRows'],
                        source['partialLineBytes'], source['coverage'], source['writerReceipt']) == (
                    'cutoff', True, str(input_bytes), '4', '0', 'unknown', None), source
            else:
                previous_source += 1
                assert metadata == {'kind': 'api-archive-packet-v1', 'sourceSequence': str(previous_source),
                                    'readerCreation100ns': CREATION}, metadata
                recorded.append((ordinal, raw_sequence, wire))
        sequence += len(decoded)

    assert recorded == [(ordinal, sequence, wire) for (ordinal, sequence), wire in zip(COORDINATES, packets)]
    return project['projectId'], segments, hashes


def capture(page, project, source, rows):
    manifest = project / 'project.ksaproj'
    page.default_page()
    page.browse('create', CREATE_TITLE, project)
    page.wait_status('empty owned project', lambda value: '已新建工程 · ' in value
                     and '工程尚无采样' in value and str(manifest).casefold() in value.casefold())

    page.controls.update({name: control(page.page, identifier) for name, identifier in API_CONTROLS.items()})
    assert all(page.controls.values()), page.controls
    page.click('switch')
    assert gui.SendMessage(page.controls['mode'], con.BM_GETCHECK, 0, 0) == con.BST_UNCHECKED
    page.click('mode')
    assert gui.SendMessage(page.controls['mode'], con.BM_GETCHECK, 0, 0) == con.BST_CHECKED
    assert text(page.controls['start']) == '开始跟随' and not gui.IsWindowVisible(page.controls['provider'])
    for name, value in (('api_pid', '42'), ('session', str(SESSION_ID)), ('creation', CREATION)):
        assert gui.IsWindowVisible(page.controls[name]), name
        set_text(page.controls[name], value)
    page.browse('browse_api', BROWSE_TITLE, source)
    assert text(page.controls['api_path']).casefold() == str(source).casefold()
    page.click('start')

    def committed(count, state, segment):
        rule_segment, rule_sequence = COORDINATES[count - 1]
        expectations = (f'被动 API · {state} · 活连接与覆盖未核实', f'已核验 {count} 行 · 已提交 {count} 包 · raw/{segment}',
                        f'规则命中 {count} · {RULE} · raw/{rule_segment} #{rule_sequence}（源行 {count}）',
                        '首个 API 原包：raw/1 #2', f'源会话 {SESSION_ID} · PID 42 · 创建 FILETIME {CREATION}')
        return page.wait_status(f'{state}: committed {count} packets and rules',
                                lambda value: all(part in value for part in expectations))

    first = committed(2, '正在跟随文件', 1)
    # 首批末条带显式返回；原生状态文档的释义和坐标属于同一次发布。
    behavior_id = 'ksword.behavior.memory-write-access-denied-return.v1'  # 本夹具指定的拒绝规则。
    explanation = (behavior_id, 'reported-api-return', display_summary(behavior_rule(behavior_id)))
    assert all(part in first for part in explanation), first
    sample_id = re.search(r' · 采样 ([0-9a-f-]{36})', first)[1]
    assert str(UUID(sample_id)) == sample_id
    sample = project / 'samples' / sample_id
    assert (sample / 'checkpoints/00000000000000000001.json').is_file()
    with source.open('ab') as stream:
        stream.write(b''.join(rows[2:]))
    second = committed(4, '正在跟随文件', 2)
    assert sample_id in second and (sample / 'checkpoints/00000000000000000002.json').is_file()
    assert not any(part in second for part in explanation), second
    print(f'LIGHT_LIVE_API_BEHAVIOR=PASS SAMPLE={sample_id} POSITIVE=1#3:2 CLEARED=2#6:4', flush=True)
    assert page.row_count() == 0, 'Passive raw packets belong to project replay, not the live list'
    page.click('stop')
    stopped = committed(4, '已停止', 3)
    assert not any(part in stopped for part in explanation), stopped
    assert sample_id in stopped and '源 cutoff' in stopped and not gui.IsWindowEnabled(page.controls['stop']), stopped
    assert text(page.controls['replay_current']) == '回放本次采样' and gui.IsWindowEnabled(page.controls['replay_current'])
    print('LIGHT_PASSIVE_API_RULES=2/4/4 LATEST=raw/2#6 SOURCE=4', flush=True)
    return manifest, sample_id


def replay(page, project_id, sample_id, segments, packets):
    """Use the actual replay button and tie every selected detail to the packet at its displayed offset."""
    page.click('replay_current')
    last_bytes = segments[-1].stat().st_size
    page.wait_status('verified terminal passive replay', lambda value: sample_id in value and
                     f'被动 API 终态检查点已验证 · raw/3 {last_bytes} B' in value and page.row_count() == 8)
    assert set(page.sample_entries()) == {sample_id}
    page.click('api_only')
    assert page.row_count() == 4
    records, detail = (page.controls[name] for name in ('records', 'detail'))
    offsets = []
    for index, ((ordinal, raw_sequence), packet) in enumerate(zip(COORDINATES, packets), 1):
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME if index == 1 else con.VK_DOWN, 0)
        source_line = f'源归档行号：{index}\r\n'
        selected = wait_for(f'Light shows raw/{ordinal} #{raw_sequence}',
                            lambda: text(detail) if source_line in text(detail) else '')
        for expected in (f'当前归档 · 采样：{sample_id}', f'项目：{project_id}',
                         f'未解析候选 · raw/{ordinal} #{raw_sequence}', f'FILETIME：{int(CREATION) + index}',
                         f'规则 ID（细分）：{RULE}', '采集覆盖：未知', packet[:128].hex(' ')):
            assert expected in selected, selected
        position = re.search(rf'归档记录序号：{raw_sequence} +所属段号：{ordinal} +块号：1 +文件字节偏移：(\d+)', selected)
        assert position, selected
        offset = int(position[1])
        data = segments[ordinal - 1].read_bytes()
        length, kind, version, _, size, stored_sequence = struct.unpack_from('<IHHIIQ', data, offset)
        assert (kind, version, length, stored_sequence) == (3, 1, size + 32, raw_sequence)
        metadata_size, = struct.unpack_from('<I', data, offset + 32)
        start = offset + 36 + metadata_size
        assert data[start:offset + length] == packet, (ordinal, raw_sequence, offset)
        offsets.append(offset)
    return offsets


def main():
    require_isolated_desktop()
    if sys.flags.optimize:
        raise RuntimeError('Run with python -B so validation assertions remain enabled')
    binary_hash = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    all_packets, all_rows = make_rows(behavior=True)
    packets, rows = all_packets[:4], all_rows[:4]
    with owned_scratch(SCRATCH) as directory:
        source = directory / 'synthetic-events.jsonl'
        with source.open('xb') as stream:
            stream.write(b''.join(rows[:2]))
        with light_window() as page:
            manifest, sample_id = capture(page, directory / 'owned project', source, rows)
            project_id, segments, hashes = read_archive(manifest, sample_id, packets, sum(map(len, rows)))
            source.unlink()  # Replay now depends only on the committed project files.
            offsets = replay(page, project_id, sample_id, segments, packets)
            assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in segments] == hashes
        assert hashlib.sha256(BINARY.read_bytes()).hexdigest() == binary_hash
    print(f'LIGHT_PASSIVE_API=PASS SAMPLE={sample_id} RAW=1#2,1#3,2#5,2#6 '
          f'OFFSETS={",".join(map(str, offsets))} PACKETS=4 LIGHT_SHA256={binary_hash}', flush=True)


if __name__ == '__main__':
    main()
