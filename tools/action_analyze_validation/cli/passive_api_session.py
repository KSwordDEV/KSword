"""用正式 CLI 验证显式授权的本地合成归档跟随、原包与停止边界。"""

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
from runpy import run_path
import struct
import subprocess
import sys
import time

# 独立运行和桌面调用共用同一个源码规则库读侧。
sys.path.insert(1, str(Path(__file__).resolve().parents[1]))
from api_evidence import archive_line, packet
from api_rule_profile import behavior_rule
from continuous_etw import cleanup_child, shutdown
from live_etw import CLI, call, controller, decode_raw
from project_v1 import owned_project_path
from smoke import SCHEMAS


CREATION = '134400565183024180'  # 合成归档中声明的调用方创建时间。
SESSION_ID = 1234  # packet() 写入相同的原包会话字段。


def make_rows(*, behavior=False):
    """返回六条相互可辨的原始包及其生产形状 JSONL，不执行包内描述。"""
    packets = []  # 用时间戳区分包，验证归档顺序时比较完整字节。
    rows = []  # 同一个文件按三批追加的六个已换行记录。
    for sequence in range(1, 7):
        # 第 2 条与末条有显式拒绝返回；第 3 条代码相同但无返回标记。
        marker = 0x52545631 if behavior and sequence in (2, 6) else 0
        status = 5 if behavior and sequence in (2, 3, 6) else 0
        wire = bytearray(packet('KernelBase', 'WriteProcessMemory', 8, marker=marker, status=status))
        struct.pack_into('<Q', wire, 16, int(CREATION) + sequence)
        packets.append(bytes(wire))
        rows.append(archive_line(sequence, wire, pid=42, processCreation100ns=CREATION))
    return packets, rows


def wait_for_segment(directory, ordinal):
    """等待后台发布检查点，等待期间不发送任何 CLI 请求。"""
    path = directory / f'{ordinal:020d}.json'  # raw 存在可能早于检查点发布。
    deadline = time.monotonic() + 10  # 子进程失败时有限退出。
    while not path.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert path.is_file(), path


def remove_plan_declaration(raw):
    """在自有夹具中移去新计划字段，保留合法的单块 Stored 封装。"""
    crc32c = run_path(str(SCHEMAS / 'check_base_v1.py'))['crc32c']  # 仓库独立参考算法。
    data = bytearray(raw)  # 仅修改传入段的临时副本。
    block, record = 96, 176  # 首块和首条 Stored 记录偏移。
    record_bytes, = struct.unpack_from('<I', data, record)
    metadata_bytes, = struct.unpack_from('<I', data, record + 32)
    declaration = b',"checkpointRequired":true'  # 新版本附加的唯一计划字段。
    start = data.index(declaration, record + 36, record + 36 + metadata_bytes)
    data[start:start + len(declaration)] = b' ' * len(declaration)
    struct.pack_into('<I', data, record + 24, crc32c(data[record + 32:record + record_bytes]))
    struct.pack_into('<I', data, record + 28, crc32c(data[record:record + 28]))
    payload_crc = crc32c(data[record:])  # CLI API 段只写一个块。
    struct.pack_into('<II', data, block + 64, payload_crc, payload_crc)
    struct.pack_into('<I', data, block + 76, crc32c(data[block:block + 76]))
    return bytes(data)


def verify_readback(project, identity, opened, segments, markers, *, verify_graph=False):
    """用新只读 CLI 核对提交水位及缺标记、坏尾、断链回执。"""
    sample = dict(identity, sampleId=opened['sampleId'], includeCapture=True)  # 历史查询仅绑定已登记采样。
    with ExitStack() as children:
        reader = controller('offline')  # 文件重开验证，不依赖原会话或源路径。
        children.callback(cleanup_child, reader)
        call(reader, 'reopen', 'project.open', {'path': str(project)})

        def query(request, ordinal):
            """每次以新 ID 读取指定段，绕过请求回执缓存。"""
            return call(reader, request, 'sample.query', dict(sample, captureOrdinal=str(ordinal)))['captureArchive']

        def graph(request, ordinal, error=None, **options):
            """按已登记采样及 raw 段请求图页，可核对失败回执。"""
            params = dict(identity, sampleId=opened['sampleId'], stream='raw', ordinal=str(ordinal), view='graph')
            return call(reader, request, 'archive.inspect', params | options, error=error)

        captures = []  # 保存四个段的独立核验回执，用于后续精确比较。
        previous_hash = None  # 首段以前没有已提交原始前缀。
        for ordinal, (segment, marker_path) in enumerate(zip(segments, markers), 1):
            marker = json.loads(marker_path.read_bytes())  # 发布的唯一标记。
            capture = query(f'segment-{ordinal}', ordinal)
            final = ordinal == len(segments)
            assert marker['kind'] == 'api-archive-checkpoint-v1' and marker['previousRawSha256'] == previous_hash, marker
            assert capture['kind'] == 'api-archive-follow' and capture['status'] == 'readback-verified', capture
            assert capture['checkpoint'] == 'verified' and capture['segmentOrdinal'] == str(ordinal), capture
            assert capture['checkedBytes'] == marker['raw']['endOffset'] == str(segment.stat().st_size), capture
            assert capture['sha256'] == marker['raw']['sha256'] == hashlib.sha256(segment.read_bytes()).hexdigest(), capture
            assert capture['lastSequence'] == marker['raw']['lastSequence'], capture
            assert capture['planRawSequence'] == marker['planRawSequence'], capture
            assert capture['previousSourceSequence'] == str(2 * (ordinal - 1)), capture
            assert capture['lastSourceSequence'] == str(min(6, 2 * ordinal)), capture
            assert capture['finalSegment'] is final and capture['sourceCoverage'] == 'unknown', capture
            assert capture['terminal'] == ({'stopReason': 'requested', 'sourceState': 'cutoff',
                                            'sourceCutoffReached': True, 'partialLineBytes': '0'} if final else None)
            captures.append(capture)
            previous_hash = capture['sha256']
        assert query('beyond-terminal', 5)['status'] == 'missing'
        assert query('bounded-history', 129)['status'] == 'limit-exceeded'

        if verify_graph:
            # 独立分页绑定项目、段及同一提交摘要。终段仍可核验但没有 API 原包。
            first_page = graph('graph-first', 3, limit=1)
            assert (first_page['archiveSource'], first_page['observationCount'], first_page['finalSegment']) == (
                'api-follow-checkpoint', '2', False), first_page
            digest = captures[2]['sha256']  # CLI 的已核验水位给出同一前缀摘要。
            assert first_page['prefix']['sha256'] == digest and first_page['nextAfterSequence'] == '8', first_page
            assert first_page['tree'] == {'unresolvedCandidates': ['8'], 'contextObservations': []}, first_page
            second_page = graph('graph-after', 3, afterSequence='8', expectedSha256=digest)
            assert second_page['nextAfterSequence'] is None and second_page['nodes'] == second_page['relations'] == [], second_page
            assert second_page['tree'] == {'unresolvedCandidates': ['9'], 'contextObservations': []}, second_page
            row, = second_page['observations']  # 第 6 行、第三段、全局原始序号 9。
            assert (row['sourceSequence'], row['raw']['segmentOrdinal'], row['raw']['recordSequence']) == ('6', '3', '9'), row
            assert row['execution'] is None and row['finding'] is None, row
            terminal = graph('graph-terminal', 4)
            assert terminal['finalSegment'] and not terminal['observations'], terminal
            assert terminal['tree'] == {'unresolvedCandidates': [], 'contextObservations': []}, terminal
            graph('graph-beyond-terminal', 5, error='project-data-not-found')

        # 后段标记存在也不能越过第 2 段未发布的缺口。
        marker_two = markers[1].read_bytes()
        markers[1].unlink()
        try:
            missing = query('skip-missing', 4)
            assert (missing['status'], missing['failedOrdinal'], missing['lastVerifiedOrdinal'],
                    missing['lastSourceSequence']) == ('pending', '2', '1', '2'), missing
            if verify_graph:
                graph('graph-after-gap', 3, error='project-data-not-found')
        finally:
            markers[1].write_bytes(marker_two)

        # 原始块仍完整时，也必须核对本段的散列及上次验过的摘要。
        wrong_chain = json.loads(marker_two)
        wrong_chain['previousRawSha256'] = '0' * 64
        wrong_hash = json.loads(marker_two)
        wrong_hash['raw']['sha256'] = '0' * 64
        try:
            for request, rewritten in (('wrong-chain', wrong_chain), ('wrong-prefix-hash', wrong_hash)):
                markers[1].write_text(json.dumps(rewritten) + '\n', encoding='utf-8', newline='\n')
                broken = query(request, 4)
                assert (broken['status'], broken['failedOrdinal'], broken['lastVerifiedOrdinal']) == ('invalid', '2', '1'), broken
        finally:
            markers[1].write_bytes(marker_two)

        # 标记端点之前的截断无效，端点之后的坏尾不改变水位。
        second = segments[1].read_bytes()
        try:
            segments[1].write_bytes(second[:-1])
            broken = query('truncated-prefix', 4)
            assert (broken['status'], broken['failedOrdinal'], broken['lastVerifiedOrdinal']) == ('invalid', '2', '1'), broken
            segments[1].write_bytes(second + b'bad-tail')
            assert query('outside-prefix', 2) == captures[1]
        finally:
            segments[1].write_bytes(second)

        # 标记仍在但对应 raw 被移走，必须报告依赖损坏并保留首段水位。
        segments[1].unlink()
        try:
            missing = query('missing-published-raw', 4)
            assert (missing['status'], missing['failedOrdinal'], missing['lastVerifiedOrdinal']) == ('invalid', '2', '1'), missing
        finally:
            segments[1].write_bytes(second)

        # 首标记缺失时区分新档与具备完整旧尾记的无标记跟随档。
        original_segments = [path.read_bytes() for path in segments]
        original_markers = [path.read_bytes() for path in markers]
        try:
            markers[0].unlink()
            assert query('missing-first-marker', 4)['status'] == 'pending'
            for path in markers[1:]:
                path.unlink()
            for path, segment_bytes in zip(segments, original_segments):
                path.write_bytes(remove_plan_declaration(segment_bytes))
            legacy = query('legacy-with-terminal', 4)
            assert (legacy['status'], legacy['lastVerifiedOrdinal']) == ('legacy-unpublished', '0'), legacy
        finally:
            for path, segment_bytes in zip(segments, original_segments):
                path.write_bytes(segment_bytes)
            for path, marker_bytes in zip(markers, original_markers):
                path.write_bytes(marker_bytes)
        assert query('restored', 4) == captures[-1]
        assert shutdown(reader) == 0


def run(project, *, verify_graph=False, behavior=False):
    """创建专用项目并核对提交与截止。返回样本 ID、段、标记及原包供桌面共用。"""
    packets, rows = make_rows(behavior=behavior)  # 同一文件的原始输入与预期包。
    if behavior:
        behavior_id = 'ksword.behavior.memory-write-access-denied-return.v1'  # 夹具正例对应的规则。
        definition = behavior_rule(behavior_id)
        explanation = {'ruleId': behavior_id, 'evidence': 'reported-api-return',
                       'summary': definition['summary'], 'summaryZh': definition.get('summaryZh')}
    source = project.parent / 'events.jsonl'  # 只使用项目夹具所在的固定目录。
    with source.open('xb') as stream:
        stream.write(b''.join(rows[:2]))
    with ExitStack() as children:
        cli = controller('r3')  # 正式 CLI，仅跟随文件，不打开目标进程。
        children.callback(cleanup_child, cli)
        created = call(cli, 'create', 'project.create', {'path': str(project),
                       'settings': {'title': 'Passive API regression', 'notes': ''}})
        identity = {'projectId': created['projectId']}  # 所有后续操作保留同一个已打开项目。
        settings = created['settings'] | {'breakpointDefinitions': []}  # 显式扩展项目格式，空集合不携带停点意图。
        saved = call(cli, 'save', 'project.save', identity | {'expectedRevisionId': created['revisionId'],
                     'settings': settings})
        assert saved['settings'] == settings and saved['revisionId'] != created['revisionId'], saved
        revision = {'expected': {'revisionId': saved['revisionId']}}  # 冻结创建采样时的扩展修订。
        api = {'path': str(source), 'sessionIdentity': str(SESSION_ID), 'authorized': True}  # 显式输入授权。
        options = dict(identity, title='Passive API fixture', pid=42, creationFileTime=CREATION, apiArchive=api)
        call(cli, 'denied', 'session.open', options | {'apiArchive': api | {'authorized': False}},
             error='source-not-authorized', **revision)
        opened = call(cli, 'open', 'session.open', options, **revision)  # 本次活会话回执。
        assert opened['capture'] == 'active' and opened['plan']['durationMs'] == 0 and opened['plan']['checkpointRequired'], opened
        assert opened['plan']['rulePresetSet'] == opened['rules']['presetSet'] == 'ksword.api.behavior-presets.v1'
        assert opened['rules']['matchedRows'] == '0' and opened['rules']['latest'] is None
        owner = {'session': opened['session']}  # 停止与关闭只提交给本次会话。
        sample = project / 'samples' / opened['sampleId']  # 实际采样根目录。
        raw = sample / 'raw'  # 输入原包的已写段。
        checkpoints = sample / 'checkpoints'  # 持久提交标记目录。

        # 查询完全空闲时提交三批，其后再检查当前状态和尾读终点。
        wait_for_segment(checkpoints, 1)
        first = call(cli, 'rules/1', 'session.query', {}, **owner)  # 首次发布后的已提交命中。
        assert first['rules']['matchedRows'] == '2', first['rules']
        if behavior:
            assert first['rules']['latest'].get('behavior') == explanation, first['rules']
        findings = call(cli, 'findings/active', 'session.findings', {}, **owner)  # 只读复用初次提交的规则视图。
        assert findings == {'session': owner['session'], 'sampleId': opened['sampleId'],
                            'state': first['rules']['state'], 'source': 'api-archive-follow',
                            'observations': '2', 'latest': first['rules']['latest']}, findings
        for ordinal, batch in ((2, rows[2:4]), (3, rows[4:])):
            with source.open('ab') as stream:
                stream.write(b''.join(batch))
            wait_for_segment(checkpoints, ordinal)
            committed = call(cli, f'rules/{ordinal}', 'session.query', {}, **owner)  # 已发布段的累计计数。
            assert committed['rules']['matchedRows'] == str(ordinal * 2), committed['rules']
            if behavior and ordinal == 2:
                assert 'behavior' not in committed['rules']['latest'], committed['rules']
        active = call(cli, 'status', 'session.query', {}, **owner)  # 以这一代次发起显式停止。
        assert active['rules'] == committed['rules']
        expected_latest = {'ruleId': 'ksword.api.memory-write-observed.v1',
                           'segmentOrdinal': '3', 'rawSequence': '9', 'sourceSequence': '6'}
        if behavior:
            expected_latest['behavior'] = explanation
        assert active['rules']['latest'] == expected_latest, active['rules']
        stopped = call(cli, 'stop', 'session.stop', {}, expected={'stateRevision': active['stateRevision']}, **owner)
        assert stopped['capture'] == 'stopped' and stopped['stopReason'] == 'requested', stopped
        assert stopped['archive']['recordedRows'] == stopped['source']['validatedRows'] == '6', stopped
        assert stopped['source']['cutoffBytes'] == str(sum(map(len, rows))) and stopped['source']['cutoffReached'], stopped
        assert stopped['source']['coverage'] == 'unknown' and stopped['source']['writerReceipt'] is None, stopped
        assert stopped['rules'] == active['rules'] and stopped['rules']['coverage'] == 'unknown'
        if verify_graph:
            assert stopped['source']['diagnosis'] == {
                'input': 'cutoff', 'prefixIdentity': 'prefix-consistent', 'producerConnection': 'unknown',
                'sessionReadySequence': None, 'captureNotice': None, 'captureNoticeSequence': None,
                'partialNoticeSequence': None, 'agentLoss': 'unknown',
            }, stopped

        # 停止后的源文件可继续追加；之前提交的项目段及其水位保持不变。
        segments = sorted(raw.glob('*.ksaseg'))  # 原始记录的生产封装。
        assert len(segments) == int(stopped['archive']['segmentOrdinal']) == 4, segments
        with source.open('ab') as stream:
            stream.write(archive_line(7, packets[-1], pid=42, processCreation100ns=CREATION))
        terminal = call(cli, 'status-after-stop', 'session.query', {}, **owner)  # 终态后的只读核对。
        assert terminal['archive'] == stopped['archive'] and terminal['rules'] == stopped['rules']
        findings = call(cli, 'findings/stopped', 'session.findings', {}, **owner)  # 查询不计入停止后追加的输入行。
        assert findings['observations'] == '6' and findings['latest'] == expected_latest, findings
        assert call(cli, 'close', 'session.close', {}, expected={'stateRevision': stopped['stateRevision']}, **owner)['closed']
        frozen = call(cli, 'frozen', 'sample.query', identity | {'sampleId': opened['sampleId']})  # 回读采样描述及冻结设置。
        assert frozen['frozenSettings'] == settings and frozen['revisionId'] == saved['revisionId'], frozen
        assert shutdown(cli) == 0

        recorded = []  # 由磁盘独立解码出的原包，按项目全局封装序号拼接。
        sequence = 1  # 下一段首次出现的连续封装序号。
        for path in segments:
            decoded, _ = decode_raw(path, sequence)
            sequence += len(decoded)
            assert decoded[0][0] == opened['plan'] and decoded[0][1] == b''
            recorded.extend((metadata['sourceSequence'], wire) for metadata, wire in decoded
                            if metadata['kind'] == 'api-archive-packet-v1')
        assert recorded == [(str(index), wire) for index, wire in enumerate(packets, 1)]
        assert decoded[-1][0]['kind'] == 'api-archive-follow-end-v1'
        markers = sorted(checkpoints.glob('*.json'))  # 仅检查本次采样已发布段。
        assert len(markers) == len(segments), markers
        source.unlink()  # 项目通过原包独立重开，无需再次访问输入文件。
        verify_readback(project, identity, opened, segments, markers, verify_graph=verify_graph)
        if behavior:
            # 让正式离线命令按同一采样重算，并以保存的坐标比对正例和缺返回标记的负例。
            replay = subprocess.run([CLI, 'analyze', 'replay-api-rules', '--project', project, '--sample',
                                     opened['sampleId'], '--profile', 'by-category', '--json'],
                                    capture_output=True, timeout=15)
            assert replay.returncode == 0, (replay.returncode, replay.stderr, replay.stdout)
            matches = json.loads(replay.stdout)['data']['matches']
            assert [row['sourceSequence'] for row in matches] == list(map(str, range(1, 7))), matches
            hits = [row for row in matches if 'behavior' in row]
            assert [(row['sourceSequence'], row['raw']['segment'], row['raw']['sequence'], row['behavior'])
                    for row in hits] == [('2', '1', '3', explanation), ('6', '3', '9', explanation)], matches
            print(f'CLI_API_BEHAVIOR_EXPLANATION=PASS SAMPLE={opened["sampleId"]} RAW=1#3,3#9', flush=True)
    print(json.dumps({'cliSha256': hashlib.sha256(CLI.read_bytes()).hexdigest(),
                      'sampleId': opened['sampleId'], 'segments': len(segments), 'rows': len(recorded),
                      'cutoffBytes': stopped['source']['cutoffBytes']}), flush=True)
    return opened['sampleId'], segments, markers, packets


if __name__ == '__main__':
    with owned_project_path() as project:
        run(project, verify_graph=True, behavior=True)
    print('CLI_PASSIVE_API_SESSION=PASS', flush=True)
