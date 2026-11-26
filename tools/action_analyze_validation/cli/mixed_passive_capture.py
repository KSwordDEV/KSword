"""Validate one Release CLI sample with real owned ETW and synthetic API JSONL.

The existing file-I/O producer emits ETW only. The API input is generated test
data with matching identity declarations, not API Monitor telemetry or proof
that individual API and ETW records refer to the same operation.
"""

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
from pathlib import Path
from shutil import rmtree
import struct
import sys
import time

from api_evidence import archive_line, packet
from continuous_etw import check_scratch, cleanup_child, regular_identity, shutdown
from live_etw import CLI, PAYLOAD, PROVIDER, RELEASE, Child, call, controller, decode_raw
from passive_api_session import SESSION_ID


SCRATCH = RELEASE / 'ActionAnalyzeMixedPassiveCaptureValidation'
PRODUCER = Path(__file__).resolve().with_name('live_etw.py')
DURATION_MS = 12000
ETW_COUNT = 12  # One existing producer command: six writes and six reads.
API_INPUT = 'synthetic-jsonl-identity-scoped-not-live-api-telemetry'


@contextmanager
def owned_scratch(keep):
    check_scratch(SCRATCH)
    SCRATCH.mkdir(exist_ok=False)
    identity = regular_identity(SCRATCH)
    passed = False
    try:
        yield SCRATCH
        passed = True
    finally:
        if not (passed and keep):
            check_scratch(SCRATCH)
            assert SCRATCH.resolve(strict=True) == SCRATCH and regular_identity(SCRATCH) == identity
            for path in SCRATCH.rglob('*'):
                regular_identity(path)
            rmtree(SCRATCH)


def write_api_fixture(path, target):
    """Use the existing packet/JSONL encoder with the owned producer's identity."""
    pid, creation = target['pid'], target['creationFileTime']
    packets, lines = [], []
    for sequence, (status, returned) in enumerate(((0, 1), (5, 0)), 1):
        # Same allowlisted memory-write packet as the passive fixture; no address or real API call.
        wire = bytearray(packet('KernelBase', 'WriteProcessMemory', 8, marker=0x52545631,
                                status=status, returned=returned))
        struct.pack_into('<IIQ', wire, 8, pid, 0, int(creation) + sequence)
        packets.append(bytes(wire))
        lines.append(archive_line(sequence, wire, pid=pid, readerPid=pid, processCreation100ns=creation))
    original = b''.join(lines)
    with path.open('xb') as output:
        assert output.write(original) == len(original)
    return packets, original


def wait_active(cli, owner, deadline, label, ready):
    index = 0
    while True:
        report = call(cli, f'{label}-{index}', 'session.query', {}, **owner)
        assert report['capture'] == 'active', report
        if ready(report):
            return report
        assert time.monotonic() < deadline, report
        index += 1
        time.sleep(.05)


def stop_session(cli, owner, revision):
    cli.send(json.dumps(dict(schemaVersion=1, requestId='stop', method='session.stop', params={},
                             expected={'stateRevision': revision}, **owner)))
    line = cli.next_line()
    frame = json.loads(line)
    # Measure the compact JSON value as sent by the CLI, excluding the envelope and newline.
    if frame.get('type') == 'summary' and isinstance(frame.get('liveSession'), dict):
        key, label = 'liveSession', 'STOP_SUMMARY_LIVE_SESSION_UTF8_BYTES'
    elif (frame.get('type'), frame.get('requestId'), frame.get('error')) == ('response', 'stop', None) and isinstance(frame.get('result'), dict):
        key, label = 'result', 'STOP_RESULT_UTF8_BYTES'
    else:
        raise AssertionError(f'Unexpected session.stop frame: {line}')
    # These envelope fields precede any nested object that could reuse the same key.
    start = line.index(f',"{key}":') + len(key) + 4
    _, end = json.JSONDecoder().raw_decode(line, start)
    print(f'{label}={len(line[start:end].encode("utf-8"))}', flush=True)
    assert key == 'result', f'Unexpected session.stop frame: {line}'
    return frame['result']


def marker(sample, stream, ordinal, kind, stopped, description_hash):
    path = sample / stream / f'{ordinal:020d}.json'
    value = json.loads(path.read_bytes())
    assert (value['kind'], value['generation'], value['descriptionHash']) == (kind, str(ordinal), description_hash), value
    assert all(value[key] == stopped[key] for key in ('projectId', 'sampleId')), value
    return value


def verify_prefix(path, prefix):
    original = path.read_bytes()
    assert prefix['endOffset'] == str(len(original)), prefix
    assert prefix['sha256'] == hashlib.sha256(original).hexdigest(), prefix


def verify_archives(sample, stopped, packets, observed):
    description_hash = hashlib.sha256((sample / 'sample.json').read_bytes()).hexdigest()
    previous_hash, sequence = None, 1
    api_markers = []
    for ordinal in (1, 2):
        final = ordinal == 2
        checkpoint = marker(sample, 'checkpoints', ordinal, 'api-archive-checkpoint-v1', stopped, description_hash)
        raw = sample / 'raw' / f'{ordinal:020d}.ksaseg'
        verify_prefix(raw, checkpoint['raw'])
        rows, digest = decode_raw(raw, sequence)
        assert rows[0] == (stopped['plan'], b''), rows[0]
        assert checkpoint['planRawSequence'] == str(sequence), checkpoint
        sequence += len(rows)
        assert checkpoint['raw']['lastSequence'] == str(sequence - 1), checkpoint
        assert checkpoint['previousRawSha256'] == previous_hash and checkpoint['finalSegment'] is final, checkpoint
        assert checkpoint['previousSourceSequence'] == str(len(packets) if final else 0), checkpoint
        assert checkpoint['lastSourceSequence'] == str(len(packets)), checkpoint
        if final:
            _, (terminal, payload) = rows
            assert (terminal['kind'], terminal['stopReason'], payload) == ('api-archive-follow-end-v1', 'requested', b''), terminal
            assert terminal['source']['cutoffReached'] and terminal['source']['validatedRows'] == str(len(packets)), terminal
        else:
            assert rows[1:] == [({'kind': 'api-archive-packet-v1', 'sourceSequence': str(index),
                                  'readerCreation100ns': stopped['plan']['readerCreation100ns']}, wire)
                                for index, wire in enumerate(packets, 1)], rows[1:]
        previous_hash = digest
        api_markers.append(checkpoint)
    assert stopped['archive']['lastSequence'] == api_markers[-1]['raw']['lastSequence']
    assert stopped['archive']['flushedBytes'] == api_markers[-1]['raw']['endOffset']

    checkpoint = marker(sample, 'checkpoints-etw', 1, 'etw-terminal-checkpoint-v1', stopped, description_hash)
    filename = '00000000000000000001.ksaseg'
    raw = sample / 'raw-etw' / filename
    verify_prefix(raw, checkpoint['raw'])
    verify_prefix(sample / 'records-etw' / filename, checkpoint['records'])
    etw = stopped['etw']
    assert checkpoint['records']['lastSequence'] == '1', checkpoint
    assert checkpoint['raw']['endOffset'] == etw['archive']['flushedBytes'], checkpoint
    assert checkpoint['raw']['lastSequence'] == etw['archive']['lastSequence'] == str(observed + 2), checkpoint
    rows, _ = decode_raw(raw)
    assert len(rows) == observed + 2 and rows[0] == (etw['plan'], b''), rows
    assert rows[-1] == ({'kind': 'etw-capture-end-v1', 'stopReason': 'requested', 'source': etw['source']}, b''), rows[-1]
    for index, (event, payload) in enumerate(rows[1:-1]):
        assert event['kind'] == 'etw-observation-v1' and event['descriptor']['id'] == 1 + index % 2, event
        assert all(event[key] == etw['plan'][key] for key in ('providerId', 'sourceEpoch', 'headerPid')), event
        assert event['originalPayloadBytes'] == len(payload) == 8, event
        assert payload == struct.pack('<II', index // 2, len(PAYLOAD)), (event, payload)
    return api_markers, checkpoint


def verify_graph(reader, sample, identity, stream, checkpoint, stopped, payloads):
    is_api = stream == 'raw'
    prefix = checkpoint['raw']
    graph = call(reader, f'graph-{stream}', 'archive.inspect',
                 dict(identity, stream=stream, ordinal='1', view='graph', expectedSha256=prefix['sha256']))
    assert all(graph[key] == identity[key] for key in identity), graph
    assert (graph['view'], graph['stream'], graph['ordinal']) == ('graph', stream, '1'), graph
    assert graph['descriptionHash'] == checkpoint['descriptionHash'], graph
    assert graph['prefix'] == {key: prefix[key] for key in ('sha256', 'endOffset', 'lastSequence')} | {
        'lastBlockOrdinal': prefix['block']}, graph
    assert graph['archiveSource'] == ('api-follow-checkpoint' if is_api else 'etw-checkpoint'), graph
    assert graph['sourceCoverage'] == 'unknown' and graph['finalSegment'] is not is_api, graph
    assert graph['nextAfterSequence'] is None and graph['observationCount'] == str(len(payloads)), graph
    assert graph['nodes'] == graph['relations'] == [], graph
    rows = graph['observations']
    assert len(rows) == len(payloads), graph
    sequences = [str(index) for index in range(2, len(payloads) + 2)]
    assert graph['tree'] == {'unresolvedCandidates': sequences if is_api else [],
                             'contextObservations': [] if is_api else sequences}, graph
    data = (sample / stream / '00000000000000000001.ksaseg').read_bytes()
    plan = stopped['plan'] if is_api else stopped['etw']['plan']
    source_id = f'api-monitor-follow:{SESSION_ID}' if is_api else f'etw:{PROVIDER}'
    for index, (row, payload) in enumerate(zip(rows, payloads), 1):
        assert row['sourceId'] == source_id and row['sourceEpoch'] == plan['sourceEpoch'], row
        assert row['sourceGroup'] == ('api-monitor' if is_api else source_id), row
        assert row['sourceSequence'] == (str(index) if is_api else None), row
        assert row['headerPid'] == plan['readerPid' if is_api else 'headerPid'], row
        assert row['execution'] is None and row['finding'] is None, row
        if is_api:
            assert (row['operation'], row['apiFamily'], row['apiCategory']) == ('WriteProcessMemory', 'memory-write', 'memory'), row
        else:
            assert row['operation'] == 'etw-observation-v1' and 'etw-context-only' in row['gaps'], row
        anchor = row['raw']
        assert (anchor['segmentOrdinal'], anchor['recordSequence'], anchor['inlineBytes']) == (
            '1', str(index + 1), str(len(payload))), anchor
        offset, inline = int(anchor['recordOffset']), int(anchor['inlineOffset'])
        assert offset >= 176 and offset < inline < len(data), anchor
        length, record_type, _, _, _, sequence = struct.unpack_from('<IHHIIQ', data, offset)
        metadata_bytes, = struct.unpack_from('<I', data, offset + 32)
        assert (record_type, sequence, inline) == (3, index + 1, offset + 36 + metadata_bytes), anchor
        assert inline + len(payload) == offset + length and data[inline:inline + len(payload)] == payload, anchor
    first = rows[0]
    return {'archiveSource': graph['archiveSource'], 'prefix': graph['prefix'],
            'observationCount': graph['observationCount'],
            'firstAnchor': {key: first[key] for key in ('sourceId', 'sourceEpoch', 'sourceGroup', 'sourceSequence', 'raw')}}


def verify_readback(reader, project, sample, stopped, markers, packets, etw_count):
    api_markers, etw_marker = markers
    identity = {key: stopped[key] for key in ('projectId', 'sampleId')}
    opened = call(reader, 'reopen', 'project.open', {'path': str(project)})
    assert opened['projectId'] == identity['projectId'] and opened['sampleCount'] == '1', opened
    for ordinal, checkpoint in enumerate(api_markers, 1):
        result = call(reader, f'read-{ordinal}', 'sample.query',
                      dict(identity, includeCapture=True, captureOrdinal=str(ordinal)))
        assert result['sampleId'] == identity['sampleId'], result
        capture = result['captureArchive']
        assert capture['kind'] == 'mixed-api-etw' and capture['requestedOrdinal'] == str(ordinal), capture
        api, etw = capture['api'], capture['etw']
        assert (api['stream'], api['status'], api['checkpoint']) == ('raw', 'readback-verified', 'verified'), api
        assert api['sha256'] == checkpoint['raw']['sha256'] and api['lastSourceSequence'] == str(len(packets)), api
        assert api['sourceCoverage'] == 'unknown' and api['finalSegment'] is (ordinal == 2), api
        assert etw['stream'] == 'raw-etw', etw
        if ordinal == 1:
            assert api['firstObservation'] == stopped['readiness']['firstRaw'] and api['terminal'] is None, api
            assert (etw['status'], etw['checkpoint'], etw['observationCount']) == ('readback-verified', 'verified', str(etw_count)), etw
            assert etw['sha256'] == etw_marker['raw']['sha256'], etw
            assert etw['terminal'] == {'stopReason': 'requested', 'nativeSessionStopped': True}, etw
        else:
            assert api['terminal'] == {'stopReason': 'requested', 'sourceState': 'cutoff',
                                       'sourceCutoffReached': True, 'partialLineBytes': '0'}, api
            assert etw == {'status': 'missing', 'stream': 'raw-etw'}, etw
    etw_payloads = [struct.pack('<II', index // 2, len(PAYLOAD)) for index in range(etw_count)]
    return {stream: verify_graph(reader, sample, identity, stream, checkpoint, stopped, payloads)
            for stream, checkpoint, payloads in (('raw', api_markers[0], packets), ('raw-etw', etw_marker, etw_payloads))}


@contextmanager
def hidden_checkpoint(path):
    """在同目录暂移指定检查点；离开 with 时还原原文件，不改内容。"""
    backup = path.with_suffix('.isolation-backup')  # 固定旁路文件名，不覆盖已有备份。
    assert not backup.exists() and not backup.is_symlink(), backup
    file_identity = regular_identity(path)
    path.rename(backup)
    try:
        yield
    finally:
        backup.rename(path)
        assert regular_identity(path) == file_identity, path


def verify_source_isolation():
    """只读重开已知保留采样，逐流验证标记缺失、健康侧与恢复后的回执。"""
    cli_hash = hashlib.sha256(CLI.read_bytes()).hexdigest()
    assert cli_hash == 'dc432a489f784c112224b368fbd04752226257e3819a258d1df706d9dce469bf', cli_hash
    identity = {'projectId': 'e9048fce-3707-4f49-9e2c-8856c8ea6c21',
                'sampleId': 'd914db1a-4ca4-47bf-9ea9-e36616f1a7a5'}
    check_scratch(SCRATCH)
    project = SCRATCH / 'project'
    sample = project / 'samples' / identity['sampleId']
    manifest, description = project / 'project.ksaproj', sample / 'sample.json'
    api_dir, etw_dir = sample / 'checkpoints', sample / 'checkpoints-etw'
    first, second = '00000000000000000001', '00000000000000000002'
    api_start, api_end, etw_start = api_dir / f'{first}.json', api_dir / f'{second}.json', etw_dir / f'{first}.json'
    api_raw, api_tail = sample / 'raw' / f'{first}.ksaseg', sample / 'raw' / f'{second}.ksaseg'
    etw_raw, etw_records = sample / 'raw-etw' / f'{first}.ksaseg', sample / 'records-etw' / f'{first}.ksaseg'

    # 所有读写目标均位于已解析的固定夹具下；任何重解析点都拒绝。
    files = (manifest, description, api_start, api_end, etw_start, api_raw, api_tail, etw_raw, etw_records)
    for file in files:
        for path in (file, *(parent for parent in file.parents if parent.is_relative_to(SCRATCH))):
            regular_identity(path)
        assert file.resolve(strict=True) == file, file
    digests = {file: hashlib.sha256(file.read_bytes()).hexdigest() for file in files}
    manifest_doc = json.loads(manifest.read_bytes())
    sample_doc = json.loads(description.read_bytes())
    assert manifest_doc['projectId'] == identity['projectId'] and manifest_doc['producer'] == 'KswordCLI', manifest_doc
    assert all(sample_doc[key] == value for key, value in identity.items()) and sample_doc['producer'] == 'KswordCLI', sample_doc
    api = marker(sample, api_dir.name, 1, 'api-archive-checkpoint-v1', identity, digests[description])
    api_terminal = marker(sample, api_dir.name, 2, 'api-archive-checkpoint-v1', identity, digests[description])
    etw = marker(sample, etw_dir.name, 1, 'etw-terminal-checkpoint-v1', identity, digests[description])
    for file, prefix in ((api_raw, api['raw']), (api_tail, api_terminal['raw']),
                         (etw_raw, etw['raw']), (etw_records, etw['records'])):
        verify_prefix(file, prefix)
    expected_hashes = {'raw': '7f01abbf8db1895c45d035adde98f8baaddde9599c63edcade01f94a3c6e16f6',
                       'raw-etw': 'e93dbe279f243e9380c327ea39f01dda122618d64763d7b35bca39d4ec3dd8a7'}
    assert (digests[api_raw], digests[etw_raw]) == (expected_hashes['raw'], expected_hashes['raw-etw'])
    results = {}  # 两次故障的坏侧回执与健康侧标识。

    with ExitStack() as children:
        reader = controller('offline')
        children.callback(cleanup_child, reader)
        opened = call(reader, 'isolation-open', 'project.open', {'path': str(project), 'access': 'read-only'})
        assert (opened['projectId'], opened['sampleCount'], opened['access']) == (identity['projectId'], '1', 'read-only'), opened

        def capture(phase):
            """以新请求 ID 回读同一采样首段的双流摘要，避免复用历史回执。"""
            result = call(reader, f'{phase}-sample', 'sample.query',
                          dict(identity, includeCapture=True, captureOrdinal='1'))
            assert result['sampleId'] == identity['sampleId'], result
            report = result['captureArchive']
            assert (report['kind'], report['requestedOrdinal']) == ('mixed-api-etw', '1'), report
            return report

        def graph(phase, stream, error=None):
            """按原段散列查询指定流，或者断言该流返回指定拒绝。"""
            request = dict(identity, stream=stream, view='graph', ordinal='1', expectedSha256=expected_hashes[stream])
            # 暂移检查点保留 Win32 ERROR_FILE_NOT_FOUND (2)，而不是 CLI 通用错误码 5。
            return call(reader, f'{phase}-graph-{stream}', 'archive.inspect', request,
                        error=error, error_code=2 if error else None)

        baseline = capture('baseline')
        baseline_graphs = {stream: graph('baseline', stream) for stream in expected_hashes}
        for lane, stream, count in (('api', 'raw', '2'), ('etw', 'raw-etw', str(ETW_COUNT))):
            assert (baseline[lane]['status'], baseline[lane]['sha256']) == ('readback-verified', expected_hashes[stream]), baseline
            page = baseline_graphs[stream]
            assert (page['stream'], page['prefix']['sha256'], page['observationCount']) == (stream, expected_hashes[stream], count), page

        try:
            for bad, good, bad_stream, good_stream, path, expected in (
                    ('api', 'etw', 'raw', 'raw-etw', api_start, 'pending'),
                    ('etw', 'api', 'raw-etw', 'raw', etw_start, 'missing')):
                with hidden_checkpoint(path):
                    report = capture(bad)
                    assert report[bad]['status'] == expected and report[bad]['stream'] == bad_stream, report
                    assert 'sha256' not in report[bad] and 'firstObservation' not in report[bad], report
                    assert report[good] == baseline[good], report
                    assert graph(bad, good_stream) == baseline_graphs[good_stream]
                    assert graph(bad, bad_stream, error='project-data-not-found') is None
                    results[bad] = {'sampleStatus': expected, 'graphError': 'project-data-not-found',
                                    'healthyStream': good_stream, 'healthySha256': expected_hashes[good_stream]}
                assert capture(f'{bad}-restored') == baseline
                assert graph(f'{bad}-restored', bad_stream) == baseline_graphs[bad_stream]
        finally:
            # 即使业务断言失败，也对账原检查点、原始流、覆盖流和项目描述的字节。
            assert digests == {file: hashlib.sha256(file.read_bytes()).hexdigest() for file in files}, files
        assert shutdown(reader) == 0
    print(json.dumps({'cliSha256': cli_hash, **identity, 'isolated': results, 'restoredFiles': len(files),
                      'manifest': str(manifest)}), flush=True)
    print('CLI_MIXED_SOURCE_ISOLATION=PASS', flush=True)


def run(keep=False):
    with owned_scratch(keep) as scratch, ExitStack() as children:
        project, input_file = scratch / 'project', scratch / 'synthetic-events.jsonl'
        payload_file = scratch / 'owned.sample'
        producer = Child([sys.executable, '-B', PRODUCER, '--sample', payload_file])
        children.callback(cleanup_child, producer, producer=True)
        target = producer.next()
        assert target['pid'] == producer.process.pid and int(target['creationFileTime']) > 0, target
        packets, original = write_api_fixture(input_file, target)

        cli = controller('r3')
        children.callback(cleanup_child, cli)
        created = call(cli, 'create', 'project.create', {'path': str(project),
                       'settings': {'title': 'Mixed passive capture validation', 'notes': API_INPUT}})
        identity = {'projectId': created['projectId']}
        api_input = {'path': str(input_file), 'sessionIdentity': str(SESSION_ID), 'authorized': True}
        options = dict(identity, **target, title='Owned ETW and synthetic API', providerId=str(PROVIDER),
                       durationMs=DURATION_MS, apiArchive=api_input)
        deadline = time.monotonic() + 8  # Leave headroom for the manual stop before the native duration limit.
        opened = call(cli, 'open', 'session.open', options, expected={'revisionId': created['revisionId']})
        assert opened['capture'] == 'active' and opened['projectId'] == identity['projectId'], opened
        etw = opened['etw']
        assert etw['rawStream'] == 'raw-etw' and opened['session']['id'] == opened['sampleId'], opened
        for plan in (opened['plan'], etw['plan']):
            assert plan['session'] == opened['session'] and plan['mixedEtw'] is True and plan['durationMs'] == DURATION_MS, plan
        api_plan, etw_plan = opened['plan'], etw['plan']
        assert opened['source']['kind'] == 'passive-api-archive', opened
        assert (api_plan['readerPid'], api_plan['readerCreation100ns'], api_plan['sessionIdentity']) == (
            target['pid'], target['creationFileTime'], str(SESSION_ID)), api_plan
        assert (etw_plan['headerPid'], etw_plan['processCreationFileTime'], etw_plan['providerId']) == (
            target['pid'], target['creationFileTime'], str(PROVIDER)), etw_plan

        owner = {'session': opened['session']}
        wait_active(cli, owner, deadline, 'ready', lambda report: report['etw']['source']['state'] == 'running')
        producer.send('write')
        assert producer.next()['operations'] == ETW_COUNT
        active = wait_active(cli, owner, deadline, 'counts', lambda report:
                             int(report['archive']['recordedRows']) >= len(packets) and
                             int(report['etw']['source']['enqueued']) >= ETW_COUNT)
        assert active['archive']['recordedRows'] == str(len(packets)) and active['archive']['segmentOrdinal'] == '1', active
        assert active['etw']['source']['enqueued'] == str(ETW_COUNT), active
        stopped = stop_session(cli, owner, active['stateRevision'])
        assert (stopped['capture'], stopped['stopReason'], stopped['sampleId']) == ('stopped', 'requested', opened['sampleId']), stopped
        source, archive = stopped['source'], stopped['archive']
        assert (archive['status'], archive['segmentOrdinal'], archive['recordedRows']) == ('raw-verified', '2', str(len(packets))), archive
        assert source['state'] == 'cutoff' and source['validatedRows'] == str(len(packets)), source
        assert source['cutoffReached'] and source['cutoffBytes'] == str(len(original)), source
        assert source['coverage'] == 'unknown' and source['writerReceipt'] is None, source
        etw = stopped['etw']
        assert etw['archive']['status'] == 'raw-verified' and etw['archive']['checkpoint'] == {'status': 'verified', 'error': None}, etw
        native = etw['source']
        assert native['nativeSessionStopped'] and not native['tailDeliveryUnconfirmed'] and native['queued'] == '0', native
        assert native['enqueued'] == str(ETW_COUNT) and native['queueDropped'] == '0', native
        assert (native['eventsLost'], native['logBuffersLost'], native['realTimeBuffersLost']) == (0, 0, 0), native
        assert call(cli, 'stopped-query', 'session.query', {}, **owner) == stopped
        closed = call(cli, 'close', 'session.close', {}, expected={'stateRevision': stopped['stateRevision']}, **owner)
        assert closed['closed'] and closed['session'] == owner['session'] and closed['sampleId'] == opened['sampleId'], closed
        assert input_file.read_bytes() == original
        input_file.unlink()  # Must succeed while the CLI is still alive (API reader released its handle).
        assert call(cli, 'close-project', 'project.close', identity)['closed']
        assert shutdown(cli) == 0
        producer.send('exit')
        assert producer.process.wait(timeout=10) == 0
        payload_file.unlink()

        sample = project / 'samples' / stopped['sampleId']
        markers = verify_archives(sample, stopped, packets, ETW_COUNT)
        reader = controller('offline')
        children.callback(cleanup_child, reader)
        graphs = verify_readback(reader, project, sample, stopped, markers, packets, ETW_COUNT)
        assert shutdown(reader) == 0
        print(json.dumps({'cliSha256': hashlib.sha256(CLI.read_bytes()).hexdigest(), 'target': target,
                          **identity, 'sampleId': stopped['sampleId'], 'apiInput': API_INPUT,
                          'apiRows': len(packets), 'etwObservations': ETW_COUNT, 'stopReceipt': stopped,
                          'apiRawSha256': [item['raw']['sha256'] for item in markers[0]],
                          'etwRawSha256': markers[1]['raw']['sha256'], 'graphs': graphs,
                          'projectKept': keep, 'manifest': str(project / 'project.ksaproj') if keep else None}), flush=True)
    print('CLI_MIXED_PASSIVE_CAPTURE=PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--keep', action='store_true', help='Keep the verified project in the fixed Release scratch directory.')
    modes.add_argument('--verify-source-isolation', action='store_true', help='Verify source isolation in the fixed kept sample.')
    args = parser.parse_args()
    if args.verify_source_isolation:
        verify_source_isolation()
    else:
        run(args.keep)
