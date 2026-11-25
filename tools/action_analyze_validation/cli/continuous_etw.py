"""Verify command-free segment commits for an owned provider on the Release CLI."""

from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
from shutil import rmtree
from stat import FILE_ATTRIBUTE_REPARSE_POINT
import struct
import subprocess
import sys
import time
from uuid import uuid4

from live_etw import CLI, PAYLOAD, PROVIDER, RELEASE, REPO, Child, call, controller, decode_raw, sample


SCRATCH = RELEASE / 'ActionAnalyzeContinuousEtwValidation'
QUERY_COUNT = 4100


def regular_identity(path):
    info = path.lstat()
    assert not info.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT, path
    return info.st_dev, info.st_ino


def check_scratch():
    assert RELEASE.resolve(strict=True) == RELEASE
    tracked = subprocess.run(['git', 'ls-files', '-z', '--', SCRATCH.relative_to(REPO).as_posix()],
                             cwd=REPO, check=True, capture_output=True, timeout=10)
    assert not tracked.stdout, SCRATCH


@contextmanager
def owned_scratch():
    check_scratch()
    SCRATCH.mkdir(exist_ok=False)
    identity = regular_identity(SCRATCH)
    try:
        yield SCRATCH
    finally:
        check_scratch()
        assert SCRATCH.resolve(strict=True) == SCRATCH and regular_identity(SCRATCH) == identity
        for path in SCRATCH.rglob('*'):
            regular_identity(path)
        rmtree(SCRATCH)
        assert not os.path.lexists(SCRATCH)
        print('TEST_PROJECT_REMOVED=True', flush=True)


def cleanup_child(child, *, producer=False):
    # On failure, let the controller finalize from EOF before falling back to terminating it.
    try:
        if child.process.poll() is None:
            if producer:
                child.send('exit')
            else:
                child.process.stdin.close()
            child.process.wait(timeout=12)
    finally:
        child.stop()


def shutdown(cli):
    assert call(cli, 'shutdown', 'controller.shutdown', {}) == {'shutdown': True}
    summary = cli.next()
    assert summary['reason'] == 'shutdown' and summary['clean'] and summary['exitCode'] == 0, summary
    return cli.process.wait(timeout=10)


def verify_segment(sample_path, ordinal, previous_sequence, previous_observations, opened, final=False):
    name = f'{ordinal:020d}'
    marker = json.loads((sample_path / 'checkpoints' / f'{name}.json').read_bytes())
    ordinal_text = str(ordinal)
    assert marker['kind'] == 'etw-terminal-checkpoint-v1' and marker['generation'] == ordinal_text, marker
    for key in ('projectId', 'sampleId'):
        assert marker[key] == opened[key], marker
    assert marker['descriptionHash'] == hashlib.sha256((sample_path / 'sample.json').read_bytes()).hexdigest()

    for stream in ('raw', 'records'):
        prefix = (sample_path / stream / f'{name}.ksaseg').read_bytes()
        assert marker[stream]['ordinal'] == ordinal_text, marker
        assert marker[stream]['endOffset'] == str(len(prefix)), marker
        assert marker[stream]['sha256'] == hashlib.sha256(prefix).hexdigest(), marker
    assert marker['records']['lastSequence'] == ordinal_text, marker

    raw = sample_path / 'raw' / f'{name}.ksaseg'
    rows, digest = decode_raw(raw, previous_sequence + 1)
    assert digest == marker['raw']['sha256']
    plan, payload = rows[0]
    assert plan == opened['plan'] and not payload, rows[0]
    terminal, payload = rows[-1]
    assert terminal['kind'] == 'etw-capture-end-v1' and not payload, rows[-1]
    assert terminal['finalSegment'] is final, terminal
    assert terminal['stopReason'] == ('requested' if final else 'segment-rotated'), terminal
    assert terminal['source']['nativeSessionStopped'] is final, terminal
    count = len(rows) - 2
    assert (final or count > 0) and count <= plan['maxRecords'], terminal
    assert terminal['segmentObservations'] == str(count), terminal
    last_sequence = previous_sequence + len(rows)
    assert marker['raw']['lastSequence'] == str(last_sequence), marker
    for index, (event, data) in enumerate(rows[1:-1], previous_observations):
        assert event['kind'] == 'etw-observation-v1', event
        for key in ('headerPid', 'providerId', 'sourceEpoch'):
            assert event[key] == plan[key], event
        assert event['descriptor']['id'] == 1 + index % 2, event
        assert event['originalPayloadBytes'] == len(data) == 8, event
        assert data == struct.pack('<II', index // 2, len(PAYLOAD)), (index, event, data)

    return {
        'segmentOrdinal': ordinal_text, 'checkedBytes': marker['raw']['endOffset'],
        'observationCount': str(count), 'lastSequence': str(last_sequence), 'rawSha256': digest,
        'finalSegment': final, 'terminal': terminal,
    }


def wait_commits(cli, sample_path, opened, segments, emitted, committed):
    deadline = time.monotonic() + 15
    while committed < emitted:
        ordinal = len(segments) + 1
        marker = sample_path / 'checkpoints' / f'{ordinal:020d}.json'
        if marker.is_file():
            previous = int(segments[-1]['lastSequence']) if segments else 0
            segment = verify_segment(sample_path, ordinal, previous, committed, opened)
            committed += int(segment['observationCount'])
            segments.append(segment)
        else:
            assert cli.process.poll() is None, f'CLI exited before publishing {marker}'
            if time.monotonic() >= deadline:
                # The command-free phase has already failed. Capture the reason before cleanup.
                files = sorted(p.relative_to(sample_path).as_posix() for p in sample_path.rglob('*') if p.is_file())
                print(json.dumps({'checkpointTimeout': {'committed': committed, 'emitted': emitted,
                                  'ordinal': ordinal, 'filesBeforeDiagnosticQuery': files}}), flush=True)
                report = call(cli, 'diagnostic-status', 'session.query', {}, session=opened['session'])
                print(json.dumps({'timeoutStatus': report}), flush=True)
                raise AssertionError(f'No checkpoint for {committed}/{emitted} events after 15 s')
            time.sleep(.05)
    assert committed == emitted
    return committed


def readback(reader, sample_identity, segment, plan):
    ordinal = segment['segmentOrdinal']
    result = call(reader, f'capture-{ordinal}', 'sample.query',
                  dict(sample_identity, includeCapture=True, captureOrdinal=ordinal))
    assert result['sampleId'] == sample_identity['sampleId'], result
    capture = result['captureArchive']
    assert capture == {
        'status': 'readback-verified', 'checkpoint': 'verified', 'segmentOrdinal': ordinal,
        'checkedBytes': segment['checkedBytes'], 'observationCount': segment['observationCount'],
        'finalSegment': segment['finalSegment'],
        'plan': {key: plan[key] for key in ('providerId', 'sourceEpoch', 'headerPid', 'processCreationFileTime')},
        'terminal': {'stopReason': segment['terminal']['stopReason'],
                     'nativeSessionStopped': segment['terminal']['source']['nativeSessionStopped']},
    }, capture
    return capture


def verify_missing_sysmon(cli, opened, target_guid):
    report = call(cli, 'findings', 'session.findings', {}, session=opened['session'])
    assert report['session'] == opened['session'] and report['sampleId'] == opened['sampleId'], report
    assert report['state'] == 'requested' and report['observations'] == '0' and report['latest'] is None, report
    source = report['source']
    assert source['state'] == 'channel-unavailable' and not source['subscribed'], report
    assert source['targetProcessGuid'] == target_guid and source['channel'] == 'Microsoft-Windows-Sysmon/Operational', report
    assert source['nativeStage'] == 'subscribe' and source['win32Error'] == 15007, report
    assert source['captureCoverage'] == 'unknown', report
    print(json.dumps({'findingsBeforeRemainingWaves': report}), flush=True)


def run(expect_missing_sysmon=False, inspect_gui=None):
    """采集并回读自有 ETW 样本。可在测试目录清理前交给正式桌面入口复验。"""
    digest = hashlib.sha256(CLI.read_bytes()).hexdigest()
    with owned_scratch() as scratch, ExitStack() as children:
        producer = Child([sys.executable, '-B', __file__, '--producer', scratch / 'owned.sample'])
        children.callback(cleanup_child, producer, producer=True)
        target = producer.next()
        cli = controller('r3')
        children.callback(cleanup_child, cli)
        project = scratch / 'project'
        created = call(cli, 'create', 'project.create', {'path': str(project),
                       'settings': {'title': 'Continuous owned ETW', 'notes': ''}})
        identity = {'projectId': created['projectId']}
        options = dict(identity, **target, title='Owned file I/O', providerId=str(PROVIDER))
        if expect_missing_sysmon:
            # A fresh selector exercises subscription reporting without requiring a Sysmon event.
            options['sysmonTargetGuid'] = str(uuid4())
        opened = call(cli, 'open', 'session.open', options, expected={'revisionId': created['revisionId']})
        assert opened['capture'] == 'active' and opened['plan']['durationMs'] == 0, opened
        assert opened['archive']['recordedObservations'] == '0' and opened['stopReason'] is None, opened
        assert opened['plan']['headerPid'] == target['pid'], opened
        assert opened['plan']['processCreationFileTime'] == target['creationFileTime'], opened
        assert opened['plan']['providerId'] == str(PROVIDER), opened
        sample_path = project / 'samples' / opened['sampleId']

        # The first two waves commit without any CLI commands. Each producer write below goes
        # to the producer's own pipe. Each wave starts after the preceding commit.
        segments = []
        emitted = committed = 0
        for wave, count in enumerate((6, 6, 50, 50, 50, 50, 50, 50), 1):
            producer.send(f'write {count}')
            assert producer.next() == {'operations': 2 * count}
            emitted += 2 * count
            committed = wait_commits(cli, sample_path, opened, segments, emitted, committed)
            if wave <= 2:
                print(json.dumps({'commandFreeWave': wave, 'committedObservations': committed,
                                  'publishedSegments': len(segments)}), flush=True)
            if wave == 2 and expect_missing_sysmon:
                verify_missing_sysmon(cli, opened, options['sysmonTargetGuid'])
        assert len(segments) >= 2 and committed > 512
        initial = call(cli, 'first-status', 'session.query', {}, session=opened['session'])
        assert initial['capture'] == 'active' and initial['stopReason'] is None, initial
        assert initial['source']['state'] == 'running' and initial['source']['enqueued'] == str(emitted), initial
        archive = initial['archive']
        assert archive['status'] == 'raw-verified' and archive['checkpoint'] == {'status': 'verified', 'error': None}, initial
        assert archive['segmentOrdinal'] == str(len(segments)) and archive['recordedObservations'] == str(emitted), initial
        assert archive['lastSequence'] == segments[-1]['lastSequence'], initial
        assert archive['flushedBytes'] == segments[-1]['checkedBytes'], initial

        for index in range(1, QUERY_COUNT + 1):
            current = call(cli, f'status-{index}', 'session.query', {}, session=opened['session'])
            assert current['capture'] == 'active' and current['stopReason'] is None, (index, current)
            assert current['session'] == opened['session'] and current['sampleId'] == opened['sampleId'], (index, current)
        assert current['archive'] == archive, current
        print(json.dumps({'uniqueStatusReplies': QUERY_COUNT + 1, 'liveArchive': current['archive']}), flush=True)

        stopped = call(cli, 'stop', 'session.stop', {}, session=opened['session'],
                       expected={'stateRevision': current['stateRevision']})
        assert stopped['capture'] == 'stopped' and stopped['stopReason'] == 'requested', stopped
        assert stopped['source']['nativeSessionStopped'] and stopped['source']['enqueued'] == str(emitted), stopped
        for key in ('eventsLost', 'logBuffersLost', 'realTimeBuffersLost', 'queueDropped', 'queued'):
            assert int(stopped['source'][key]) == 0, stopped
        final_ordinal = len(segments) + 1
        final = verify_segment(sample_path, final_ordinal, int(segments[-1]['lastSequence']), committed, opened, final=True)
        assert final['terminal']['source']['enqueued'] == str(emitted) and final['observationCount'] == '0', final
        assert stopped['archive']['recordedObservations'] == str(emitted), stopped
        assert stopped['archive']['status'] == 'raw-verified' and stopped['archive']['checkpoint']['status'] == 'verified', stopped
        for receipt_key, segment_key in (('segmentOrdinal', 'segmentOrdinal'), ('flushedBytes', 'checkedBytes'),
                                         ('lastSequence', 'lastSequence')):
            assert stopped['archive'][receipt_key] == final[segment_key], stopped
        assert call(cli, 'close', 'session.close', {}, session=opened['session'],
                    expected={'stateRevision': stopped['stateRevision']})['closed']
        writer_exit = shutdown(cli)

        reader = controller('offline')
        children.callback(cleanup_child, reader)
        reopened = call(reader, 'reopen', 'project.open', {'path': str(project)})
        assert reopened['projectId'] == opened['projectId'] and reopened['sampleCount'] == '1', reopened
        sample_identity = dict(identity, sampleId=opened['sampleId'])
        second = readback(reader, sample_identity, segments[1], opened['plan'])
        final_capture = readback(reader, sample_identity, final, opened['plan'])
        reader_exit = shutdown(reader)
        producer.send('exit')
        producer_exit = producer.process.wait(timeout=10)
        assert writer_exit == reader_exit == producer_exit == 0
        assert hashlib.sha256(CLI.read_bytes()).hexdigest() == digest
        print(json.dumps({'cliSha256': digest, 'sampleId': opened['sampleId'], 'pid': target['pid'],
                          'observations': emitted, 'preStopSegments': segments, 'finalSegment': final,
                          'secondSegmentReadback': second, 'finalSegmentReadback': final_capture, 'stop': stopped,
                           'exitCodes': {'writer': writer_exit, 'reader': reader_exit, 'producer': producer_exit}}), flush=True)
        if inspect_gui:
            inspect_gui(sample_path / 'raw/00000000000000000001.ksaseg',
                        etw_segments=segments + [final])


if __name__ == '__main__':
    if sys.argv[1:2] == ['--producer']:
        sample(Path(sys.argv[2]), batched=True)
    elif sys.argv[1:] == ['--expect-missing-sysmon']:
        run(expect_missing_sysmon=True)
    elif not sys.argv[1:]:
        run()
    else:
        raise SystemExit('Usage: continuous_etw.py [--expect-missing-sysmon]')
