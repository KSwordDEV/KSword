"""Verify command-free ETW commits, optionally with a paced long run on the Release CLI."""

import argparse
from contextlib import ExitStack, contextmanager
import ctypes as ct
from ctypes import wintypes as win
import hashlib
from itertools import repeat
import json
import os
from pathlib import Path
from shutil import rmtree
from stat import FILE_ATTRIBUTE_REPARSE_POINT
import struct
import subprocess
import sys
import time
from uuid import UUID, uuid4

import live_etw
from live_etw import CLI, PAYLOAD, PROVIDER, RELEASE, REPO, Child, call, controller, decode_raw, sample, verify_findings


SCRATCH = RELEASE / 'ActionAnalyzeContinuousEtwValidation'
LONG_SCRATCH = RELEASE / 'ActionAnalyzeContinuousEtwLongValidation'
QUERY_COUNT = 4100
WAVE_PERIOD_SECONDS = 2
NATIVE_LOSS_COUNTERS = ('eventsLost', 'logBuffersLost', 'realTimeBuffersLost')


def regular_identity(path):
    info = path.lstat()
    assert not info.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT, path
    return info.st_dev, info.st_ino


def check_scratch(path):
    assert RELEASE.resolve(strict=True) == RELEASE
    tracked = subprocess.run(['git', 'ls-files', '-z', '--', path.relative_to(REPO).as_posix()],
                             cwd=REPO, check=True, capture_output=True, timeout=10)
    assert not tracked.stdout, path


@contextmanager
def owned_scratch(path):
    check_scratch(path)
    path.mkdir(exist_ok=False)
    identity = regular_identity(path)
    try:
        yield path
    finally:
        check_scratch(path)
        assert path.resolve(strict=True) == path and regular_identity(path) == identity
        for entry in path.rglob('*'):
            regular_identity(entry)
        rmtree(path)
        assert not os.path.lexists(path)
        print('TEST_PROJECT_REMOVED=True', flush=True)


@contextmanager
def process_metrics(pid):
    class MemoryCounters(ct.Structure):
        _fields_ = [('cb', win.DWORD), ('pageFaultCount', win.DWORD)] + [
            (name, ct.c_size_t) for name in ('peakWorkingSet', 'workingSet', 'quotaPeakPagedPool',
            'quotaPagedPool', 'quotaPeakNonPagedPool', 'quotaNonPagedPool', 'pagefileUsage',
            'peakPagefileUsage', 'privateUsage')]

    kernel = ct.WinDLL('kernel32', use_last_error=True)
    open_process = kernel.OpenProcess
    open_process.argtypes = [win.DWORD, win.BOOL, win.DWORD]
    open_process.restype = win.HANDLE
    close_handle = kernel.CloseHandle
    close_handle.argtypes = [win.HANDLE]
    get_times = kernel.GetProcessTimes
    get_times.argtypes = [win.HANDLE] + [ct.POINTER(win.FILETIME)] * 4
    get_memory = kernel.K32GetProcessMemoryInfo
    get_memory.argtypes = [win.HANDLE, ct.POINTER(MemoryCounters), win.DWORD]
    handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        raise ct.WinError(ct.get_last_error())

    def read():
        times = [win.FILETIME() for _ in range(4)]
        memory = MemoryCounters(cb=ct.sizeof(MemoryCounters))
        if not get_times(handle, *(ct.byref(value) for value in times)):
            raise ct.WinError(ct.get_last_error())
        if not get_memory(handle, ct.byref(memory), memory.cb):
            raise ct.WinError(ct.get_last_error())
        return {'cpu100ns': sum((value.dwHighDateTime << 32) | value.dwLowDateTime for value in times[2:]),
                'workingSetBytes': memory.workingSet, 'lifetimePeakWorkingSetBytes': memory.peakWorkingSet,
                'privateCommitBytes': memory.privateUsage}

    try:
        yield read
    finally:
        if not close_handle(handle):
            raise ct.WinError(ct.get_last_error())


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


def verify_long_archive(reader, identity, opened, sample_path, segments, emitted):
    cumulative = max_queued = raw_bytes = coverage_bytes = live_stats_known = 0
    for segment in segments:
        cumulative += int(segment['observationCount'])
        source = segment['terminal']['source']
        queued = int(source['queued'])
        assert int(source['enqueued']) == cumulative + queued, segment
        assert int(source['providerEvents']) == int(source['enqueued']), segment
        for key in ('headerFiltered', 'queueDropped', 'payloadTruncated', 'malformedPayload'):
            assert int(source[key]) == 0, segment
        assert not source['callbackFailed'] and not source['tailDeliveryUnconfirmed'], segment
        native_losses = tuple(source[key] for key in NATIVE_LOSS_COUNTERS)
        if segment['finalSegment'] or any(value is not None for value in native_losses):
            assert native_losses == (0, 0, 0), segment
            live_stats_known += not segment['finalSegment']
        max_queued = max(max_queued, queued)
        raw_bytes += int(segment['checkedBytes'])
        name = f"{int(segment['segmentOrdinal']):020d}.ksaseg"
        coverage_bytes += (sample_path / 'records' / name).stat().st_size
        readback(reader, identity, segment, opened['plan'])
    assert cumulative == emitted and int(segments[-1]['lastSequence']) == emitted + 2 * len(segments)
    assert len(list((sample_path / 'checkpoints').glob('*.json'))) == len(segments)
    return {'segmentsReadBack': len(segments), 'rawBytes': raw_bytes, 'coverageBytes': coverage_bytes,
            'liveSegmentsWithNativeLossStatistics': live_stats_known, 'maxQueuedAfterSegmentDrain': max_queued}


def run(inspect_gui=None, *, long_seconds=None):
    """采集并回读自有 ETW 样本。可在测试目录清理前交给正式桌面入口复验。"""
    assert long_seconds is None or long_seconds > 0
    long_run = long_seconds is not None
    digest = hashlib.sha256(CLI.read_bytes()).hexdigest()
    with owned_scratch(LONG_SCRATCH if long_run else SCRATCH) as scratch, ExitStack() as children:
        provider = uuid4() if long_run else PROVIDER  # Keep concurrent desktop fixtures on their own source.
        producer_args = [sys.executable, '-B', __file__, '--producer', scratch / 'owned.sample']
        if long_run:
            producer_args.append(str(provider))
        producer = Child(producer_args)
        children.callback(cleanup_child, producer, producer=True)
        target = producer.next()
        cli = controller('r3')
        children.callback(cleanup_child, cli)
        project = scratch / 'project'
        created = call(cli, 'create', 'project.create', {'path': str(project),
                       'settings': {'title': 'Continuous owned ETW', 'notes': ''}})
        identity = {'projectId': created['projectId']}
        options = dict(identity, **target, title='Owned file I/O', providerId=str(provider))
        opened = call(cli, 'open', 'session.open', options, expected={'revisionId': created['revisionId']})
        assert opened['capture'] == 'active' and opened['plan']['durationMs'] == 0, opened
        assert opened['archive']['recordedObservations'] == '0' and opened['stopReason'] is None, opened
        assert opened['plan']['headerPid'] == target['pid'], opened
        assert opened['plan']['processCreationFileTime'] == target['creationFileTime'], opened
        assert opened['plan']['providerId'] == str(provider), opened
        sample_path = project / 'samples' / opened['sampleId']

        # Each wave commits before the next. All writes go to the producer's own pipe.
        segments = []
        emitted = committed = 0
        if long_run:
            metrics = children.enter_context(process_metrics(cli.process.pid))
            start_metrics = metrics()
            started = time.monotonic()
            deadline = started + long_seconds
            wave_count = 0
            print(json.dumps({'longStart': {'requestedSeconds': long_seconds, 'cliSha256': digest,
                  'cliPid': cli.process.pid, 'producerPid': target['pid'], 'providerId': str(provider),
                  'writer': start_metrics}}), flush=True)
        counts = repeat(100) if long_run else (6, 6, 50, 50, 50, 50, 50, 50)
        for wave, count in enumerate(counts, 1):
            if long_run:
                wave_start = time.monotonic()
                if wave_count and wave_start >= deadline:
                    break
            producer.send(f'write {count}')
            assert producer.next() == {'operations': 2 * count}
            if long_run:
                acknowledged = time.monotonic()
            emitted += 2 * count
            committed = wait_commits(cli, sample_path, opened, segments, emitted, committed)
            if long_run:
                committed_at = time.monotonic()
                wave_count = wave
                print(json.dumps({'longWave': wave, 'committedObservations': committed,
                                  'publishedSegments': len(segments), 'observedAtSeconds': round(committed_at - started, 3),
                                  'producerAckMs': round((acknowledged - wave_start) * 1000, 2),
                                  'checkpointObservedMs': round((committed_at - wave_start) * 1000, 2),
                                  'writer': metrics()}), flush=True)
                time.sleep(max(0, min(wave_start + WAVE_PERIOD_SECONDS, deadline) - time.monotonic()))
            if wave <= 2:
                print(json.dumps({'commandFreeWave': wave, 'committedObservations': committed,
                                  'publishedSegments': len(segments)}), flush=True)
            if wave == 2 and not long_run:
                report = call(cli, 'findings', 'session.findings', {}, session=opened['session'])
                verify_findings(report, opened)
                print(json.dumps({'findingsBeforeRemainingWaves': report}), flush=True)
        if long_run:
            end_metrics = metrics()
            elapsed = time.monotonic() - started
            cpu_seconds = (end_metrics['cpu100ns'] - start_metrics['cpu100ns']) / 10_000_000
            assert elapsed >= long_seconds and cpu_seconds >= 0
            long_report = {'requestedSeconds': long_seconds, 'measuredSeconds': round(elapsed, 3),
                           'waves': wave_count, 'wavePeriodSeconds': WAVE_PERIOD_SECONDS,
                           'observationsPerSecond': round(emitted / elapsed, 2),
                           'writerCpuSeconds': round(cpu_seconds, 6),
                           'writerMeanCpuPercentOfOneCore': round(100 * cpu_seconds / elapsed, 3),
                           'writerAtStart': start_metrics, 'writerAtEnd': end_metrics}
            print(json.dumps({'longCapture': long_report}), flush=True)
        else:
            assert len(segments) >= 2 and committed > 512
        initial = call(cli, 'first-status', 'session.query', {}, session=opened['session'])
        assert initial['capture'] == 'active' and initial['stopReason'] is None, initial
        assert initial['source']['state'] == 'running' and initial['source']['enqueued'] == str(emitted), initial
        archive = initial['archive']
        assert archive['status'] == 'raw-verified' and archive['checkpoint'] == {'status': 'verified', 'error': None}, initial
        assert archive['segmentOrdinal'] == str(len(segments)) and archive['recordedObservations'] == str(emitted), initial
        assert archive['lastSequence'] == segments[-1]['lastSequence'], initial
        assert archive['flushedBytes'] == segments[-1]['checkedBytes'], initial

        current = initial
        if not long_run:
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
        for key in (*NATIVE_LOSS_COUNTERS, 'queueDropped', 'queued'):
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
        if long_run:
            offline_start = time.monotonic()
            archive_report = verify_long_archive(reader, sample_identity, opened, sample_path, segments + [final], emitted)
            archive_report['offlineReadbackSeconds'] = round(time.monotonic() - offline_start, 3)
            print(json.dumps({'longArchive': archive_report}), flush=True)
            readbacks = {'longArchiveReadback': archive_report}
        else:
            readbacks = {'secondSegmentReadback': readback(reader, sample_identity, segments[1], opened['plan']),
                         'finalSegmentReadback': readback(reader, sample_identity, final, opened['plan'])}
        reader_exit = shutdown(reader)
        producer.send('exit')
        producer_exit = producer.process.wait(timeout=10)
        assert writer_exit == reader_exit == producer_exit == 0
        assert hashlib.sha256(CLI.read_bytes()).hexdigest() == digest
        print(json.dumps({'cliSha256': digest, 'sampleId': opened['sampleId'], 'pid': target['pid'],
                          'observations': emitted, 'preStopSegments': segments, 'finalSegment': final,
                           **readbacks, 'stop': stopped,
                           'exitCodes': {'writer': writer_exit, 'reader': reader_exit, 'producer': producer_exit}}), flush=True)
        if inspect_gui:
            inspect_gui(sample_path / 'raw/00000000000000000001.ksaseg',
                        etw_segments=segments + [final])


if __name__ == '__main__':
    if sys.argv[1:2] == ['--producer']:
        if len(sys.argv) == 4:
            live_etw.PROVIDER = UUID(sys.argv[3])
        sample(Path(sys.argv[2]), batched=True)
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--long-seconds', type=int, metavar='SECONDS',
                            help='capture for at least SECONDS with paced 200-event waves and process counters')
        args = parser.parse_args()
        if args.long_seconds is not None and args.long_seconds < 1:
            parser.error('--long-seconds must be positive')
        run(long_seconds=args.long_seconds)
