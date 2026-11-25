"""Exercise the Release CLI with an owned Windows ETW provider and file sample."""

import ctypes as ct
from ctypes import wintypes as win
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import struct
import subprocess
import sys
import threading
import time
from uuid import UUID


REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
PROJECT = RELEASE / 'ActionAnalyzeLiveEtwValidation'
PROVIDER = UUID('d4a71ada-81b0-4b15-a173-417f33bc8107')
PAYLOAD = b'KSword owned benign file I/O'
KERNEL = ct.WinDLL('kernel32', use_last_error=True)


class EventDescriptor(ct.Structure):
    _fields_ = [('id', ct.c_uint16), ('version', ct.c_ubyte), ('channel', ct.c_ubyte),
                ('level', ct.c_ubyte), ('opcode', ct.c_ubyte), ('task', ct.c_uint16),
                ('keyword', ct.c_uint64)]


class EventData(ct.Structure):
    _fields_ = [('ptr', ct.c_uint64), ('size', ct.c_uint32), ('reserved', ct.c_uint32)]


def creation_time():
    """Return the sample's exact 100 ns creation identity without datetime conversion."""
    current = KERNEL.GetCurrentProcess
    current.restype = win.HANDLE
    get_times = KERNEL.GetProcessTimes
    get_times.argtypes = [win.HANDLE] + [ct.POINTER(win.FILETIME)] * 4
    times = [win.FILETIME() for _ in range(4)]
    if not get_times(current(), *(ct.byref(value) for value in times)):
        raise ct.WinError(ct.get_last_error())
    return str(times[0].dwHighDateTime << 32 | times[0].dwLowDateTime)


def sample(path):
    """Emit one event after each successful write and verified read of the owned file."""
    api = ct.WinDLL('advapi32')
    api.EventRegister.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_uint64)]
    api.EventUnregister.argtypes = [ct.c_uint64]
    api.EventWrite.argtypes = [ct.c_uint64, ct.POINTER(EventDescriptor), ct.c_uint32, ct.POINTER(EventData)]
    api.EventProviderEnabled.argtypes = [ct.c_uint64, ct.c_ubyte, ct.c_uint64]
    api.EventProviderEnabled.restype = ct.c_ubyte
    guid = (ct.c_ubyte * 16).from_buffer_copy(PROVIDER.bytes_le)
    handle = ct.c_uint64()
    assert api.EventRegister(guid, None, None, ct.byref(handle)) == 0
    try:
        print(json.dumps({'pid': os.getpid(), 'creationFileTime': creation_time()}), flush=True)
        assert input() == 'write'
        assert api.EventProviderEnabled(handle, 4, 0)

        def recorded(event_id, iteration):
            data = struct.pack('<II', iteration, len(PAYLOAD))
            owned = ct.create_string_buffer(data)
            descriptor = EventDescriptor(event_id, 0, 0, 4, 0, 0, 0)
            event_data = EventData(ct.addressof(owned), len(data), 0)
            assert api.EventWrite(handle, ct.byref(descriptor), 1, ct.byref(event_data)) == 0

        with path.open('x+b') as output:
            for iteration in range(6):
                output.seek(0)
                assert output.write(PAYLOAD) == len(PAYLOAD)
                output.flush()
                os.fsync(output.fileno())
                recorded(1, iteration)
                output.seek(0)
                assert output.read() == PAYLOAD
                recorded(2, iteration)
        print('{"operations":12}', flush=True)
        assert input() == 'exit'
    finally:
        assert api.EventUnregister(handle) == 0


class Child:
    """Bound pipe reads and retain each child's own lifecycle for cleanup."""

    def __init__(self, args):
        self.process = subprocess.Popen(args, cwd=RELEASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, encoding='utf-8')
        self.output = queue.Queue()
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in self.process.stdout:
            self.output.put(line)
        self.output.put('')

    def send(self, value):
        self.process.stdin.write(value + '\n')
        self.process.stdin.flush()

    def next(self):
        line = self.output.get(timeout=12)
        assert line, f'Child closed stdout, exit={self.process.poll()}'
        return json.loads(line)

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=8)
        self.process.stdin.close()
        self.process.stdout.close()


def call(cli, request_id, method, params, error=None, **fields):
    cli.send(json.dumps(dict(schemaVersion=1, requestId=request_id, method=method, params=params, **fields)))
    message = cli.next()
    assert (message['type'], message['requestId']) == ('response', request_id), message
    assert (message['error']['errorId'] if message['error'] else None) == error, message
    return message['result']


def decode_raw(path):
    """Cross-check the bytes and source descriptors independently of the C++ Stored reader."""
    data = path.read_bytes()
    assert data[:8] == b'KSAASEG\0'
    offset = 96
    rows = []
    while offset < len(data):
        assert data[offset:offset + 4] == b'AAB1'
        header, version, codec = struct.unpack_from('<HHH', data, offset + 4)
        assert (header, version, codec) == (80, 1, 0)
        count, = struct.unpack_from('<I', data, offset + 12)
        size, = struct.unpack_from('<I', data, offset + 40)
        offset += header
        end = offset + size
        for _ in range(count):
            length, record_type, schema, _, payload_size, seq = struct.unpack_from('<IHHIIQ', data, offset)
            assert (record_type, schema, length, seq) == (3, 1, payload_size + 32, len(rows) + 1)
            metadata_size, = struct.unpack_from('<I', data, offset + 32)
            start = offset + 36
            rows.append((json.loads(data[start:start + metadata_size]), data[start + metadata_size:offset + length]))
            offset += length
        assert offset == end
    assert offset == len(data)
    return rows, hashlib.sha256(data).hexdigest()


def controller(backend):
    child = Child([CLI, 'analyze', 'session', '--input', 'jsonl', '--output', 'jsonl', '--backend', backend])
    hello = child.next()
    assert hello['capabilities']['backend'] == backend
    assert hello['capabilities']['nativeCapture'] == (backend == 'r3')
    return child


def run():
    relative = PROJECT.relative_to(REPO).as_posix()
    assert not PROJECT.exists() and not PROJECT.is_symlink()
    tracked = subprocess.run(['git', 'ls-files', '--', relative], cwd=REPO, check=True, capture_output=True)
    assert not tracked.stdout
    created_project = False
    children = []
    try:
        cli = controller('r3')
        children.append(cli)
        report = call(cli, 'p', 'project.create', {'path': str(PROJECT), 'settings': {'title': 'ETW', 'notes': ''}})
        created_project = True
        identity = {'projectId': report['projectId']}
        revision = {'expected': {'revisionId': report['revisionId']}}
        producer = Child([sys.executable, '-B', __file__, '--sample', PROJECT / 'owned.sample'])
        children.append(producer)
        target = producer.next()
        options = dict(identity, **target, title='Owned file writes', providerId=str(PROVIDER), durationMs=12000)
        bad = dict(options, creationFileTime=str(int(target['creationFileTime']) + 1))
        call(cli, 'bad', 'session.open', bad, error='target-identity-mismatch', **revision)
        assert call(cli, 'p0', 'project.query', identity)['sampleCount'] == '0'
        opened = call(cli, 'start', 'session.open', options, **revision)
        assert opened['capture'] == 'active', opened
        assert call(cli, 'start', 'session.open', options, **revision) == opened
        assert call(cli, 'p1', 'project.query', identity)['sampleCount'] == '1'
        call(cli, 'start', 'session.open', options, error='request-id-conflict',
             expected={'revisionId': '00000000-0000-0000-0000-000000000001'})
        owner = {'session': opened['session']}
        call(cli, 'pbusy', 'project.close', identity, error='project-session-open')
        call(cli, 'wrong-epoch', 'session.query', {}, error='session-id-mismatch',
             session=dict(opened['session'], epoch='wrong'))
        call(cli, 'stale', 'session.stop', {}, error='stale-state-revision', expected={'stateRevision': '0'}, **owner)
        producer.send('write')
        assert producer.next()['operations'] == 12
        for index in range(45):
            current = call(cli, f'query-{index}', 'session.query', {}, **owner)
            if int(current['source']['enqueued']) >= 12:
                break
            time.sleep(.05)
        else:
            raise AssertionError(current)
        stop_fields = dict(owner, expected={'stateRevision': current['stateRevision']})
        stopped = call(cli, 'stop', 'session.stop', {}, **stop_fields)
        assert stopped['capture'] == 'stopped' and stopped['archive']['status'] == 'raw-verified', stopped
        assert stopped['source']['nativeSessionStopped'] and stopped['source']['queueDropped'] == '0', stopped
        assert call(cli, 'stop', 'session.stop', {}, **stop_fields) == stopped
        close_fields = dict(owner, expected={'stateRevision': stopped['stateRevision']})
        closed = call(cli, 'close', 'session.close', {}, **close_fields)
        assert closed['closed'] and call(cli, 'close', 'session.close', {}, **close_fields) == closed
        sample_id = stopped['sampleId']

        timed = call(cli, 'start-timed', 'session.open', dict(options, durationMs=1000, title='Timed sample'), **revision)
        time.sleep(1.2)
        timed_result = call(cli, 'query-timed', 'session.query', {}, session=timed['session'])
        assert timed_result['stopReason'] == 'duration-limit' and timed_result['archive']['status'] == 'raw-verified', timed_result
        call(cli, 'close-timed', 'session.close', {}, session=timed['session'], expected={'stateRevision': timed_result['stateRevision']})

        # Closing an idle input pipe must finalize an active sample before releasing the project lock.
        eof_capture = call(cli, 'start-again', 'session.open', dict(options, title='EOF sample'), **revision)
        cli.process.stdin.close()
        summary = cli.next()
        assert summary['reason'] == 'eof' and summary['clean'] and summary['liveSession']['stopReason'] == 'eof', summary
        assert summary['archive']['status'] == 'raw-verified', summary
        assert cli.process.wait(timeout=10) == summary['exitCode']
        reader = controller('offline')
        children.append(reader)
        project = call(reader, 'reopen', 'project.open', {'path': str(PROJECT)})
        assert project['sampleCount'] == '3'
        request = dict(identity, sampleId=sample_id, stream='raw', ordinal='1')
        reopened = call(reader, 'inspect', 'archive.inspect', request)
        assert reopened['framingStatus'] == 'framing-complete', reopened
        assert reopened['framingCoverage']['framedBytes'] == stopped['archive']['flushedBytes']
        assert reopened['framingCoverage']['lastSequence'] == stopped['archive']['lastSequence']
        assert call(reader, 'inspect-eof', 'archive.inspect', dict(request, sampleId=eof_capture['sampleId']))['framingStatus'] == 'framing-complete'
        rows, digest = decode_raw(PROJECT / 'samples' / sample_id / 'raw' / '00000000000000000001.ksaseg')
        plan, terminal = rows[0][0], rows[-1][0]
        assert plan['kind'] == 'etw-capture-plan-v1' and plan['processCreationFileTime'] == target['creationFileTime']
        assert terminal['kind'] == 'etw-capture-end-v1' and terminal['source']['eventsLost'] == 0
        events = [(row, data) for row, data in rows[1:-1] if row['descriptor']['id'] in {1, 2}]
        assert len(events) == 12, events
        for index, (row, data) in enumerate(events):
            assert row['headerPid'] == target['pid'] and row['providerId'] == str(PROVIDER), row
            assert row['sourceEpoch'] == plan['sourceEpoch'] and row['descriptor']['id'] == 1 + index % 2, row
            assert len(data) == row['originalPayloadBytes'] == 8, row
            assert data == struct.pack('<II', index // 2, len(PAYLOAD)), row
        call(reader, 'shutdown', 'controller.shutdown', {})
        assert reader.next()['reason'] == 'shutdown'
        assert reader.process.wait(timeout=10) == 0

        repl = subprocess.run([CLI, 'analyze', 'session', '--backend', 'r3'], cwd=RELEASE,
                              input='\n'.join(['help open', f'project open "{PROJECT}" read-write',
                                               f'open {target["pid"]} {target["creationFileTime"]} {PROVIDER} 1000 "REPL sample"',
                                               'status', 'stop', 'close', 'project close', 'quit', '']),
                              text=True, encoding='utf-8', capture_output=True, timeout=20, check=True)
        assert not repl.stderr and 'error:' not in repl.stdout, repl
        repl_objects = [json.loads(line) for line in repl.stdout.splitlines() if line.startswith('{')]
        assert len(repl_objects) == 6 and repl_objects[3]['archive']['status'] == 'raw-verified', repl.stdout
        assert repl_objects[4]['closed'] and repl_objects[5]['closed'], repl.stdout
        producer.send('exit')
        assert producer.process.wait(timeout=10) == 0
        print(json.dumps({'cliSha256': hashlib.sha256(CLI.read_bytes()).hexdigest(), 'pid': target['pid'],
                          'sampleId': sample_id, 'observations': len(events), 'rawSha256': digest,
                          'stopReceipt': stopped, 'reopened': reopened, 'deadlineReceipt': timed_result,
                          'eofSummary': summary, 'replStopReceipt': repl_objects[3]}))
    finally:
        for child in reversed(children):
            child.stop()
        if created_project:
            assert PROJECT.resolve() == PROJECT and not PROJECT.is_symlink()
            shutil.rmtree(PROJECT)
            print('TEST_PROJECT_REMOVED=True')


if __name__ == '__main__':
    if sys.argv[1:2] == ['--sample']:
        sample(Path(sys.argv[2]))
    else:
        run()
