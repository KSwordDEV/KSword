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

        def recorded(event_id, iteration):
            data = struct.pack('<II', iteration, len(PAYLOAD))
            owned = ct.create_string_buffer(data)
            descriptor = EventDescriptor(event_id, 0, 0, 4, 0, 0, 0)
            event_data = EventData(ct.addressof(owned), len(data), 0)
            assert api.EventWrite(handle, ct.byref(descriptor), 1, ct.byref(event_data)) == 0

        with path.open('x+b') as output:
            # 两次采样共享同一自有进程和文件。每条写入命令独立产生六次读写。
            while (command := input()) != 'exit':
                assert command == 'write', command
                assert api.EventProviderEnabled(handle, 4, 0)
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
    finally:
        assert api.EventUnregister(handle) == 0


class Child:
    """Bound pipe reads and retain each child's own lifecycle for cleanup."""

    def __init__(self, args, read_limit=None):
        self.process = subprocess.Popen(args, cwd=RELEASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, encoding='utf-8')
        self.output = queue.Queue()
        self.validate = None  # 夹具目标不使用控制器消息格式。
        self.sequence = 0  # 按完整已收帧推进。
        self.controller_id = None  # 第一帧记录本连接的控制器身份。
        self.reader = threading.Thread(target=self.read, args=(read_limit,), daemon=True)
        self.reader.start()

    def read(self, limit):
        count = 0
        for line in self.process.stdout:
            self.output.put(line)
            count += 1
            if count == limit:
                return
        self.output.put('')

    def send(self, value):
        self.process.stdin.write(value + '\n')
        self.process.stdin.flush()

    def next_line(self):
        """从子进程获得下一条完整文本行，超时或 EOF 时报告失败。"""
        line = self.output.get(timeout=12)
        assert line, f'Child closed stdout, exit={self.process.poll()}'
        return line

    def next(self):
        """解析并核对控制器输出的一帧 JSON。"""
        message = json.loads(self.next_line())
        if self.validate:
            self.validate(message)
            self.sequence += 1
            assert int(message['streamSequence']) == self.sequence, message
            if self.controller_id is None:
                self.controller_id = message['controllerId']
            assert message['controllerId'] == self.controller_id, message
        return message

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
    if cli.validate and not error:
        cli.validate(message, method)
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


def controller(backend, read_limit=None, validate=None):
    child = Child([CLI, 'analyze', 'session', '--input', 'jsonl', '--output', 'jsonl', '--backend', backend], read_limit)
    child.validate = validate if backend == 'r3' else None
    try:
        hello = child.next()
        assert hello['capabilities']['backend'] == backend
        assert hello['capabilities']['nativeCapture'] == (backend == 'r3')
    except Exception:
        child.stop()
        raise
    return child


def read_repl(child):
    """跳过人工会话的普通文字，返回下一条业务回执。"""
    for _ in range(8):
        line = child.next_line()  # 同一进程的 stdout 带上线超时。
        assert not line.startswith('error:'), line
        if line.startswith('{'):
            return json.loads(line)
    raise AssertionError('REPL did not return a JSON receipt')


def verify_empty_stop(receipt, segment, reason):
    """核对没有生产记录时的停止及回读，保留原生启动竞态的实际回执。"""
    assert receipt['stopReason'] == reason and receipt['archive']['status'] == 'raw-verified', receipt
    assert receipt['archive']['checkpoint'] == {'status': 'verified', 'error': None}, receipt
    source = receipt['source']
    assert source['nativeSessionStopped'] and source['enqueued'] == '0', receipt
    if not source['processAttempted'] or source['processWin32Error'] not in (0, 1223):
        assert receipt['capture'] == 'partial', receipt
    rows, _ = decode_raw(segment)
    assert len(rows) == 2, rows
    assert rows[0] == (receipt['plan'], b''), rows[0]
    assert rows[-1] == ({'kind': 'etw-capture-end-v1', 'stopReason': reason, 'source': source}, b''), rows[-1]
    assert segment.stat().st_size == int(receipt['archive']['flushedBytes']), receipt


def verify_checkpoint(reader, query, capture, segment):
    """核对跨流前缀、坏尾，以及未发布或损坏的提交。"""
    sample = segment.parents[1]
    marker = sample / 'checkpoints' / '00000000000000000001.json'
    records = sample / 'records' / segment.name
    checkpoint = json.loads(marker.read_bytes())
    assert checkpoint['kind'] == 'etw-terminal-checkpoint-v1' and checkpoint['sampleId'] == query['sampleId']
    assert checkpoint['projectId'] == query['projectId'] and checkpoint['generation'] == '1'
    sample_doc = sample / 'sample.json'
    assert checkpoint['descriptionHash'] == hashlib.sha256(sample_doc.read_bytes()).hexdigest()
    for name, path in (('raw', segment), ('records', records)):
        prefix = path.read_bytes()
        assert checkpoint[name]['endOffset'] == str(len(prefix))
        assert checkpoint[name]['sha256'] == hashlib.sha256(prefix).hexdigest()

    expected_failure = {'status': 'invalid', 'checkpoint': 'invalid'}

    def alter(path, edited, request_id, expected):
        saved = path.read_bytes()
        try:
            if edited is None:
                path.unlink()
            else:
                path.write_bytes(edited(saved))
            actual = call(reader, request_id, 'sample.query', query)['captureArchive']
            assert actual == expected, actual
        finally:
            path.write_bytes(saved)

    # 这几种只读错误不改变冻结配置。完整 checkpoint 始终只验证已公布前缀。
    alter(segment, lambda bytes_: bytes_ + b'torn tail', 'checkpoint-raw-tail', capture)
    alter(records, lambda bytes_: bytes_ + b'torn tail', 'checkpoint-records-tail', capture)
    alter(records, None, 'checkpoint-missing-records', expected_failure)
    alter(records, lambda bytes_: bytes_[:-1], 'checkpoint-short-records', expected_failure)
    alter(marker, lambda _: json.dumps(dict(checkpoint, sampleId=query['projectId'])).encode(),
          'checkpoint-wrong-sample', expected_failure)
    alter(marker, lambda _: json.dumps(dict(checkpoint, raw=dict(checkpoint['raw'], sha256='0' * 64))).encode(),
          'checkpoint-wrong-raw-hash', expected_failure)
    alter(marker, None, 'checkpoint-not-published', {key: value for key, value in capture.items() if key != 'checkpoint'})


def run(readback=(), inspect_gui=None, validate=None):
    relative = PROJECT.relative_to(REPO).as_posix()
    assert not PROJECT.exists() and not PROJECT.is_symlink()
    tracked = subprocess.run(['git', 'ls-files', '--', relative], cwd=REPO, check=True, capture_output=True)
    assert not tracked.stdout
    created_project = False
    children = []
    try:
        cli = controller('r3', validate=validate)
        children.append(cli)
        if validate:
            cli.send('{')  # 独立核对无有效请求 ID 的协议错误帧。
            assert cli.next()['type'] == 'protocolError'
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
        # 活采样还未生成原始段，历史查询返回缺失而不接管活会话。
        active_sample = dict(identity, sampleId=opened['sampleId'], includeCapture=True)
        assert call(cli, 'sample-active', 'sample.query', active_sample)['captureArchive'] == {'status': 'missing'}
        call(cli, 'sample-bad-option', 'sample.query', dict(active_sample, includeCapture='true'), error='invalid-params')
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
        assert stopped['archive']['checkpoint'] == {'status': 'verified', 'error': None}, stopped
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
        eof_segment = PROJECT / 'samples' / eof_capture['sampleId'] / 'raw' / '00000000000000000001.ksaseg'
        verify_empty_stop(summary['liveSession'], eof_segment, 'eof')
        assert summary['exitCode'] == (6 if summary['liveSession']['capture'] == 'partial' else 0), summary
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
        segment = PROJECT / 'samples' / sample_id / 'raw' / '00000000000000000001.ksaseg'
        rows, digest = decode_raw(segment)
        plan, terminal = rows[0][0], rows[-1][0]
        assert plan['kind'] == 'etw-capture-plan-v1' and plan['processCreationFileTime'] == target['creationFileTime']
        assert terminal['kind'] == 'etw-capture-end-v1' and terminal['source']['eventsLost'] == 0
        # 同一离线会话先验证旧调用，再按需读取采集摘要。
        selected = dict(identity, sampleId=sample_id)
        descriptor = call(reader, 'sample-descriptor', 'sample.query', selected)
        assert descriptor['status'] == 'not-collected' and 'captureArchive' not in descriptor
        capture = call(reader, 'sample-capture', 'sample.query', dict(selected, includeCapture=True))['captureArchive']
        assert capture == {
            'status': 'readback-verified', 'segmentOrdinal': '1', 'checkedBytes': stopped['archive']['flushedBytes'],
            'checkpoint': 'verified',
            'observationCount': '12', 'plan': {key: plan[key] for key in
                                              ('providerId', 'sourceEpoch', 'headerPid', 'processCreationFileTime')},
            'terminal': {'stopReason': terminal['stopReason'], 'nativeSessionStopped': True},
        }, capture
        eof_sample = dict(identity, sampleId=eof_capture['sampleId'], includeCapture=True)
        eof_archive = call(reader, 'sample-capture-eof', 'sample.query', eof_sample)['captureArchive']
        assert eof_archive['terminal']['stopReason'] == 'eof', eof_archive

        # 临时截尾只作用于本测试生成的段，恢复原字节后供两端读取。
        original_bytes = segment.read_bytes()
        try:
            segment.write_bytes(original_bytes[:-1])
            damaged = call(reader, 'sample-capture-short', 'sample.query', dict(selected, includeCapture=True))
            assert damaged['captureArchive'] == {'status': 'invalid', 'checkpoint': 'invalid'}, damaged
            assert damaged['frozenSettings'] == descriptor['frozenSettings'], damaged
        finally:
            segment.write_bytes(original_bytes)
        verify_checkpoint(reader, dict(selected, includeCapture=True), capture, segment)

        events = [(row, data) for row, data in rows[1:-1] if row['descriptor']['id'] in {1, 2}]
        assert len(events) == 12, events
        for index, (row, data) in enumerate(events):
            assert row['headerPid'] == target['pid'] and row['providerId'] == str(PROVIDER), row
            assert row['sourceEpoch'] == plan['sourceEpoch'] and row['descriptor']['id'] == 1 + index % 2, row
            assert len(data) == row['originalPayloadBytes'] == 8, row
            assert data == struct.pack('<II', index // 2, len(PAYLOAD)), row
        # 两个读取器使用同一正式段，生成的项目仍由本用例负责清理。
        for validator in readback:
            subprocess.run([validator, '--etw-file', segment], cwd=RELEASE, check=True, timeout=15)
        if inspect_gui:
            inspect_gui(segment, events[0])
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
        quick_segment = PROJECT / 'samples' / repl_objects[1]['sampleId'] / 'raw' / '00000000000000000001.ksaseg'
        verify_empty_stop(repl_objects[3], quick_segment, 'requested')

        # 用人工命令重开同一份采样报告，核对与 JSONL 回执一致。
        history = subprocess.run([CLI, 'analyze', 'session'], cwd=RELEASE,
                                 input=f'project open "{PROJECT}"\nsample status {sample_id} capture\nquit\n',
                                 text=True, encoding='utf-8', capture_output=True, timeout=15, check=True)
        history_rows = [json.loads(line) for line in history.stdout.splitlines() if line.startswith('{')]
        assert len(history_rows) == 2 and history_rows[1]['captureArchive'] == capture, history.stdout

        # 用同一自有目标验证人工会话从就绪、生产记录到阻塞等待中的实际命令输入。
        repl_live = Child([CLI, 'analyze', 'session', '--backend', 'r3'])
        children.append(repl_live)
        repl_live.send(f'project open "{PROJECT}" read-write')
        assert read_repl(repl_live)['projectId'] == report['projectId']
        repl_live.send(f'open {target["pid"]} {target["creationFileTime"]} {PROVIDER} 12000 "REPL observed sample"')
        repl_opened = read_repl(repl_live)  # 冻结本次人工会话的采样 ID。
        assert repl_opened['capture'] == 'active', repl_opened
        for _ in range(40):
            repl_live.send('status')
            repl_status = read_repl(repl_live)  # 等待原生消费线程进入 ProcessTrace。
            if repl_status['source']['state'] == 'running':
                break
            time.sleep(.05)
        else:
            raise AssertionError(repl_status)
        producer.send('write')  # 此处使用同一进程，再产生 12 条独立观察。
        assert producer.next()['operations'] == 12
        for _ in range(45):
            repl_live.send('status')
            repl_status = read_repl(repl_live)
            if repl_status['source']['enqueued'] == '12':
                break
            time.sleep(.05)
        else:
            raise AssertionError(repl_status)
        repl_live.send('stop')
        repl_observed = read_repl(repl_live)  # 停止后再读取已刷盘段。
        assert repl_observed['capture'] == 'stopped' and repl_observed['archive']['status'] == 'raw-verified', repl_observed
        repl_segment = PROJECT / 'samples' / repl_opened['sampleId'] / 'raw' / '00000000000000000001.ksaseg'
        repl_rows, _ = decode_raw(repl_segment)  # 按归档原序比对载荷。
        assert len(repl_rows) == 14 and [data for _, data in repl_rows[1:-1]] == [data for _, data in events]
        repl_live.send('close')
        assert read_repl(repl_live)['closed']
        repl_live.send('project close')
        assert read_repl(repl_live)['closed']
        repl_live.send('quit')
        assert repl_live.process.wait(timeout=10) == 0

        # 读完前三帧后停止读 stdout，保持 stdin 活跃以制造真实管道背压。
        slow = controller('r3', read_limit=3, validate=validate)
        children.append(slow)
        call(slow, 'slow-project', 'project.open', {'path': str(PROJECT), 'access': 'read-write'})
        slow_capture = call(slow, 'slow-open', 'session.open', dict(options, durationMs=30000, title='Slow output'), **revision)
        slow.reader.join(timeout=3)
        assert not slow.reader.is_alive()
        messages = ''.join(json.dumps(dict(schemaVersion=1, requestId=f'slow-{index}', method='session.query',
                                           params={}, session=slow_capture['session'])) + '\n' for index in range(30))
        slow.process.stdin.write(messages)
        slow.process.stdin.flush()
        assert slow.process.wait(timeout=12) == 3, 'Expected the CLI transport to fail on blocked output'
        slow_path = PROJECT / 'samples' / slow_capture['sampleId'] / 'raw' / '00000000000000000001.ksaseg'
        slow_rows, _ = decode_raw(slow_path)
        slow_terminal = slow_rows[-1][0]  # 停止回执从已写档案回读，stdout 无法保证交付。
        assert slow_terminal['stopReason'] == 'output-lost' and slow_terminal['source']['nativeSessionStopped'], slow_terminal

        # 让真实目标自行退出，确认冻结的进程句柄会触发会话收尾。
        exit_controller = controller('r3', validate=validate)
        children.append(exit_controller)
        call(exit_controller, 'reopen-rw', 'project.open', {'path': str(PROJECT), 'access': 'read-write'})
        exit_capture = call(exit_controller, 'start-exit', 'session.open', dict(options, title='Target exit'), **revision)
        exit_owner = {'session': exit_capture['session']}
        producer.send('exit')
        assert producer.process.wait(timeout=10) == 0
        for index in range(60):
            exit_receipt = call(exit_controller, f'exit-query-{index}', 'session.query', {}, **exit_owner)
            if exit_receipt['stopReason'] == 'target-exited':
                break
            time.sleep(.05)
        assert exit_receipt['stopReason'] == 'target-exited', exit_receipt
        assert exit_receipt['archive']['status'] == 'raw-verified' and exit_receipt['source']['nativeSessionStopped'], exit_receipt
        call(exit_controller, 'exit-close', 'session.close', {}, **exit_owner,
             expected={'stateRevision': exit_receipt['stateRevision']})
        call(exit_controller, 'exit-shutdown', 'controller.shutdown', {})
        assert exit_controller.next()['clean'] and exit_controller.process.wait(timeout=10) == 0
        print(json.dumps({'cliSha256': hashlib.sha256(CLI.read_bytes()).hexdigest(), 'pid': target['pid'],
                          'sampleId': sample_id, 'observations': len(events), 'rawSha256': digest,
                          'stopReceipt': stopped, 'reopened': reopened, 'deadlineReceipt': timed_result,
                          'eofSummary': summary, 'replStopReceipt': repl_objects[3], 'targetExitReceipt': exit_receipt,
                          'slowOutputTerminal': slow_terminal, 'captureReadback': capture,
                          'replObservationReceipt': repl_observed}))
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
    elif sys.argv[1:2] == ['--readback']:
        run([Path(path).resolve(strict=True) for path in sys.argv[2:]])
    else:
        run()
