"""AA-03: capture self-only API calls from an owned x64 or WOW64 cooperative target."""

import argparse
import configparser
from contextlib import contextmanager, nullcontext
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
from queue import Queue
from stat import FILE_ATTRIBUTE_REPARSE_POINT
import struct
import subprocess
import sys
from threading import Event, Thread
import time
from uuid import UUID

# 独立运行和桌面调用共用同一个源码规则库读侧。
sys.path.insert(1, str(Path(__file__).resolve().parents[1]))
from api_rule_profile import behavior_rule


SCRIPT = Path(__file__).resolve()
RELEASE = SCRIPT.parents[3] / 'Ksword5.1/x64/Release'
CLI = RELEASE / 'KswordCLI.exe'
AGENT = RELEASE / 'APIMonitor_x64.dll'
AGENT_X86 = RELEASE / 'APIMonitor_x86.dll'
TARGET_X86 = RELEASE / 'ApiMonitorStartupTarget_x86.exe'
BUFFER_SIZE = 4096
TARGET_TIMEOUT = 65
COOPERATIVE_ENV = 'KSWORD_APIMON_COOPERATIVE_SESSION_V1'
ERROR_NOT_READY = 21
ERROR_ACCESS_DENIED = 5
ERROR_OPERATION_ABORTED = 995
ERROR_TIMEOUT = 1460
BEHAVIOR_PRESET_SET = 'ksword.api.behavior-presets.v1'
LOCAL_STARTUP_TIMEOUT_MS = 15000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C
IDENTITY_NEGATIVE_CASES = ('wrong-filetime', 'missing-agent')


def winapi(dll, name, result, *args):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, args
    return function


def target(identity_negative=None, behavior=False, startup_gate=False):
    kernel = C.WinDLL('kernel32', use_last_error=True)
    get_current_process = winapi(kernel, 'GetCurrentProcess', W.HANDLE)
    process_times = winapi(kernel, 'GetProcessTimes', W.BOOL, W.HANDLE, *([C.POINTER(W.FILETIME)] * 4))
    native_tid = winapi(kernel, 'GetCurrentThreadId', W.DWORD)()
    process = get_current_process()  # Only this process's pseudo-handle; no PID or handle input.
    if identity_negative:
        process_machine, native_machine = W.WORD(), W.WORD()
        architecture = winapi(kernel, 'IsWow64Process2', W.BOOL, W.HANDLE,
                              C.POINTER(W.WORD), C.POINTER(W.WORD))
        if not architecture(process, C.byref(process_machine), C.byref(native_machine)):
            raise C.WinError(C.get_last_error())
        assert (process_machine.value or native_machine.value) == IMAGE_FILE_MACHINE_AMD64, 'AMD64 target required'
        get_module = winapi(kernel, 'GetModuleHandleW', W.HMODULE, W.LPCWSTR)
        assert not get_module(AGENT.name), 'Agent was already present at fixture startup'
    times = [W.FILETIME() for _ in range(4)]
    if not process_times(process, *(C.byref(value) for value in times)):
        raise C.WinError(C.get_last_error())
    creation = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    kernelbase = C.WinDLL('KernelBase', use_last_error=True)
    write = winapi(kernelbase, 'WriteProcessMemory', W.BOOL, W.HANDLE, C.c_void_p,
                   C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t))
    destination = C.create_string_buffer(BUFFER_SIZE)
    source = C.create_string_buffer(b'Z')
    written = C.c_size_t()
    base = C.addressof(destination)

    # Never let this fresh target pick up a stale PID-scoped configuration.
    directory = Path(os.environ[COOPERATIVE_ENV])
    pid = os.getpid()
    assert not any(directory.iterdir()), f'Unexpected files before target startup: {directory}'
    agent = None
    startup = {}
    identity = dict(pid=pid, tid=native_tid, creation=creation, base=base)
    if identity_negative != 'missing-agent':
        # Opt in before loading our first-party Agent into this process.
        start = time.perf_counter_ns()
        agent = C.WinDLL(str(AGENT))
        load_ns = time.perf_counter_ns() - start
        if startup_gate:
            wait_startup = winapi(agent, 'KSwordApiMonitorWaitForCooperativeStartup', W.DWORD, W.DWORD)
            assert wait_startup(0) == ERROR_NOT_READY, 'startup gate accepted a target before explicit opt-in'
        enable = winapi(agent, 'KSwordApiMonitorEnableCooperativeCapture', W.DWORD)
        deadline = time.monotonic() + 5
        status = enable()
        while status == ERROR_NOT_READY and time.monotonic() < deadline:
            time.sleep(0.025)
            status = enable()
        if status:
            raise C.WinError(status)
        enabled_ns = time.perf_counter_ns() - start
        identity.update(agentLoadNs=load_ns, agentEnabledNs=enabled_ns)
        if startup_gate:
            identity['localStartupBeforeController'] = wait_startup(25)
            assert identity['localStartupBeforeController'] == ERROR_TIMEOUT, identity
    if identity_negative:
        identity['agentLoaded'] = bool(get_module(AGENT.name))
    # 只打开自己的查询句柄。失败调用使用独立缓冲区，成功样本不受影响。
    denied_destination = C.create_string_buffer(1)
    query_handle = None
    if behavior:
        open_process = winapi(kernel, 'OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
        query_handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not query_handle:
            raise C.WinError(C.get_last_error())
        identity.update(deniedBase=C.addressof(denied_destination), queryHandle=query_handle)
    stop = Event()

    def wait_for_eof():
        sys.stdin.buffer.read()
        stop.set()

    # Only closes our own fixture cleanly after the controller finishes.
    Thread(target=wait_for_eof, daemon=True).start()
    print(json.dumps(identity), flush=True)
    if startup_gate:
        status = wait_startup(LOCAL_STARTUP_TIMEOUT_MS)
        if status:
            raise C.WinError(status)
        startup['localReadyNs'] = time.perf_counter_ns()
    deadline = time.monotonic() + TARGET_TIMEOUT
    count = 0
    try:
        while time.monotonic() < deadline and not stop.is_set() and count < BUFFER_SIZE:
            if startup_gate and count == 0:
                startup['firstActionNs'] = time.perf_counter_ns()
            if not write(process, base + count, source, 1, C.byref(written)):
                raise C.WinError(C.get_last_error())
            assert written.value == 1 and destination[count] == b'Z'
            if behavior:
                written.value = 0
                C.set_last_error(0)
                returned = write(query_handle, identity['deniedBase'], source, 1, C.byref(written))
                assert (returned, C.get_last_error(), written.value, denied_destination.raw) == (
                    0, ERROR_ACCESS_DENIED, 0, b'\0'), 'owned query-only handle did not produce access denied'
            count += 1
            stop.wait(0.025)
    finally:
        if query_handle:
            close_handle = winapi(kernel, 'CloseHandle', W.BOOL, W.HANDLE)
            if not close_handle(query_handle):
                raise C.WinError(C.get_last_error())
    assert stop.is_set(), 'fixture lifetime expired before controller returned'
    loaded = bool(get_module(AGENT.name)) if identity_negative else bool(agent._handle)
    if startup_gate:
        startup['localStartupAfterStop'] = wait_startup(0)
    print(json.dumps(dict(calls=count, agentLoaded=loaded, **startup)), flush=True)


def receipt(code, stdout, stderr, accepted):
    assert code in accepted, (code, stdout, stderr)
    return json.loads(stdout)['data']


def invoke(*args, accepted=(0,)):
    result = subprocess.run([CLI, *args, '--json'], capture_output=True, timeout=15)
    return receipt(result.returncode, result.stdout, result.stderr, accepted)


def create_session_directory(directory):
    class SecurityAttributes(C.Structure):
        _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit_handle', W.BOOL)]

    sid = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                          '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],
                         capture_output=True, timeout=15, check=True).stdout.decode('ascii').strip()
    assert sid.startswith('S-1-') and all(part.isdecimal() for part in sid[2:].split('-')), sid
    assert sid != 'S-1-5-18', 'Run the same-user fixture as a regular Windows user, not LocalSystem'
    kernel = C.WinDLL('kernel32', use_last_error=True)
    advapi = C.WinDLL('advapi32', use_last_error=True)
    convert = winapi(advapi, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', W.BOOL,
                     W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD))
    create = winapi(kernel, 'CreateDirectoryW', W.BOOL, W.LPCWSTR, C.POINTER(SecurityAttributes))
    free = winapi(kernel, 'LocalFree', C.c_void_p, C.c_void_p)
    descriptor = C.c_void_p()
    # Create atomically with a protected DACL. Both children run under this SID.
    if not convert(f'O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)', 1, C.byref(descriptor), None):
        raise C.WinError(C.get_last_error())
    try:
        attributes = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor.value, False)
        if not create(str(directory), C.byref(attributes)):
            raise C.WinError(C.get_last_error())
    finally:
        free(descriptor)


def cleanup_session(directory, target_pid, creation, controller_pid):
    config = directory / f'config_{target_pid}_{creation}.ini'
    stop = directory / f'stop_{target_pid}_{creation}.flag'
    paths = [path for path in (config, stop) if os.path.lexists(path)]
    if not paths:
        return
    assert controller_pid is not None and config in paths, paths
    for path in paths:
        assert not (path.lstat().st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) and path.is_file(), path
    ini = configparser.ConfigParser(interpolation=None)
    ini.read_string(config.read_text(encoding='utf-16'))
    assert ini['monitor']['session_id'].startswith(f'cli_{controller_pid}_'), config
    if stop in paths:
        assert stop.read_bytes() == b'stop', stop
    for path in paths:  # Both owned processes have exited; no late Agent can reread these files.
        path.unlink()
    print(f'OWNED_SESSION_FILES_REMOVED={len(paths)}', flush=True)


def verify_archive(project, identity, captured, emitted, require_first=False, require_multiple=False):
    from live_etw import decode_raw

    archived = captured['archive']
    assert archived and archived['status'] == 'readback-verified' and archived['rawSegment'] == '1', captured
    sample = captured['sampleId']
    sample_dir = project / 'samples' / sample
    segments = int(archived['committedSegments'])
    assert segments >= (2 if require_multiple else 1) and archived['finalSegment'], archived
    assert archived['sourceState'] == ('pipe-eof' if captured['cleanPipeEof'] else 'unconfirmed-end'), archived
    assert archived['sourceRows'] == captured['archivedPackets'] == captured['ordinaryPackets'], captured
    assert int(archived['sourceRows']) >= int(archived['clueRows']) > 0, archived
    if require_multiple:
        assert int(archived['sourceRows']) > int(archived['clueRows']), archived

    # 检查每段的实际字节、前一段散列与完整普通包的连续性。
    raw_sequence = 1
    source_sequence = 0
    previous_digest = None
    packets = []
    behavior = 'deniedBase' in identity
    if behavior:
        assert captured['rules']['presetSet'] == BEHAVIOR_PRESET_SET, captured['rules']
    for ordinal in range(1, segments + 1):
        records, digest = decode_raw(sample_dir / 'raw' / f'{ordinal:020d}.ksaseg', raw_sequence)
        marker = json.loads((sample_dir / 'checkpoints' / f'{ordinal:020d}.json').read_bytes())
        assert marker['raw']['sha256'] == digest and marker['previousRawSha256'] == previous_digest, marker
        assert marker['lastSourceSequence'] == str(source_sequence + len(records) - 1 - (ordinal == segments)), marker
        plan, body = records[0]
        assert not body and plan['archiveSource'] == 'cooperative-pipe', plan
        if behavior:
            assert plan['rulePresetSet'] == captured['rules']['presetSet'], (ordinal, plan, captured['rules'])
        assert marker['finalSegment'] == (ordinal == segments), marker
        previous_digest = digest
        for index, (metadata, wire) in enumerate(records[1:], raw_sequence + 1):
            if metadata['kind'] == 'api-archive-follow-end-v1':
                assert index == raw_sequence + len(records) - 1 and ordinal == segments and not wire, metadata
                assert metadata['source']['validatedRows'] == captured['ordinaryPackets'], metadata
                continue
            source_sequence += 1
            assert len(wire) == 1000 and metadata['sourceSequence'] == str(source_sequence), metadata
            assert struct.unpack_from('<I', wire, 8)[0] == identity['pid'], metadata
            assert struct.unpack_from('<Q', wire, 896)[0] == int(captured['sourceSessionIdentity']), metadata
            packets.append((ordinal, index, metadata, wire))
        raw_sequence += len(records)
    assert source_sequence == int(captured['ordinaryPackets']), source_sequence
    print(f'COOPERATIVE_API_FULL_PACKETS=PASS SEGMENTS={segments} ORDINARY={source_sequence} '
          f'CLUES={archived["clueRows"]} FINAL_SHA256={previous_digest}', flush=True)

    offsets = []
    timestamps = []
    first = None
    first_denied = None  # 来自合作夹具独立缓冲区的第一条明确拒绝。
    for ordinal, index, metadata, wire in packets:
        if struct.unpack_from('<I', wire, 12)[0] != identity['tid']:
            continue
        if wire[96:224].decode('utf-16-le').split('\0', 1)[0] != 'WriteProcessMemory':
            continue
        detail = dict(field.split('=', 1) for field in wire[224:864].decode('utf-16-le').split('\0', 1)[0].split())
        if identity.get('deniedBase') == int(detail['base'], 16):
            assert int(detail['process'], 16) == identity['queryHandle'] and detail['size'] == '1', detail
            assert struct.unpack_from('<i', wire, 28)[0] == ERROR_ACCESS_DENIED and detail['written'] == '0', detail
            if first_denied is None:
                first_denied = (ordinal, index, metadata, wire)
            continue
        offset = int(detail['base'], 16) - identity['base']
        assert 0 <= offset < emitted and detail['size'] == detail['written'] == '1', (offset, detail)
        # The producer serializes GetCurrentProcess() as a 64-bit all-ones value on both architectures.
        assert int(detail['process'], 16) == 0xFFFFFFFFFFFFFFFF, detail
        assert struct.unpack_from('<IIIIQIi', wire)[:4] == (1000, 0x20261003, identity['pid'], identity['tid'])
        assert struct.unpack_from('<i', wire, 28)[0] == 0
        assert struct.unpack_from('<Q', wire, 896)[0] == int(captured['sourceSessionIdentity'])
        if first is None:
            first = (ordinal, index, metadata, wire)
        offsets.append(offset)
        timestamps.append(struct.unpack_from('<Q', wire, 16)[0])
    assert len(offsets) >= 2 and offsets == list(range(offsets[0], offsets[-1] + 1)), offsets
    if require_first:
        assert offsets[0] == 0, f'first action after the local gate was not captured: {offsets[0]}'

    ordinal, index, metadata, wire = first
    replay = invoke('analyze', 'api-evidence', 'replay', '--project', project, '--sample', sample,
                    '--packet', '1', '--after', str(index - 1), '--limit', '1')
    row, = replay['rows']
    assert (replay['status'], replay['rawSegment']) == ('readback-verified', '1'), replay
    assert (row['rawSegment'], row['rawSequence'], row['sourceSequence'], row['packet']) == (
        str(ordinal), str(index), metadata['sourceSequence'], wire.hex()), row
    assert (row['pid'], row['tid'], row['archivedCallerCreation100ns'], row['sourceSessionIdentity']) == (
        identity['pid'], identity['tid'], str(identity['creation']), captured['sourceSessionIdentity']), row
    assert (row['family'], row['phase'], row['reportedStatusCode']) == ('memory-write', 'return', 0), row
    assert int(row['reportedReturnBits'], 16) != 0 and row['targetIdentity'] is None, row
    print(json.dumps(dict(sampleId=sample, rawSegment=ordinal, rawSequence=index, sourceSequence=row['sourceSequence'],
                          packetSha256=hashlib.sha256(wire).hexdigest(),
                          emitted=emitted, capturedSelfWrites=len(offsets), firstOffset=offsets[0],
                          lastOffset=offsets[-1])), flush=True)
    if behavior:
        assert first_denied is not None, 'no denied call from the owned query-only handle was archived'
        verify_behavior(project, captured, first_denied, first)
        print(f'COOPERATIVE_API_RULE_VERSION=PASS SAMPLE={sample} PRESET_SET={BEHAVIOR_PRESET_SET} '
              f'PLAN_SEGMENTS=1..{segments} VERIFIED_RULE_REPLAYS=3', flush=True)
    return timestamps


def verify_behavior(project, captured, denied, successful):
    """对账同一采样的真实返回字节、正例语义及成功调用负例。"""
    sample = captured['sampleId']
    live = captured['rules']
    preset = live['presetSet']
    ordinal, sequence, metadata, wire = denied
    replay = invoke('analyze', 'api-evidence', 'replay', '--project', project, '--sample', sample,
                    '--packet', '1', '--after', str(sequence - 1), '--limit', '1')
    row, = replay['rows']
    assert (row['rawSequence'], row['sourceSequence'], row['packet']) == (
        str(sequence), metadata['sourceSequence'], wire.hex()), row
    assert row['reportedStatusCode'] == ERROR_ACCESS_DENIED and int(row['reportedReturnBits'], 16) == 0, row

    # 规则页偏移统计线索，不等于包含所有原包及计划头的 Stored 序号。
    offsets = {}
    after = 0
    clue_index = 0
    while len(offsets) < 2:
        page = invoke('analyze', 'api-evidence', 'replay', '--project', project, '--sample', sample,
                      '--after', str(after), '--limit', '100')
        for entry in page['rows']:
            if int(entry['rawSequence']) in (sequence, successful[1]):
                offsets[int(entry['rawSequence'])] = clue_index
            clue_index += 1
        if not page['nextAfter']:
            break
        after = int(page['nextAfter'])
    for item, expect_behavior in ((denied, True), (successful, False)):
        segment, raw, source, _ = item
        result = invoke('analyze', 'replay-api-rules', '--project', project, '--sample', sample,
                        '--profile', 'by-category', '--offset', str(offsets[raw]), '--limit', '1')
        match, = result['matches']
        assert (result['presetSet'], result['recordedPresetSet']) == (preset, preset), result
        assert result['archiveSource'] == 'cooperative-pipe', result
        assert (result['status'], result['sampleId'], match['raw']['segment'], match['raw']['sequence'],
                match['sourceSequence']) == ('readback-verified', sample, str(segment), str(raw), source['sourceSequence']), match
        if expect_behavior:
            behavior_id = 'ksword.behavior.memory-write-access-denied-return.v1'  # 同一原包的预期行为规则。
            definition = behavior_rule(behavior_id)
            assert match['behavior'] == dict(ruleId=behavior_id, evidence='reported-api-return',
                                              summary=definition['summary'], summaryZh=definition.get('summaryZh')), match
        else:
            assert 'behavior' not in match and match['api'] == 'WriteProcessMemory', match
    print(f'COOPERATIVE_API_BEHAVIOR=PASS SAMPLE={sample} RAW={ordinal}#{sequence} SOURCE={metadata["sourceSequence"]} '
          f'NO_EXPLANATION={successful[0]}#{successful[1]}:{successful[2]["sourceSequence"]}', flush=True)

    # 采集中按段求值；用关闭后的独立回读校验坐标。
    assert live['state'] == 'ready' and live['matchedRows'] == captured['archive']['clueRows'], live
    latest = live['latest']
    assert int(latest['segmentOrdinal']) > 1, latest
    replay = invoke('analyze', 'replay-api-rules', '--project', project, '--sample', sample,
                    '--profile', live['profile'], '--offset', str(int(live['matchedRows']) - 1), '--limit', '1')
    match, = replay['matches']
    assert (replay['presetSet'], replay['recordedPresetSet']) == (preset, preset), replay
    assert replay['archiveSource'] == 'cooperative-pipe' and replay['nextOffset'] is None, replay
    assert (latest['segmentOrdinal'], latest['rawSequence'], latest['sourceSequence'], latest['ruleId'],
            latest.get('behavior')) == (match['raw']['segment'], match['raw']['sequence'], match['sourceSequence'],
                                       match['ruleId'], match.get('behavior')), (live, match)
    print(f'COOPERATIVE_API_COMMITTED_RULES=PASS MATCHES={live["matchedRows"]} '
          f'LATEST={latest["segmentOrdinal"]}#{latest["rawSequence"]}:{latest["sourceSequence"]}', flush=True)

    # 同一段再通过正式图入口读取，核对输入来源、链水位及原包坐标。
    from api_evidence import read_graph

    project_id = json.loads((project / 'project.ksaproj').read_bytes())['projectId']
    sample_dir = project / 'samples' / sample
    last_hit_segment = latest['segmentOrdinal']
    marker = json.loads((sample_dir / 'checkpoints' / f'{int(last_hit_segment):020d}.json').read_bytes())
    reply, = read_graph(project, project_id, sample,
                        {'ordinal': last_hit_segment, 'afterSequence': str(int(latest['rawSequence']) - 1),
                         'expectedSha256': marker['raw']['sha256'], 'limit': 1})
    assert reply['error'] is None, reply
    graph = reply['result']
    assert (graph['archiveSource'], graph['apiInputKind'], graph['sourceCoverage'], graph['finalSegment']) == (
        'api-follow-checkpoint', 'cooperative-pipe', 'unknown', marker['finalSegment']), graph
    row, = graph['observations']
    assert (row['raw']['recordSequence'], row['sourceSequence']) == (
        latest['rawSequence'], latest['sourceSequence']), row
    print(f'COOPERATIVE_API_CHECKPOINT_GRAPH=PASS RAW={last_hit_segment}#{row["raw"]["recordSequence"]}', flush=True)


def verify_missing_segment(project, captured):
    """保留最后一段的检查点，临时移开本次夹具创建的原始段，核对前缀回执。"""
    sample = captured['sampleId']
    ordinal = int(captured['archive']['committedSegments'])
    sample_dir = project / 'samples' / sample
    final_raw = sample_dir / 'raw' / f'{ordinal:020d}.ksaseg'
    moved = final_raw.with_suffix('.unavailable')
    assert not moved.exists()
    previous = json.loads((sample_dir / 'checkpoints' / f'{ordinal - 1:020d}.json').read_bytes())
    final_raw.rename(moved)
    try:
        prefix = invoke('analyze', 'api-evidence', 'replay', '--project', project, '--sample', sample, accepted=(4,))
        assert (prefix['status'], prefix['committedSegments'], prefix['failedSegment'], prefix['sourceRows']) == (
            'readback-prefix', str(ordinal - 1), str(ordinal), previous['lastSourceSequence']), prefix
        assert prefix['rows'] and all(int(row['rawSegment']) < ordinal for row in prefix['rows']), prefix
    finally:
        moved.rename(final_raw)
    print(f'COOPERATIVE_API_PREFIX=PASS LAST_VERIFIED={ordinal - 1} MISSING_RAW={ordinal} '
          f'ORDINARY={prefix["sourceRows"]}', flush=True)


def create_project(project, title):
    created = subprocess.run([CLI, 'analyze', 'session'],
                             input=f'project create "{project}" "{title}"\nquit\n'.encode(),
                             capture_output=True, check=True, timeout=15)
    assert (project / 'project.ksaproj').is_file(), created.stdout


@contextmanager
def owned_etw_session(project, identity):
    """Keep the R3 ETW project lease open during standalone cooperative capture."""
    from live_etw import PROVIDER, call, controller

    cli = controller('r3')
    try:
        created = call(cli, 'project', 'project.create', {
            'path': str(project), 'settings': {'title': 'AA-03 cooperative Agent ETW', 'notes': ''}})
        selected = {'projectId': created['projectId']}
        options = dict(selected, pid=identity['pid'], creationFileTime=str(identity['creation']),
                       providerId=str(PROVIDER), durationMs=45000, title='Cooperative Agent lifecycle')
        opened = call(cli, 'start', 'session.open', options, expected={'revisionId': created['revisionId']})
        session = {'session': opened['session']}
        for index in range(40):
            current = call(cli, f'ready-{index}', 'session.query', {}, **session)
            assert current['capture'] == 'active', current
            if current['source']['state'] == 'running':
                break
            time.sleep(.05)
        else:
            raise AssertionError(current)
        assert current['source']['enableWin32Error'] == 0 and current['source']['openWin32Error'] == 0, current
        assert current['source']['enqueued'] == '0', current
        print(f'OWNED_ETW_SUBSCRIBED PID={identity["pid"]} CREATION={identity["creation"]} '
              f'PROVIDER={PROVIDER} SAMPLE={opened["sampleId"]}', flush=True)

        evidence = {}
        yield evidence

        # The standalone API command has exited. Give the real-time buffers a chance to deliver HooksRestored.
        for index in range(60):
            current = call(cli, f'drain-{index}', 'session.query', {}, **session)
            assert current['capture'] == 'active', current
            if int(current['source']['enqueued']) >= 3:
                break
            time.sleep(.05)
        stopped = call(cli, 'stop', 'session.stop', {}, expected={'stateRevision': current['stateRevision']}, **session)
        print('OWNED_ETW_STOP=' + json.dumps(stopped), flush=True)
        assert call(cli, 'close', 'session.close', {}, expected={'stateRevision': stopped['stateRevision']}, **session)['closed']
        assert call(cli, 'release-project', 'project.close', selected)['closed']
        reopened = call(cli, 'reopen', 'project.open', {'path': str(project)})
        assert (reopened['projectId'], reopened['sampleCount'], reopened['access']) == (
            selected['projectId'], '1', 'read-only'), reopened
        sample = dict(selected, sampleId=stopped['sampleId'])
        readback = call(cli, 'readback', 'sample.query', dict(sample, includeCapture=True))
        graph = call(cli, 'graph', 'archive.inspect', dict(sample, stream='raw', ordinal='1', view='graph'))
        evidence.update(projectId=selected['projectId'], stopped=stopped, readback=readback['captureArchive'], graph=graph)
        assert call(cli, 'close-readback', 'project.close', selected)['closed']
        assert call(cli, 'shutdown', 'controller.shutdown', {})['shutdown']
        summary = cli.next()
        assert (summary['reason'], summary['clean'], summary['exitCode']) == ('shutdown', True, 0), summary
        assert cli.process.wait(timeout=10) == 0
        print(f'OWNED_ETW_CLI_EXIT=0 PID={cli.process.pid}', flush=True)
    finally:
        # EOF also requests product cleanup on a failed assertion. Wait for that exact child to exit.
        cli.process.stdin.close()
        cli.process.wait(timeout=15)
        cli.process.stdout.close()


def verify_owned_etw(etw_project, api_project, identity, etw, captured, api_times):
    from live_etw import PROVIDER, decode_raw

    stopped, readback = etw['stopped'], etw['readback']
    source, archive, plan = stopped['source'], stopped['archive'], stopped['plan']
    sample = stopped['sampleId']
    api_project_id = json.loads((api_project / 'project.ksaproj').read_bytes())['projectId']
    assert etw['projectId'] == stopped['projectId'] != api_project_id and sample != captured['sampleId'], (etw, captured)
    assert stopped['capture'] == 'stopped' and stopped['stopReason'] == 'requested', stopped
    assert archive['status'] == 'raw-verified' and archive['checkpoint'] == {'status': 'verified', 'error': None}, archive
    assert source['nativeSessionStopped'] and source['processWin32Error'] == 0, source
    assert not source['tailDeliveryUnconfirmed'] and not source['callbackFailed'], source
    loss = {key: source[key] for key in ('eventsLost', 'logBuffersLost', 'realTimeBuffersLost', 'queueDropped',
                                         'payloadTruncated', 'malformedPayload')}
    assert tuple(loss.values()) == (0, 0, 0, '0', '0', '0'), loss
    assert int(source['providerEvents']) - int(source['headerFiltered']) == int(source['enqueued']) == 3, source
    assert (plan['providerId'], plan['headerPid'], plan['processCreationFileTime']) == (
        str(PROVIDER), identity['pid'], str(identity['creation'])), plan
    assert readback == {
        'status': 'readback-verified', 'segmentOrdinal': '1', 'checkpoint': 'verified',
        'checkedBytes': archive['flushedBytes'], 'observationCount': '3', 'terminal': {
            'stopReason': 'requested', 'nativeSessionStopped': True},
        'plan': {key: plan[key] for key in ('providerId', 'sourceEpoch', 'headerPid', 'processCreationFileTime')},
    }, readback
    segment = etw_project / 'samples' / sample / 'raw/00000000000000000001.ksaseg'
    rows, digest = decode_raw(segment)
    assert rows[0] == (plan, b'') and rows[-1] == (
        {'kind': 'etw-capture-end-v1', 'stopReason': 'requested', 'source': source}, b''), rows
    assert len(rows) == int(archive['lastSequence']) == 5, rows
    observations = []
    event_times = []
    for row, payload in rows[1:-1]:
        assert (row['kind'], row['providerId'], row['sourceEpoch'], row['headerPid']) == (
            'etw-observation-v1', str(PROVIDER), plan['sourceEpoch'], identity['pid']), row
        assert (row['descriptor']['version'], row['originalPayloadBytes'], row['storedPayloadBytes'], payload) == (
            1, 0, '0', b''), row
        observations.append(row['descriptor']['id'])
        event_times.append(int(row['sourceFileTime100ns']))
    assert observations == [1, 3 if captured['partialHooks'] else 2, 5], (observations, captured)
    assert identity['creation'] <= event_times[0] <= event_times[1] < event_times[2], event_times
    overlapping_calls = sum(event_times[1] <= timestamp < event_times[2] for timestamp in api_times)
    assert overlapping_calls >= 2, (event_times, api_times)

    graph = etw['graph']
    assert (graph['archiveSource'], graph['observationCount'], graph['prefix']['sha256']) == (
        'etw-checkpoint', '3', digest), graph
    operation_names = ['etw.agent.pipe-ready.v1',
                       'etw.agent.hooks-partial.v1' if captured['partialHooks'] else 'etw.agent.hooks-installed.v1',
                       'etw.agent.hooks-restored.v1']
    for index, (row, operation) in enumerate(zip(graph['observations'], operation_names, strict=True), 2):
        assert (row['operation'], row['sourceId'], row['headerPid']) == (
            operation, f'etw:{PROVIDER}', identity['pid']), row
        assert (row['raw']['recordSequence'], row['raw']['inlineBytes']) == (str(index), '0'), row
        assert 'etw-context-only' in row['gaps'], row

    api_archive = captured['archive']
    assert api_archive['archiveSource'] == 'cooperative-pipe' and int(api_archive['clueRows']) > 0, captured
    assert captured['hooksInstalled'] and captured['hooksRemoved'] and captured['cleanPipeEof'], captured
    assert captured['omittedClues'] == '0', captured
    print('OWNED_ETW_API_READBACK=' + json.dumps(dict(
        targetPid=identity['pid'], creationFileTime=str(identity['creation']),
        etwProjectId=etw['projectId'], etwSampleId=sample, providerId=str(PROVIDER), eventVersion=1,
        eventIds=observations, eventCount=len(observations), eventOperations=operation_names,
        eventFileTime100ns=list(map(str, event_times)), etwSegmentSha256=digest, etwLoss=loss,
        apiProjectId=api_project_id, apiSampleId=captured['sampleId'], apiSource=api_archive['archiveSource'],
        apiSourceSession=captured['sourceSessionIdentity'], apiOrdinaryPackets=captured['ordinaryPackets'],
        apiArchivedClues=api_archive['clueRows'], apiAgentReportedDrops=captured['agentReportedDrops'],
        apiInvalidPackets=captured['invalidPackets'], apiOmittedClues=captured['omittedClues'],
        apiSelfWritesBetweenHookEvents=overlapping_calls)), flush=True)


def run(project, directory, behavior=False, etw_project=None, win32=False):
    create_project(project, 'AA-03 cooperative target')
    environment = os.environ | {COOPERATIVE_ENV: str(directory)}
    startup_gate = not behavior and etw_project is None
    target_mode = '--startup-target' if startup_gate else '--behavior-target' if behavior else '--target'
    command = [TARGET_X86, '--cooperative-target'] if win32 else [sys.executable, '-B', SCRIPT, target_mode]
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    controller = None
    identity = None
    try:
        lines = Queue()
        Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        identity = json.loads(lines.get(timeout=10))
        assert identity['pid'] == process.pid, identity
        if win32:
            assert (identity['processMachine'], identity['nativeMachine']) == (
                IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64), identity
            print('COOPERATIVE_TARGET_MACHINE=0x014c NATIVE_MACHINE=0x8664', flush=True)
        basic = invoke('process', 'detail', 'basic', 'query', '--pid', str(process.pid),
                       '--backend', 'r3', accepted=(0, 6))
        creation, = (item for item in basic['fields'] if item['name'] == 'creation-time')
        assert creation['available'] and int(creation['value']) == identity['creation'], basic
        assert identity['agentEnabledNs'] >= identity['agentLoadNs'] >= 0, identity
        print(f'COOPERATIVE_AGENT_LOAD_NS={identity["agentLoadNs"]} '
              f'COOPERATIVE_AGENT_ENABLED_NS={identity["agentEnabledNs"]} TARGET_CREATION={identity["creation"]}', flush=True)
        assert not any(directory.iterdir()), f'Unexpected files before controller startup: {directory}'
        command = [CLI, 'analyze', 'api-evidence', 'capture', '--project', project, '--title', 'AA-03 self writes',
                   '--pid', str(process.pid), '--creation-filetime', str(identity['creation']),
                   '--confirm', '--duration-ms', '3000', '--json']
        with (owned_etw_session(etw_project, identity) if etw_project else nullcontext()) as etw:
            controller = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, env=environment)
            observed_live = False  # 超时收尾也必须明确是否在运行中看到了检查点。
            live_readback = None  # 合作规则场景另核对写租约期间的只读入口。
            try:
                # 前缀必须在本轮结束以前发布；只观察夹具自己的采样目录。
                live_marker = None
                deadline = time.monotonic() + 35
                while controller.poll() is None and time.monotonic() < deadline:
                    live_marker = next(iter((project / 'samples').glob('*/checkpoints/00000000000000000001.json')), None)
                    if live_marker is not None:
                        break
                    time.sleep(.025)
                observed_live = live_marker is not None and controller.poll() is None
                if behavior and observed_live:
                    live_sample = live_marker.parent.parent.name
                    reader = subprocess.run([CLI, 'analyze', 'api-evidence', 'replay', '--project', project,
                                             '--sample', live_sample, '--limit', '1', '--json'],
                                            capture_output=True, timeout=10)
                    live_readback = reader, controller.poll() is None
                output, error = controller.communicate(timeout=52)
            except subprocess.TimeoutExpired:
                process.stdin.close()  # Let the owned target exit so the controller can drain normally.
                output, error = controller.communicate(timeout=20)
            assert observed_live, 'no live checkpoint before capture exit'
            first_marker = json.loads(live_marker.read_bytes())
            assert not first_marker['finalSegment'] and int(first_marker['lastSourceSequence']) > 0, first_marker
            print(f'COOPERATIVE_API_LIVE_CHECKPOINT=PASS SOURCE_ROWS={first_marker["lastSourceSequence"]}', flush=True)
            if behavior:
                reader, running = live_readback
                prefix = receipt(reader.returncode, reader.stdout, reader.stderr, (0,))
                assert running and prefix['status'] == 'readback-prefix' and not prefix['finalSegment'], prefix
                assert int(prefix['sourceRows']) >= int(first_marker['lastSourceSequence']), prefix
                print(f'COOPERATIVE_API_LIVE_READBACK=PASS SOURCE_ROWS={prefix["sourceRows"]}', flush=True)
            print(f'CLI_CAPTURE_EXIT={controller.returncode} {output.decode("utf-8", errors="replace").strip()}', flush=True)
            captured = receipt(controller.returncode, output, error, (0, 6))
        assert process.poll() is None, 'owned target did not survive the interval'
        tail, target_error = process.communicate(timeout=10)  # Closes stdin; the owned target exits normally.
        assert process.returncode == 0, (process.returncode, tail, target_error)
        emitted = json.loads(tail)
        assert emitted['agentLoaded'], emitted
        assert all(captured[key] for key in ('residentVerified', 'connected', 'agentReady',
                                              'completedInterval', 'cleanupComplete')), captured
        assert (captured['pid'], int(captured['creationFileTime'])) == (process.pid, identity['creation']), captured
        assert not captured['cancelled'] and not captured['targetExited'], captured
        assert int(captured['sourceSessionIdentity']) > 0 and captured['invalidPackets'] == '0', captured
        assert captured['agentReportedDrops'] == '0', captured
        assert int(captured['elapsedMs']) >= 3000, captured
        ready_revision = int(captured['readyCoverageRevision'])
        assert 0 < ready_revision <= int(captured['requiredFinalCoverageRevision']), captured
        print(f'COOPERATIVE_AGENT_READY=True SESSION={captured["sourceSessionIdentity"]} '
              f'READY_COVERAGE_REVISION={ready_revision}', flush=True)
        if startup_gate:
            assert identity['localStartupBeforeController'] == ERROR_TIMEOUT, identity
            assert 0 < emitted['localReadyNs'] <= emitted['firstActionNs'], emitted
            assert emitted['localStartupAfterStop'] == ERROR_OPERATION_ABORTED, emitted
            assert all(captured[key] for key in ('stopMarkerWritten', 'hooksRemoved', 'cleanPipeEof')), captured
        api_times = verify_archive(project, identity, captured, emitted['calls'], require_first=startup_gate,
                                   require_multiple=True)
        if win32:
            verify_missing_segment(project, captured)
        if startup_gate:
            marker = 'COOPERATIVE_LOCAL_STARTUP_WIN32' if win32 else 'COOPERATIVE_LOCAL_STARTUP'
            print(f'{marker}=PASS NO_CONTROLLER={ERROR_TIMEOUT} '
                  f'FIRST_ACTION_OFFSET=0 AFTER_STOP={ERROR_OPERATION_ABORTED}', flush=True)
        if etw is not None:
            verify_owned_etw(etw_project, project, identity, etw, captured, api_times)
    finally:
        if process.poll() is None:
            if not process.stdin.closed:
                process.stdin.close()
            process.wait(timeout=10)  # Never force-terminate either process.
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        print(f'OWNED_TARGET_EXIT={process.returncode}', flush=True)
        assert controller is None or controller.poll() is not None, 'controller still running; leaving its session files intact'
        if identity is not None:
            cleanup_session(directory, process.pid, identity['creation'], controller.pid if controller is not None else None)


def run_identity_negative(project, directory, case):
    environment = os.environ | {COOPERATIVE_ENV: str(directory)}
    process = subprocess.Popen([sys.executable, '-B', SCRIPT, '--identity-negative-target', case],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    try:
        lines = Queue()
        Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        identity = json.loads(lines.get(timeout=10))
        has_agent = case != 'missing-agent'
        assert process.poll() is None and identity['pid'] == process.pid and identity['creation'] > 0, identity
        assert identity['agentLoaded'] is has_agent, identity
        creation = identity['creation']
        controller_environment = environment.copy()
        if case == 'wrong-filetime':
            creation += 1
            expected_error = f'capture target identity changed: {process.pid}'
        elif case == 'missing-directory':
            del controller_environment[COOPERATIVE_ENV]
            expected_error = f'{COOPERATIVE_ENV} must name a private session directory'
        else:
            expected_error = 'resident product Agent not verified; error=126'
        assert not list(directory.iterdir()), f'Unexpected files before {case}: {directory}'
        title = f'AA-03 identity negative {case}'
        command = [CLI, 'analyze', 'api-evidence', 'capture', '--project', project, '--title', title,
                   '--pid', str(process.pid), '--creation-filetime', str(creation),
                   '--confirm', '--duration-ms', '3000', '--json']
        controller = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=controller_environment)
        try:
            output, error = controller.communicate(timeout=52)
        except subprocess.TimeoutExpired:
            process.stdin.close()  # On failure, release only this fixture via EOF; do not terminate either process.
            controller.communicate(timeout=20)
            raise
        print(f'IDENTITY_NEGATIVE_CASE={case} CLI_CAPTURE_EXIT={controller.returncode} '
              f'{output.decode("utf-8", errors="replace").strip()}', flush=True)
        captured = receipt(controller.returncode, output, error, (3,))
        assert captured['status'] == 'capture-failed' and captured['errors'] == [expected_error], captured
        assert (captured['pid'], captured['creationFileTime']) == (process.pid, str(creation)), captured
        assert captured['residentVerified'] is (case == 'missing-directory'), captured
        assert all(captured[key] is False for key in ('configPublished', 'connected', 'agentReady', 'stopMarkerWritten',
                                                     'completedInterval', 'cancelled', 'targetExited')), captured
        assert captured['cleanupComplete'] is True, captured
        assert all(captured[key] is None for key in ('sourceSessionIdentity', 'agentReportedDrops', 'archive',
                                                    'readyCoverageRevision')), captured
        assert all(captured[key] == '0' for key in ('ordinaryPackets', 'invalidPackets', 'omittedClues')), captured
        sample_id = captured['sampleId']
        assert sample_id == str(UUID(sample_id)), captured
        sample = project / 'samples' / sample_id
        metadata = json.loads((sample / 'sample.json').read_bytes())
        assert (metadata['sampleId'], metadata['title']) == (sample_id, title), metadata
        assert not os.path.lexists(sample / 'raw'), f'Unexpected raw archive: {sample}'
        files = list(directory.iterdir())
        assert not files, f'Config/stop residue before target exit: {files}'
        assert process.poll() is None, f'Owned target exited during {case}'
        tail, target_error = process.communicate(timeout=10)
        assert process.returncode == 0, (process.returncode, tail, target_error)
        emitted = json.loads(tail)
        assert emitted['agentLoaded'] is has_agent, emitted
        files = list(directory.iterdir())
        assert not files, f'Config/stop residue after target exit: {files}'
        print(f'IDENTITY_NEGATIVE_CASE={case} TARGET_CREATION={identity["creation"]} '
              f'REQUESTED_CREATION={creation} OWNED_TARGET_EXIT=0 RESULT=PASS', flush=True)
    finally:
        if process.poll() is None:
            if not process.stdin.closed:
                process.stdin.close()
            process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--target', action='store_true', help=argparse.SUPPRESS)
    mode.add_argument('--behavior-target', action='store_true', help=argparse.SUPPRESS)
    mode.add_argument('--startup-target', action='store_true', help=argparse.SUPPRESS)
    mode.add_argument('--win32', action='store_true', help='run the existing native Win32 target under WOW64')
    mode.add_argument('--behavior', action='store_true', help='replay real access-denied and successful self calls')
    mode.add_argument('--owned-etw', nargs=2, metavar=('AGENT_SHA256', 'CLI_SHA256'),
                      help='verify these product builds in separate, overlapping cooperative API and R3 ETW samples')
    mode.add_argument('--identity-negative', action='store_true',
                      help='run only the wrong-FILETIME and missing-Agent rejection fixtures')
    mode.add_argument('--missing-directory', action='store_true',
                      help='run only the resident Agent rejection with no controller session directory')
    mode.add_argument('--identity-negative-target', choices=(*IDENTITY_NEGATIVE_CASES, 'missing-directory'),
                      help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        parser.error('Windows x64 Python is required')
    if not __debug__:
        parser.error('fixture assertions must be enabled')
    expected_hashes = dict(zip((AGENT, CLI), args.owned_etw)) if args.owned_etw else {}
    for expected_hash in expected_hashes.values():
        if len(expected_hash) != 64 or any(digit not in '0123456789abcdefABCDEF' for digit in expected_hash):
            parser.error('--owned-etw requires 64-digit Agent and CLI SHA-256 values')
    if args.target or args.behavior_target or args.startup_target or args.identity_negative_target:
        target(args.identity_negative_target, behavior=args.behavior_target, startup_gate=args.startup_target)
        return
    from project_v1 import owned_project_path, regular_identity

    if args.win32:
        for image in (TARGET_X86, AGENT_X86):
            with image.open('rb') as binary:
                assert binary.read(2) == b'MZ', image
                binary.seek(0x3c)
                binary.seek(struct.unpack('<I', binary.read(4))[0])
                assert struct.unpack('<4sH', binary.read(6)) == (b'PE\0\0', IMAGE_FILE_MACHINE_I386), image
    for image in (CLI, AGENT_X86 if args.win32 else AGENT):
        binary = image.read_bytes()
        # Old builds ignore the opt-in and can touch the shared session ACL.
        assert (COOPERATIVE_ENV + '\0').encode('utf-16-le') in binary, f'Rebuild cooperative transport: {image}'
        digest = hashlib.sha256(binary).hexdigest()
        print(f'{image.name}_SHA256={digest}', flush=True)
        if image in expected_hashes:
            assert digest == expected_hashes[image].lower(), f'{image.name} differs from the authorized SHA-256'
    with owned_project_path() as project:
        directory = project.parent / 'KswordApiMonCooperative'
        create_session_directory(directory)
        original_directory = regular_identity(directory)
        if args.identity_negative or args.missing_directory:
            create_project(project, 'AA-03 cooperative identity negatives')
            for case in ('missing-directory',) if args.missing_directory else IDENTITY_NEGATIVE_CASES:
                run_identity_negative(project, directory, case)
        else:
            etw_project = project.parent / 'owned Agent ETW project' if args.owned_etw else None
            run(project, directory, behavior=args.behavior, etw_project=etw_project, win32=args.win32)
        assert regular_identity(directory) == original_directory, directory
        assert not any(directory.iterdir()), f'Unexpected files retained in {directory}'
        directory.rmdir()
        print('COOPERATIVE_SESSION_DIRECTORY_REMOVED=True', flush=True)
    if args.win32:
        result = 'AA03_COOPERATIVE_API_WIN32'
    elif args.missing_directory:
        result = 'AA03_COOPERATIVE_API_MISSING_DIRECTORY'
    elif args.owned_etw:
        result = 'AA03_COOPERATIVE_API_OWNED_ETW'
    else:
        result = 'AA03_COOPERATIVE_API_IDENTITY_NEGATIVE' if args.identity_negative else 'AA03_COOPERATIVE_API_CAPTURE'
    print(f'{result}=PASS', flush=True)


if __name__ == '__main__':
    main()
