"""AA-03：正式 CLI 持续合作采集（--duration-ms 0）定向验收。

复用 cooperative_api_capture 的自有目标、归档回读和会话清理，
复用 cooperative_capture_lifecycle 的管道见证、私有 console 与 CTRL_BREAK。
所有就绪判断都来自真实管道证据，不用经过时间猜就绪。
"""

import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from queue import Queue
from threading import Thread

import cooperative_api_capture as baseline
import cooperative_capture_lifecycle as lifecycle
from cooperative_api_capture import AGENT, CLI, COOPERATIVE_ENV, winapi
from live_etw import decode_raw
from project_v1 import owned_project_path


SCRIPT = Path(__file__).resolve()
# 本批长程目标只在子进程内放宽这两项，避免污染共享夹具与其它验收。
LONG_TARGET_SECONDS = 240
LONG_TARGET_BUFFER = 16000
CONTINUOUS_SECONDS = 125
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200


def long_target():
    """子进程入口：只在本进程放宽夹具时限，随后调用原有自有目标。"""
    baseline.TARGET_TIMEOUT = LONG_TARGET_SECONDS
    baseline.BUFFER_SIZE = LONG_TARGET_BUFFER
    baseline.target()


def start_target(children, directory, long_running):
    """启动自有 AMD64 目标，通过环境变量绑定本轮专用会话目录。"""
    env = os.environ | {COOPERATIVE_ENV: str(directory)}
    command = [sys.executable, '-B', str(SCRIPT),
               '--owned-target-long' if long_running else '--target']
    return children.start(command, env=env, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          creationflags=CREATE_NO_WINDOW)


def read_identity(target):
    """读取目标打印的首行身份声明，并核对进程身份。"""
    line = Queue()
    Thread(target=lambda: line.put(target.stdout.readline()), daemon=True).start()
    try:
        raw = line.get(timeout=20)
    except Exception as exc:
        raise AssertionError(f'自有目标未公布身份: {exc}') from exc
    assert raw, '自有目标在公布身份前退出'
    identity = json.loads(raw)
    assert identity['pid'] == target.pid, identity
    assert identity['creation'] > 0, identity
    print(f'OWNED_TARGET_READY PID={identity["pid"]} TID={identity["tid"]} '
          f'CREATION={identity["creation"]}', flush=True)
    return identity


def capture_command(project, title, pid, creation, duration_ms):
    return [CLI, 'analyze', 'api-evidence', 'capture', '--project', str(project),
            '--title', title, '--pid', str(pid), '--creation-filetime', str(creation),
            '--confirm', '--duration-ms', str(duration_ms), '--json']


def checkpoints(project):
    """统计已发布的检查点数量，作为分段增长的外部证据。"""
    root = project / 'samples'
    if not root.is_dir():
        return 0
    return len(list(root.glob('*/checkpoints/*.json')))


def growth_witness(project, controller, target, ready_at, seconds, label):
    """在持续采集期间按真实检查点文件观察分段增长。"""
    series = []
    while time.monotonic() - ready_at < seconds:
        assert controller.poll() is None and target.poll() is None, '采集尚未到时已结束'
        series.append((round(time.monotonic() - ready_at, 1), checkpoints(project)))
        time.sleep(5)
    assert len(series) >= 2 and series[-1][1] > series[0][1] and series[-1][1] >= 2, series
    print(f'{label}_CHECKPOINT_GROWTH={json.dumps(series)}', flush=True)
    return series


def stop_reason(project, captured):
    """从最终段的真实原包回读结束回执里的停止原因。"""
    sample = captured['sampleId']
    ordinal = int(captured['archive']['committedSegments'])
    sample_dir = project / 'samples' / sample
    marker = json.loads((sample_dir / 'checkpoints' / f'{ordinal:020d}.json').read_bytes())
    records, _ = decode_raw(sample_dir / 'raw' / f'{ordinal:020d}.ksaseg',
                            int(marker['planRawSequence']))
    end = records[-1][0]
    assert end['kind'] == 'api-archive-follow-end-v1', end
    return end['stopReason'], end['source']['state'], ordinal


def self_write_detail(wire):
    """兼容两种自有 Agent 详情：旧 key=value 与并行接线后的 AAIP1 定长十六进制。"""
    text = wire[224:864].decode('utf-16-le', errors='replace').split('\0', 1)[0]
    if text.startswith('AAIP1|'):
        fields = text.split('|')
        assert fields[0] == 'AAIP1' and len(fields) == 15, text
        values = [int(field, 16) for field in fields[1:]]
        # 字段序：操作/标志/发起者时间/目标PID/目标时间/目标TID/目标线程时间/
        # 地址/请求长度/完成长度/入口/进入QPC/返回QPC/输入句柄。
        return dict(base=values[7], requested=values[8], completed=values[9], process=values[13])
    return dict(field.split('=', 1) for field in text.split())


def verify_readback(project, captured, identity, emitted):
    """复用 decode_raw 与正式 CLI replay，逐段核对原包字节、身份、散列链及原包回读。"""
    from struct import unpack_from

    archived = captured['archive']
    assert archived and archived['status'] == 'readback-verified' and archived['rawSegment'] == '1', captured
    sample = captured['sampleId']
    sample_dir = project / 'samples' / sample
    segments = int(archived['committedSegments'])
    assert segments >= 1 and archived['finalSegment'], archived
    assert archived['sourceState'] == ('pipe-eof' if captured['cleanPipeEof'] else 'unconfirmed-end'), archived
    assert archived['sourceRows'] == captured['archivedPackets'] == captured['ordinaryPackets'], captured
    assert int(archived['sourceRows']) >= int(archived['clueRows']) > 0, archived

    raw_sequence = 1
    source_sequence = 0
    previous_digest = None
    packets = []
    for ordinal in range(1, segments + 1):
        records, digest = decode_raw(sample_dir / 'raw' / f'{ordinal:020d}.ksaseg', raw_sequence)
        marker = json.loads((sample_dir / 'checkpoints' / f'{ordinal:020d}.json').read_bytes())
        assert marker['raw']['sha256'] == digest and marker['previousRawSha256'] == previous_digest, marker
        assert marker['lastSourceSequence'] == str(source_sequence + len(records) - 1 - (ordinal == segments)), marker
        plan, body = records[0]
        assert not body and plan['archiveSource'] == 'cooperative-pipe', plan
        assert marker['finalSegment'] == (ordinal == segments), marker
        previous_digest = digest
        for index, (metadata, wire) in enumerate(records[1:], raw_sequence + 1):
            if metadata['kind'] == 'api-archive-follow-end-v1':
                assert index == raw_sequence + len(records) - 1 and ordinal == segments and not wire, metadata
                assert metadata['source']['validatedRows'] == captured['ordinaryPackets'], metadata
                continue
            source_sequence += 1
            assert len(wire) == 1000 and metadata['sourceSequence'] == str(source_sequence), metadata
            assert unpack_from('<I', wire, 8)[0] == identity['pid'], metadata
            assert unpack_from('<Q', wire, 896)[0] == int(captured['sourceSessionIdentity']), metadata
            packets.append((ordinal, index, metadata, wire))
        raw_sequence += len(records)
    assert source_sequence == int(captured['ordinaryPackets']), source_sequence

    offsets = []
    first = None
    for ordinal, index, metadata, wire in packets:
        if unpack_from('<I', wire, 12)[0] != identity['tid']:
            continue
        if wire[96:224].decode('utf-16-le', errors='replace').split('\0', 1)[0] != 'WriteProcessMemory':
            continue
        detail = self_write_detail(wire)
        base = detail['base']
        if 'requested' in detail:
            size, written = detail['requested'], detail['completed']
        else:
            size, written = int(detail['size'], 16), int(detail['written'])
        assert 0 <= base - identity['base'] < emitted['calls'] and size == written == 1, detail
        handle = int(detail['process'], 16) if isinstance(detail['process'], str) else detail['process']
        assert handle == 0xFFFFFFFFFFFFFFFF, detail
        offsets.append(base - identity['base'])
        if first is None:
            first = (ordinal, index, metadata, wire)
    assert len(offsets) >= 2 and offsets == list(range(offsets[0], offsets[-1] + 1)), offsets

    ordinal, index, metadata, wire = first
    replay = baseline.invoke('analyze', 'api-evidence', 'replay', '--project', project,
                             '--sample', sample, '--packet', '1', '--after', str(index - 1), '--limit', '1')
    row, = replay['rows']
    assert (replay['status'], replay['rawSegment']) == ('readback-verified', '1'), replay
    assert (row['rawSegment'], row['rawSequence'], row['sourceSequence'], row['packet']) == (
        str(ordinal), str(index), metadata['sourceSequence'], wire.hex()), row
    assert (row['pid'], row['tid'], row['archivedCallerCreation100ns'], row['sourceSessionIdentity']) == (
        identity['pid'], identity['tid'], str(identity['creation']), captured['sourceSessionIdentity']), row
    assert (row['family'], row['phase'], row['reportedStatusCode']) == ('memory-write', 'return', 0), row
    print(f'READBACK_PASS SEGMENTS={segments} ORDINARY={source_sequence} CLUES={archived["clueRows"]} '
          f'FINAL_SHA256={previous_digest} PACKET_SHA256={__import__("hashlib").sha256(wire).hexdigest()} '
          f'FIRST_OFFSET={offsets[0]} LAST_OFFSET={offsets[-1]}', flush=True)


def verify_sample(project, captured, identity, emitted, expected_reason, require_multiple):
    """回读全部原包、核对终段原因与原包字节，再核对触发前管道见证。"""
    reason, state, ordinal = stop_reason(project, captured)
    assert reason == expected_reason, (reason, expected_reason)
    print(f'FINAL_SEGMENT={ordinal} STOP_REASON={reason} SOURCE_STATE={state}', flush=True)
    verify_readback(project, captured, identity, emitted)


def cleanup_owned(children, target, controller, controller_read, directory, identity):
    """按原有身份核对清退会话文件，并确认所有自有进程退出。"""
    try:
        if target is not None and target.poll() is None and not target.stdin.closed:
            target.stdin.close()
        if target is not None and target.poll() is None:
            target.wait(timeout=15)
    finally:
        if controller is not None and not controller_read:
            out, err = controller.communicate(timeout=60)
            print(f'CLEANUP_CONTROLLER_EXIT={controller.returncode} '
                  f'{out.decode("utf-8", errors="replace").strip()}', flush=True)
    if identity is not None and target is not None and target.poll() is not None:
        baseline.cleanup_session(directory, target.pid, identity['creation'],
                                 None if controller is None else controller.pid)
    live = [child.pid for child in children.processes if child.poll() is None]
    assert not live, f'自有进程仍在运行: {live}'


def continuous_stop(kernel):
    """持续 0 超过 120 秒后由私有 console 定向 CTRL_BREAK 停止。"""
    children = lifecycle.OwnedChildren()
    with owned_project_path() as project:
        directory = project.parent / 'KswordApiMonCooperative'
        baseline.create_session_directory(directory)
        target = controller = None
        identity = controller_read = None
        try:
            baseline.create_project(project, 'AA-03 continuous 0 explicit stop')
            target = start_target(children, directory, True)
            identity = read_identity(target)
            assert not any(directory.iterdir()), f'会话目录不为空: {directory}'
            stop = directory / f'stop_{target.pid}_{identity["creation"]}.flag'
            env = os.environ | {COOPERATIVE_ENV: str(directory)}
            command = capture_command(project, 'AA-03 continuous 0 explicit stop',
                                      target.pid, identity['creation'], 0)
            controller = children.start(command, env=env,
                                        creationflags=CREATE_NEW_PROCESS_GROUP,
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            session, witnessed = lifecycle.CapturePipeWitness(kernel).ready_and_ordinary(
                controller, target, identity, stop)
            print(f'PRE_TRIGGER_WITNESS session={session} ordinary={len(witnessed)}', flush=True)
            assert controller.poll() is None and target.poll() is None and not stop.exists()
            ready_at = time.monotonic()
            growth_witness(project, controller, target, ready_at, CONTINUOUS_SECONDS,
                           'CONTINUOUS')
            lifecycle.cancel_owned_cli(kernel, controller)
            stdout, stderr = controller.communicate(timeout=90)
            controller_read = True
            captured = baseline.receipt(controller.returncode, stdout, stderr, (6,))
            print(f'CLI_CAPTURE_EXIT={controller.returncode} '
                  f'{stdout.decode("utf-8", errors="replace").strip()}', flush=True)
            assert captured['status'] == 'capture-partial', captured
            assert captured['completedInterval'] is False, captured
            assert captured['cancelled'] is True and captured['targetExited'] is False, captured
            for key in ('residentVerified', 'connected', 'agentReady', 'cleanupComplete',
                        'stopMarkerWritten', 'hooksRemoved', 'cleanPipeEof'):
                assert captured[key] is True, (key, captured)
            assert captured['invalidPackets'] == '0' and captured['omittedClues'] == '0', captured
            print(f'AGENT_REPORTED_DROPS={captured["agentReportedDrops"]}', flush=True)
            assert target.poll() is None, '明确停止后目标不应退出'
            tail, _ = target.communicate(timeout=20)
            emitted = json.loads(tail)
            assert emitted['agentLoaded'] and emitted['calls'] >= 2, emitted
            verify_sample(project, captured, identity, emitted, 'cancelled', False)
            lifecycle.verify_witness(project, captured, session, witnessed)
            print('AA03_CONTINUOUS_EXPLICIT_STOP=PASS', flush=True)
        finally:
            cleanup_owned(children, target, controller, controller_read, directory, identity)


def natural_exit(kernel):
    """持续 0 期间目标自行退出，仍返回部分采样且标记 targetExited。"""
    children = lifecycle.OwnedChildren()
    with owned_project_path() as project:
        directory = project.parent / 'KswordApiMonCooperative'
        baseline.create_session_directory(directory)
        target = controller = None
        identity = controller_read = None
        try:
            baseline.create_project(project, 'AA-03 continuous 0 target exit')
            target = start_target(children, directory, True)
            identity = read_identity(target)
            assert not any(directory.iterdir())
            stop = directory / f'stop_{target.pid}_{identity["creation"]}.flag'
            env = os.environ | {COOPERATIVE_ENV: str(directory)}
            command = capture_command(project, 'AA-03 continuous 0 target exit',
                                      target.pid, identity['creation'], 0)
            controller = children.start(command, env=env, creationflags=CREATE_NO_WINDOW,
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            session, witnessed = lifecycle.CapturePipeWitness(kernel).ready_and_ordinary(
                controller, target, identity, stop)
            print(f'PRE_TRIGGER_WITNESS session={session} ordinary={len(witnessed)}', flush=True)
            tail, _ = target.communicate(timeout=20)  # EOF 让自有目标自然退出
            assert target.returncode == 0, target.returncode
            stdout, stderr = controller.communicate(timeout=60)
            controller_read = True
            captured = baseline.receipt(controller.returncode, stdout, stderr, (6,))
            print(f'CLI_CAPTURE_EXIT={controller.returncode} '
                  f'{stdout.decode("utf-8", errors="replace").strip()}', flush=True)
            assert captured['status'] == 'capture-partial', captured
            assert captured['completedInterval'] is False, captured
            assert captured['targetExited'] is True and captured['cancelled'] is False, captured
            assert all(captured[key] is True for key in
                       ('residentVerified', 'connected', 'agentReady', 'cleanupComplete')), captured
            emitted = json.loads(tail)
            assert emitted['agentLoaded'] and emitted['calls'] >= 2, emitted
            verify_sample(project, captured, identity, emitted, 'target-exited', False)
            lifecycle.verify_witness(project, captured, session, witnessed)
            print('AA03_CONTINUOUS_NATURAL_EXIT=PASS', flush=True)
        finally:
            cleanup_owned(children, target, controller, controller_read, directory, identity)


def finite_positive(kernel):
    """原有限时 1000ms 正例仍报告 completedInterval=true。"""
    children = lifecycle.OwnedChildren()
    with owned_project_path() as project:
        directory = project.parent / 'KswordApiMonCooperative'
        baseline.create_session_directory(directory)
        target = controller = None
        identity = controller_read = None
        try:
            baseline.create_project(project, 'AA-03 finite 1000ms')
            target = start_target(children, directory, True)
            identity = read_identity(target)
            assert not any(directory.iterdir())
            env = os.environ | {COOPERATIVE_ENV: str(directory)}
            command = capture_command(project, 'AA-03 finite 1000ms',
                                      target.pid, identity['creation'], 1000)
            controller = children.start(command, env=env, creationflags=CREATE_NO_WINDOW,
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = controller.communicate(timeout=60)
            controller_read = True
            # 有限时正例以 completedInterval=true 为准；partialHooks 由 Agent 覆盖决定，历史正例同样接受 0/6。
            captured = baseline.receipt(controller.returncode, stdout, stderr, (0, 6))
            print(f'CLI_CAPTURE_EXIT={controller.returncode} '
                  f'{stdout.decode("utf-8", errors="replace").strip()}', flush=True)
            assert captured['completedInterval'] is True, captured
            assert captured['cancelled'] is False and captured['targetExited'] is False, captured
            assert captured['cleanupComplete'] is True and captured['hooksRemoved'] is True, captured
            tail, _ = target.communicate(timeout=20)
            emitted = json.loads(tail)
            verify_sample(project, captured, identity, emitted, 'duration-limit', False)
            print('AA03_FINITE_POSITIVE_1000MS=PASS', flush=True)
        finally:
            cleanup_owned(children, target, controller, controller_read, directory, identity)


def negatives():
    """时长负例与共享仅 resident 准入/超时边界的原生检查。"""
    root = Path(baseline.__file__).resolve().parents[3]
    source = (root / 'shared' / 'ApiMonitorCapture.cpp').read_text(encoding='utf-8')
    # 门禁语义检查：谓词名在并行接线中可能由 residentOnly 改为 strictObservation，
    # 因此只固定“仅严格/驻留模式允许 0”及有限时、启动/停止超时区间这些稳定片段。
    assert ('request.durationMs == 0' in source and
            '(request.durationMs >= 100 && request.durationMs <= 120000)' in source), source
    assert any(token in source for token in ('strictObservation() && request.durationMs == 0',
                                             'residentOnly() && request.durationMs == 0')), source
    assert any(token in source for token in ('(strict && request.durationMs == 0)',
                                             '(resident && request.durationMs == 0)')), source
    required = ('request.startupTimeoutMs >= 1000 && request.startupTimeoutMs <= 120000 && request.stopTimeoutMs >= 1000 && request.stopTimeoutMs <= 120000',
                'result.completedInterval = !continuous')
    for fragment in required:
        assert fragment in source, f'源码准入/超时门禁缺失: {fragment}'
    print('SHARED_RESIDENT_ONLY_AND_TIMEOUTS_SOURCE=PASS', flush=True)

    for duration in (1, 999, 120001):
        command = [CLI, 'analyze', 'api-evidence', 'capture', '--project', 'unused',
                   '--title', 'negative', '--pid', '8', '--creation-filetime', '1',
                   '--confirm', '--duration-ms', str(duration), '--json']
        result = subprocess.run(command, capture_output=True, timeout=15)
        data = baseline.receipt(result.returncode, result.stdout, result.stderr, (1,))
        assert data['status'] == 'invalid-resident-capture-scope', (duration, data)
        print(f'NEGATIVE_CAPTURE_DURATION={duration} EXIT={result.returncode} REJECTED', flush=True)

    for option, value in (('--duration-ms', '0'), ('--startup-timeout-ms', '999'),
                          ('--stop-timeout-ms', '120001')):
        command = [CLI, 'monitor', 'api', 'capture', '--pid', '8', '--confirm',
                   option, value, '--json']
        result = subprocess.run(command, capture_output=True, timeout=15)
        data = json.loads(result.stdout)['data']
        assert result.returncode == 1, (option, result.returncode, result.stdout, result.stderr)
        print(f'NEGATIVE_MONITOR_API {option}={value} EXIT=1 STATUS={data.get("status")}', flush=True)
    print('AA03_CONTINUOUS_NEGATIVES=PASS', flush=True)


def run_case(case, kernel):
    if case in ('all', 'continuous-stop'):
        continuous_stop(kernel)
    if case in ('all', 'natural-exit'):
        natural_exit(kernel)
    if case in ('all', 'finite'):
        finite_positive(kernel)
    if case in ('all', 'negative'):
        negatives()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=('all', 'continuous-stop', 'natural-exit',
                                           'finite', 'negative'), default='all')
    parser.add_argument('--private-console-worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--owned-target-long', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8 or not __debug__:
        parser.error('需要 AMD64 Windows 且启用断言的 Python')
    if args.owned_target_long:
        long_target()
        return 0
    kernel = C.WinDLL('kernel32', use_last_error=True)
    try:
        if not args.private_console_worker:
            startup = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW,
                                             wShowWindow=subprocess.SW_HIDE)
            worker = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--case', args.case,
                                       '--private-console-worker'],
                                      creationflags=subprocess.CREATE_NEW_CONSOLE,
                                      startupinfo=startup, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = worker.communicate(timeout=600)
            sys.stdout.buffer.write(stdout)
            sys.stderr.buffer.write(stderr)
            return worker.returncode
        run_case(args.case, kernel)
    except (lifecycle.Blocked, subprocess.TimeoutExpired, AssertionError) as exc:
        print(f'CONTINUOUS_COOPERATIVE_BLOCKED: {exc}', file=sys.stderr, flush=True)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
