"""AA-03: end an active cooperative capture by owned target EOF or isolated CTRL_BREAK."""

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
from queue import Empty, Queue
from shutil import rmtree
import struct
import subprocess
import sys
from threading import Thread
import time
from types import SimpleNamespace

import cooperative_api_capture as baseline
from cooperative_api_capture import AGENT, CLI, COOPERATIVE_ENV, winapi


SCRIPT = Path(__file__).resolve()
DURATION_MS = 20_000
PACKET_SIZE = 1000
VERSION = 0x20261003
CTRL_BREAK_EVENT = 1
DUPLICATE_SAME_ACCESS = 2
FILE_TYPE_PIPE = 3
FILE_GENERIC_READ = 0x120089
PROCESS_HANDLE_INFORMATION = 51
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_BUFFER_TOO_SMALL = 0xC0000023


class Blocked(RuntimeError):
    pass


class HandleEntry(C.Structure):
    _fields_ = [('handle', W.HANDLE), ('handles', C.c_size_t), ('pointers', C.c_size_t),
                ('access', W.DWORD), ('type_index', W.DWORD), ('attributes', W.DWORD), ('reserved', W.DWORD)]


class OwnedChildren:
    def __init__(self):
        self.processes = []

    def start(self, command, **options):
        child = subprocess.Popen(command, **options)
        self.processes.append(child)
        return child

    def run(self, command, *, input=None, capture_output=False, check=False, timeout=None, **options):
        # 共享 helper 原用 run(timeout)，超时会强杀。这里只替换其进程包装，不改 helper。
        child = self.start(command, stdin=subprocess.PIPE if input is not None else None,
                           stdout=subprocess.PIPE if capture_output else None,
                           stderr=subprocess.PIPE if capture_output else None, **options)
        out, err = child.communicate(input, timeout=timeout)
        result = subprocess.CompletedProcess(command, child.returncode, out, err)
        if check:
            result.check_returncode()
        return result


class CapturePipeWitness:
    """Peek the actual owned CLI reader. Never open a second client or consume bytes."""

    def __init__(self, kernel):
        native = C.WinDLL('ntdll')
        self.snapshot = winapi(native, 'NtQueryInformationProcess', W.LONG, W.HANDLE, W.DWORD,
                               C.c_void_p, W.DWORD, C.POINTER(W.DWORD))
        self.current = winapi(kernel, 'GetCurrentProcess', W.HANDLE)()
        self.duplicate = winapi(kernel, 'DuplicateHandle', W.BOOL, W.HANDLE, W.HANDLE, W.HANDLE,
                                C.POINTER(W.HANDLE), W.DWORD, W.BOOL, W.DWORD)
        self.file_type = winapi(kernel, 'GetFileType', W.DWORD, W.HANDLE)
        self.server_pid = winapi(kernel, 'GetNamedPipeServerProcessId', W.BOOL, W.HANDLE, C.POINTER(W.ULONG))
        self.close = winapi(kernel, 'CloseHandle', W.BOOL, W.HANDLE)
        self.peek = winapi(kernel, 'PeekNamedPipe', W.BOOL, W.HANDLE, C.c_void_p, W.DWORD,
                           C.POINTER(W.DWORD), C.POINTER(W.DWORD), C.POINTER(W.DWORD))

    def reader(self, controller, target):
        # 只枚举 Popen 持有的本轮 CLI 进程句柄表，不查询系统全局句柄。
        source = W.HANDLE(int(controller._handle))
        size = 4096
        while size <= 1024 * 1024:
            snapshot = C.create_string_buffer(size)
            needed = W.DWORD()
            status = self.snapshot(source, PROCESS_HANDLE_INFORMATION, snapshot, size, C.byref(needed)) & 0xffffffff
            if not status:
                break
            if status not in (STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_TOO_SMALL):
                raise Blocked(f'Cannot inspect the owned CLI pipe handles: NTSTATUS={status:#010x}')
            size = max(size * 2, needed.value)
        else:
            raise Blocked('Owned CLI handle snapshot exceeds fixture limit')
        first = 2 * C.sizeof(C.c_size_t)
        count = C.c_size_t.from_buffer(snapshot).value
        assert first + count * C.sizeof(HandleEntry) <= size, 'Invalid owned CLI handle snapshot'
        for entry in (HandleEntry * count).from_buffer(snapshot, first):
            if entry.access & FILE_GENERIC_READ != FILE_GENERIC_READ:
                continue
            copy = W.HANDLE()
            if not self.duplicate(source, entry.handle, self.current, C.byref(copy), 0, False, DUPLICATE_SAME_ACCESS):
                continue  # The own child may have closed it since the snapshot.
            peer = W.ULONG()
            if (self.file_type(copy) == FILE_TYPE_PIPE and self.server_pid(copy, C.byref(peer))
                    and peer.value == target.pid and target.poll() is None):
                return copy
            self.close(copy)
        return None

    def ready_and_ordinary(self, controller, target, identity, stop):
        pipe = None
        deadline = time.monotonic() + 30
        header = struct.pack('<III', PACKET_SIZE, VERSION, target.pid)
        buffer = C.create_string_buffer(64 * 1024)
        ready_session = None
        writes = set()
        try:
            while time.monotonic() < deadline and controller.poll() is None and target.poll() is None:
                if pipe is None:
                    pipe = self.reader(controller, target)
                    if pipe is None:
                        time.sleep(0.005)
                        continue
                copied, available = W.DWORD(), W.DWORD()
                if not self.peek(pipe, buffer, len(buffer), C.byref(copied), C.byref(available), None):
                    raise Blocked(f'Owned capture pipe became unreadable before the witness: {C.get_last_error()}')
                payload = buffer[:copied.value]
                start = payload.find(header)
                while 0 <= start <= len(payload) - PACKET_SIZE:
                    wire = payload[start:start + PACKET_SIZE]
                    tid, timestamp, category, result = struct.unpack_from('<IQIi', wire, 12)
                    result_kind, event_kind = struct.unpack_from('<II', wire, 864)
                    session, = struct.unpack_from('<Q', wire, 896)
                    module = packet_text(wire[32:96])
                    name = packet_text(wire[96:224])
                    if session and timestamp and (result_kind, event_kind, result) == (0, 0, 0):
                        if category == 6 and (module, name) == ('Agent', 'HooksInstalled'):
                            ready_session = session
                        if tid == identity['tid'] and category != 6 and module and name == 'WriteProcessMemory':
                            writes.add((session, wire))
                    start = payload.find(header, start + len(header))
                if ready_session is not None and not available.value:
                    # 空读缓冲证明真实 CLI 已取走窥见的包。夹具未消费任何字节。
                    witnessed = {wire for session, wire in writes if session == ready_session}
                    if len(witnessed) >= 2 and not os.path.lexists(stop):
                        return ready_session, witnessed
                time.sleep(0)  # Yield only; do not use an elapsed-time guess as a readiness barrier.
        finally:
            # 发 EOF/CTRL_BREAK 前交还副本，否则副本可能延迟管道真实 EOF。
            if pipe is not None:
                self.close(pipe)
        raise Blocked(f'No live witness of HooksInstalled and two drained ordinary self-writes '
                      f'(readySession={ready_session}, ordinarySeen={len(writes)}). No test trigger sent.')


def packet_text(field):
    return field.decode('utf-16-le', errors='replace').split('\0', 1)[0]


def console_members(kernel):
    query = winapi(kernel, 'GetConsoleProcessList', W.DWORD, C.POINTER(W.DWORD), W.DWORD)
    pids = (W.DWORD * 4)()
    count = query(pids, len(pids))
    if not 0 < count <= len(pids):
        raise Blocked(f'Cannot prove private console membership: count={count}, error={C.get_last_error()}')
    return set(pids[:count])


def cancel_owned_cli(kernel, controller):
    members = console_members(kernel)
    if members != {os.getpid(), controller.pid} or controller.poll() is not None:
        raise Blocked(f'Refusing CTRL_BREAK: private worker/CLI membership not confirmed: {members}')
    # CLI 由本 worker 以 CREATE_NEW_PROCESS_GROUP 启动；从不使用 group=0。
    send = winapi(kernel, 'GenerateConsoleCtrlEvent', W.BOOL, W.DWORD, W.DWORD)
    if not send(CTRL_BREAK_EVENT, controller.pid):
        raise Blocked(f'Targeted CTRL_BREAK was not accepted: {C.get_last_error()}')


def verify_witness(project, captured, session, witnessed):
    from live_etw import decode_raw

    assert captured['sourceSessionIdentity'] == str(session), 'Capture receipt/session differs from pipe witness'
    raw = project / 'samples' / captured['sampleId'] / 'raw'
    remaining = set(witnessed)  # 触发前的证据可能跨段，不依赖首段位置。
    first_sequence = 1
    for ordinal in range(1, int(captured['archive']['committedSegments']) + 1):
        records, _ = decode_raw(raw / f'{ordinal:020d}.ksaseg', first_sequence)
        remaining.difference_update(wire for _, wire in records)
        first_sequence += len(records)
    assert not remaining, 'Witnessed pre-trigger packets missing from archived prefix'


def exercise(project, directory, case, children, kernel):
    baseline.create_project(project, f'AA-03 cooperative lifecycle {case}')
    env = os.environ | {COOPERATIVE_ENV: str(directory)}
    target = children.start([sys.executable, '-B', baseline.SCRIPT, '--identity-negative-target', 'wrong-filetime'],
                            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    # 复用该 target 入口的 AMD64 与初始未加载检查；传给正式 CLI 的仍是真实 FILETIME。
    controller = identity = None
    controller_read = False
    try:
        lines = Queue()
        Thread(target=lambda: lines.put(target.stdout.readline()), daemon=True).start()
        try:
            line = lines.get(timeout=10)
        except Empty as exc:
            raise Blocked('Owned AMD64 target did not announce itself') from exc
        assert line, 'Owned AMD64 target exited before announcing its identity'
        identity = json.loads(line)
        assert identity['pid'] == target.pid and identity['creation'] > 0 and identity['agentLoaded'], identity
        assert not any(directory.iterdir()), f'Unexpected files before capture: {directory}'
        stop = directory / f'stop_{target.pid}_{identity["creation"]}.flag'
        command = [CLI, 'analyze', 'api-evidence', 'capture', '--project', project, '--title', f'AA-03 {case}',
                   '--pid', str(target.pid), '--creation-filetime', str(identity['creation']), '--confirm',
                   '--duration-ms', str(DURATION_MS), '--json']
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if case == 'cancel' else subprocess.CREATE_NO_WINDOW
        controller = children.start(command, env=env, creationflags=flags, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        session, witnessed = CapturePipeWitness(kernel).ready_and_ordinary(controller, target, identity, stop)
        print(f'PRE_TRIGGER_WITNESS case={case} session={session} ordinary={len(witnessed)}', flush=True)
        if controller.poll() is not None or target.poll() is not None or os.path.lexists(stop):
            raise Blocked('Owned capture stopped before the test trigger')
        if case == 'target-exit':
            tail, target_error = target.communicate(timeout=10)  # Sends EOF, not a console event.
        else:
            cancel_owned_cli(kernel, controller)
        stdout, stderr = controller.communicate(timeout=25)
        controller_read = True
        print(f'CLI_CAPTURE_EXIT={controller.returncode} {stdout.decode("utf-8", errors="replace").strip()}', flush=True)
        captured = baseline.receipt(controller.returncode, stdout, stderr, (6,))
        assert (captured['status'], captured['pid'], int(captured['creationFileTime'])) == (
            'capture-partial', target.pid, identity['creation']), captured
        assert all(captured[key] is True for key in ('residentVerified', 'connected', 'agentReady', 'cleanupComplete')), captured
        assert captured['completedInterval'] is False, captured
        assert (captured['targetExited'], captured['cancelled']) == (case == 'target-exit', case == 'cancel'), captured
        assert int(captured['ordinaryPackets']) > 0, captured
        assert all(captured[key] == '0' for key in ('invalidPackets', 'omittedClues', 'agentReportedDrops')), captured
        from project_v1 import regular_identity
        regular_identity(stop)
        assert stop.read_bytes() == b'stop', 'CLI did not persist its own stop marker'
        if case == 'target-exit':
            for key in ('sessionReady', 'hooksInstalled', 'configPublished', 'stopMarkerWritten', 'cleanPipeEof'):
                assert captured[key] is True, (key, captured)
            # 该用例直接退出目标，不以正常 EOF 代替 Agent 的停钩回执。
            assert captured['hooksRemoved'] is False, captured
        if case == 'cancel':
            # 持续存活时 cleanupComplete 才能证明 HooksRemoved + clean EOF，不靠目标死亡清退。
            assert target.poll() is None, 'Cancellation did not leave the owned target alive'
            assert captured['pipeError'] is None and not captured['errors'], captured
            tail, target_error = target.communicate(timeout=10)
        assert target.returncode == 0, (target.returncode, tail, target_error)
        emitted = json.loads(tail)
        assert emitted['agentLoaded'] and emitted['calls'] >= 2, emitted
        baseline.verify_archive(project, identity, captured, emitted['calls'])
        verify_witness(project, captured, session, witnessed)
    finally:
        try:
            if target.poll() is None:
                if not target.stdin.closed:
                    target.stdin.close()
                target.wait(timeout=10)
        finally:
            if controller is not None and not controller_read:
                out, err = controller.communicate(timeout=55)  # Error recovery: EOF only.
                print(f'CLI_CAPTURE_FALLBACK_EXIT={controller.returncode} '
                      f'{out.decode("utf-8", errors="replace").strip()} '
                      f'{err.decode("utf-8", errors="replace").strip()}', flush=True)
        print(f'OWNED_TARGET_EXIT={target.returncode}', flush=True)
        if identity is not None and target.poll() is not None:
            baseline.cleanup_session(directory, target.pid, identity['creation'],
                                     None if controller is None else controller.pid)


def run_case(case, kernel):
    import project_v1

    children = OwnedChildren()
    original_subprocess = baseline.subprocess, project_v1.subprocess
    baseline.subprocess = project_v1.subprocess = SimpleNamespace(run=children.run)
    try:
        run_in_scratch(case, kernel, children)
    finally:
        baseline.subprocess, project_v1.subprocess = original_subprocess


def run_in_scratch(case, kernel, children):
    from project_v1 import SCRATCH, check_scratch_location, raise_walk_error, regular_identity

    for image in (CLI, AGENT):
        binary = image.read_bytes()
        assert (COOPERATIVE_ENV + '\0').encode('utf-16-le') in binary, f'Rebuild cooperative transport: {image}'
        print(f'{image.name}_SHA256={hashlib.sha256(binary).hexdigest()}', flush=True)
    check_scratch_location()
    SCRATCH.mkdir(exist_ok=False)
    scratch_id = regular_identity(SCRATCH)
    directory = SCRATCH / 'KswordApiMonCooperative'
    directory_id = None
    try:
        baseline.create_session_directory(directory)
        directory_id = regular_identity(directory)
        exercise(SCRATCH / 'offline project fixture', directory, case, children, kernel)
    finally:
        live = [child.pid for child in children.processes if child.poll() is None]
        if live:
            raise Blocked(f'Owned processes still running (not terminated): {live}; retained {SCRATCH}')
        if directory_id is not None:
            assert regular_identity(directory) == directory_id and not any(directory.iterdir()), (
                f'Private session directory changed or retained unverified files: {directory}')
            directory.rmdir()
            print('COOPERATIVE_SESSION_DIRECTORY_REMOVED=True', flush=True)
        check_scratch_location()
        assert SCRATCH.resolve(strict=True) == SCRATCH and regular_identity(SCRATCH) == scratch_id, SCRATCH
        for parent, directories, files in os.walk(SCRATCH, followlinks=False, onerror=raise_walk_error):
            for name in directories + files:
                regular_identity(Path(parent) / name)
        rmtree(SCRATCH)
        assert not os.path.lexists(SCRATCH), SCRATCH
        print(f'Cleaned {SCRATCH}', flush=True)
    print(f'AA03_COOPERATIVE_CAPTURE_LIFECYCLE_{case.upper().replace("-", "_")}=PASS', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=('target-exit', 'cancel'), default='target-exit')
    parser.add_argument('--private-console-worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8 or not __debug__:
        parser.error('AMD64 Windows Python with assertions enabled is required')
    kernel = C.WinDLL('kernel32', use_last_error=True)
    try:
        if args.case == 'cancel' and not args.private_console_worker:
            startup = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=subprocess.SW_HIDE)
            try:
                worker = subprocess.Popen([sys.executable, '-B', SCRIPT, '--case', 'cancel', '--private-console-worker'],
                                          creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup,
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError as exc:
                raise Blocked(f'Private console could not be created: {exc}') from exc
            stdout, stderr = worker.communicate(timeout=145)
            sys.stdout.buffer.write(stdout)
            sys.stderr.buffer.write(stderr)
            return worker.returncode
        if args.case == 'cancel' and console_members(kernel) != {os.getpid()}:
            raise Blocked('Cancel worker does not own a private, empty console; no CLI or target was started')
        run_case(args.case, kernel)
    except (Blocked, subprocess.TimeoutExpired) as exc:
        print(f'AA03_COOPERATIVE_CAPTURE_LIFECYCLE_BLOCKED: {exc}', file=sys.stderr, flush=True)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
