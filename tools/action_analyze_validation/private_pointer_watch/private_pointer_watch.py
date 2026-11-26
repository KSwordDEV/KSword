"""正式 CLI 私有内存指针导出的本机验收夹具。

流程：GCC 构建自有 AMD64 合作目标，目标在启动后分配 MEM_PRIVATE 区域并发布
8 字节对齐指针，先置位 Ready，收到宿主 Gate 字节 '1' 后才执行业务写入。
每条用例独立启动 CLI 与目标，核对真实地址、区域属性、停点线程和清退结果。
"""

import argparse
import ctypes as ct
from ctypes import wintypes as win
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time
from uuid import uuid4


REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
TARGET = RELEASE / 'ActionAnalyzePrivatePointerWatch.exe'
INT_DIR = Path(__file__).resolve().parent / 'x64' / 'Release'
SOURCE = Path(__file__).with_name('PrivatePointerWatchChild.c')
EVIDENCE_DIR = REPO / '.codex-build-logs' / 'behavior-planning'
MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
BELOW_NORMAL = 0x4000
WAIT_OBJECT = 0
WAIT_TIMEOUT = 258
ERROR_ALREADY_EXISTS = 183
ERROR_BROKEN_PIPE = 109
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_TERMINATE = 0x1
SYNCHRONIZE = 0x100000
THREAD_QUERY_LIMITED = 0x800
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
# 仅用于重建前诊断：旧构建未把 --watch-pointer-export 声明为无值开关。
LEGACY_FLAG_VALUE = os.environ.get('KSWORD_POINTER_EXPORT_LEGACY_VALUE')


def pointer_export_args():
    return ['--watch-pointer-export'] + ([LEGACY_FLAG_VALUE] if LEGACY_FLAG_VALUE else [])


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


KERNEL = ct.WinDLL('kernel32', use_last_error=True)


def api(name, result, *args):
    function = getattr(KERNEL, name)
    function.restype = result
    function.argtypes = args
    return function


CreateEvent = api('CreateEventW', win.HANDLE, ct.c_void_p, win.BOOL, win.BOOL, win.LPCWSTR)
CreateMutex = api('CreateMutexW', win.HANDLE, ct.c_void_p, win.BOOL, win.LPCWSTR)
ReleaseMutex = api('ReleaseMutex', win.BOOL, win.HANDLE)
OpenProcess = api('OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
OpenThread = api('OpenThread', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
GetProcessIdOfThread = api('GetProcessIdOfThread', win.DWORD, win.HANDLE)
CloseHandle = api('CloseHandle', win.BOOL, win.HANDLE)
SetEvent = api('SetEvent', win.BOOL, win.HANDLE)
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
GetProcessTimes = api('GetProcessTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetThreadTimes = api('GetThreadTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetExitCode = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetImagePath = api('QueryFullProcessImageNameW', win.BOOL, win.HANDLE, win.DWORD, win.LPWSTR, ct.POINTER(win.DWORD))
CheckDebugger = api('CheckRemoteDebuggerPresent', win.BOOL, win.HANDLE, ct.POINTER(win.BOOL))
TerminateProcess = api('TerminateProcess', win.BOOL, win.HANDLE, win.UINT)
GetLastError = ct.get_last_error


def fingerprint(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def build_fixture(log):
    """按固定输出位置构建自有目标；GCC 不可用时只报告阻塞，不复制运行目录。"""
    compiler = shutil.which('gcc')
    require(compiler, 'GCC (MSYS2 UCRT64) is required for the fixture build')
    INT_DIR.mkdir(parents=True, exist_ok=True)
    log.write(f'FIXTURE_COMPILER={compiler}\nFIXTURE_INTDIR={INT_DIR}\nFIXTURE_OUTDIR={TARGET}\n'
              'FIXTURE_PRIORITY=BelowNormal\n')
    log.flush()
    command = [compiler, '-O2', '-Wall', '-Wextra', '-Wno-unused-parameter', '-o', str(TARGET), str(SOURCE),
               '-Wl,--dynamicbase', '-Wl,--nxcompat']
    result = subprocess.run(command, cwd=INT_DIR, capture_output=True, text=True,
                            creationflags=BELOW_NORMAL, timeout=120)
    log.write('FIXTURE_CMD=' + subprocess.list2cmdline(command) + '\n')
    log.write('FIXTURE_STDOUT=' + result.stdout + '\nFIXTURE_STDERR=' + result.stderr +
              f'\nFIXTURE_BUILD_EXIT={result.returncode}\n')
    log.flush()
    require(result.returncode == 0 and TARGET.is_file(), 'fixture build failed')


@contextmanager
def named_mutex(log, wait_seconds=0):
    """整批构建与运行只持一个固定名互斥；同线程 try/finally 释放。"""
    handle = CreateMutex(None, False, MUTEX_NAME)
    require(handle, f'CreateMutex failed: {GetLastError()}')
    acquired = GetLastError() != ERROR_ALREADY_EXISTS
    deadline = time.monotonic() + wait_seconds
    while not acquired and time.monotonic() < deadline:
        CloseHandle(handle)
        time.sleep(0.25)
        handle = CreateMutex(None, False, MUTEX_NAME)
        require(handle, f'CreateMutex failed: {GetLastError()}')
        acquired = GetLastError() != ERROR_ALREADY_EXISTS
    try:
        require(acquired, 'another ActionAnalyze CLI validation holds the fixed mutex')
        log.write(f'MUTEX={MUTEX_NAME} ACQUIRED=true THREAD={threading.get_ident()}\n')
        log.flush()
        yield
    finally:
        if acquired:
            ReleaseMutex(handle)
        CloseHandle(handle)


def checked_target(hello):
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, False, hello['targetPid'])
    require(handle, f'OpenProcess failed for owned target: {GetLastError()}')
    try:
        created, exited, kernel, user = (win.FILETIME() for _ in range(4))
        require(GetProcessTimes(handle, ct.byref(created), ct.byref(exited), ct.byref(kernel), ct.byref(user)),
                f'GetProcessTimes failed: {GetLastError()}')
        require(str((created.dwHighDateTime << 32) | created.dwLowDateTime) == hello['targetCreationFileTime'], hello)
        length = win.DWORD(32768)
        path = ct.create_unicode_buffer(length.value)
        require(GetImagePath(handle, 0, path, ct.byref(length)) and Path(path.value) == TARGET, path.value)
        return handle
    except BaseException:
        CloseHandle(handle)
        raise


def attached(handle):
    active = win.BOOL()
    require(CheckDebugger(handle, ct.byref(active)), f'CheckRemoteDebuggerPresent failed: {GetLastError()}')
    return bool(active.value)


def thread_creation(pid, tid):
    thread = OpenThread(THREAD_QUERY_LIMITED, False, tid)
    require(thread, f'OpenThread failed: {GetLastError()}')
    try:
        created, exited, kernel, user = (win.FILETIME() for _ in range(4))
        require(GetProcessIdOfThread(thread) == pid and
                GetThreadTimes(thread, ct.byref(created), ct.byref(exited), ct.byref(kernel), ct.byref(user)),
                f'GetThreadTimes failed for PID {pid}, TID {tid}: {GetLastError()}')
        return (created.dwHighDateTime << 32) | created.dwLowDateTime
    finally:
        CloseHandle(thread)


def read_receipt(path):
    require(path.is_file(), f'fixture receipt missing: {path}')
    values = {}
    for line in path.read_text(encoding='ascii').splitlines():
        key, _, value = line.partition('=')
        values[key] = value
    for key in ('pointer', 'allocationBase', 'regionBase', 'regionBytes', 'regionProtection', 'type', 'protectMode'):
        require(key in values, f'receipt field missing: {key}')
    return values


class Session:
    """JSONL 控制通道；所有断言使用 CLI 的实际回执，不读目标自述状态。"""

    def __init__(self, env, log, width, mode):
        self.log = log
        self.lines = queue.Queue()
        self.session = None
        self.sequence = 0
        self.query_sequence = 0
        self.process = subprocess.Popen(
            [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(TARGET),
             '--export', 'WatchedPointer', '--watch-write-bytes', str(width),
             *pointer_export_args(), '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl'],
            cwd=RELEASE, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
            encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def receive(self, kind=None, request_id=None, timeout=12):
        line = self.lines.get(timeout=timeout)
        require(line is not None, f'CLI closed stdout (exit={self.process.poll()})')
        self.log.write('RX ' + line)
        self.log.flush()
        frame = json.loads(line)
        self.sequence += 1
        require(frame['schemaVersion'] == 1 and frame['streamSequence'] == str(self.sequence), frame)
        if kind is not None:
            require(frame['type'] == kind and frame['requestId'] == request_id, frame)
        if self.session is None:
            self.session = frame['session']
        require(frame['session'] == self.session, frame)
        return frame['result']

    def send(self, request_id, method, expected=None):
        request = dict(schemaVersion=1, requestId=request_id, method=method, session=self.session, params={})
        if expected is not None:
            request['expected'] = expected
        line = json.dumps(request, separators=(',', ':')) + '\n'
        self.log.write('TX ' + line)
        self.log.flush()
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def request(self, request_id, method, expected=None, kind='response'):
        self.send(request_id, method, expected)
        return self.receive(kind, request_id)

    def status(self):
        self.query_sequence += 1
        return self.request(f'query/{self.query_sequence}', 'control.query')

    def wait_for_state(self, states, identity, timeout=6):
        deadline = time.monotonic() + timeout
        last = None
        while True:
            last = self.status()
            require((last['pid'], last['creationFileTime'], last['processInstanceId']) == identity, last)
            state = (last.get('breakpoint') or {}).get('state')
            if state in states:
                return last
            require(time.monotonic() < deadline, f'binding never reached {states}: {last}')
            time.sleep(0.01)

    def close_pipes(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()


@contextmanager
def events(prefix):
    handles = []
    try:
        for suffix in ('trigger', 'done'):
            handle = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(handle, f'CreateEvent failed: {GetLastError()}')
            handles.append(handle)
        yield handles
    finally:
        for handle in handles:
            CloseHandle(handle)


def start(env, log, width, mode):
    session = Session(env, log, width, mode)
    try:
        hello = session.receive('hello')
    except BaseException:
        session.close_pipes()
        raise
    return session, hello


def target_identity(hello):
    control = hello['control']
    return (hello['targetPid'], hello['targetCreationFileTime'], control['processInstanceId'])


def check_binding(binding, receipt, width):
    require(binding['state'] == 'armed', binding)
    require(binding['watchedBytes'] == width, binding)
    require(binding['siteKind'] == 'private-pointer-export', binding)
    require(binding['allocationGenerationVerified'] is False, binding)
    address = int(binding['address'], 16)
    pointer_export = int(binding['pointerExportAddress'], 16)
    require(address == int(receipt['pointer'], 16), (binding, receipt))
    require(pointer_export > 0 and pointer_export != address, binding)
    require(int(binding['allocationBase'], 16) == int(receipt['allocationBase'], 16), (binding, receipt))
    require(int(binding['regionBase'], 16) == int(receipt['regionBase'], 16), (binding, receipt))
    require(int(binding['regionBytes']) == int(receipt['regionBytes']), (binding, receipt))
    require(binding['regionProtection'] == int(receipt['regionProtection']), (binding, receipt))
    require(receipt['type'] == '131072', receipt)  # MEM_PRIVATE
    return address


def wait_done(done, timeout=6000):
    return Wait(done, timeout) == WAIT_OBJECT


def wait_child(child, timeout=6000):
    require(Wait(child, timeout) == WAIT_OBJECT, 'owned child did not exit')
    code = win.DWORD()
    require(GetExitCode(child, ct.byref(code)), f'GetExitCodeProcess failed: {GetLastError()}')
    return code.value


def write_round_checks(session, child, identity, trigger, done, width, log):
    """范围外、同值、真实变化、后建线程、旧令牌、继续和关闭的完整链路。"""
    # 第 0 轮：范围外字节和同值写都不得产生停点，业务完成事件必须自然出现。
    require(SetEvent(trigger), 'trigger outside-range and same-value round')
    require(wait_done(done), 'outside-range or same-value write did not complete')
    idle = session.status()
    require(idle['breakpoint']['state'] == 'armed' and 'stop' not in idle and 'hit' not in idle, idle)
    log.write('ROUND0=OUTSIDE_RANGE_AND_SAME_VALUE_PASSED\n')

    # 第 1 轮：主线程真实改变首字节，必须在同一停点读到掩码和登记顺序。
    require(SetEvent(trigger), 'trigger first real change')
    first = session.wait_for_state({'held'}, identity)
    hit = first['hit']
    require(hit['phase'] == 'data-write-observed' and hit['watchedBytes'] == width and
            hit['changedByteMask'] == 1 and hit['enrolledAfterStop'] == '0', first)
    require(not wait_done(done, 0), 'first write body ran before continue')
    require(thread_creation(identity[0], hit['tid']) == int(hit['threadCreationFileTime']), hit)
    stop = first['stop']
    released = session.request('continue/1', 'control.continue',
                               dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
    require(released['release']['result'] == 'continued' and wait_done(done), released)
    require(released['stopGroup']['historical'] and 'stop' not in released, released)
    log.write(f'ROUND1=MASK=1 TID={hit["tid"]} CREATED={hit["threadCreationFileTime"]} CONTINUE=continued\n')

    # 第 2 轮：首次停点之后新建的线程写关注范围末字节，必须有独立身份。
    require(SetEvent(trigger), 'trigger new-thread change')
    second = session.wait_for_state({'held'}, identity)
    hit2 = second['hit']
    mask = 1 << (width - 1)
    require(hit2['changedByteMask'] == mask and hit2['enrolledAfterStop'] == '1', second)
    require(hit2['tid'] != hit['tid'] and hit2['threadId'] != hit['threadId'] and
            int(hit2['threadCreationFileTime']) > int(hit['threadCreationFileTime']), second)
    require(thread_creation(identity[0], hit2['tid']) == int(hit2['threadCreationFileTime']), hit2)
    # 用上一代的停点令牌继续必须被拒绝，且当前事件仍持有。
    stale = session.request('continue/2', 'control.continue',
                            dict(stopId=stop['id'], stateRevision=stop['stateRevision']), kind='error')
    require(stale['errorId'] == 'stale-stop' and session.status()['stop'] == second['stop'], stale)
    log.write(f'ROUND2=MASK={mask} TID={hit2["tid"]} ENROLLED_AFTER_STOP=1 STALE_STOP=rejected\n')

    # 关闭：释放当前停点、脱离并清零登记；目标继续完成本轮并等待脱离后的写入。
    session.send('shutdown', 'controller.shutdown')
    summary = session.receive('summary')
    closed = summary['control']
    require(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['clean'] and
            not closed['attached'] and closed['breakpoint']['state'] == 'retired' and
            closed['breakpoint']['enrolledThreads'] == '0', summary)
    require(session.process.wait(timeout=8) == 0 and not attached(child), summary)
    require(wait_done(done), 'new-thread body did not run after shutdown')
    # 第 3 轮：脱离后目标仍能写同一私有区间并正常退出。
    require(SetEvent(trigger) and wait_done(done), 'detached target could not write again')
    require(wait_child(child) == 0, 'detached target did not exit 0')
    log.write(f'CLOSE=PASS WIDTH={width} CLI_EXIT=0 CHILD_EXIT=0\n')


def valid_case(log, width, protect='rw', stamp=''):
    prefix = r'Local\KSwordPrivatePointer-' + uuid4().hex
    receipt = EVIDENCE_DIR / f'private-pointer-{stamp}-{width}-{protect}-{os.getpid()}.txt'
    env = dict(os.environ, KSWORD_PRIVATE_POINTER_EVENTS=prefix, KSWORD_PRIVATE_POINTER_MODE='valid',
               KSWORD_PRIVATE_POINTER_WIDTH=str(width), KSWORD_PRIVATE_POINTER_PROTECT=protect,
               KSWORD_PRIVATE_POINTER_RECEIPT=str(receipt))
    session = child = None
    try:
        with events(prefix) as (trigger, done):
            session, hello = start(env, log, width, 'valid')
            child = checked_target(hello)
            identity = target_identity(hello)
            armed = session.wait_for_state({'armed'}, identity)
            require(armed['attached'] and attached(child), armed)
            data = read_receipt(receipt)
            address = check_binding(armed['breakpoint'], data, width)
            log.write(f'BINDING=PASS WIDTH={width} PROTECT={protect} ADDRESS=0x{address:X} '
                      f'POINTER_EXPORT={armed["breakpoint"]["pointerExportAddress"]} '
                      f'ALLOCATION=0x{int(data["allocationBase"], 16):X} '
                      f'REGION_BYTES={data["regionBytes"]} REGION_PROTECTION={data["regionProtection"]}\n')
            write_round_checks(session, child, identity, trigger, done, width, log)
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                try:
                    if Wait(child, 0) == WAIT_TIMEOUT:
                        require(TerminateProcess(child, 3) and Wait(child, 5000) == WAIT_OBJECT,
                                'test target could not be stopped after failure')
                finally:
                    CloseHandle(child)
            receipt.unlink(missing_ok=True)


def invalid_case(log, mode, width, label):
    """指针空、未对齐、只读、非私有和越界必须在武装时拒绝，不产生停点。"""
    prefix = r'Local\KSwordPrivatePointer-' + uuid4().hex
    receipt = EVIDENCE_DIR / f'private-pointer-invalid-{label}-{os.getpid()}.txt'
    env = dict(os.environ, KSWORD_PRIVATE_POINTER_EVENTS=prefix, KSWORD_PRIVATE_POINTER_MODE=mode,
               KSWORD_PRIVATE_POINTER_WIDTH=str(width), KSWORD_PRIVATE_POINTER_RECEIPT=str(receipt))
    session = child = None
    try:
        session, hello = start(env, log, width, mode)
        child = checked_target(hello)
        identity = target_identity(hello)
        state = session.wait_for_state({'retired', 'rejected', 'recovery-required'}, identity, timeout=8)
        binding = state['breakpoint']
        require(binding['state'] != 'armed' and binding['address'] is None, state)
        require(binding['stage'] == 'resolve-requested-image-site' or
                'resolve-requested-image-site' in str(binding.get('stage')), state)
        require(binding['win32Error'] != 0, state)  # 原生拒绝原因必须保留。
        log.write(f'INVALID={label} MODE={mode} STATE={binding["state"]} STAGE={binding["stage"]} '
                  f'WIN32={binding["win32Error"]}\n')
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        require(summary['exitCode'] in (0, 6), summary)
        # 目标在武装前只等待 Gate；宿主关闭写端后按 EOF 正常退出。
        require(wait_child(child) == 0, f'{label}: child did not cancel through EOF')
        log.write(f'INVALID_{label}=PASS EOF_CANCEL=true CHILD_EXIT=0\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                try:
                    if Wait(child, 0) == WAIT_TIMEOUT:
                        TerminateProcess(child, 3)
                        Wait(child, 5000)
                finally:
                    CloseHandle(child)
            receipt.unlink(missing_ok=True)


def invalidation_case(log, mode, label):
    """指针/保护/释放复用后，下一次真实写入必须清退旧绑定且不重绑。"""
    prefix = r'Local\KSwordPrivatePointer-' + uuid4().hex
    receipt = EVIDENCE_DIR / f'private-pointer-invalidate-{label}-{os.getpid()}.txt'
    env = dict(os.environ, KSWORD_PRIVATE_POINTER_EVENTS=prefix, KSWORD_PRIVATE_POINTER_MODE=mode,
               KSWORD_PRIVATE_POINTER_WIDTH='8', KSWORD_PRIVATE_POINTER_RECEIPT=str(receipt))
    session = child = None
    try:
        with events(prefix) as (trigger, done):
            session, hello = start(env, log, 8, mode)
            child = checked_target(hello)
            identity = target_identity(hello)
            armed = session.wait_for_state({'armed'}, identity)
            original = armed['breakpoint']
            old_address = int(original['address'], 16)
            old_pointer = int(armed['breakpoint']['pointerExportAddress'], 16)

            require(SetEvent(trigger) and wait_done(done), f'{label}: round 0 did not complete')
            require(SetEvent(trigger), f'{label}: trigger first real change')
            first = session.wait_for_state({'held'}, identity)
            stop = first['stop']
            released = session.request('continue/1', 'control.continue',
                                       dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
            require(released['release']['result'] == 'continued' and wait_done(done), released)

            # 第 2 轮在目标内破坏区间后写旧地址；CLI 必须清退而不是跟随新指针。
            require(SetEvent(trigger), f'{label}: trigger invalidated write')
            retired = session.wait_for_state({'retired', 'rejected', 'recovery-required'}, identity, timeout=8)
            binding = retired['breakpoint']
            require(binding['address'] == original['address'] and
                    binding['pointerExportAddress'] == original['pointerExportAddress'], (retired, original))
            require(binding['stage'] in ('write-watch-private-region-changed', 'breakpoint-close-requested'),
                    retired)
            require(wait_done(done), f'{label}: invalidated write did not complete')
            after = session.status()
            require('stop' not in after and (after.get('breakpoint') or {}).get('state') in
                    ('retired', 'rejected', 'recovery-required'), after)
            # 目标在选择器被改指后仍使用原关注地址；CLI 不发布第二个绑定。
            require(int(after['breakpoint']['address'], 16) == old_address and
                    int(after['breakpoint']['pointerExportAddress'], 16) == old_pointer, after)
            log.write(f'INVALIDATE={label} MODE={mode} STAGE={binding["stage"]} '
                      f'OLD_ADDRESS=0x{old_address:X} POINTER_EXPORT=0x{old_pointer:X} REBIND=false\n')

            session.send('shutdown', 'controller.shutdown')
            summary = session.receive('summary')
            require(summary['exitCode'] in (0, 6), summary)
            require(session.process.wait(timeout=8) in (0, 6), summary)
            require(SetEvent(trigger) and wait_done(done), f'{label}: post-detach write failed')
            require(wait_child(child) == 0, f'{label}: child did not exit 0')
            log.write(f'INVALIDATE_{label}=PASS NO_REBIND=true CHILD_EXIT=0\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                try:
                    if Wait(child, 0) == WAIT_TIMEOUT:
                        TerminateProcess(child, 3)
                        Wait(child, 5000)
                finally:
                    CloseHandle(child)
            receipt.unlink(missing_ok=True)


def startup_cancel_case(log, mode, label, expected_error, min_seconds, max_seconds):
    """Ready 前取消：无 Ready 走 5 秒上限，提前退出必须立即报告。"""
    prefix = r'Local\KSwordPrivatePointer-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRIVATE_POINTER_EVENTS=prefix, KSWORD_PRIVATE_POINTER_MODE=mode,
               KSWORD_PRIVATE_POINTER_WIDTH='8')
    began = time.monotonic()
    process = subprocess.Popen(
        [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(TARGET),
         '--export', 'WatchedPointer', '--watch-write-bytes', '8',
         *pointer_export_args(), '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl'],
        cwd=RELEASE, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
        encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        line = process.stdout.readline()
        require(line, f'{label}: CLI produced no summary')
        log.write('RX ' + line)
        frame = json.loads(line)
        elapsed = time.monotonic() - began
        require(frame['type'] == 'summary' and frame['requestId'] is None, frame)
        result = frame['result']
        require(result['reason'] == 'private-data-target-not-ready' and result['exitCode'] == 3, result)
        require(result['win32Error'] == expected_error, (result, expected_error))
        require(min_seconds <= elapsed <= max_seconds, (label, elapsed))
        require(process.wait(timeout=8) == 3, f'{label}: CLI exit code')
        log.write(f'STARTUP_CANCEL={label} MODE={mode} REASON={result["reason"]} '
                  f'WIN32={result["win32Error"]} ELAPSED={elapsed:.3f}s CLI_EXIT=3\n')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        try:
            process.stdin.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-cli-sha256')
    parser.add_argument('--mutex-wait', type=int, default=0, help='Wait this many seconds for the fixed validation mutex')
    parser.add_argument('--allow-digest-change', action='store_true',
                        help='Diagnostic only: record a concurrent rebuild instead of failing the run')
    parser.add_argument('--only', help='Optional comma-separated subset for diagnosis')
    args = parser.parse_args()
    require(CLI.is_file(), f'Build the official CLI first: {CLI}')
    digest = fingerprint(CLI)
    if args.expected_cli_sha256:
        expected = args.expected_cli_sha256.lower()
        require(len(expected) == 64 and set(expected) <= set('0123456789abcdef'), 'invalid expected digest')
        require(digest == expected, f'CLI SHA-256 mismatch: expected {expected}, got {digest}')
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    evidence = EVIDENCE_DIR / f'action-analyze-private-pointer-watch-{stamp}-{os.getpid()}.log'
    print(f'EVIDENCE={evidence}', flush=True)
    selected = set(args.only.split(',')) if args.only else None
    try:
        with evidence.open('x', encoding='utf-8', buffering=1) as log:
            log.write('【子代理｜第5项私有内存指针导出】\n')
            log.write(f'FORMAL_CLI={CLI}\nFORMAL_CLI_SHA256={digest}\n')
            with named_mutex(log, args.mutex_wait):
                if not TARGET.is_file() or TARGET.stat().st_mtime < SOURCE.stat().st_mtime:
                    build_fixture(log)
                log.write(f'FIXTURE_SHA256={fingerprint(TARGET)}\n')
                cases = {
                    'valid': lambda: [valid_case(log, width, 'rw', stamp) for width in (1, 2, 4, 8)],
                    'rwx': lambda: valid_case(log, 8, 'rwx', stamp),
                    'invalid': lambda: [invalid_case(log, mode, width, label) for mode, width, label in (
                        ('null', 8, 'null'), ('misaligned', 8, 'misaligned'), ('readonly', 8, 'readonly'),
                        ('image', 8, 'non-private'), ('boundary', 8, 'boundary'))],
                    'invalidate': lambda: [invalidation_case(log, mode, label) for mode, label in (
                        ('pointer-change', 'pointer'), ('protect-change', 'protect'), ('mapped-reuse', 'mapped'))],
                    'startup': lambda: [startup_cancel_case(log, 'no-ready', 'no-ready', 1460, 4.5, 7.5),
                                        startup_cancel_case(log, 'exit-before-ready', 'exit-before', 1067, 0.0, 3.0)],
                }
                for name, case in cases.items():
                    if selected is None or name in selected:
                        case()
    finally:
        final_digest = fingerprint(CLI)
        if final_digest != digest:
            require(args.allow_digest_change,
                    f'formal CLI digest changed during validation: {digest} -> {final_digest}')
            with evidence.open('a', encoding='utf-8') as log:
                log.write(f'CONCURRENT_REBUILD_START={digest} END={final_digest}\n')
        TARGET.unlink(missing_ok=True)
        shutil.rmtree(INT_DIR, ignore_errors=True)
    print(f'PRIVATE_POINTER_WATCH=PASS CLI_SHA256={digest} FIXTURE_CLEANED=true')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        print(f'PRIVATE_POINTER_WATCH=FAIL {error}', file=sys.stderr)
        raise
