"""Validate long-running JSONL breakpoints against the built AMD64 Release CLI."""

import ctypes as ct
from ctypes import wintypes as win
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time
from uuid import UUID, uuid4


REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
TARGET = RELEASE / 'ActionAnalyzeProductBreakpointLongRun.exe'
INT_DIR = REPO / 'KswordCLI' / 'ActionAnalyze' / 'Control' / 'tests' / 'x64' / 'Release' / 'ProductBreakpointLongRun'
SOURCE = Path(__file__).with_name('product_breakpoint_child.c')
CONTINUES = 130
WAIT_OBJECT = 0
WAIT_TIMEOUT = 258
BELOW_NORMAL = 0x4000
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_TERMINATE = 0x1
SYNCHRONIZE = 0x100000


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def api(name, result, *args):
    function = getattr(KERNEL, name)
    function.restype = result
    function.argtypes = args
    return function


KERNEL = ct.WinDLL('kernel32', use_last_error=True)
CreateEvent = api('CreateEventW', win.HANDLE, ct.c_void_p, win.BOOL, win.BOOL, win.LPCWSTR)
OpenProcess = api('OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
OpenThread = api('OpenThread', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
GetProcessIdOfThread = api('GetProcessIdOfThread', win.DWORD, win.HANDLE)
CloseHandle = api('CloseHandle', win.BOOL, win.HANDLE)
SetEvent = api('SetEvent', win.BOOL, win.HANDLE)
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
GetProcessTimes = api('GetProcessTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetThreadTimes = api('GetThreadTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetSystemTimeAsFileTime = api('GetSystemTimeAsFileTime', None, ct.POINTER(win.FILETIME))
GetExitCode = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetImagePath = api('QueryFullProcessImageNameW', win.BOOL, win.HANDLE, win.DWORD, win.LPWSTR, ct.POINTER(win.DWORD))
CheckDebugger = api('CheckRemoteDebuggerPresent', win.BOOL, win.HANDLE, ct.POINTER(win.BOOL))
TerminateProcess = api('TerminateProcess', win.BOOL, win.HANDLE, win.UINT)


def fingerprint(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def build_fixture(log):
    choices = [Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'), Path(r'D:\Software\VS')]
    setup = next((base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat' for base in choices
                  if (base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat').is_file()), None)
    require(setup is not None, 'MSVC vcvars64.bat is required')
    initialize = f'call "{setup}" >nul'
    shell = f'"{os.environ["ComSpec"]}" /d /c '
    paths = subprocess.check_output(shell + initialize + ' && where cl.exe', cwd=INT_DIR,
                                    creationflags=BELOW_NORMAL, text=True, timeout=30).splitlines()
    compiler = next((Path(path) for path in paths if path.lower().endswith(r'\hostx64\x64\cl.exe')), None)
    require(compiler is not None and compiler.is_file(), f'HostX64 compiler required: {paths}')
    log.write(f'INTDIR={INT_DIR}\nOUTDIR={RELEASE}\nHOSTX64={compiler}\nPRIORITY=BelowNormal\n')
    log.flush()
    command = (f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 '
               f'"{SOURCE}" /link /OUT:"{TARGET}" /IMPLIB:fixture.lib /MACHINE:X64')
    subprocess.run(shell + command, cwd=INT_DIR, stdout=log, stderr=subprocess.STDOUT,
                   creationflags=BELOW_NORMAL, timeout=30, check=True)
    log.seek(0, os.SEEK_END)


@contextmanager
def installed_fixture(log):
    """在既定 IntDir/Release 构建同一个 C 目标，离开作用域时清理本轮产物。"""
    require(not TARGET.exists() and not INT_DIR.exists(), f'Fixture outputs already exist: {TARGET}, {INT_DIR}')
    INT_DIR.mkdir(parents=True)
    try:
        build_fixture(log)
        yield TARGET
    finally:
        TARGET.unlink(missing_ok=True)
        shutil.rmtree(INT_DIR)


@contextmanager
def write_watch_events():
    """返回自有目标继承的环境及 ready/trigger/done 句柄，供三端复用。"""
    prefix = r'Local\KSwordProductBreakpoint-' + uuid4().hex  # 每轮事件独立命名。
    handles = []  # 完整记录本轮创建的事件，包括失败前已创建项。
    try:
        for suffix in ('ready', 'trigger', 'done'):
            handle = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(handle, f'CreateEvent failed: {ct.get_last_error()}')
            handles.append(handle)
        yield dict(KSWORD_PRODUCT_BREAKPOINT_EVENTS=prefix, KSWORD_PRODUCT_BREAKPOINT_WRITE_WATCH='1'), handles
    finally:
        for handle in handles:
            CloseHandle(handle)


class Session:
    def __init__(self, env, log, watch_width, condition=None, cooperative_pair=False):
        self.log = log
        self.lines = queue.Queue()
        self.session = None
        self.sequence = 0
        self.query_sequence = 0
        site = ['--export', 'WatchedData', '--watch-write-bytes', str(watch_width)] if watch_width else ['--export', 'ExportedTick']
        predicate = [] if condition is None else ['--condition', condition]
        pair = ['--cooperative-pair'] if cooperative_pair else []
        self.process = subprocess.Popen(
            [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(TARGET), *site,
             '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl', *predicate, *pair],
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

    def receive(self, kind, request_id=None):
        line = self.lines.get(timeout=8)
        require(line is not None, f'CLI closed stdout (exit={self.process.poll()})')
        self.log.write('RX ' + line)
        frame = json.loads(line)
        self.sequence += 1
        require(frame['schemaVersion'] == 1 and frame['streamSequence'] == str(self.sequence), frame)
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
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def request(self, request_id, method, expected=None, kind='response'):
        self.send(request_id, method, expected)
        return self.receive(kind, request_id)

    def status(self):
        self.query_sequence += 1
        return self.request(f'query/{self.query_sequence}', 'control.query')

    def wait_for(self, state, target_identity):
        deadline = time.monotonic() + 5
        while True:
            result = self.status()
            require((result['pid'], result['creationFileTime'], result['processInstanceId']) == target_identity, result)
            binding = result['breakpoint']['state']
            if binding == state:
                return result
            require(binding in ('installing', 'armed') and time.monotonic() < deadline, result)
            time.sleep(0.01)

    def close_pipes(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()


def checked_target(hello):
    # 仅持有与本次 CLI 回执及固定夹具路径相符的真实进程对象。
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, False, hello['targetPid'])
    require(handle, f'OpenProcess failed for owned target: {ct.get_last_error()}')
    try:
        created, exited, kernel, user = (win.FILETIME() for _ in range(4))
        require(GetProcessTimes(handle, ct.byref(created), ct.byref(exited), ct.byref(kernel), ct.byref(user)),
                f'GetProcessTimes failed: {ct.get_last_error()}')
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
    require(CheckDebugger(handle, ct.byref(active)), f'CheckRemoteDebuggerPresent failed: {ct.get_last_error()}')
    return bool(active.value)


def owned_thread_creation(pid, tid):
    thread = OpenThread(0x800, False, tid)  # THREAD_QUERY_LIMITED_INFORMATION
    require(thread, f'OpenThread failed: {ct.get_last_error()}')
    try:
        created, exited, kernel, user = (win.FILETIME() for _ in range(4))
        require(GetProcessIdOfThread(thread) == pid and
                GetThreadTimes(thread, ct.byref(created), ct.byref(exited), ct.byref(kernel), ct.byref(user)),
                f'GetThreadTimes failed for owned PID {pid}, TID {tid}: {ct.get_last_error()}')
        return (created.dwHighDateTime << 32) | created.dwLowDateTime
    finally:
        CloseHandle(thread)


def check_write_hit(session, identity, trigger, done, width, mask, enrolled_after):
    # 触发线程仍停在原生事件上，独立核对 PID、TID 的创建 FILETIME 与业务进度。
    require(SetEvent(trigger), 'start owned write')
    held = session.wait_for('held', identity)
    hit = held['hit']
    require(hit['phase'] == 'data-write-observed' and hit['watchedBytes'] == width and hit['changedByteMask'] == mask
            and hit['enrolledAfterStop'] == str(enrolled_after), held)
    require(held['stopGroup']['state'] == 'held-complete' and Wait(done, 0) == WAIT_TIMEOUT, held)
    require(str(owned_thread_creation(identity[0], hit['tid'])) == hit['threadCreationFileTime'], hit)
    return held


def write_watch_regression(session, child, identity, trigger, done, width, log):
    # 正常范围和同值写必须自然完成，再由原主线程产生首次真实变化停点。
    require(SetEvent(trigger) and Wait(done, 5000) == WAIT_OBJECT and session.status()['breakpoint']['state'] == 'armed',
            'outside-range or same-value write did not complete automatically')
    first = check_write_hit(session, identity, trigger, done, width, 1, 0)
    stop = first['stop']
    released = session.request('continue/1', 'control.continue', dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
    require(released['release']['result'] == 'continued' and Wait(done, 5000) == WAIT_OBJECT, released)
    require(released['hit'] == first['hit'] and released['stopGroup']['historical'], released)

    # 新线程在首次命中后才存在，必须在下一次原生停点上有独立身份。
    new_thread_mask = 1 << (width - 1)  # 第二次命中只改关注范围的最后一个字节。
    second = check_write_hit(session, identity, trigger, done, width, new_thread_mask, 1)
    require(first['hit']['tid'] != second['hit']['tid'] and first['hit']['threadId'] != second['hit']['threadId'] and
            int(first['hit']['threadCreationFileTime']) < int(second['hit']['threadCreationFileTime']), second)
    # 将首次停点交给新的继续请求。原生事件仍属于后建线程，且业务完成事件不能提前出现。
    stale = session.request('continue/2', 'control.continue',
                            dict(stopId=stop['id'], stateRevision=stop['stateRevision']), kind='error')
    require(stale['errorId'] == 'stale-stop' and session.status()['stop'] == second['stop'] and
            Wait(done, 0) == WAIT_TIMEOUT, stale)
    session.send('shutdown', 'controller.shutdown')
    summary = session.receive('summary')
    clean = summary['control']
    require(summary['exitCode'] == 0 and clean['clean'] and not clean['attached'] and
            clean['breakpoint']['state'] == 'retired' and clean['breakpoint']['enrolledThreads'] == '0', summary)
    require(session.process.wait(timeout=8) == 0 and Wait(done, 5000) == WAIT_OBJECT and not attached(child), summary)
    require(SetEvent(trigger) and Wait(done, 5000) == WAIT_OBJECT and Wait(child, 5000) == WAIT_OBJECT,
            'the detached target could not write or exit')
    code = win.DWORD()
    require(GetExitCode(child, ct.byref(code)) and code.value == 0, f'fixture exit: {code.value}')
    log.write(f'WATCH_WIDTH={width} OUTSIDE_RANGE=CONTINUED SAME_VALUE=CONTINUED FIRST_MASK=1 '
              f'NEW_THREAD_MASK={new_thread_mask} AFTER_STOP=1 CLI_EXIT=0 CHILD_EXIT=0\n')


def condition_regression(session, child, identity, trigger, done, armed, expression, truth, bounds, log):
    address = armed['breakpoint']['address']
    require(int(address, 16) > 0xffffffff, f'fixture needs a full-width RIP: {address}')
    lower, upper = bounds
    require(0 < lower <= int(identity[1]) <= upper, (identity, bounds))
    require(SetEvent(trigger), 'start the owned execution site')
    if truth == 'true':
        result = session.wait_for('held', identity)
        stop = result['stop']
        tid = result['hit']['tid']
        created = owned_thread_creation(identity[0], tid)
        require(int(identity[1]) <= created <= upper, (identity, tid, created, bounds))
        log.write(f'FROZEN_TID={tid} THREAD_CREATION_FILETIME={created} LOWER={lower} UPPER={upper}\n')
        require(Wait(done, 0) == WAIT_TIMEOUT, 'body ran before the matching stop was continued')
    else:
        require(Wait(done, 5000) == WAIT_OBJECT, 'body did not run after automatic continue')
        result = session.status()
        require('stop' not in result and result['stopGroup']['historical'] and
                result['stopGroup']['state'] == 'released', result)

    condition = result['condition']
    decision = condition['last']
    require(result['hit']['address'] == address and decision['groupId'] == result['stopGroup']['id'], result)
    require(condition['expression'] == expression and condition['phase'] == 'execution-enter-attempt' and
            condition['profile'] == 'predicate-expr-v2', condition)
    for name in ('true', 'false', 'unknown'):
        require(condition[name + 'Count'] == ('1' if name == truth else '0'), condition)
    require(decision['truth'] == truth and decision['evaluationFault'] is None, decision)
    if truth == 'true':
        require(decision['action'] == 'hold' and decision['release'] is None and
                decision['stateRevision'] == stop['stateRevision'], decision)
        released = session.request('continue/1', 'control.continue',
                                   dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
        require(released['release']['result'] == 'continued' and Wait(done, 5000) == WAIT_OBJECT, released)
    else:
        require(decision['action'] == 'auto-continue' and decision['release'] == 'continued', decision)

    session.send('shutdown', 'controller.shutdown')
    summary = session.receive('summary')
    closed = summary['control']
    require(summary['exitCode'] == 0 and closed['clean'] and not closed['attached'] and
            closed['breakpoint']['state'] == 'retired' and closed['condition'] == condition, summary)
    require(session.process.wait(timeout=8) == 0 and not attached(child), summary)
    for index in range(CONTINUES + 1):
        require(SetEvent(trigger) and Wait(done, 5000) == WAIT_OBJECT, f'detached execution {index + 1}')
    code = win.DWORD()
    require(Wait(child, 5000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code)) and code.value == 0,
            f'condition fixture did not exit normally: {code.value}')
    log.write(f'RIP={address} TRUTH={truth} CLI_EXIT=0 CHILD_EXIT=0\n')


def invalid_condition(log):
    expression = 'stop.thread.rip =='
    result = subprocess.run(
        [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(TARGET), '--export', 'ExportedTick',
         '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl', '--condition', expression],
        cwd=RELEASE, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=8,
    )
    log.write(f'INVALID_CONDITION_EXIT={result.returncode} STDERR={result.stderr}')
    require(result.returncode == 1 and not result.stdout and
            'expression-expected-literal at UTF-8 byte 18 (length 0, line 1, byte column 19)' in result.stderr,
            result)


def regression(log, watch_width, truth=None):
    prefix = r'Local\KSwordProductBreakpoint-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_BREAKPOINT_EVENTS=prefix)
    env['KSWORD_PRODUCT_BREAKPOINT_WRITE_WATCH'] = '1' if watch_width else '0'
    env['KSWORD_PRODUCT_BREAKPOINT_WATCH_WIDTH'] = str(watch_width)
    events = []
    session = child = None
    try:
        for suffix in ('ready', 'trigger', 'done'):
            handle = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(handle, f'CreateEvent failed: {ct.get_last_error()}')
            events.append(handle)
        ready, trigger, done = events
        expression = None
        if truth is not None:
            before = win.FILETIME()
            GetSystemTimeAsFileTime(ct.byref(before))
            lower = (before.dwHighDateTime << 32) | before.dwLowDateTime
            upper = lower + 60 * 10_000_000  # FILETIME counts 100 ns ticks.
            rip = 'stop.thread.rip > 0xffffffffu64'
            timestamp = 'stop.thread.creationFileTime'
            expression = {
                'true': f'{rip} && {timestamp} >= {lower}u64 && {timestamp} <= {upper}u64',
                'false': f'{rip} && {timestamp} < {lower}u64',
                'unknown': f'{rip} && stop.thread.rax == 0u64',
            }[truth]
        session = Session(env, log, watch_width, expression)
        hello = session.receive('hello')
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        protocol = hello['continueProtocol']
        require(protocol['firstRequestId'] == 'continue/1' and int(protocol['replayEntries']) == 128, protocol)
        require(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_for('armed', identity)
        require(armed['attached'] and attached(child), armed)
        if watch_width:
            require(armed['breakpoint']['watchedBytes'] == watch_width, armed)
            write_watch_regression(session, child, identity, trigger, done, watch_width, log)
            return
        if truth is not None:
            condition_regression(session, child, identity, trigger, done, armed, expression, truth, (lower, upper), log)
            return
        address = armed['breakpoint']['address']
        stops = set()
        groups = set()
        first = first_receipt = None
        for index in range(1, CONTINUES + 2):
            require(SetEvent(trigger), f'trigger {index}')
            held = session.wait_for('held', identity)
            stop = held['stop']
            group = held['stopGroup']  # 当前事件的冻结组应与可继续令牌属于同一修订。
            require(group['id'] == stop['groupId'] and group['stateRevision'] == stop['stateRevision']
                    and group['state'] == 'held-complete' and group['heldMembers'] != '0'
                    and group['heldMembers'] == group['requestedMembers'] == stop['memberCount'], group)
            require(held['attached'] and held['hit']['address'] == address, held)
            require(stop['id'] not in stops and stop['groupId'] not in groups, stop)
            stops.add(stop['id'])
            groups.add(stop['groupId'])
            require(Wait(done, 0) == WAIT_TIMEOUT, f'body ran before release {index}')
            expected = dict(stopId=stop['id'], stateRevision=stop['stateRevision'])
            if index == 2:
                replay = session.request('continue/1', 'control.continue', first)
                require(replay == first_receipt and session.status()['stop'] == stop, replay)
                require(Wait(done, 25) == WAIT_TIMEOUT, 'retained replay released a later stop')
            if index == CONTINUES + 1:
                for payload in (first, expected):
                    expired = session.request('continue/1', 'control.continue', payload, kind='error')
                    require(expired['errorId'] == 'release-replay-expired' and session.status()['stop'] == stop, expired)
                    require(Wait(done, 25) == WAIT_TIMEOUT, 'expired replay released a later stop')
                break
            receipt = session.request(f'continue/{index}', 'control.continue', expected)
            require(receipt['release']['result'] == 'continued' and receipt['attached'] and
                     receipt['breakpoint']['state'] == 'armed', receipt)
            require('stop' not in receipt and receipt['stopGroup']['id'] == group['id']
                    and receipt['stopGroup']['historical'] and receipt['stopGroup']['state'] == 'released', receipt)
            require(Wait(done, 5000) == WAIT_OBJECT, f'body did not execute after continue {index}')
            if index == 1:
                first, first_receipt = expected, receipt

        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        closed = summary['control']
        require(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['clean'] and
                not closed['attached'] and closed['breakpoint']['state'] == 'retired' and
                closed['breakpoint']['enrolledThreads'] == '0' and closed['release']['result'] == 'continued', summary)
        require(session.process.wait(timeout=8) == 0, 'formal CLI exit code')
        require(Wait(done, 5000) == WAIT_OBJECT and not attached(child), 'shutdown did not release and detach')
        require(SetEvent(trigger) and Wait(done, 5000) == WAIT_OBJECT, 'detached target could not execute the site')
        require(Wait(child, 5000) == WAIT_OBJECT, 'cooperating target did not exit')
        code = win.DWORD()
        require(GetExitCode(child, ct.byref(code)) and code.value == 0, f'fixture exit: {code.value}')
        log.write(f'CONTINUES={CONTINUES} UNIQUE_HELD_STOPS={len(stops)} CLI_EXIT=0 CHILD_EXIT=0\n')
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
            for handle in events:
                CloseHandle(handle)


def pair_members(report, identities):
    members = report['members']
    require(report['mode'] == 'cooperative-pair' and report['frozen'] and
            [(member['pid'], member['creationFileTime']) for member in members] == identities, report)
    return members


def wait_pair(session, state, identities, *, require_exits=False):
    """逐轮核对固定成员身份，直到观察到预期组状态。"""
    deadline = time.monotonic() + 5
    while True:
        report = session.status()
        members = pair_members(report, identities)
        if report['state'] == state and (not require_exits or
                (report['clean'] and all(member['exitCode'] is not None for member in members))):
            return report
        pending = ('starting', 'running', 'held-partial', 'closing', 'ended') if require_exits else (
            'starting', 'running', 'held-partial')
        require(report['state'] in pending and time.monotonic() < deadline, report)
        time.sleep(0.01)


@contextmanager
def armed_pair(log, condition=None, spawn_member=None):
    """拉起双目标合作会话；可选条件表达式随会话启动时交给正式 CLI。"""
    prefix = r'Local\KSwordProductPair-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_BREAKPOINT_PAIR_EVENTS=prefix)
    events = []  # 保存本轮创建的所有事件，失败也会释放。
    children = []  # 只保存通过固定映像和创建时间核验的自有目标。
    session = None

    def create_event(name, manual=False):
        handle = CreateEvent(None, manual, False, f'{prefix}-{name}')
        require(handle, f'CreateEvent failed for {name}: {ct.get_last_error()}')
        events.append(handle)
        return handle

    try:
        configured = create_event('configured', manual=True)
        session = Session(env, log, 0, condition=condition, cooperative_pair=True)
        hello = session.receive('hello')
        control = hello['control']
        members = control['members']
        require(control['mode'] == 'cooperative-pair' and control['frozen'] and
                control['state'] == 'starting' and not control['clean'] and
                len(members) == 2 and all(member['ready'] and not member['gateOpened'] for member in members), hello)
        identities = [(member['pid'], member['creationFileTime']) for member in members]
        require(len({pid for pid, _ in identities}) == 2, identities)
        triggers, completions = [], []
        for index, (pid, creation_time) in enumerate(identities):
            children.append(checked_target(dict(targetPid=pid, targetCreationFileTime=creation_time)))
            triggers.append(create_event(f'{pid}-trigger'))
            completions.append(create_event(f'{pid}-done'))
            if spawn_member is not None and index == spawn_member:
                # 仅测试模式：本成员存在 spawn 事件时由新建线程执行命中点。
                create_event(f'{pid}-spawn')
        require(SetEvent(configured), 'allow both cooperative workloads to initialize')

        armed = wait_pair(session, 'running', identities)
        require(all(member['gateOpened'] and member['control']['breakpoint']['state'] == 'armed'
                     for member in armed['members']) and all(attached(child) for child in children), armed)
        require('endReason' not in armed and all(member['exitCode'] is None and
                'retirement' not in member['control'] and 'firstRecoveryFailure' not in member['control']
                for member in armed['members']), armed)
        yield session, identities, children, triggers, completions
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            for child in children:
                try:
                    if Wait(child, 0) == WAIT_TIMEOUT:
                        TerminateProcess(child, 3)  # 仅在测试失败后清理已核验的固定夹具。
                        Wait(child, 5000)
                finally:
                    CloseHandle(child)
            for handle in events:
                CloseHandle(handle)


def check_pair_retirement(member, kind):
    control = member['control']
    retirement = control['retirement']
    backend = retirement['backendInstanceId']
    require(not member['held'] and control['clean'] and not control['attached'] and
            'firstRecoveryFailure' not in control and retirement['kind'] == kind and UUID(backend).int != 0, member)
    if kind == 'detached':
        require(retirement['exitEvent'] is None and retirement['exitCode'] is None, member)
    else:
        event = retirement['exitEvent']
        serial = event['serial']
        require(event['backendInstanceId'] == backend and isinstance(serial, str) and
                0 < int(serial) <= (1 << 64) - 1 and serial == str(int(serial)) and
                type(retirement['exitCode']) is int and retirement['exitCode'] == member['exitCode'], member)
    return backend


def checked_exit_code(child):
    code = win.DWORD()
    require(Wait(child, 5000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code)),
            f'cooperative child exit not readable: {ct.get_last_error()}')
    return code.value


def cooperative_pair_regression(log):
    """用两个独立业务信号，验证部分持有、精确释放、旧令牌和清退。"""
    with armed_pair(log) as (session, identities, children, triggers, completions):
        require(SetEvent(triggers[0]), 'trigger the first, still independent owner')
        partial = wait_pair(session, 'held-partial', identities)
        require([member['held'] for member in partial['members']] == [True, False] and 'stop' not in partial and
                'release' not in partial and all(Wait(done, 0) == WAIT_TIMEOUT for done in completions), partial)
        log.write('PAIR_PARTIAL=PASS HELD_MEMBERS=1 GROUP_TOKEN=absent\n')

        require(SetEvent(triggers[1]), 'trigger the second independent owner')
        held = wait_pair(session, 'held-complete', identities)
        stop = held['stop']
        native_groups = [member['control']['stopGroup']['id'] for member in held['members']]
        require(all(member['held'] and member['control']['stopGroup']['state'] == 'held-complete' for member in held['members'])
                and len(set(native_groups)) == 2 and all(Wait(done, 0) == WAIT_TIMEOUT for done in completions), held)
        expected = dict(stopId=stop['id'], stateRevision=stop['stateRevision'])
        released = session.request('continue/1', 'control.continue', expected)
        receipt = released['release']
        require(receipt['continued'] and receipt['stopId'] == stop['id'] and
                receipt['stateRevision'] == stop['stateRevision'] and len(receipt['members']) == 2, released)
        for member, group, (pid, creation_time) in zip(receipt['members'], native_groups, identities, strict=True):
            require(member['pid'] == pid and member['creationFileTime'] == creation_time and
                    member['release']['result'] == 'continued' and member['stopGroup']['id'] == group and
                    member['stopGroup']['historical'] and member['stopGroup']['state'] == 'released', member)
        require(all(Wait(done, 5000) == WAIT_OBJECT for done in completions), 'both released targets must execute')
        log.write('PAIR_CONTINUE=PASS NATIVE_RECEIPTS=2\n')

        require(all(SetEvent(trigger) for trigger in triggers), 'trigger the next pair of real stops')
        second = wait_pair(session, 'held-complete', identities)
        require(second['stop']['id'] != stop['id'] and
                int(second['stop']['stateRevision']) > int(stop['stateRevision']), second)
        require(session.request('continue/1', 'control.continue', expected) == released, 'exact replay changed its receipt')
        stale = session.request('continue/2', 'control.continue', expected, kind='error')
        require(stale['errorId'] == 'stale-stop' and session.status()['stop'] == second['stop'] and
                all(Wait(done, 25) == WAIT_TIMEOUT for done in completions), stale)
        log.write('PAIR_REPLAY=PASS STALE_STOP=REJECTED HELD_MEMBERS=2\n')

        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        closed = summary['control']
        require(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['state'] == 'closed' and
                closed['endReason'] == 'requested' and closed['outcomeMember'] is None and
                closed['clean'] and 'stop' not in closed and closed['release'] == receipt, summary)
        backends = set()
        for member in pair_members(closed, identities):
            native = member['control']
            backends.add(check_pair_retirement(member, 'detached'))
            require(member['exitCode'] is None and native['breakpoint']['state'] == 'retired' and
                    native['breakpoint']['enrolledThreads'] == '0' and native['release']['result'] == 'continued', member)
        require(len(backends) == 2 and session.process.wait(timeout=8) == 0 and
                all(Wait(child, 0) == WAIT_TIMEOUT and not attached(child) for child in children), summary)
        require(all(Wait(done, 5000) == WAIT_OBJECT for done in completions), 'shutdown must release both held targets')
        require(all(SetEvent(trigger) for trigger in triggers) and
                all(Wait(done, 5000) == WAIT_OBJECT for done in completions), 'both detached targets must execute again')
        require([checked_exit_code(child) for child in children] == [0, 0], 'detached children must exit normally')
        log.write(f'PAIR_CLOSE=PASS END_REASON=requested RETIREMENTS=detached,detached '
                  f'EXIT_CODES_AT_CLOSE=null,null CLI_EXIT=0 CHILD_EXITS=0,0 PIDS={identities[0][0]},{identities[1][0]}\n')


def cooperative_pair_exit_regression(log):
    with armed_pair(log) as (session, identities, children, triggers, completions):
        # The same fixture returns from main after its third tick. Keep the CLI open to observe that exit.
        for index in range(1, 4):
            require(all(SetEvent(trigger) for trigger in triggers), f'trigger natural-exit round {index}')
            stop = wait_pair(session, 'held-complete', identities)['stop']
            released = session.request(f'continue/{index}', 'control.continue',
                                       dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
            receipt = released['release']
            require(receipt['continued'] and receipt['stopId'] == stop['id'] and
                    receipt['stateRevision'] == stop['stateRevision'], released)
            require(all(Wait(done, 5000) == WAIT_OBJECT for done in completions), f'execute natural-exit round {index}')

        ended = wait_pair(session, 'ended', identities, require_exits=True)
        origin = ended['outcomeMember']
        require(ended['endReason'] == 'member-ended' and ended['win32Error'] == 0 and
                type(origin) is int and origin in (0, 1) and 'stop' not in ended and ended['release'] == receipt, ended)
        members = pair_members(ended, identities)
        backends, kinds = [], []
        for index, (member, child) in enumerate(zip(members, children, strict=True)):
            kind = member['control']['retirement']['kind']
            # The peer may already have its own exit event or may be detached first during group cleanup.
            require(kind == 'exit-event-continued' or (index != origin and kind == 'detached'), member)
            require(type(member['exitCode']) is int and member['exitCode'] == checked_exit_code(child) == 0, member)
            backends.append(check_pair_retirement(member, kind))
            kinds.append(kind)
        require(len(set(backends)) == 2, ended)
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        require(summary['reason'] == 'requested' and summary['exitCode'] == 0 and
                summary['control'] == ended and session.process.wait(timeout=8) == 0, summary)
        log.write(f'PAIR_NATURAL_EXIT=PASS END_REASON=member-ended OUTCOME_MEMBER={origin} '
                  f'RETIREMENTS={",".join(kinds)} CLI_EXIT=0 CHILD_EXITS=0,0 PIDS={identities[0][0]},{identities[1][0]}\n')


PAIR_CONDITION_TRUTHS = ('true', 'false', 'unknown')


def pair_condition_expression(truth, lower, upper):
    """与单目标条件同一组字段；假条件落在本次会话之前的线程创建时间之前。"""
    rip = 'stop.thread.rip > 0xffffffffu64'
    created = 'stop.thread.creationFileTime'
    return {
        'true': f'{rip} && {created} >= {lower}u64 && {created} <= {upper}u64',
        'false': f'{rip} && {created} < {lower}u64',
        'unknown': f'{rip} && stop.thread.rax == 0u64',
    }[truth]


def wait_pair_condition(session, identities, action, timeout=10):
    """等待完整组的条件判定；真条件保持持有，假/未知条件已自动继续。"""
    deadline = time.monotonic() + timeout
    while True:
        report = session.status()
        pair_members(report, identities)
        last = (report.get('condition') or {}).get('last')
        if isinstance(last, dict) and last.get('action') == action:
            return report, last
        require(time.monotonic() < deadline, f'pair condition never reached {action}: {report}')
        time.sleep(0.01)


def pair_condition_members(report, identities, truth):
    """核对完整组逐成员的三值判定、身份和各自的原生组。"""
    members = report['condition']['last']['members']
    require(len(members) == 2 and
            [(member['pid'], member['creationFileTime']) for member in members] == identities and
            all(member['truth'] == truth and member['evaluationFault'] is None for member in members) and
            len({member['groupId'] for member in members}) == 2 and
            all(int(member['eventSerial']) > 0 and int(member['stateRevision']) > 0 for member in members), report)
    return members


def check_pair_condition_members(report, members, identities, lower, upper, held):
    """核对逐成员判定与真实原生身份；持有态再核对命中线程的创建时间。"""
    for decision, member, (pid, _) in zip(members, report['members'], identities, strict=True):
        control = member['control']
        require(decision['pid'] == pid and decision['groupId'] == control['stopGroup']['id'], decision)
        require(int(control['breakpoint']['address'], 16) > 0xffffffff, control)
        if not held:
            # 自动继续后原生待决事件已归还，只核对两份真实释放回执。
            require(not member['held'] and control['state'] == 'released' and
                    control['release']['result'] == 'continued', member)
            continue
        hit = control['hit']
        require(member['held'] and int(hit['address'], 16) > 0xffffffff and hit['tid'], member)
        created = owned_thread_creation(pid, hit['tid'])
        require(lower <= created <= upper, (pid, hit['tid'], created, lower, upper))


def close_pair_condition(session, identities, children, triggers, completions, log, note):
    """关闭双目标：两份脱离，自有目标跑完剩余两轮并正常退出。"""
    session.send('shutdown', 'controller.shutdown')
    summary = session.receive('summary')
    closed = summary['control']
    require(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['state'] == 'closed' and
            closed['endReason'] == 'requested' and closed['outcomeMember'] is None and
            closed['clean'] and 'stop' not in closed and closed['release']['continued'], summary)
    backends = set()
    for member in pair_members(closed, identities):
        native = member['control']
        backends.add(check_pair_retirement(member, 'detached'))
        require(member['exitCode'] is None and native['breakpoint']['state'] == 'retired' and
                native['breakpoint']['enrolledThreads'] == '0' and
                native['release']['result'] == 'continued', member)
    require(len(backends) == 2 and session.process.wait(timeout=8) == 0 and
            all(Wait(child, 0) == WAIT_TIMEOUT and not attached(child) for child in children), summary)
    # 脱离后的自有目标仍能执行剩余两轮并正常退出。
    for index in range(2):
        require(all(SetEvent(trigger) for trigger in triggers) and
                all(Wait(done, 5000) == WAIT_OBJECT for done in completions), f'detached round {index + 1}')
    require([checked_exit_code(child) for child in children] == [0, 0], 'detached members must exit normally')
    log.write(f'{note} PAIR_CLOSE=PASS END_REASON=requested RETIREMENTS=detached,detached '
              f'CLI_EXIT=0 CHILD_EXITS=0,0 PIDS={identities[0][0]},{identities[1][0]}\n')


def pair_condition_regression(log, truth):
    """双目标条件：部分持有不求值；完整组逐成员求值，真条件保持，假/未知自动继续。"""
    before = win.FILETIME()
    GetSystemTimeAsFileTime(ct.byref(before))
    lower = (before.dwHighDateTime << 32) | before.dwLowDateTime
    upper = lower + 60 * 10_000_000  # FILETIME counts 100 ns ticks.
    expression = pair_condition_expression(truth, lower, upper)
    with armed_pair(log, expression) as (session, identities, children, triggers, completions):
        # 部分持有：不求值、不发布组令牌、不释放任何成员。
        require(SetEvent(triggers[0]), 'trigger only the first owner')
        partial = wait_pair(session, 'held-partial', identities)
        condition = partial['condition']
        require([member['held'] for member in partial['members']] == [True, False] and
                'stop' not in partial and 'release' not in partial and condition['last'] is None and
                condition['trueCount'] == '0' and condition['falseCount'] == '0' and
                condition['unknownCount'] == '0' and
                all(Wait(done, 0) == WAIT_TIMEOUT for done in completions), partial)
        log.write('PAIR_CONDITION_PARTIAL=PASS EVALUATIONS=0 GROUP_TOKEN=absent\n')

        # 完整组：同一表达式逐成员求值，任一为真保持整组。
        require(SetEvent(triggers[1]), 'trigger the second owner')
        action = 'hold' if truth == 'true' else 'auto-continue'
        report, last = wait_pair_condition(session, identities, action)
        condition = report['condition']
        expected = {'true': '0', 'false': '0', 'unknown': '0'}
        expected[truth] = '2'
        require(condition['profile'] == 'predicate-expr-v2' and condition['phase'] == 'execution-enter-attempt' and
                condition['aggregation'] == 'any-true-holds-group' and condition['expression'] == expression and
                condition['trueCount'] == expected['true'] and condition['falseCount'] == expected['false'] and
                condition['unknownCount'] == expected['unknown'] and
                last['stopId'] and int(last['stateRevision']) > 0, condition)
        members = pair_condition_members(report, identities, truth)
        check_pair_condition_members(report, members, identities, lower, upper, truth == 'true')

        token = dict(stopId=last['stopId'], stateRevision=last['stateRevision'])
        if truth == 'true':
            require(report['state'] == 'held-complete' and 'stop' in report and
                    report['stop']['id'] == last['stopId'] and
                    report['stop']['stateRevision'] == last['stateRevision'] and
                    last['continued'] is False, report)
            # 重复查询不改变计数，也不重新发布判定。
            for _ in range(3):
                again = session.status()
                pair_members(again, identities)
                require(again['condition']['trueCount'] == '2' and again['condition']['falseCount'] == '0' and
                        again['condition']['unknownCount'] == '0' and again['condition']['last'] == last, again)
            released = session.request('continue/1', 'control.continue', token)
            receipt = released['release']
            require(receipt['continued'] and receipt['stopId'] == last['stopId'] and
                    receipt['stateRevision'] == last['stateRevision'] and len(receipt['members']) == 2, released)
            require(all(Wait(done, 5000) == WAIT_OBJECT for done in completions), 'both released members must execute')
            after = session.status()
            require('stop' not in after and after['release']['continued'] and
                    after['condition']['trueCount'] == '2', after)
            # 旧组令牌：序号仍然合法，但令牌已过期。
            stale = session.request('continue/2', 'control.continue', token, kind='error')
            require(stale['errorId'] == 'stale-stop', stale)
            log.write('PAIR_CONDITION_HOLD=PASS TRUE_COUNT=2 REPEAT_QUERY=unchanged '
                      'CONTINUE=continued STALE_STOP=rejected\n')
        else:
            require('stop' not in report and last['continued'] is True, report)
            require(all(Wait(done, 5000) == WAIT_OBJECT for done in completions),
                    'auto-continued members must execute without a client request')
            # 自动继续后客户端 continue/1 仍合法：旧组令牌报 stale-stop 而不是序号错误。
            stale = session.request('continue/1', 'control.continue', token, kind='error')
            require(stale['errorId'] == 'stale-stop', stale)
            after = session.status()
            require('stop' not in after and after['release']['continued'] and
                    after['condition'][truth + 'Count'] == '2', after)
            log.write(f'PAIR_CONDITION_AUTO_CONTINUE=PASS TRUTH={truth} '
                      f'{truth.upper()}_COUNT=2 CLIENT_CONTINUE=stale-stop\n')

        close_pair_condition(session, identities, children, triggers, completions, log,
                             f'PAIR_CONDITION_TRUTH={truth}')


MIXED_THRESHOLD_TICKS = 10 * 10_000_000  # 阈值在会话启动前冻结，给双目标启动与武装留出余量。
MIXED_AFTER_MARGIN_TICKS = 2 * 10_000_000  # 第二成员的命中线程必须在阈值之后创建。
ONE_SECOND_TICKS = 10_000_000  # 进程创建时间与初始线程创建时间的比较窗口。


def mixed_pair_expression(threshold):
    """第一成员命中主线程（创建早于阈值），第二成员命中阈值之后新建的线程。"""
    return f'stop.thread.rip > 0xffffffffu64 && stop.thread.creationFileTime < {threshold}u64'


def system_file_time():
    """读取当前系统 FILETIME，与内核记录的线程创建时间同一时钟。"""
    now = win.FILETIME()
    GetSystemTimeAsFileTime(ct.byref(now))
    return (now.dwHighDateTime << 32) | now.dwLowDateTime


def wait_past(threshold, margin):
    """等待系统时间越过阈值加余量，保证后建线程一定落在阈值之后。"""
    limit = threshold + margin
    while system_file_time() < limit:
        time.sleep(0.05)
    return system_file_time()


def pair_condition_mixed_regression(log):
    """同一冻结组内一真一假：任一成员为真即保持整组，显式继续后两成员都释放。"""
    startup = system_file_time()
    threshold = startup + MIXED_THRESHOLD_TICKS  # 启动前冻结的线程创建 FILETIME 阈值。
    expression = mixed_pair_expression(threshold)
    # 第二成员由新建线程执行命中点，第一成员仍由主线程命中。
    with armed_pair(log, expression, spawn_member=1) as (session, identities, children, triggers, completions):
        # 第一成员：主线程命中，创建时间早于阈值，该成员必须判真。
        require(SetEvent(triggers[0]), 'trigger the main-thread owner')
        partial = wait_pair(session, 'held-partial', identities)
        condition = partial['condition']
        require([member['held'] for member in partial['members']] == [True, False] and
                'stop' not in partial and 'release' not in partial and condition['last'] is None and
                condition['trueCount'] == '0' and condition['falseCount'] == '0' and
                condition['unknownCount'] == '0' and
                all(Wait(done, 0) == WAIT_TIMEOUT for done in completions), partial)
        old_hit = partial['members'][0]['control']['hit']
        old_created = owned_thread_creation(identities[0][0], old_hit['tid'])
        # 首成员命中进程初始线程：创建时间与进程创建时间同量级，且早于阈值。
        require(old_created < threshold and old_created >= startup and
                abs(old_created - int(identities[0][1])) < ONE_SECOND_TICKS,
                (old_hit, old_created, identities[0][1], startup, threshold))
        log.write(f'PAIR_MIXED_PARTIAL=PASS MAIN_THREAD_TID={old_hit["tid"]} '
                  f'MAIN_THREAD_CREATED={old_created} PROCESS_CREATED={identities[0][1]} '
                  f'STARTUP={startup} THRESHOLD={threshold} EVALUATIONS=0 GROUP_TOKEN=absent\n')

        # 第二成员：命中线程在阈值之后创建，该成员必须判假，整组仍因第一成员为真而保持。
        require(wait_past(threshold, MIXED_AFTER_MARGIN_TICKS) >= threshold + MIXED_AFTER_MARGIN_TICKS,
                'the mixed threshold was not reached')
        require(SetEvent(triggers[1]), 'trigger the new-thread owner')
        report, last = wait_pair_condition(session, identities, 'hold')
        condition = report['condition']
        require(condition['profile'] == 'predicate-expr-v2' and
                condition['aggregation'] == 'any-true-holds-group' and
                condition['expression'] == expression and condition['phase'] == 'execution-enter-attempt' and
                condition['trueCount'] == '1' and condition['falseCount'] == '1' and
                condition['unknownCount'] == '0' and last['action'] == 'hold' and
                last['continued'] is False and last['stopId'] and int(last['stateRevision']) > 0, condition)
        decisions = last['members']
        require(len(decisions) == 2 and
                [(item['pid'], item['creationFileTime']) for item in decisions] == identities and
                [item['truth'] for item in decisions] == ['true', 'false'] and
                all(item['evaluationFault'] is None and int(item['eventSerial']) > 0 and
                    int(item['stateRevision']) > 0 for item in decisions), report)
        # 完整组仍然双持有：真成员与假成员都停在原生事件上，组令牌同时发布。
        require(report['state'] == 'held-complete' and 'stop' in report and
                report['stop']['id'] == last['stopId'] and
                report['stop']['stateRevision'] == last['stateRevision'] and
                all(member['held'] for member in report['members']) and
                all(member['control']['stopGroup']['state'] == 'held-complete' for member in report['members']) and
                all(Wait(done, 0) == WAIT_TIMEOUT for done in completions), report)
        # 独立核对两个命中线程的真实身份：主线程早于阈值，新线程晚于阈值。
        new_hit = report['members'][1]['control']['hit']
        new_created = owned_thread_creation(identities[1][0], new_hit['tid'])
        require(new_created > threshold and
                new_created - int(identities[1][1]) > ONE_SECOND_TICKS,
                (new_hit, new_created, identities[1][1], threshold))
        log.write(f'PAIR_MIXED_GROUP=PASS TRUE_COUNT=1 FALSE_COUNT=1 NEW_THREAD_TID={new_hit["tid"]} '
                  f'NEW_THREAD_CREATED={new_created} HELD_MEMBERS=2\n')

        # 重复查询不重复计数，也不重新发布判定。
        for _ in range(3):
            again = session.status()
            pair_members(again, identities)
            require(again['condition']['trueCount'] == '1' and again['condition']['falseCount'] == '1' and
                    again['condition']['unknownCount'] == '0' and again['condition']['last'] == last, again)

        token = dict(stopId=last['stopId'], stateRevision=last['stateRevision'])
        released = session.request('continue/1', 'control.continue', token)
        receipt = released['release']
        require(receipt['continued'] and receipt['stopId'] == last['stopId'] and
                receipt['stateRevision'] == last['stateRevision'] and len(receipt['members']) == 2, released)
        require(all(Wait(done, 5000) == WAIT_OBJECT for done in completions), 'both released members must execute')
        after = session.status()
        require('stop' not in after and after['release']['continued'] and
                after['condition']['trueCount'] == '1' and after['condition']['falseCount'] == '1', after)
        # 旧组令牌：序号仍然合法，但令牌已过期。
        stale = session.request('continue/2', 'control.continue', token, kind='error')
        require(stale['errorId'] == 'stale-stop', stale)
        log.write('PAIR_MIXED_HOLD=PASS REPEAT_QUERY=unchanged CONTINUE=continued '
                  'RELEASED_MEMBERS=2 STALE_STOP=rejected\n')

        close_pair_condition(session, identities, children, triggers, completions, log,
                             'PAIR_MIXED_TRUTH=true,false')


def main():
    options = argparse.ArgumentParser()
    mode = options.add_mutually_exclusive_group()
    mode.add_argument('--write-watch', action='store_true')
    mode.add_argument('--condition-registers', action='store_true')
    mode.add_argument('--cooperative-pair', action='store_true')
    mode.add_argument('--pair-condition', action='store_true')
    mode.add_argument('--pair-condition-mixed', action='store_true')
    options.add_argument('--expected-cli-sha256', help='Require this Release CLI SHA-256 before any fixture starts')
    args = options.parse_args()
    expected_digest = args.expected_cli_sha256.lower() if args.expected_cli_sha256 is not None else None
    if expected_digest is not None and (len(expected_digest) != 64 or not set(expected_digest) <= set('0123456789abcdef')):
        options.error('--expected-cli-sha256 must be a 64-digit hexadecimal digest')
    require(CLI.is_file(), f'Build the official CLI first: {CLI}')
    digest = fingerprint(CLI)
    require(expected_digest is None or digest == expected_digest, f'Release CLI SHA-256 mismatch: expected {expected_digest}, got {digest}')
    logs = REPO / '.codex-build-logs' / 'behavior-planning'
    logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    evidence = logs / f'action-analyze-product-breakpoint-long-{stamp}-{os.getpid()}.log'
    print(f'EVIDENCE={evidence}', flush=True)
    try:
        with evidence.open('x', encoding='utf-8', buffering=1) as log:
            if args.cooperative_pair:
                log.write('【子代理｜第6项调试恢复】\n')
            if args.pair_condition:
                log.write('【子代理｜第10项双目标条件】\n')
            if args.pair_condition_mixed:
                log.write('【子代理｜第10项双目标条件混合真假】\n')
            log.write(f'FORMAL_CLI_SHA256={digest}\n')
            with installed_fixture(log):
                if args.pair_condition_mixed:
                    pair_condition_mixed_regression(log)
                elif args.pair_condition:
                    for truth in PAIR_CONDITION_TRUTHS:
                        pair_condition_regression(log, truth)
                elif args.cooperative_pair:
                    cooperative_pair_regression(log)
                    cooperative_pair_exit_regression(log)
                elif args.condition_registers:
                    invalid_condition(log)
                    for truth in ('true', 'false', 'unknown'):
                        regression(log, 0, truth)
                else:
                    for width in (1, 2, 4, 8) if args.write_watch else (0,):
                        regression(log, width)
    finally:
        require(fingerprint(CLI) == digest, 'formal CLI digest changed during validation')
    if args.pair_condition_mixed:
        result = 'PAIR_CONDITION_MIXED=PASS TRUTHS=true,false AGGREGATION=any-true-holds-group'
    elif args.pair_condition:
        result = 'PAIR_CONDITION=PASS TRUTHS=true,false,unknown'
    elif args.cooperative_pair:
        result = 'COOPERATIVE_PAIR=PASS'
    elif args.condition_registers:
        result = 'CONDITION_REGISTERS=PASS'
    elif args.write_watch:
        result = 'DATA_WRITE_WATCH=PASS WIDTHS=1,2,4,8'
    else:
        result = f'PRODUCT_RESULT=PASS CONTINUES={CONTINUES}'
    print(f'{result} CLI_SHA256={digest} FIXTURE_CLEANED=true')


if __name__ == '__main__':
    main()
