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
from uuid import uuid4


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


def wait_pair(session, state, identities):
    """逐轮核对固定成员身份，直到观察到预期组状态。"""
    deadline = time.monotonic() + 5
    while True:
        report = session.status()
        members = report['members']
        require(report['mode'] == 'cooperative-pair' and report['frozen'] and
                [(member['pid'], member['creationFileTime']) for member in members] == identities, report)
        if report['state'] == state:
            return report
        require(report['state'] in ('starting', 'running', 'held-partial') and time.monotonic() < deadline, report)
        time.sleep(0.01)


def cooperative_pair_regression(log):
    """用两个独立业务信号，验证部分持有、精确释放、旧令牌和清退。"""
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
        session = Session(env, log, 0, cooperative_pair=True)
        hello = session.receive('hello')
        control = hello['control']
        members = control['members']
        require(control['mode'] == 'cooperative-pair' and control['frozen'] and
                control['state'] == 'starting' and not control['clean'] and
                len(members) == 2 and all(member['ready'] and not member['gateOpened'] for member in members), hello)
        identities = [(member['pid'], member['creationFileTime']) for member in members]
        require(len({pid for pid, _ in identities}) == 2, identities)
        triggers, completions = [], []
        for pid, creation_time in identities:
            children.append(checked_target(dict(targetPid=pid, targetCreationFileTime=creation_time)))
            triggers.append(create_event(f'{pid}-trigger'))
            completions.append(create_event(f'{pid}-done'))
        require(SetEvent(configured), 'allow both cooperative workloads to initialize')

        armed = wait_pair(session, 'running', identities)
        require(all(member['gateOpened'] and member['control']['breakpoint']['state'] == 'armed'
                    for member in armed['members']) and all(attached(child) for child in children), armed)
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
                closed['clean'] and 'stop' not in closed and closed['release'] == receipt, summary)
        for member in closed['members']:
            native = member['control']
            require(not member['held'] and native['clean'] and not native['attached'] and
                    native['breakpoint']['state'] == 'retired' and native['breakpoint']['enrolledThreads'] == '0' and
                    native['release']['result'] == 'continued', member)
        require(session.process.wait(timeout=8) == 0 and all(not attached(child) for child in children), summary)
        require(all(Wait(done, 5000) == WAIT_OBJECT for done in completions), 'shutdown must release both held targets')
        require(all(SetEvent(trigger) for trigger in triggers) and
                all(Wait(done, 5000) == WAIT_OBJECT for done in completions), 'both detached targets must execute again')
        for child in children:
            code = win.DWORD()
            require(Wait(child, 5000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code)) and code.value == 0,
                    f'cooperative child exit code: {code.value}')
        log.write(f'PAIR_CLOSE=PASS CLI_EXIT=0 CHILD_EXITS=0,0 PIDS={identities[0][0]},{identities[1][0]}\n')
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


def main():
    options = argparse.ArgumentParser()
    mode = options.add_mutually_exclusive_group()
    mode.add_argument('--write-watch', action='store_true')
    mode.add_argument('--condition-registers', action='store_true')
    mode.add_argument('--cooperative-pair', action='store_true')
    args = options.parse_args()
    require(CLI.is_file(), f'Build the official CLI first: {CLI}')
    digest = fingerprint(CLI)
    logs = REPO / '.codex-build-logs' / 'behavior-planning'
    logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    evidence = logs / f'action-analyze-product-breakpoint-long-{stamp}-{os.getpid()}.log'
    print(f'EVIDENCE={evidence}', flush=True)
    try:
        with evidence.open('x', encoding='utf-8', buffering=1) as log:
            if args.cooperative_pair:
                log.write('【子代理｜第6项调试恢复】\n')
            log.write(f'FORMAL_CLI_SHA256={digest}\n')
            with installed_fixture(log):
                if args.cooperative_pair:
                    cooperative_pair_regression(log)
                elif args.condition_registers:
                    invalid_condition(log)
                    for truth in ('true', 'false', 'unknown'):
                        regression(log, 0, truth)
                else:
                    for width in (1, 2, 4, 8) if args.write_watch else (0,):
                        regression(log, width)
    finally:
        require(fingerprint(CLI) == digest, 'formal CLI digest changed during validation')
    if args.cooperative_pair:
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
