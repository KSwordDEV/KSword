"""Validate long-running JSONL breakpoints against the built AMD64 Release CLI."""

import ctypes as ct
from ctypes import wintypes as win
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
CloseHandle = api('CloseHandle', win.BOOL, win.HANDLE)
SetEvent = api('SetEvent', win.BOOL, win.HANDLE)
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
GetProcessTimes = api('GetProcessTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
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


class Session:
    def __init__(self, env, log):
        self.log = log
        self.lines = queue.Queue()
        self.session = None
        self.sequence = 0
        self.query_sequence = 0
        self.process = subprocess.Popen(
            [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(TARGET), '--export', 'ExportedTick',
             '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl'],
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


def regression(log):
    prefix = r'Local\KSwordProductBreakpoint-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_BREAKPOINT_EVENTS=prefix)
    events = []
    session = child = None
    try:
        for suffix in ('ready', 'trigger', 'done'):
            handle = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(handle, f'CreateEvent failed: {ct.get_last_error()}')
            events.append(handle)
        ready, trigger, done = events
        session = Session(env, log)
        hello = session.receive('hello')
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        protocol = hello['continueProtocol']
        require(protocol['firstRequestId'] == 'continue/1' and int(protocol['replayEntries']) == 128, protocol)
        require(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_for('armed', identity)
        require(armed['attached'] and attached(child), armed)
        address = armed['breakpoint']['address']
        stops = set()
        groups = set()
        first = first_receipt = None
        for index in range(1, CONTINUES + 2):
            require(SetEvent(trigger), f'trigger {index}')
            held = session.wait_for('held', identity)
            stop = held['stop']
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


def main():
    require(CLI.is_file(), f'Build the official CLI first: {CLI}')
    require(not TARGET.exists() and not INT_DIR.exists(), f'Fixture outputs already exist: {TARGET}, {INT_DIR}')
    digest = fingerprint(CLI)
    logs = REPO / '.codex-build-logs' / 'behavior-planning'
    logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    evidence = logs / f'action-analyze-product-breakpoint-long-{stamp}-{os.getpid()}.log'
    print(f'EVIDENCE={evidence}', flush=True)
    INT_DIR.mkdir(parents=True)
    try:
        with evidence.open('x', encoding='utf-8', buffering=1) as log:
            log.write(f'FORMAL_CLI_SHA256={digest}\n')
            build_fixture(log)
            regression(log)
    finally:
        TARGET.unlink(missing_ok=True)
        shutil.rmtree(INT_DIR)
        require(fingerprint(CLI) == digest, 'formal CLI digest changed during validation')
    print(f'PRODUCT_RESULT=PASS CONTINUES={CONTINUES} CLI_SHA256={digest} FIXTURE_CLEANED=true')


if __name__ == '__main__':
    main()
