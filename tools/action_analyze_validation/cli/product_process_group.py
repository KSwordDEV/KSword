"""Validate the formal ActionAnalyze process-group CLI against self-owned AMD64 targets.

Scope: the `analyze process-group session` command layer only. The native owner layer keeps
its own fixture receipts (KswordCLI/ActionAnalyze/Control/tests/OwnedProcessGroupTests.cpp);
this harness drives the shipped CLI binary and proves the observable protocol from outside.

Every target is a fresh child of this harness. No Explorer, DWM, system or pre-existing
process is touched, no driver or Sysmon path is used, and no GUI is started.
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
import threading
import time
from uuid import uuid4


REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
TARGET = RELEASE / 'ActionAnalyzeProcessGroupTarget.exe'
TARGET32 = RELEASE / 'ActionAnalyzeProcessGroupTarget32.exe'
INT_DIR = REPO / 'KswordCLI' / 'ActionAnalyze' / 'Control' / 'tests' / 'x64' / 'Release' / 'ProcessGroupTarget'
SOURCE = Path(__file__).with_name('product_process_group_child.c')
LOG_DIR = REPO / '.codex-build-logs'
BELOW_NORMAL = 0x4000
CREATE_NO_WINDOW = 0x08000000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_TERMINATE = 0x1
SYNCHRONIZE = 0x100000
FILE_MAP_ALL_ACCESS = 0xF001F
PAGE_READWRITE = 0x04
INVALID_HANDLE_VALUE = ct.c_void_p(-1).value
ERROR_ACCESS_DENIED = 5
ERROR_NOT_SUPPORTED = 50
ERROR_PROCESS_ABORTED = 1067
RECEIPT_WINDOW = 128
FROZEN_WINDOW_MS = 260
PULSE_TIMEOUT_MS = 320
STEP = 'PID:CREATION'


class SharedState(ct.Structure):
    _fields_ = [('counter', ct.c_int64), ('ready', ct.c_int32), ('reserved', ct.c_int32)]


class SecurityAttributes(ct.Structure):
    _fields_ = [('nLength', win.DWORD), ('lpSecurityDescriptor', win.LPVOID), ('bInheritHandle', win.BOOL)]


def api(name, result, *args):
    function = getattr(KERNEL, name)
    function.restype = result
    function.argtypes = args
    return function


KERNEL = ct.WinDLL('kernel32', use_last_error=True)
CreateEvent = api('CreateEventW', win.HANDLE, ct.c_void_p, win.BOOL, win.BOOL, win.LPCWSTR)
CreateFileMapping = api('CreateFileMappingW', win.HANDLE, win.HANDLE, win.LPVOID, win.DWORD, win.DWORD, win.DWORD, win.LPCWSTR)
MapViewOfFile = api('MapViewOfFile', ct.c_void_p, win.HANDLE, win.DWORD, win.DWORD, win.DWORD, ct.c_size_t)
UnmapViewOfFile = api('UnmapViewOfFile', win.BOOL, ct.c_void_p)
OpenProcess = api('OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
OpenThread = api('OpenThread', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
GetProcessIdOfThread = api('GetProcessIdOfThread', win.DWORD, win.HANDLE)
CloseHandle = api('CloseHandle', win.BOOL, win.HANDLE)
SetEvent = api('SetEvent', win.BOOL, win.HANDLE)
ResetEvent = api('ResetEvent', win.BOOL, win.HANDLE)
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
GetProcessTimes = api('GetProcessTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetExitCode = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetImagePath = api('QueryFullProcessImageNameW', win.BOOL, win.HANDLE, win.DWORD, win.LPWSTR, ct.POINTER(win.DWORD))
CheckDebugger = api('CheckRemoteDebuggerPresent', win.BOOL, win.HANDLE, ct.POINTER(win.BOOL))
TerminateProcess = api('TerminateProcess', win.BOOL, win.HANDLE, win.UINT)


class Checker:
    """Collects named checks so the final receipt lists real executed assertions."""

    def __init__(self, log):
        self.log = log
        self.checks = 0
        self.passed = 0
        self.failures = []

    def require(self, condition, detail):
        self.checks += 1
        if condition:
            self.passed += 1
            return True
        message = f'{detail}'
        self.failures.append(message)
        self.log.write(f'FAIL {message}\n')
        raise RuntimeError(message)

    def note(self, text):
        self.log.write(f'NOTE {text}\n')
        self.log.flush()


def fingerprint(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def file_time_value(time):
    return (time.dwHighDateTime << 32) | time.dwLowDateTime


def inheritable_event():
    attributes = SecurityAttributes()
    attributes.nLength = ct.sizeof(attributes)
    attributes.lpSecurityDescriptor = None
    attributes.bInheritHandle = True
    return attributes


def build_fixture(log):
    """Compile the self-owned target for x64 and x86 into the fixed IntDir and unified Release."""
    choices = [Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'),
               Path(r'D:\Software\VS')]
    setup = next((base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat' for base in choices
                  if (base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat').is_file()), None)
    require(setup is not None, 'MSVC vcvars64.bat is required')
    shell = f'"{os.environ["ComSpec"]}" /d /c '

    def host_compiler(setup_command, architecture='x64'):
        paths = subprocess.check_output(shell + setup_command + ' && where cl.exe', cwd=INT_DIR,
                                        creationflags=BELOW_NORMAL, text=True, timeout=60).splitlines()
        suffix = rf'\hostx64\{architecture}\cl.exe'
        compiler = next((Path(path) for path in paths if path.lower().endswith(suffix)), None)
        require(compiler is not None and compiler.is_file(), f'HostX64 {architecture} compiler required: {paths}')
        return compiler

    compiler = host_compiler(f'call "{setup}" >nul')
    log.write(f'INTDIR={INT_DIR}\nOUTDIR={RELEASE}\nHOSTX64={compiler}\nPRIORITY=BelowNormal\n')
    log.flush()
    command = (f'call "{setup}" >nul && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 '
               f'"{SOURCE}" /link /OUT:"{TARGET}" /IMPLIB:fixture64.lib /MACHINE:X64')
    subprocess.run(shell + command, cwd=INT_DIR, stdout=log, stderr=subprocess.STDOUT,
                   creationflags=BELOW_NORMAL, timeout=120, check=True)

    x86_setup = setup.parent / 'vcvarsall.bat'
    if x86_setup.is_file():
        x86_setup_line = f'call "{x86_setup}" amd64_x86 >nul'
        x86 = host_compiler(x86_setup_line, 'x86')
        x86_command = (f'{x86_setup_line} && "{x86}" /nologo /W4 /WX /O2 /MT /utf-8 '
                       f'"{SOURCE}" /link /OUT:"{TARGET32}" /IMPLIB:fixture32.lib /MACHINE:X86')
        subprocess.run(shell + x86_command, cwd=INT_DIR, stdout=log, stderr=subprocess.STDOUT,
                       creationflags=BELOW_NORMAL, timeout=120, check=True)
        log.write(f'HOSTX64_X86={x86}\n')
    log.flush()


def remove_outputs():
    """Remove only this harness's own fixed fixture outputs; retry transient locks."""
    for path in (TARGET, TARGET32):
        for _ in range(20):
            try:
                path.unlink(missing_ok=True)
                break
            except PermissionError:
                time.sleep(0.25)
    for _ in range(20):
        if not INT_DIR.exists():
            break
        shutil.rmtree(INT_DIR, ignore_errors=True)
        if INT_DIR.exists():
            time.sleep(0.25)


@contextmanager
def installed_fixture(log):
    """Build the self-owned target in the fixed IntDir; remove only this round's artifacts."""
    remove_outputs()  # 只清理本夹具自己的固定输出；正式产物与源码不受影响。
    INT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        build_fixture(log)
        yield TARGET
    finally:
        remove_outputs()


class Target:
    """One self-owned AMD64 (or WOW64) heartbeat child with an inherited pulse protocol."""

    def __init__(self, log, executable=TARGET, label='target'):
        self.log = log
        self.label = label
        self.handles = []
        self.map_handle = None
        self.view = None
        self.state = None
        self.process = None
        self.pid = 0
        self.creation = 0
        self.executable = Path(executable)

        self.map_name = 'Local\\KSwordProcessGroupTarget-' + uuid4().hex
        self.map_handle = CreateFileMapping(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0,
                                            ct.sizeof(SharedState), self.map_name)
        require(self.map_handle, f'CreateFileMapping failed: {ct.get_last_error()}')
        self.view = MapViewOfFile(self.map_handle, FILE_MAP_ALL_ACCESS, 0, 0, ct.sizeof(SharedState))
        require(self.view, f'MapViewOfFile failed: {ct.get_last_error()}')
        self.state = ct.cast(self.view, ct.POINTER(SharedState)).contents

        attributes = inheritable_event()
        self.ready = CreateEvent(ct.byref(attributes), False, False, None)
        self.pulse = CreateEvent(ct.byref(attributes), False, False, None)
        self.reply = CreateEvent(ct.byref(attributes), False, False, None)
        self.stop = CreateEvent(ct.byref(attributes), True, False, None)
        for handle in (self.ready, self.pulse, self.reply, self.stop):
            require(handle, f'CreateEvent failed: {ct.get_last_error()}')
            self.handles.append(handle)

        command = [str(self.executable), '--target', self.map_name,
                   str(self.ready), str(self.pulse), str(self.reply), str(self.stop)]
        try:
            self.process = subprocess.Popen(command, cwd=RELEASE, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=log, close_fds=False,
                                            creationflags=CREATE_NO_WINDOW | BELOW_NORMAL)
            self.pid = self.process.pid
            require(Wait(self.ready, 10000) == WAIT_OBJECT_0, f'{label} did not become ready')
            require(self.state.ready == 1, f'{label} shared state not published')
            self.creation = self.read_creation()
        except BaseException:
            # 构造失败必须清退已经启动的自有目标，不留下占用正式 Release 输出的进程。
            self.terminate()
            raise

    def read_creation(self):
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, False, self.pid)
        require(handle, f'OpenProcess failed for {self.label}: {ct.get_last_error()}')
        try:
            created, exited, kernel, user = (win.FILETIME() for _ in range(4))
            require(GetProcessTimes(handle, ct.byref(created), ct.byref(exited),
                                    ct.byref(kernel), ct.byref(user)),
                    f'GetProcessTimes failed: {ct.get_last_error()}')
            return file_time_value(created)
        finally:
            CloseHandle(handle)

    @property
    def target_text(self):
        return f'{self.pid}:{self.creation}'

    def target_value(self):
        return {'pid': self.pid, 'creationFileTime': str(self.creation)}

    def counter(self):
        return self.state.counter

    def counter_delta(self, milliseconds):
        first = self.counter()
        time.sleep(milliseconds / 1000.0)
        return self.counter() - first

    def running(self, milliseconds=FROZEN_WINDOW_MS):
        return self.counter_delta(milliseconds) > 0

    def frozen(self, milliseconds=FROZEN_WINDOW_MS):
        return self.counter_delta(milliseconds) == 0

    def pulse_answers(self, timeout_ms=PULSE_TIMEOUT_MS):
        ResetEvent(self.reply)
        require(SetEvent(self.pulse), 'SetEvent(pulse) failed')
        return Wait(self.reply, timeout_ms) == WAIT_OBJECT_0

    def attached(self):
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, False, self.pid)
        require(handle, f'OpenProcess failed for {self.label}: {ct.get_last_error()}')
        try:
            active = win.BOOL()
            require(CheckDebugger(handle, ct.byref(active)), f'CheckRemoteDebuggerPresent failed: {ct.get_last_error()}')
            return bool(active.value)
        finally:
            CloseHandle(handle)

    def alive(self):
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, False, self.pid)
        if not handle:
            return False
        try:
            return Wait(handle, 0) == WAIT_TIMEOUT
        finally:
            CloseHandle(handle)

    def exit_code(self):
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, False, self.pid)
        if not handle:
            return None
        try:
            code = win.DWORD()
            if not GetExitCode(handle, ct.byref(code)):
                return None
            return code.value
        finally:
            CloseHandle(handle)

    def stop_naturally(self):
        require(SetEvent(self.stop), 'SetEvent(stop) failed')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                return self.process.returncode
            time.sleep(0.02)
        raise RuntimeError(f'{self.label} did not exit')

    def terminate(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                TerminateProcess(ct.c_void_p(self.process._handle), 3)
                self.process.wait(timeout=10)
            except Exception:
                pass
        for handle in self.handles:
            CloseHandle(handle)
        self.handles = []
        if self.view:
            UnmapViewOfFile(self.view)
            self.view = None
        if self.map_handle:
            CloseHandle(self.map_handle)
            self.map_handle = None


class Cli:
    """The formal CLI process; JSONL and REPL share the same frame envelope."""

    def __init__(self, log, targets, mode='jsonl', extra=None):
        self.log = log
        self.mode = mode
        command = [str(CLI), 'analyze', 'process-group', 'session', '--targets', targets,
                   '--confirm', '--disposition', 'resume-detach', '--input', mode]
        if extra:
            command = extra
        self.process = subprocess.Popen(command, cwd=RELEASE, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=log, encoding='utf-8',
                                        creationflags=CREATE_NO_WINDOW | BELOW_NORMAL)
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.session = None
        self.sequence = 0

    def _read(self):
        try:
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def send(self, text):
        self.log.write(f'TX {text}\n')
        self.log.flush()
        self.process.stdin.write(text + '\n')
        self.process.stdin.flush()

    def request(self, request_id, method, params=None, expected=None, session=None, omit_session=False):
        body = {'schemaVersion': 1, 'requestId': request_id, 'method': method,
                'params': {} if params is None else params}
        identity = self.session if session is None else session
        if identity is not None and not omit_session:
            body['session'] = identity
        if expected is not None:
            body['expected'] = expected
        self.send(json.dumps(body, separators=(',', ':')))
        return self.receive(request_id=request_id)

    def repl(self, line):
        self.send(line)
        return self.receive()

    def receive(self, kind=None, request_id=None):
        line = self.lines.get(timeout=60)
        require(line is not None, f'CLI closed stdout (exit={self.process.poll()})')
        self.log.write(f'RX {line}')
        self.log.flush()
        frame = json.loads(line)
        self.sequence += 1
        require(frame['schemaVersion'] == 1, frame)
        require(frame['streamSequence'] == str(self.sequence), frame)
        if self.session is None:
            self.session = frame['session']
        require(frame['session'] == self.session, frame)
        if kind is not None:
            require(frame['type'] == kind, frame)
        if request_id is not None:
            require(frame['requestId'] == request_id, frame)
        return frame

    def query(self, request_id='query/1'):
        if self.mode == 'jsonl':
            return self.request(request_id, 'control.query')['result']
        return self.repl('status')['result']

    def wait_state(self, state, timeout=15.0, request_id='query/1'):
        deadline = time.monotonic() + timeout
        report = None
        while True:
            report = self.query(request_id)
            if report['state'] == state:
                return report
            require(time.monotonic() < deadline, f'never reached {state}: {report}')
            time.sleep(0.02)

    def close(self, timeout=30):
        try:
            if self.process.poll() is None:
                self.process.stdin.close()
        except Exception:
            pass
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.log.write('WARN the CLI did not exit on its own and was stopped by the harness\n')
            self.process.kill()
            self.process.wait(timeout=timeout)
        self.reader.join(timeout=5)

    def expect_exit(self, code=0, timeout=30):
        """The CLI must leave by itself; the harness never kills a session with pending duty."""
        actual = self.process.wait(timeout=timeout)
        require(actual == code, f'formal CLI exit {actual}')
        self.log.write(f'CLI_EXIT={actual} SELF_EXIT=true\n')
        self.log.flush()
        return actual


def require(condition, detail):
    if not condition:
        raise RuntimeError(str(detail))


def member_map(report):
    return {member['target']['pid']: member for member in report['members']}


def stops_of(report):
    return [member['stop'] for member in report['members'] if member['stop'] is not None]


def scenario_fixture(check, log):
    """The self-owned target itself: a live heartbeat, a pulse answer and a natural exit."""
    target = Target(log, label='fixture')
    try:
        check.require(target.alive(), 'the self-owned target is not alive')
        check.require(target.running(), 'the self-owned target does not advance its counter')
        check.require(target.pulse_answers(), 'the self-owned target did not answer a pulse')
        check.require(not target.attached(), 'the self-owned target is already debugged')
        first = target.counter()
        time.sleep(0.2)
        check.require(target.counter() > first, 'the heartbeat counter did not advance')
        code = target.stop_naturally()
        check.require(code == 0, f'the self-owned target exit code {code}')
        check.require(not target.alive(), 'the self-owned target survived its stop')
        log.write('FIXTURE=PASS HEARTBEAT=advancing PULSE=answered EXIT=0\n')
    finally:
        target.terminate()


def scenario_help(check, log):
    """The shipped CLI must document the process-group entry."""
    result = subprocess.run([str(CLI), 'help', 'analyze process-group session'], cwd=RELEASE,
                            capture_output=True, text=True, encoding='utf-8',
                            creationflags=CREATE_NO_WINDOW, timeout=30)
    log.write(f'HELP_EXIT={result.returncode}\n{result.stdout}\n')
    check.require(result.returncode == 0, f'help exit {result.returncode}: {result.stderr}')
    check.require('analyze process-group session' in result.stdout, result.stdout[:400])
    for token in ('--targets', '--confirm', '--disposition', 'resume-detach'):
        check.require(token in result.stdout, f'help missing {token}')
    check.require('control.pause' in result.stdout and 'control.continue' in result.stdout,
                  'help missing the JSONL control methods')


def scenario_rejections(check, log):
    """Command-level refusals never attach anything."""
    def run(arguments):
        result = subprocess.run([str(CLI)] + arguments, cwd=RELEASE, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding='utf-8',
                                creationflags=CREATE_NO_WINDOW, timeout=30)
        log.write(f'REJECT {arguments} EXIT={result.returncode} STDERR={result.stderr.strip()}\n')
        return result

    missing = run(['analyze', 'process-group', 'session', '--targets', '1:1',
                   '--disposition', 'resume-detach', '--input', 'jsonl'])
    check.require(missing.returncode == 1 and 'Require --confirm' in missing.stderr,
                  f'missing --confirm was not refused: {missing.returncode} {missing.stderr}')
    wrong = run(['analyze', 'process-group', 'session', '--targets', '1:1',
                 '--confirm', '--disposition', 'suspend', '--input', 'jsonl'])
    check.require(wrong.returncode == 1 and 'Require --confirm' in wrong.stderr,
                  f'wrong disposition was not refused: {wrong.returncode} {wrong.stderr}')
    bad_input = run(['analyze', 'process-group', 'session', '--targets', '1:1',
                     '--confirm', '--disposition', 'resume-detach', '--input', 'bogus'])
    check.require(bad_input.returncode == 1 and 'Require --confirm' in bad_input.stderr,
                  f'wrong input mode was not refused: {bad_input.returncode} {bad_input.stderr}')


def scenario_configure_refusals(check, log, target):
    """Instance identity gates are enforced before any native attachment."""
    cases = [
        ('wrong creation', f'{target.pid}:{target.creation + 1}', 'process-group-pin-instance', 'identity-mismatch'),
        ('duplicate pid', f'{target.pid}:{target.creation},{target.pid}:{target.creation}',
         'process-group-duplicate-pid', 'conflict'),
        ('system target', '4:1', 'process-group-pin-instance', 'identity-mismatch'),
    ]
    for name, targets, stage, ledger in cases:
        process = subprocess.Popen([str(CLI), 'analyze', 'process-group', 'session', '--targets', targets,
                                    '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl'],
                                   cwd=RELEASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, encoding='utf-8',
                                   creationflags=CREATE_NO_WINDOW | BELOW_NORMAL)
        hello = json.loads(process.stdout.readline())
        summary = json.loads(process.stdout.readline())
        code = process.wait(timeout=30)
        control = hello['result']['control']
        log.write(f'CONFIGURE_REFUSAL name={name} exit={code} stage={control["stage"]} '
                  f'ledger={control["ledgerResult"]} error={control["win32Error"]}\n')
        check.require(code == 3, f'{name} exit {code}')
        check.require(control['stage'] == stage, f'{name} stage {control["stage"]}')
        check.require(control['ledgerResult'] == ledger, f'{name} ledger {control["ledgerResult"]}')
        check.require(control['members'] == [], f'{name} published members')
        check.require(summary['type'] == 'summary' and summary['result']['exitCode'] == 3, summary)
    check.require(not target.attached(), 'a refused configuration attached the target')
    check.require(target.running(), 'a refused configuration stopped the target')


def scenario_jsonl_full(check, log):
    """Full-set pause, exact continue, immutable replay, token rejection, recover and close."""
    targets = [Target(log, label=f'full-{index}') for index in range(3)]
    cli = Cli(log, ','.join(item.target_text for item in targets), 'jsonl')
    try:
        hello = cli.receive('hello')
        control = hello['result']['control']
        protocol = hello['result']['groupProtocol']
        check.require(control['state'] == 'ready' and control['clean'], hello)
        check.require(control['operation'] is None, 'configure created an operation')
        check.require(len(control['members']) == 3, control)
        check.require(protocol['configurationPauses'] is False, protocol)
        check.require(protocol['replayEntries'] == str(RECEIPT_WINDOW), protocol)
        check.require(protocol['maxMembers'] == '16', protocol)
        check.require(protocol['firstRequestId'] == 'group/1', protocol)
        for member, item in zip(control['members'], targets):
            check.require(member['target'] == item.target_value(), member)
            check.require(member['control'] is None and member['stop'] is None, member)
            check.require(item.running(), 'configure paused a target')
            check.require(not item.attached(), 'configure attached a target')
        check.require(cli.session is not None and cli.session['id'], hello)

        queried = cli.query('query/1')
        check.require(queried['state'] == 'ready' and queried['operation'] is None, queried)
        check.require(len(queried['members']) == 3, queried)

        paused = cli.request('group/1', 'control.pause')['result']
        check.require(paused['operation']['requestId'] == 'group/1', paused)
        check.require(paused['operation']['action'] == 'pause', paused)
        check.require(paused['operation']['ledgerResult'] == 'applied', paused)
        check.require(paused['operation']['win32Error'] == 0, paused)
        check.require(len(paused['operation']['outcomes']) == 3, paused)
        held = cli.wait_state('held-complete')
        check.require(len(stops_of(held)) == 3, held)
        for member, item in zip(held['members'], targets):
            check.require(member['stop'] is not None, member)
            check.require(member['control']['attached'] is True, member)
            check.require(member['control']['state'] == 'held', member)
            check.require(item.attached(), 'held member is not attached')
            check.require(item.frozen(), 'held member kept running')
            check.require(not item.pulse_answers(), 'held member answered a pulse')
        first_stops = stops_of(held)
        for stop in first_stops:
            check.require(set(stop.keys()) == {'target', 'groupId', 'stopId', 'event', 'stateRevision'}, stop)
            check.require(set(stop['event'].keys()) == {'backendInstanceId', 'serial'}, stop)

        repeat = cli.request('group/1', 'control.pause')['result']
        check.require(repeat['ledgerResult'] == 'duplicate', repeat)
        check.require(repeat['operation'] == paused['operation'], 'duplicate pause changed its receipt')
        check.require(repeat['state'] == 'held-complete', repeat)
        for item in targets:
            check.require(item.frozen(), 'duplicate pause took a second native action')

        conflict = cli.request('group/1', 'control.pause',
                                params={'targets': [targets[0].target_value()]})['result']
        check.require(conflict['ledgerResult'] == 'conflict', conflict)
        check.require(conflict['stage'] == 'process-group-request-conflict', conflict)
        for item in targets:
            check.require(item.frozen(), 'conflicting pause disturbed the held set')

        stale_revision = json.loads(json.dumps(first_stops[0]))
        stale_revision['stateRevision'] = str(int(stale_revision['stateRevision']) + 1)
        wrong_event = json.loads(json.dumps(first_stops[0]))
        wrong_event['event']['serial'] = str(int(wrong_event['event']['serial']) + 1000)
        wrong_backend = json.loads(json.dumps(first_stops[0]))
        wrong_backend['event']['backendInstanceId'] = '00000000-0000-0000-0000-000000000000'
        for offset, (name, payload) in enumerate((('stale revision', stale_revision),
                                                  ('wrong event serial', wrong_event),
                                                  ('wrong backend', wrong_backend))):
            rejected = cli.request(f'group/{2 + offset}', 'control.continue',
                                   expected={'stops': [payload]})['result']
            check.require(rejected['ledgerResult'] == 'stale-revision', f'{name}: {rejected}')
            check.require(rejected['stage'] == 'process-group-stale-stop', f'{name}: {rejected}')
            check.require(rejected['operation'] is not None, f'{name} produced no operation receipt')
            check.require(rejected['operation']['ledgerResult'] == 'stale-revision', f'{name}: {rejected}')
            check.require(rejected['operation']['stage'] == 'process-group-stale-stop', f'{name}: {rejected}')
            check.require(rejected['operation']['requestId'] == f'group/{2 + offset}', f'{name}: {rejected}')
        for item in targets:
            check.require(item.frozen(), 'a rejected continue released part of the set')
            check.require(item.attached(), 'a rejected continue detached a member')
        still = cli.query('query/9')
        check.require(len(stops_of(still)) == 3, 'a rejected continue changed the member stops')

        replay_rejected = cli.request('group/2', 'control.continue',
                                      expected={'stops': [stale_revision]})['result']
        check.require(replay_rejected['ledgerResult'] == 'duplicate', replay_rejected)
        check.require(replay_rejected['operation']['ledgerResult'] == 'stale-revision', replay_rejected)
        reuse_rejected = cli.request('group/2', 'control.continue',
                                     expected={'stops': first_stops})['result']
        check.require(reuse_rejected['ledgerResult'] == 'conflict', reuse_rejected)
        check.require(reuse_rejected['stage'] == 'process-group-request-conflict', reuse_rejected)
        for item in targets:
            check.require(item.frozen(), 'a rejected ID was reused for a real release')

        released = cli.request('group/5', 'control.continue',
                               expected={'stops': first_stops})['result']
        check.require(released['operation']['action'] == 'continue', released)
        check.require(len(released['operation']['outcomes']) == 3, released)
        for outcome in released['operation']['outcomes']:
            check.require(outcome['control']['release']['result'] == 'continued', outcome)
        after = cli.wait_state('active')
        check.require(len(stops_of(after)) == 0, after)
        for item in targets:
            check.require(not item.attached(), 'continued member stayed attached')
            check.require(item.alive(), 'continued member died')
            check.require(item.running(), 'continued member did not resume')
            check.require(item.pulse_answers(), 'continued member did not answer a pulse')

        replay = cli.request('group/5', 'control.continue', expected={'stops': first_stops})['result']
        check.require(replay['ledgerResult'] == 'duplicate', replay)
        check.require(replay['operation'] == released['operation'], 'duplicate continue changed its receipt')
        for item in targets:
            check.require(item.running(), 'duplicate continue touched a released target')

        recovered = cli.request('recover/1', 'control.recover',
                                params={'requestId': 'group/5'})['result']
        check.require(recovered['operation']['action'] == 'recover', recovered)
        check.require(recovered['operation']['requestId'] == 'group/5', recovered)
        check.require(len(recovered['operation']['outcomes']) == 3, recovered)
        for item in targets:
            check.require(item.running(), 'recover paused a released target')
            check.require(not item.attached(), 'recover attached a released target')

        wrong_recover = cli.request('recover/2', 'control.recover',
                                    params={'requestId': 'group/1'})['result']
        check.require(wrong_recover['ledgerResult'] == 'readback-required', wrong_recover)
        check.require(wrong_recover['stage'] == 'process-group-original-release-required', wrong_recover)
        unknown_recover = cli.request('recover/3', 'control.recover',
                                      params={'requestId': 'group/999'})['result']
        check.require(unknown_recover['ledgerResult'] == 'readback-required', unknown_recover)
        check.require(unknown_recover['stage'] == 'process-group-original-release-required', unknown_recover)
        rejected_recover = cli.request('recover/4', 'control.recover',
                                       params={'requestId': 'group/2'})['result']
        check.require(rejected_recover['ledgerResult'] == 'readback-required', rejected_recover)
        check.require(rejected_recover['operation']['ledgerResult'] == 'stale-revision', rejected_recover)
        for item in targets:
            check.require(item.running(), 'a refused recover touched a released target')

        wrong_session = cli.request('query/2', 'control.query',
                                    session={'id': 'not-the-session', 'epoch': cli.session['epoch']})
        check.require(wrong_session['type'] == 'error', wrong_session)
        check.require(wrong_session['result']['errorId'] == 'wrong-session', wrong_session)
        wrong_epoch = cli.request('query/3', 'control.query',
                                  session={'id': cli.session['id'], 'epoch': 'not-the-epoch'})
        check.require(wrong_epoch['type'] == 'error', wrong_epoch)
        check.require(wrong_epoch['result']['errorId'] == 'wrong-session', wrong_epoch)

        no_session = cli.request('group/6', 'control.pause', omit_session=True)
        check.require(no_session['type'] == 'error', no_session)
        check.require(no_session['result']['errorId'] == 'session-required', no_session)
        unchanged = cli.query('query/4')
        check.require(unchanged['state'] == 'active' and len(stops_of(unchanged)) == 0, unchanged)
        check.require(unchanged['operation'] is None, unchanged)
        for item in targets:
            check.require(item.running(), 'a session-less pause reached the native owner')
            check.require(not item.attached(), 'a session-less pause attached a target')
        no_session_close = cli.request('close/0', 'controller.shutdown', omit_session=True)
        check.require(no_session_close['type'] == 'error', no_session_close)
        check.require(no_session_close['result']['errorId'] == 'session-required', no_session_close)
        check.require(cli.query('query/5')['state'] == 'active', 'a session-less close ended the session')

        bad_target = cli.request('group/7', 'control.pause',
                                 params={'targets': [{'pid': str(targets[0].pid),
                                                      'creationFileTime': str(targets[0].creation)}]})
        check.require(bad_target['type'] == 'error', bad_target)
        check.require(bad_target['result']['errorId'] == 'invalid-target', bad_target)
        check.require(bad_target['result']['stage'] == 'process-group-control', bad_target)

        closed = cli.request('close/1', 'controller.shutdown')['result']
        check.require(closed['clean'] is True, closed)
        summary = cli.receive('summary')
        check.require(summary['result']['reason'] == 'requested', summary)
        check.require(summary['result']['exitCode'] == 0, summary)
        check.require(summary['result']['control']['clean'] is True, summary)
        check.require(summary['result']['control']['state'] == 'closed', summary)
        code = cli.expect_exit()
        for item in targets:
            check.require(item.alive(), 'close killed a target')
            check.require(not item.attached(), 'close left a target attached')
            check.require(item.running(), 'close left a target stopped')
        log.write('JSONL_FULL=PASS MEMBERS=3 PAUSE=held-complete CONTINUE=exact RECOVER=readback '
                  'CLOSE=clean CLI_EXIT=0\n')
        return targets
    finally:
        cli.close()
        for item in targets:
            item.terminate()


def scenario_subset(check, log):
    """A subset pause keeps the remaining members in their previous state."""
    targets = [Target(log, label=f'subset-{index}') for index in range(3)]
    cli = Cli(log, ','.join(item.target_text for item in targets), 'jsonl')
    try:
        cli.receive('hello')
        paused = cli.request('group/1', 'control.pause',
                             params={'targets': [targets[1].target_value()]})['result']
        check.require(paused['operation']['action'] == 'pause', paused)
        check.require(len(paused['operation']['outcomes']) == 1, paused)
        partial = cli.wait_state('held-partial')
        check.require(partial['members'][1]['stop'] is not None, partial)
        check.require(partial['members'][0]['stop'] is None, partial)
        check.require(partial['members'][2]['stop'] is None, partial)
        check.require(targets[1].frozen(), 'subset member kept running')
        check.require(targets[0].running(), 'untouched member was paused')
        check.require(targets[2].running(), 'untouched member was paused')

        again = cli.request('group/2', 'control.pause',
                            params={'targets': [targets[1].target_value()]})['result']
        check.require(again['ledgerResult'] == 'invalid-transition', again)
        check.require(again['stage'] == 'process-group-member-still-owned', again)
        check.require(targets[1].frozen(), 'the refused second pause released the held member')
        check.require(partial['members'][1]['stop'] is not None, 'the refused second pause dropped the stop')

        stop = partial['members'][1]['stop']
        released = cli.request('group/3', 'control.continue', expected={'stops': [stop]})['result']
        check.require(len(released['operation']['outcomes']) == 1, released)
        check.require(released['operation']['outcomes'][0]['control']['release']['result'] == 'continued',
                      released)
        check.require(targets[1].running(), 'subset member did not resume')
        check.require(targets[0].running() and targets[2].running(), 'untouched members changed')

        whole = cli.request('group/4', 'control.pause')['result']
        check.require(len(whole['operation']['outcomes']) == 3, whole)
        full = cli.wait_state('held-complete')
        for item in targets:
            check.require(item.frozen(), 'full pause left a member running')
        stops = stops_of(full)
        final = cli.request('group/5', 'control.continue', expected={'stops': stops})['result']
        check.require(len(final['operation']['outcomes']) == 3, final)
        for item in targets:
            check.require(item.running(), 'member did not resume after the full continue')
        cli.request('close/1', 'controller.shutdown')
        summary = cli.receive('summary')
        check.require(summary['result']['exitCode'] == 0, summary)
        cli.expect_exit()
        log.write('JSONL_SUBSET=PASS HELD=1 UNTOUCHED=2 RUNNING STILL_OWNED=rejected\n')
    finally:
        cli.close()
        for item in targets:
            item.terminate()


def scenario_partial_failure(check, log):
    """A member that exits before the pause fails alone and keeps the successful member."""
    alive = Target(log, label='partial-alive')
    gone = Target(log, label='partial-gone')
    cli = Cli(log, f'{alive.target_text},{gone.target_text}', 'jsonl')
    try:
        hello = cli.receive('hello')
        check.require(hello['result']['control']['state'] == 'ready', hello)
        gone.stop_naturally()
        check.require(not gone.alive(), 'the second target did not exit')
        paused = cli.request('group/1', 'control.pause')['result']
        check.require(len(paused['operation']['outcomes']) == 2, paused)
        outcomes = {outcome['target']['pid']: outcome for outcome in paused['operation']['outcomes']}
        failed = outcomes[gone.pid]
        check.require(failed['control']['state'] == 'rejected', failed)
        check.require(failed['control']['stage'] == 'process-already-exited', failed)
        check.require(failed['control']['win32Error'] == ERROR_PROCESS_ABORTED, failed)
        check.require(failed['control']['clean'] is True, failed)
        partial = cli.wait_state('held-partial')
        members = member_map(partial)
        check.require(members[alive.pid]['stop'] is not None, partial)
        check.require(members[gone.pid]['stop'] is None, partial)
        check.require(members[gone.pid]['clean'] is True, partial)
        check.require(alive.frozen(), 'the surviving member kept running')
        stop = members[alive.pid]['stop']
        released = cli.request('group/2', 'control.continue', expected={'stops': [stop]})['result']
        check.require(len(released['operation']['outcomes']) == 1, released)
        check.require(released['operation']['outcomes'][0]['control']['release']['result'] == 'continued',
                      released)
        check.require(alive.running(), 'the surviving member did not resume')
        cli.request('close/1', 'controller.shutdown')
        summary = cli.receive('summary')
        check.require(summary['result']['exitCode'] == 0, summary)
        check.require(summary['result']['control']['clean'] is True, summary)
        cli.expect_exit()
        log.write('JSONL_PARTIAL=PASS SURVIVOR=held-and-released EXITED=rejected '
                  'STAGE=process-already-exited\n')
    finally:
        cli.close()
        alive.terminate()
        gone.terminate()


def scenario_receipt_window(check, log):
    """The 128 receipt window expires old IDs without repeating a native action."""
    target = Target(log, label='receipt-window')
    cli = Cli(log, target.target_text, 'jsonl')
    try:
        cli.receive('hello')
        target.stop_naturally()
        last = None
        for index in range(1, RECEIPT_WINDOW + 2):
            last = cli.request(f'group/{index}', 'control.pause')['result']
            check.require(last['ledgerResult'] == 'applied', f'group/{index}: {last}')
            check.require(last['operation']['requestId'] == f'group/{index}', last)
        expired = cli.request('group/1', 'control.pause')['result']
        check.require(expired['ledgerResult'] == 'replay-expired', expired)
        check.require(expired['stage'] == 'process-group-replay-expired', expired)
        check.require(expired['operation'] is None, 'an expired ID produced an operation')
        check.require(not target.attached(), 'the expired loop attached the target')
        cli.request('close/1', 'controller.shutdown')
        summary = cli.receive('summary')
        check.require(summary['result']['exitCode'] == 0, summary)
        cli.expect_exit(timeout=60)
        log.write(f'JSONL_RECEIPT_WINDOW=PASS RECEIPTS={RECEIPT_WINDOW + 1} EXPIRED=group/1\n')
    finally:
        cli.close()
        target.terminate()


def scenario_wow64(check, log):
    """A non-AMD64 target is refused by the native owner and never attached."""
    if not TARGET32.exists():
        check.note('SKIP wow64 target: the x86 fixture was not produced')
        return
    target = Target(log, executable=TARGET32, label='wow64')
    cli = Cli(log, target.target_text, 'jsonl')
    try:
        hello = cli.receive('hello')
        check.require(hello['result']['control']['state'] == 'ready', hello)
        paused = cli.request('group/1', 'control.pause')['result']
        outcome = paused['operation']['outcomes'][0]
        check.require(outcome['control']['state'] == 'rejected', outcome)
        check.require(outcome['control']['stage'] == 'native-amd64-target-required', outcome)
        check.require(outcome['control']['win32Error'] == ERROR_NOT_SUPPORTED, outcome)
        check.require(not target.attached(), 'the wow64 target was attached')
        cli.request('close/1', 'controller.shutdown')
        summary = cli.receive('summary')
        check.require(summary['result']['exitCode'] == 0, summary)
        cli.expect_exit()
        log.write('JSONL_WOW64=PASS STAGE=native-amd64-target-required ERROR=50\n')
    finally:
        cli.close()
        target.terminate()


def scenario_repl(check, log):
    """The same flow through the human REPL surface."""
    targets = [Target(log, label=f'repl-{index}') for index in range(2)]
    cli = Cli(log, ','.join(item.target_text for item in targets), 'repl')
    try:
        hello = cli.receive('hello')
        check.require(hello['result']['control']['state'] == 'ready', hello)
        status = cli.repl('status')['result']
        check.require(status['state'] == 'ready' and status['operation'] is None, status)
        cli.repl('pause group/1 all')
        held = cli.wait_state('held-complete')
        check.require(len(stops_of(held)) == 2, held)
        for item in targets:
            check.require(item.frozen(), 'REPL pause left a member running')
        tokens = []
        for member in held['members']:
            stop = member['stop']
            tokens.append(':'.join([f"{stop['target']['pid']}:{stop['target']['creationFileTime']}",
                                    stop['groupId'], stop['stopId'], stop['event']['backendInstanceId'],
                                    stop['event']['serial'], stop['stateRevision']]))
        cli.repl(f'continue group/2 {",".join(tokens)}')
        after = cli.wait_state('active')
        check.require(len(stops_of(after)) == 0, after)
        for item in targets:
            check.require(item.running(), 'REPL continue did not resume a member')
        recovered = cli.repl('recover group/2')['result']
        check.require(recovered['operation']['action'] == 'recover', recovered)
        check.require(recovered['operation']['requestId'] == 'group/2', recovered)
        wrong = cli.repl('recover group/1')['result']
        check.require(wrong['ledgerResult'] == 'readback-required', wrong)
        check.require(wrong['stage'] == 'process-group-original-release-required', wrong)
        cli.repl('close')
        summary = cli.receive('summary')
        check.require(summary['result']['exitCode'] == 0, summary)
        check.require(summary['result']['control']['clean'] is True, summary)
        cli.expect_exit()
        for item in targets:
            check.require(item.alive() and not item.attached(), 'REPL close disturbed a target')
        log.write('REPL=PASS PAUSE=all CONTINUE=exact RECOVER=readback CLOSE=clean CLI_EXIT=0\n')
    finally:
        cli.close()
        for item in targets:
            item.terminate()


def main():
    options = argparse.ArgumentParser()
    options.add_argument('--expected-cli-sha256', help='Require this Release CLI SHA-256 before any fixture starts')
    options.add_argument('--fixture-only', action='store_true',
                          help='Build and verify the self-owned target only; no CLI is started')
    args = options.parse_args()
    expected = args.expected_cli_sha256.lower() if args.expected_cli_sha256 else None
    if expected is not None and (len(expected) != 64 or not set(expected) <= set('0123456789abcdef')):
        options.error('--expected-cli-sha256 must be a 64-digit hexadecimal digest')
    digest = None
    if not args.fixture_only:
        require(CLI.is_file(), f'Build the official CLI first: {CLI}')
        digest = fingerprint(CLI)
        require(expected is None or digest == expected,
                f'Release CLI SHA-256 mismatch: expected {expected}, got {digest}')
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    evidence = LOG_DIR / 'action-analyze-process-group-cli.log'
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    print(f'EVIDENCE={evidence}', flush=True)
    try:
        with evidence.open('a', encoding='utf-8', buffering=1) as log:
            log.write(f'=== HARNESS RUN {stamp} PID={os.getpid()} ===\n')
            log.write('【子代理｜进程集合CLI-CodeBuddy验收】\n')
            log.write(f'FORMAL_CLI_SHA256={digest or "not-built"}\n')
            check = Checker(log)
            with installed_fixture(log):
                scenario_fixture(check, log)
                if not args.fixture_only:
                    scenario_help(check, log)
                    scenario_rejections(check, log)
                    holder = Target(log, label='configure-refusal')
                    try:
                        scenario_configure_refusals(check, log, holder)
                    finally:
                        holder.terminate()
                    scenario_jsonl_full(check, log)
                    scenario_subset(check, log)
                    scenario_partial_failure(check, log)
                    scenario_receipt_window(check, log)
                    scenario_wow64(check, log)
                    scenario_repl(check, log)
            log.write('BOUNDARY=NATIVE_FAULT_INJECTION_NOT_AVAILABLE '
                      'RECOVER_CHECKED=HEALTHY_READBACK_ONLY '
                      'PENDING_CLEANUP_RETENTION=NOT_EXECUTED '
                      'MEMORY_SNAPSHOT=NOT_COVERED_HERE '
                      'NATIVE_OWNER_LAYER=SEPARATE_FIXTURE_RECEIPT\n')
            log.write(f'RESULT=PASS checks={check.checks}\n')
            print(f'RESULT=PASS checks={check.checks} CLI_SHA256={digest} FIXTURE_CLEANED=true', flush=True)
    finally:
        if digest is not None:
            require(fingerprint(CLI) == digest, 'formal CLI digest changed during validation')


if __name__ == '__main__':
    main()
