"""Formal CLI native step protocol validation (single-target execution breakpoints).

Validates the formal Release KswordCLI step entry end to end on owned fixture
targets with fully known instruction bytes (MASM nop/call/ret sites):

  * JSONL control.step submit/replay/conflict, control.step.query/cancel
  * REPL step/step-status/step-cancel
  * into, over-call, out (entry-proof frame) on known NOP/CALL paths
  * mixed continue/N and step/N sequencing with independent client namespaces
  * in-flight step query and cancellation (blocking callee)
  * condition sessions must not auto-release ordinary step stops
  * pair and data-write sessions reject the step entry

The caller holds Local\\KSword.ActionAnalyze.CliValidation for the whole CLI
build + run batch; this script acquires it itself, releases it on the same
(main) thread in finally, and writes the machine receipt to
tools/action_analyze_validation/cli/product_step_receipt.json.
"""

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
STEP_TARGET = RELEASE / 'ActionAnalyzeProductStepChild.exe'
AUX_TARGET = RELEASE / 'ActionAnalyzeStepAuxChild.exe'
INT_DIR = REPO / 'KswordCLI' / 'ActionAnalyze' / 'Control' / 'tests' / 'x64' / 'Release' / 'ProductStepValidation'
STEP_C = Path(__file__).with_name('product_step_child.c')
STEP_ASM = Path(__file__).with_name('product_step_child.asm')
STEP_DEF = Path(__file__).with_name('product_step_child.def')
AUX_C = Path(__file__).with_name('product_breakpoint_child.c')
BUILD_SCRIPT = REPO / 'tools' / 'Invoke-KSwordNativeBuildCheck.ps1'
RECEIPT = Path(__file__).with_name('product_step_receipt.json')
MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
ROUNDS = 3
WAIT_OBJECT = 0
WAIT_ABANDONED = 128
WAIT_TIMEOUT = 258
BELOW_NORMAL = 0x4000
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_TERMINATE = 0x1
PROCESS_VM_READ = 0x10
PROCESS_VM_WRITE = 0x20
PROCESS_VM_OPERATION = 0x08
SYNCHRONIZE = 0x100000


class Blocked(Exception):
    """A real environment blocker; never reported as a product pass."""


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
ResetEvent = api('ResetEvent', win.BOOL, win.HANDLE)
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
GetThreadTimes = api('GetThreadTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetExitCode = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetImagePath = api('QueryFullProcessImageNameW', win.BOOL, win.HANDLE, win.DWORD, win.LPWSTR, ct.POINTER(win.DWORD))
CheckDebugger = api('CheckRemoteDebuggerPresent', win.BOOL, win.HANDLE, ct.POINTER(win.BOOL))
TerminateProcess = api('TerminateProcess', win.BOOL, win.HANDLE, win.UINT)
ReadMemory = api('ReadProcessMemory', win.BOOL, win.HANDLE, win.LPCVOID, win.LPVOID, ct.c_size_t,
                 ct.POINTER(ct.c_size_t))
WriteMemory = api('WriteProcessMemory', win.BOOL, win.HANDLE, win.LPVOID, win.LPCVOID, ct.c_size_t,
                   ct.POINTER(ct.c_size_t))
CreateMutex = api('CreateMutexW', win.HANDLE, ct.c_void_p, win.BOOL, win.LPCWSTR)

CHECKS = 0


def ok(condition, detail):
    """One recorded assertion; failures abort the current case."""
    global CHECKS
    CHECKS += 1
    require(condition, detail)
    return condition


def fingerprint(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def read_bytes(handle, address, count):
    buffer = ct.create_string_buffer(count)
    read = ct.c_size_t()
    require(ReadMemory(handle, ct.c_void_p(address), buffer, count, ct.byref(read)) and read.value == count,
            f'ReadProcessMemory failed at {address:#x}: {ct.get_last_error()}')
    return buffer.raw[:count]


def acquire_mutex(timeout_ms=30000):
    """Wait for the shared validation lease once; a busy lease is reported as blocked."""
    handle = CreateMutex(None, False, MUTEX_NAME)
    if not handle:
        raise Blocked(f'Cannot open {MUTEX_NAME}: {ct.get_last_error()}')
    result = Wait(handle, timeout_ms)
    # 128 = WAIT_ABANDONED: the previous holder died while owning the mutex; this call now owns it.
    if result not in (WAIT_OBJECT, WAIT_ABANDONED):
        CloseHandle(handle)
        raise Blocked(f'{MUTEX_NAME} busy (WaitForSingleObject={result})')
    return handle


def release_mutex(handle):
    # Same-thread release: all harness work runs on the main thread.
    CloseHandle(handle)


def build_cli(log):
    """One necessary BelowNormal HostX64 incremental build of the formal CLI."""
    started = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
    host = next((candidate for candidate in ('pwsh', 'powershell') if shutil.which(candidate)), None)
    require(host is not None, 'No PowerShell host is available for the repository build check')
    result = None
    for attempt in range(3):
        result = subprocess.run(
            [host, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(BUILD_SCRIPT), '-Product', 'CLI'],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800,
        )
        log.write(result.stdout)
        if result.stderr:
            log.write('STDERR ' + result.stderr)
        log.flush()
        # 并行会话可能短暂占用统一 Release 输出；只重试输出占用，不掩盖真实编译错误。
        if result.returncode == 0 or 'LNK1104' not in result.stdout:
            break
        log.write(f'BUILD_RETRY_OUTPUT_LOCK attempt={attempt + 1}\n')
        time.sleep(5)
    require(result.returncode == 0, f'CLI build failed: exit {result.returncode}')
    properties = {}
    for line in result.stdout.splitlines():
        for key in ('IntDir', 'OutDir', 'VC_ExecutablePath_x64', 'Priority', 'SHA256'):
            if line.startswith(key + '='):
                properties[key] = line[len(key) + 1:]
    ok(properties.get('OutDir') == str(RELEASE), f'unexpected OutDir: {properties}')
    ok('HostX64' in properties.get('VC_ExecutablePath_x64', ''), f'unexpected compiler host: {properties}')
    ok(properties.get('Priority') == 'BelowNormal', f'unexpected build priority: {properties}')
    ok((properties.get('SHA256') or '').upper() == fingerprint(CLI).upper(),
       'build script SHA does not match the tested artifact')
    log.write(f'CLI_BUILD_EXIT={result.returncode} HOST={host} STARTED={started}\n')
    log.flush()
    return properties


def build_fixtures(log):
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
    assembler = compiler.with_name('ml64.exe')
    require(assembler.is_file(), f'HostX64 ml64 required next to {compiler}')
    log.write(f'INTDIR={INT_DIR}\nOUTDIR={RELEASE}\nHOSTX64={compiler}\nML64={assembler}\nPRIORITY=BelowNormal\n')
    commands = [
        f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 /c /Fostep_c.obj "{STEP_C}"',
        f'{initialize} && "{assembler}" /nologo /c /Fostep_asm.obj "{STEP_ASM}"',
        f'{initialize} && "{compiler}" /nologo step_c.obj step_asm.obj /link /OUT:"{STEP_TARGET}" '
        f'/DEF:"{STEP_DEF}" /IMPLIB:step_child.lib /MACHINE:X64',
        f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 "{AUX_C}" /link /OUT:"{AUX_TARGET}" '
        f'/IMPLIB:aux_child.lib /MACHINE:X64',
    ]
    for command in commands:
        log.write('RUN ' + command + '\n')
        log.flush()
        # 每个编译步骤都重新初始化 vcvars64，保证 INCLUDE/LIB 指向 HostX64 工具链。
        subprocess.run(shell + initialize + ' && ' + command, cwd=INT_DIR, stdout=log, stderr=subprocess.STDOUT,
                       creationflags=BELOW_NORMAL, timeout=180, check=True)
    log.write('STEP_CHILD_SHA256=' + fingerprint(STEP_TARGET) + '\nAUX_CHILD_SHA256=' + fingerprint(AUX_TARGET) + '\n')
    log.flush()


def remove_stale_fixtures():
    """Clear leftovers of an earlier interrupted run of this fixture only."""
    for target in (STEP_TARGET, AUX_TARGET):
        for _ in range(40):
            try:
                target.unlink(missing_ok=True)
                break
            except PermissionError:
                time.sleep(0.25)
    shutil.rmtree(INT_DIR, ignore_errors=True)


@contextmanager
def installed_fixtures(log):
    remove_stale_fixtures()
    require(not STEP_TARGET.exists() and not AUX_TARGET.exists() and not INT_DIR.exists(),
            f'Fixture outputs already exist: {STEP_TARGET}, {AUX_TARGET}, {INT_DIR}')
    INT_DIR.mkdir(parents=True)
    failed = False
    try:
        build_fixtures(log)
        yield
    except BaseException:
        failed = True  # 保留标记目录供异常取证；成功路径照常清理。
        raise
    finally:
        # 失败路径可能仍有自有目标持有映像；先等待退出再清理固定位置。
        for target in (STEP_TARGET, AUX_TARGET):
            for _ in range(40):
                try:
                    target.unlink(missing_ok=True)
                    break
                except PermissionError:
                    time.sleep(0.25)
        if not failed:
            shutil.rmtree(INT_DIR, ignore_errors=True)


class Session:
    def __init__(self, env, log, exe, site, *, input_mode='jsonl', condition=None, cooperative_pair=False):
        self.log = log
        self.lines = queue.Queue()
        self.session = None
        self.sequence = 0
        self.query_sequence = 0
        predicate = [] if condition is None else ['--condition', condition]
        pair = ['--cooperative-pair'] if cooperative_pair else []
        mode = ['--input', input_mode]
        self.process = subprocess.Popen(
            [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(exe), *site,
             '--confirm', '--disposition', 'resume-detach', *mode, *predicate, *pair],
            cwd=RELEASE, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
            encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.jsonl = input_mode == 'jsonl'
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def receive(self, kind, request_id=None):
        line = self.lines.get(timeout=10)
        require(line is not None, f'CLI closed stdout (exit={self.process.poll()})')
        self.log.write(f'[{datetime.now():%H:%M:%S}.{datetime.now().microsecond // 1000:03d}] RX ' + line)
        frame = json.loads(line)
        self.sequence += 1
        require(frame['schemaVersion'] == 1 and frame['streamSequence'] == str(self.sequence), frame)
        require(frame['type'] == kind and frame['requestId'] == request_id, frame)
        if self.session is None:
            self.session = frame['session']
        require(frame['session'] == self.session, frame)
        return frame['result']

    def send_raw(self, payload):
        line = json.dumps(payload, separators=(',', ':')) + '\n'
        self.log.write(f'[{datetime.now():%H:%M:%S}.{datetime.now().microsecond // 1000:03d}] TX ' + line)
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def send_line(self, text):
        self.log.write('TX ' + text + '\n')
        self.process.stdin.write(text + '\n')
        self.process.stdin.flush()

    def send(self, request_id, method, params=None, expected=None):
        request = dict(schemaVersion=1, requestId=request_id, method=method, session=self.session,
                       params=params if params is not None else {})
        if expected is not None:
            request['expected'] = expected
        self.send_raw(request)

    def request(self, request_id, method, params=None, expected=None, kind='response'):
        self.send(request_id, method, params, expected)
        return self.receive(kind, request_id)

    def status(self):
        if not self.jsonl:
            self.send_line('status')
            return self.receive('response')
        self.query_sequence += 1
        return self.request(f'query/{self.query_sequence}', 'control.query')

    def wait_armed(self, identity):
        deadline = time.monotonic() + 8
        while True:
            result = self.status()
            if not cooperative_pair_result(result):
                require((result['pid'], result['creationFileTime'], result['processInstanceId']) == identity, result)
            binding = result['breakpoint']['state']
            if binding == 'armed' and result.get('attached'):
                return result
            require(binding in ('installing', 'armed') and time.monotonic() < deadline, result)
            time.sleep(0.01)

    def wait_held(self, identity):
        deadline = time.monotonic() + 8
        while True:
            result = self.status()
            require((result['pid'], result['creationFileTime'], result['processInstanceId']) == identity, result)
            binding = result['breakpoint']['state']
            if binding == 'held' and 'stop' in result:
                return result
            require(binding in ('installing', 'armed', 'held') and time.monotonic() < deadline, result)
            time.sleep(0.01)

    def poll_step(self, request_id, states, timeout=12, after_stop_id=None):
        """Wait for a terminal step receipt; require the adopted stop to differ from the old one."""
        deadline = time.monotonic() + timeout
        while True:
            result = self.status()
            step = result.get('step')
            adopted = after_stop_id is None or result.get('stop', {}).get('id') != after_stop_id
            if step and step.get('requestId') == request_id and step.get('state') in states and adopted:
                return result, step
            require(time.monotonic() < deadline, f'step {request_id} never reached {states}: {result}')
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


def cooperative_pair_result(result):
    return result.get('mode') == 'cooperative-pair'


def checked_target(hello):
    # Only keep the real owned process object matching this CLI receipt and fixture path.
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_VM_READ |
                          PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, hello['targetPid'])
    require(handle, f'OpenProcess failed for owned target: {ct.get_last_error()}')
    try:
        created, exited, kernel, user = (win.FILETIME() for _ in range(4))
        require(GetThreadTimesForProcess(handle, created, exited, kernel, user), 'GetProcessTimes failed')
        require(str((created.dwHighDateTime << 32) | created.dwLowDateTime) == hello['targetCreationFileTime'], hello)
        length = win.DWORD(32768)
        path = ct.create_unicode_buffer(length.value)
        require(GetImagePath(handle, 0, path, ct.byref(length)), f'GetImagePath failed: {ct.get_last_error()}')
        require(Path(path.value) in (STEP_TARGET, AUX_TARGET), path.value)
        return handle
    except BaseException:
        CloseHandle(handle)
        raise


def GetThreadTimesForProcess(handle, *times):
    get = getattr(KERNEL, 'GetProcessTimes')
    get.restype = win.BOOL
    get.argtypes = [win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4]
    return get(handle, *times)


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


def step_params(mode, origin, *, mode_override=None, thread_override=None, tid_override=None,
                creation_override=None):
    return dict(mode=mode_override or mode,
                threadId=thread_override or origin['threadId'],
                tid=tid_override if tid_override is not None else origin['tid'],
                threadCreationFileTime=creation_override or origin['creationFileTime'])


def step_request_id(sequence):
    return f'step/{sequence}'


def error_step(session, sequence, params, *, omit_session=False, wrong_session=False, expected=True,
               method='control.step', request_id=None, stop=None):
    """Submit a step-shaped request expected to fail with a protocol error."""
    request_id = request_id or step_request_id(sequence)
    request = dict(schemaVersion=1, requestId=request_id, method=method, params=params)
    if not omit_session:
        request['session'] = (dict(id=str(uuid4()), epoch='0') if wrong_session else session.session)
    if expected:
        request['expected'] = dict(stopId=stop['id'], stateRevision=stop['stateRevision'])
    session.send_raw(request)
    return session.receive('error', request_id)


def submit_step(session, sequence, mode, stop, origin, kind='response'):
    expected = dict(stopId=stop['id'], stateRevision=stop['stateRevision'])
    return session.request(step_request_id(sequence), 'control.step', step_params(mode, origin), expected, kind=kind)


def query_step(session, sequence, request_id=None, kind='response'):
    session.query_sequence += 1
    return session.request(request_id or f'qstep/{session.query_sequence}', 'control.step.query',
                           dict(requestId=step_request_id(sequence)), kind=kind)


def cancel_step(session, sequence, request_id=None, kind='response'):
    session.query_sequence += 1
    return session.request(request_id or f'cstep/{session.query_sequence}', 'control.step.cancel',
                           dict(requestId=step_request_id(sequence)), kind=kind)


def check_execution_enter(result, address, identity, origin, stop):
    """A DR0 execution stop must project exactly one enter-attempt execution observation."""
    execution = result.get('execution')
    ok(execution is not None, 'held execution stop without an execution projection')
    ok(execution['kind'] == 'execution-enter-attempt', execution)
    ok(int(execution['instructionAddress'], 16) == address and execution['nextInstructionAddress'] is None, execution)
    ok(execution['pid'] == identity[0] and execution['processCreationFileTime'] == identity[1], execution)
    ok(execution['threadId'] == origin['threadId'] and execution['tid'] == origin['tid'] and
       execution['threadCreationFileTime'] == origin['creationFileTime'], execution)
    ok(execution['groupId'] == stop['groupId'] and execution['stopId'] == stop['id'] and
       execution['stateRevision'] == stop['stateRevision'], execution)
    ok(execution['source'] == 'native-debug-owner' and execution['event'] is not None and
       isinstance(execution['observedQpc'], str) and int(execution['observedQpc']) > 0 and
       int(execution['qpcFrequency']) > 0, execution)
    return execution


def check_execution_completed(result, start_ip, next_ip, identity, origin, stop):
    """A completed Into TF step must project the executed instruction and its next RIP."""
    execution = result.get('execution')
    ok(execution is not None, 'completed step stop without an execution projection')
    ok(execution['kind'] == 'instruction-completed', execution)
    ok(execution['instructionAddress'] == start_ip and execution['nextInstructionAddress'] == next_ip, execution)
    ok(execution['pid'] == identity[0] and execution['processCreationFileTime'] == identity[1], execution)
    ok(execution['threadId'] == origin['threadId'] and execution['tid'] == origin['tid'] and
       execution['threadCreationFileTime'] == origin['creationFileTime'], execution)
    ok(execution['groupId'] == stop['groupId'] and execution['stopId'] == stop['id'], execution)
    ok(execution['source'] == 'native-debug-owner' and execution['event'] is not None, execution)
    return execution


def check_no_execution(result, detail):
    """Over-call/out completions and data writes must not claim an executed instruction."""
    ok('execution' not in result or result.get('execution') is None, detail)


def check_step_identity(receipt, origin, sequence, mode):
    ok(receipt['requestId'] == step_request_id(sequence), receipt)
    ok(receipt['mode'] == mode, receipt)
    ok(receipt['threadId'] == origin['threadId'] and receipt['tid'] == origin['tid'] and
       receipt['threadCreationFileTime'] == origin['creationFileTime'], receipt)


def cli_module_base():
    """Base address of the formal CLI image in its own process (crash cross-reference)."""
    class ModuleEntry(ct.Structure):
        _fields_ = [('dwSize', win.DWORD), ('th32ModuleID', win.DWORD), ('th32ProcessID', win.DWORD),
                    ('GlblcntUsage', win.DWORD), ('ProccntUsage', win.DWORD), ('modBaseAddr', ct.c_void_p),
                    ('modBaseSize', win.DWORD), ('hModule', win.HANDLE), ('szModule', ct.c_char * 256),
                    ('szExePath', ct.c_char * 260)]

    snapshot = api('CreateToolhelp32Snapshot', win.HANDLE, win.DWORD, win.DWORD)(
        0x8 | 0x10, 0)  # TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    if not snapshot or snapshot == -1:
        return None
    try:
        entry = ModuleEntry()
        entry.dwSize = ct.sizeof(ModuleEntry)
        if not api('Module32First', win.BOOL, win.HANDLE, ct.POINTER(ModuleEntry))(snapshot, ct.byref(entry)):
            return None
        return entry.modBaseAddr
    finally:
        api('CloseHandle', win.BOOL, win.HANDLE)(snapshot)


def marker_path(name):
    """Fixed per-case marker file inside this fixture's own intermediate directory."""
    return INT_DIR / f'step-marker-{name}.txt'


def marker_text(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace').replace('\n', ' | ')
    except OSError:
        return '<no marker file>'


def marker_value(path, key):
    """Read one '<key>=<value>' entry from the fixture marker file."""
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith(key + '='):
            return line[len(key) + 1:]
    return None


def marker_count(path, key):
    """Count marker entries equal to the key or carrying it as a 'key=value' line."""
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return 0
    return sum(1 for line in text.splitlines()
               if line.strip() == key or line.strip().startswith(key + '='))


def wait_marker(path, key, timeout=8, count=1):
    """Wait until the owned fixture reports a marker entry."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker_count(path, key) >= count:
            return True
        time.sleep(0.02)
    return False


def spin_release(child, flag_address, value=1):
    """Write the owned fixture's user-mode spin flag; no syscall boundary is crossed."""
    require(flag_address is not None, 'the fixture did not publish its spin flag address')
    written = ct.c_size_t()
    payload = ct.c_int(value)
    require(WriteMemory(child, ct.c_void_p(flag_address), ct.byref(payload), ct.sizeof(payload),
                         ct.byref(written)) and written.value == ct.sizeof(payload),
            f'WriteProcessMemory failed for the spin flag: {ct.get_last_error()}')
    return flag_address


def wait_done(session, done, timeout, detail, child=None, marker=None):
    """Wait for the fixture's business completion while watching the live session state."""
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        if Wait(done, 100) == WAIT_OBJECT:
            return True, status
        try:
            status = session.status()
        except Exception:  # noqa: BLE001 - the session may already be closed
            status = None
    threads = ''
    if child is not None:
        threads = f' CHILD_ALIVE={Wait(child, 0) == WAIT_TIMEOUT}'
    trace = ''
    if marker is not None:
        trace = f' MARKER={marker_text(marker)}'
    raise RuntimeError(f'{detail} (last status={status}{threads}{trace})')


def drain_rounds(trigger, done, count=1, go=None):
    for _ in range(count):
        require(SetEvent(trigger), 'trigger detached round')
        if go is not None:
            require(SetEvent(go), 'release blocking callee')
        require(Wait(done, 8000) == WAIT_OBJECT, 'detached round did not complete')


def finish_child(session, child, trigger, done, go=None, rounds=1):
    session.send('shutdown', 'controller.shutdown')
    summary = session.receive('summary')
    closed = summary['control']
    ok(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['clean'] and
       not closed['attached'], summary)
    ok(closed['breakpoint']['state'] == 'retired' and closed['breakpoint']['enrolledThreads'] == '0', closed)
    ok(session.process.wait(timeout=8) == 0, 'formal CLI exit code')
    require(not attached(child), 'shutdown did not detach the owned target')
    drain_rounds(trigger, done, rounds, go)
    code = win.DWORD()
    exited = Wait(child, 8000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code))
    ok(exited and code.value == 0, f'fixture exit code: {code.value if exited else "unreadable"}')
    return summary


def cleanup_child(child):
    try:
        if Wait(child, 0) == WAIT_TIMEOUT:
            require(TerminateProcess(child, 3) and Wait(child, 5000) == WAIT_OBJECT,
                    'test target could not be stopped after failure')
    finally:
        CloseHandle(child)


def check_step_bytes(child, address, layout):
    """Verify the exact known instruction bytes at the breakpoint site.

    The fast callee is an ASM nop/ret leaf with fixed bytes; the slow callee is a
    real C function whose prologue is intentionally unknown (entered only via the
    proven TF frame, never decoded)."""
    raw = read_bytes(child, address, 16)
    if layout == 'fast':
        ok(raw[0] == 0x90 and raw[1] == 0x90 and raw[2] == 0xE8, raw.hex())
        callee = address + 7 + int.from_bytes(raw[3:7], 'little', signed=True)
        after = address + 7
        ok(read_bytes(child, callee, 2) == b'\x90\xc3', f'unexpected callee entry bytes at {callee:#x}')
    else:
        ok(raw[0] == 0x90 and raw[1] == 0xE8, raw.hex())
        callee = address + 6 + int.from_bytes(raw[2:6], 'little', signed=True)
        after = address + 6
        # 慢速被调方是真实 C 函数，其序言不可解码，只能确认它不是 ASM 叶子。
        ok(read_bytes(child, callee, 2) != b'\x90\xc3', f'slow callee must be the compiled function at {callee:#x}')
    ok(read_bytes(child, after, 2) == b'\x90\xc3', f'unexpected bytes at {after:#x}')
    return callee, after


def fast_session(log):
    """Round 1: protocol negatives, stale tokens, into chain, native rejections, replay.
    Round 2: into-chain into the call and an entry-proof step out."""
    global CHECKS
    name = 'fast'
    prefix = r'Local\KSwordProductStep-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = {}
    session = child = None
    try:
        for suffix in ('ready', 'trigger', 'done'):
            events[suffix] = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(events[suffix], f'CreateEvent {suffix} failed: {ct.get_last_error()}')
        ready, trigger, done = events['ready'], events['trigger'], events['done']
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'])
        hello = session.receive('hello')
        protocol = hello['stepProtocol']
        ok(protocol['modes'] == ['into', 'over-call', 'out'] and protocol['firstRequestId'] == 'step/1' and
           protocol['requestIdFormat'] == 'step/<next positive uint64 decimal>' and
           protocol['replayEntries'] == '128' and protocol['queryMethod'] == 'control.step.query', protocol)
        ok(hello['continueProtocol']['firstRequestId'] == 'continue/1', hello['continueProtocol'])
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_armed(identity)
        ok(armed['attached'] and attached(child), armed)
        address = int(armed['breakpoint']['address'], 16)
        callee_entry, after_call = check_step_bytes(child, address, 'fast')

        # ---- Round 1 -------------------------------------------------------
        require(SetEvent(trigger), 'trigger round 1')
        held = session.wait_held(identity)
        stop = held['stop']
        origin = held['originThread']
        ok(held['hit']['address'] == armed['breakpoint']['address'] and held['hit']['tid'] == origin['tid'], held)
        ok(origin['threadId'] and origin['tid'] and
           origin['creationFileTime'] == str(owned_thread_creation(identity[0], origin['tid'])), origin)
        ok('stop' in held and held['stopGroup']['id'] == stop['groupId'], held)
        check_execution_enter(held, address, identity, origin, stop)

        # Protocol negatives: wrong shape, missing/wrong session, bad query, missing expected.
        cases = [
            ('invalid-step', error_step(session, 1, step_params('sideways', origin), stop=stop)),
            ('invalid-step', error_step(session, 2, step_params('into', origin), omit_session=True, stop=stop)),
            ('wrong-session', error_step(session, 3, step_params('into', origin), wrong_session=True, stop=stop)),
            ('step-replay-expired', error_step(session, None, dict(requestId='step/999'),
                                               method='control.step.query', request_id='qneg/1', expected=False)),
            ('invalid-step-query', error_step(session, None, dict(requestId='step/1'),
                                              method='control.step.query', request_id='qneg/2',
                                              stop=stop)),
            ('invalid-step-request-id', error_step(session, None, dict(requestId='continue/1'),
                                                   method='control.step.query', request_id='qneg/3',
                                                   expected=False)),
            ('invalid-step', error_step(session, 4, step_params('into', origin), expected=False)),
        ]
        for index, (expected_error, result) in enumerate(cases):
            ok(result['errorId'] == expected_error, (index, result))
            ok(session.status()['stop'] == stop and Wait(done, 0) == WAIT_TIMEOUT, f'negative {index} moved the stop')

        # Frozen-identity mismatches consume their sequence and are replayable as saved errors.
        stale = [
            error_step(session, 1, step_params('into', origin, creation_override=str(int(origin['creationFileTime']) + 1)), stop=stop),
            error_step(session, 2, step_params('into', origin, tid_override=origin['tid'] + 1), stop=stop),
            error_step(session, 3, step_params('into', origin, thread_override='not-the-frozen-origin'), stop=stop),
            error_step(session, 4, step_params('into', origin),
                       stop={'id': stop['id'] + '0', 'stateRevision': stop['stateRevision']}),
            error_step(session, 5, step_params('into', origin),
                       stop={'id': stop['id'], 'stateRevision': str(int(stop['stateRevision']) + 1)}),
        ]
        for index, result in enumerate(stale):
            ok(result['errorId'] == 'stale-stop', (index, result))
        replay_error = query_step(session, 1, kind='error')
        ok(replay_error['errorId'] == 'stale-stop', replay_error)
        ok(session.status()['stop'] == stop and Wait(done, 0) == WAIT_TIMEOUT, 'stale round moved the stop')

        # First positive: one TF single step from site[0] to site[1].
        first = submit_step(session, 6, 'into', stop, origin)
        ok(first['step']['state'] == 'running' and first['step']['requestId'] == 'step/6', first)
        result, receipt = session.poll_step('step/6', ('completed',), after_stop_id=stop['id'])
        check_step_identity(receipt, origin, 6, 'into')
        ok(int(receipt['startIp'], 16) == address and int(receipt['observedIp'], 16) == address + 1 and
           receipt['observedSp'] == receipt['startSp'], receipt)
        ok(receipt['destination'] is None and receipt['win32Error'] == 0 and receipt['resourcesRestored'] is True,
           receipt)
        stop2 = result['stop']
        ok(receipt['stopGroupId'] == stop2['groupId'] and stop2['id'] != stop['id'] and
           receipt['observedEvent'] is not None, (receipt, stop2))
        ok('hit' not in result and result['originThread']['tid'] == origin['tid'], result)
        check_execution_completed(result, receipt['startIp'], receipt['observedIp'], identity, origin, stop2)

        # Exact replay returns the same submission receipt without executing again.
        replay = submit_step(session, 6, 'into', stop, origin)
        ok(replay == first, 'step replay changed its receipt')
        ok(session.status()['stop'] == stop2 and Wait(done, 0) == WAIT_TIMEOUT, 'replay executed a second step')
        conflict = submit_step(session, 6, 'over-call', stop, origin, kind='error')
        ok(conflict['errorId'] == 'request-id-conflict', conflict)
        saved = query_step(session, 6)
        ok(saved['step']['state'] == 'completed' and saved['step']['stopGroupId'] == stop2['groupId'], saved)

        # Native rejections at a non-call stop keep the original stop held. The owner
        # reports the failed Prepare via a recovery-required step receipt even though
        # nothing was armed (handoff note: validation-only failure, no recovery needed).
        rejected_over = submit_step(session, 7, 'over-call', stop2, origin)
        ok(rejected_over['state'] == 'rejected' and rejected_over['stage'] == 'step-over-requires-call' and
           rejected_over['step']['requestId'] == 'step/7' and
           rejected_over['step']['state'] == 'recovery-required', rejected_over)
        rejected_out = submit_step(session, 8, 'out', stop2, origin)
        ok(rejected_out['state'] == 'rejected' and rejected_out['stage'] == 'step-out-frame-unproven' and
           rejected_out['step']['requestId'] == 'step/8', rejected_out)
        ok(session.status()['stop'] == stop2 and Wait(done, 0) == WAIT_TIMEOUT, 'rejection moved the stop')

        # into-chain: site[1] -> call -> over-call -> after-call -> ret -> return site.
        submit_step(session, 9, 'into', stop2, origin)
        result, r9 = session.poll_step('step/9', ('completed',), after_stop_id=stop2['id'])
        stop3 = result['stop']
        ok(int(r9['observedIp'], 16) == address + 2 and r9['resourcesRestored'] is True, r9)
        submit_step(session, 10, 'over-call', stop3, origin)
        result, r10 = session.poll_step('step/10', ('completed',), after_stop_id=stop3['id'])
        stop4 = result['stop']
        check_step_identity(r10, origin, 10, 'over-call')
        ok(int(r10['destination'], 16) == address + 7 and int(r10['observedIp'], 16) == address + 7 and
           r10['observedSp'] == r10['startSp'], r10)
        check_no_execution(result, 'over-call completion must not claim an executed instruction')
        submit_step(session, 11, 'into', stop4, origin)
        result, r11 = session.poll_step('step/11', ('completed',), after_stop_id=stop4['id'])
        stop5 = result['stop']
        ok(int(r11['observedIp'], 16) == address + 8, r11)
        submit_step(session, 12, 'into', stop5, origin)
        result, r12 = session.poll_step('step/12', ('completed',), after_stop_id=stop5['id'])
        stop6 = result['stop']
        ok(int(r12['observedIp'], 16) not in range(address, address + 9) and
           int(r12['observedSp'], 16) == int(r12['startSp'], 16) + 8, r12)
        released = session.request('continue/1', 'control.continue',
                                   expected=dict(stopId=stop6['id'], stateRevision=stop6['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 5000) == WAIT_OBJECT, released)
        ok(session.wait_armed(identity)['breakpoint']['state'] == 'armed', 'breakpoint not re-armed')

        # ---- Round 2: step into the call and step out via the entry proof --
        require(SetEvent(trigger), 'trigger round 2')
        held = session.wait_held(identity)
        stopA, originA = held['stop'], held['originThread']
        ok(originA == origin, originA)
        # The previous Into receipt must not pollute this fresh DR0 hit.
        check_execution_enter(held, address, identity, originA, stopA)
        submit_step(session, 13, 'into', stopA, originA)
        result, _ = session.poll_step('step/13', ('completed',), after_stop_id=stopA['id'])
        stopB = result['stop']
        submit_step(session, 14, 'into', stopB, originA)
        result, _ = session.poll_step('step/14', ('completed',), after_stop_id=stopB['id'])
        stopC = result['stop']
        submit_step(session, 15, 'into', stopC, originA)
        result, r15 = session.poll_step('step/15', ('completed',), after_stop_id=stopC['id'])
        stopD = result['stop']
        ok(int(r15['observedIp'], 16) == callee_entry and int(r15['observedSp'], 16) == int(r15['startSp'], 16) - 8, r15)
        out = submit_step(session, 16, 'out', stopD, originA)
        ok(out['step']['state'] == 'running' and int(out['step']['destination'], 16) == address + 7, out)
        result, r16 = session.poll_step('step/16', ('completed',), after_stop_id=stopD['id'])
        stopE = result['stop']
        check_step_identity(r16, originA, 16, 'out')
        ok(int(r16['observedIp'], 16) == address + 7 and int(r16['observedSp'], 16) == int(r16['startSp'], 16) + 8 and
           r16['resourcesRestored'] is True and int(r16['destination'], 16) == address + 7, r16)
        check_no_execution(result, 'step-out completion must not claim an executed instruction')
        released = session.request('continue/2', 'control.continue',
                                   expected=dict(stopId=stopE['id'], stateRevision=stopE['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 5000) == WAIT_OBJECT, released)

        finish_child(session, child, trigger, done, rounds=1)
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            for handle in events.values():
                CloseHandle(handle)


def slow_session(log, cancel=True):
    """Round 1: in-flight over-call query and cancellation while the callee spins in user mode.
    Round 2: in-flight step out completed by releasing the user-mode spin."""
    global CHECKS
    name = 'slow-cancel' if cancel else 'slow-out'
    drain = 1 if cancel else 2
    prefix = r'Local\KSwordProductStep-' + uuid4().hex
    marker = marker_path(name)
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='slow',
               KSWORD_PRODUCT_STEP_MARKER=str(marker), KSWORD_PRODUCT_STEP_MARK_ROUNDS='1',
               KSWORD_PRODUCT_STEP_SPIN='0')
    events = {}
    session = child = None
    flag = None
    try:
        for suffix in ('ready', 'trigger', 'done'):
            events[suffix] = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(events[suffix], f'CreateEvent {suffix} failed: {ct.get_last_error()}')
        # 被调方在原良性系统调用等待（g_block）上阻塞：手动复位事件保证放行信号不早于等待丢失。
        events['go'] = CreateEvent(None, True, False, f'{prefix}-go')
        require(events['go'], f'CreateEvent go failed: {ct.get_last_error()}')
        ready, trigger, done = (events[k] for k in ('ready', 'trigger', 'done'))
        go = events['go']
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSlowSite'])
        hello = session.receive('hello')
        ok(hello['stepProtocol']['modes'] == ['into', 'over-call', 'out'], hello['stepProtocol'])
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_armed(identity)
        address = int(armed['breakpoint']['address'], 16)
        blocking_entry, after_call = check_step_bytes(child, address, 'slow')
        require(wait_marker(marker, 'flag'), 'the fixture did not publish its spin flag')
        flag = int(marker_value(marker, 'flag'), 16)
        log.write(f'CLI_MODULE_BASE=0x{cli_module_base() or 0:x} SPIN_FLAG=0x{flag:x} '
                  f'CALLEE_WAIT=system-call-event\n')
        log.flush()

        def release_callee():
            """放行被调方：复用夹具原有的 g_block 事件句柄，不写目标内存。"""
            require(SetEvent(go), 'release the blocked callee')

        # ---- Round 1: in-flight over-call and (optional) cancellation ------
        sequence = 0

        def step_number():
            nonlocal sequence
            sequence += 1
            return sequence

        require(SetEvent(trigger), 'trigger slow round 1')
        held = session.wait_held(identity)
        stop, origin = held['stop'], held['originThread']
        check_execution_enter(held, address, identity, origin, stop)
        first_step = step_number()
        submit_step(session, first_step, 'into', stop, origin)
        result, _ = session.poll_step(f'step/{first_step}', ('completed',), after_stop_id=stop['id'])
        stop2 = result['stop']
        if cancel:
            over_step = step_number()
            over = submit_step(session, over_step, 'over-call', stop2, origin)
            ok(over['step']['state'] == 'running' and int(over['step']['destination'], 16) == address + 6, over)
            require(wait_marker(marker, 'round-enter'), 'the fixture did not enter the round')
            inflight = query_step(session, over_step)
            ok(inflight['step']['state'] == 'running' and inflight['step']['resourcesRestored'] is False, inflight)
            cancelled = cancel_step(session, over_step)
            ok(cancelled['step']['state'] in ('running', 'cancelled'), cancelled)
            result, receipt = session.poll_step(f'step/{over_step}', ('cancelled',), timeout=15,
                                                after_stop_id=stop2['id'])
            stop3 = result['stop']
            ok(receipt['state'] == 'cancelled' and receipt['resourcesRestored'] is True and
               receipt['stopGroupId'] == stop3['groupId'], receipt)
            ok('hit' not in result and stop3['id'] != stop2['id'] and Wait(done, 0) == WAIT_TIMEOUT, result)
            check_no_execution(result, 'cancelled step must not claim an executed instruction')
            released = session.request('continue/1', 'control.continue',
                                       expected=dict(stopId=stop3['id'], stateRevision=stop3['stateRevision']))
            ok(released['release']['result'] == 'continued', released)
            release_callee()
            finished, _ = wait_done(session, done, 8, 'the blocked callee did not finish after cancel', child, marker)
            ok(finished, 'the blocked callee did not finish after cancel')
            ok(session.wait_armed(identity)['breakpoint']['state'] == 'armed',
               'breakpoint not re-armed after cancel')
            # 下一轮重新武装放行事件：手动复位事件放行后保持置位，必须显式复位。
            require(ResetEvent(go), 'arm the second slow round')

            # ---- Round 2: step into the blocked callee, query in flight, out --
            require(SetEvent(trigger), 'trigger slow round 2')
            held = session.wait_held(identity)
            stop4, origin4 = held['stop'], held['originThread']
            check_execution_enter(held, address, identity, origin4, stop4)
            round2 = step_number()
            submit_step(session, round2, 'into', stop4, origin4)
            result, _ = session.poll_step(f'step/{round2}', ('completed',), after_stop_id=stop4['id'])
            stop5 = result['stop']
            round2 = step_number()
            submit_step(session, round2, 'into', stop5, origin4)
            result, r4 = session.poll_step(f'step/{round2}', ('completed',), after_stop_id=stop5['id'])
            stop6 = result['stop']
            ok(int(r4['observedIp'], 16) == blocking_entry and int(r4['observedSp'], 16) == int(r4['startSp'], 16) - 8, r4)
            out_step = step_number()
            out = submit_step(session, out_step, 'out', stop6, origin4)
            ok(out['step']['state'] == 'running' and int(out['step']['destination'], 16) == address + 6, out)
            require(wait_marker(marker, 'round-enter', count=2), 'the fixture did not enter the second round')
            inflight = query_step(session, out_step)
            ok(inflight['step']['state'] == 'running' and inflight['step']['resourcesRestored'] is False, inflight)
            release_callee()
            result, r5 = session.poll_step(f'step/{out_step}', ('completed',), after_stop_id=stop6['id'])
            stop7 = result['stop']
            check_step_identity(r5, origin4, out_step, 'out')
            ok(int(r5['observedIp'], 16) == address + 6 and int(r5['observedSp'], 16) == int(r5['startSp'], 16) + 8 and
               r5['resourcesRestored'] is True, r5)
            check_no_execution(result, 'step-out completion must not claim an executed instruction')
            released = session.request('continue/2', 'control.continue',
                                       expected=dict(stopId=stop7['id'], stateRevision=stop7['stateRevision']))
            ok(released['release']['result'] == 'continued', released)
            finished, _ = wait_done(session, done, 8, 'the released round did not finish', child, marker)
            ok(finished, 'the released round did not finish')
            after = cancel_step(session, out_step)
            ok(after['step']['state'] == 'completed' and after['step']['stopGroupId'] == stop7['groupId'], after)
        else:
            # 只走跳出路径：步入被调方后在途查询，放行自旋后由硬件断点完成。
            second = step_number()
            submit_step(session, second, 'into', stop2, origin)
            result, r4 = session.poll_step(f'step/{second}', ('completed',), after_stop_id=stop2['id'])
            stop6 = result['stop']
            ok(int(r4['observedIp'], 16) == blocking_entry and int(r4['observedSp'], 16) == int(r4['startSp'], 16) - 8, r4)
            out_step = step_number()
            out = submit_step(session, out_step, 'out', stop6, origin)
            ok(out['step']['state'] == 'running' and int(out['step']['destination'], 16) == address + 6, out)
            require(wait_marker(marker, 'round-enter'), 'the fixture did not enter the round')
            inflight = query_step(session, out_step)
            ok(inflight['step']['state'] == 'running' and inflight['step']['resourcesRestored'] is False, inflight)
            release_callee()
            result, r5 = session.poll_step(f'step/{out_step}', ('completed',), after_stop_id=stop6['id'])
            stop7 = result['stop']
            check_step_identity(r5, origin, out_step, 'out')
            ok(int(r5['observedIp'], 16) == address + 6 and int(r5['observedSp'], 16) == int(r5['startSp'], 16) + 8 and
               r5['resourcesRestored'] is True, r5)
            check_no_execution(result, 'step-out completion must not claim an executed instruction')
            released = session.request('continue/1', 'control.continue',
                                       expected=dict(stopId=stop7['id'], stateRevision=stop7['stateRevision']))
            ok(released['release']['result'] == 'continued', released)
            finished, _ = wait_done(session, done, 8, 'the released round did not finish', child, marker)
            ok(finished, 'the released round did not finish')

        # 关闭后自有目标仍会进入一次被调方；脱离后由协调者放行自旋并等待正常退出。
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        closed = summary['control']
        ok(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['clean'] and
           not closed['attached'] and closed['breakpoint']['state'] == 'retired' and
           closed['breakpoint']['enrolledThreads'] == '0', summary)
        ok(session.process.wait(timeout=8) == 0, 'formal CLI exit code')
        require(not attached(child), 'shutdown did not detach the owned target')
        require(ResetEvent(go), 'arm the detached round')
        require(SetEvent(trigger), 'trigger the detached round')
        release_callee()
        require(Wait(done, 8000) == WAIT_OBJECT, 'the detached round did not complete')
        for _ in range(drain - 1):
            require(ResetEvent(go), 'arm the remaining detached round')
            require(SetEvent(trigger), 'trigger the remaining detached round')
            release_callee()
            require(Wait(done, 8000) == WAIT_OBJECT, 'a detached round did not complete')
        code = win.DWORD()
        exited = Wait(child, 8000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code))
        ok(exited and code.value == 0, f'fixture exit code: {code.value if exited else "unreadable"}')
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            for handle in events.values():
                CloseHandle(handle)


def condition_session(log):
    """Condition sessions hold breakpoint hits but never auto-release step stops."""
    global CHECKS
    name = 'condition'
    prefix = r'Local\KSwordProductStep-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = {}
    session = child = None
    try:
        for suffix in ('ready', 'trigger', 'done'):
            events[suffix] = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(events[suffix], f'CreateEvent {suffix} failed: {ct.get_last_error()}')
        ready, trigger, done = events['ready'], events['trigger'], events['done']
        # 恒真表达式：命中真实用户态停点即成立，不依赖会话启动耗时的时间窗。
        expression = 'stop.thread.rip > 0xffffffffu64 && stop.thread.creationFileTime > 0u64'
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], condition=expression)
        hello = session.receive('hello')
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_armed(identity)
        address = int(armed['breakpoint']['address'], 16)

        require(SetEvent(trigger), 'trigger condition round 1')
        held = session.wait_held(identity)
        stop, origin = held['stop'], held['originThread']
        condition = held['condition']
        ok(condition['trueCount'] == '1' and condition['falseCount'] == '0' and
           condition['unknownCount'] == '0' and condition['last']['action'] == 'hold' and
           condition['last']['truth'] == 'true' and condition['last']['groupId'] == held['stopGroup']['id'],
           condition)

        submit = submit_step(session, 1, 'into', stop, origin)
        result, receipt = session.poll_step('step/1', ('completed',), after_stop_id=stop['id'])
        stop2 = result['stop']
        ok(receipt['state'] == 'completed' and int(receipt['observedIp'], 16) == address + 1, receipt)
        # The ordinary step stop must not be judged by, or released through, the breakpoint condition.
        ok('hit' not in result and condition['trueCount'] == '1' and result['condition']['trueCount'] == '1' and
           result['stop'] == stop2 and Wait(done, 0) == WAIT_TIMEOUT, result)
        released = session.request('continue/1', 'control.continue',
                                   expected=dict(stopId=stop2['id'], stateRevision=stop2['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 5000) == WAIT_OBJECT, released)

        require(SetEvent(trigger), 'trigger condition round 2')
        held = session.wait_held(identity)
        stop3 = held['stop']
        condition = held['condition']
        ok(condition['trueCount'] == '2' and condition['last']['action'] == 'hold' and
           condition['last']['groupId'] == held['stopGroup']['id'] and stop3['id'] != stop['id'], condition)
        submit_step(session, 2, 'into', stop3, held['originThread'])
        result, _ = session.poll_step('step/2', ('completed',), after_stop_id=stop3['id'])
        stop4 = result['stop']
        ok(result['condition']['trueCount'] == '2' and Wait(done, 0) == WAIT_TIMEOUT, result)
        released = session.request('continue/2', 'control.continue',
                                   expected=dict(stopId=stop4['id'], stateRevision=stop4['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 5000) == WAIT_OBJECT, released)

        finish_child(session, child, trigger, done, rounds=1)
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            for handle in events.values():
                CloseHandle(handle)


def repl_session(log):
    """REPL step / step-status / step-cancel plus usage errors and quit."""
    global CHECKS
    name = 'repl'
    prefix = r'Local\KSwordProductStep-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = {}
    session = child = None
    try:
        for suffix in ('ready', 'trigger', 'done'):
            events[suffix] = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(events[suffix], f'CreateEvent {suffix} failed: {ct.get_last_error()}')
        ready, trigger, done = events['ready'], events['trigger'], events['done']
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], input_mode='repl')
        hello = session.receive('hello')
        ok(hello['stepProtocol']['firstRequestId'] == 'step/1', hello['stepProtocol'])
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_armed(identity)
        address = int(armed['breakpoint']['address'], 16)

        session.send_line('help')
        usage = session.receive('response')
        ok('step into|over-call|out' in usage and 'step-status STEP_REQUEST_ID' in usage, usage)

        require(SetEvent(trigger), 'trigger repl round')
        held = session.wait_held(identity)
        stop, origin = held['stop'], held['originThread']
        session.send_line(f"step into {stop['id']} {stop['stateRevision']} {origin['threadId']} "
                          f"{origin['tid']} {origin['creationFileTime']}")
        reply = session.receive('response')
        ok(reply['step']['state'] == 'running' and reply['step']['requestId'] == 'step/1', reply)
        result, receipt = session.poll_step('step/1', ('completed',), after_stop_id=stop['id'])
        stop2 = result['stop']
        ok(int(receipt['observedIp'], 16) == address + 1 and receipt['resourcesRestored'] is True, receipt)

        session.send_line('step-status step/1')
        saved = session.receive('response')
        ok(saved['step']['state'] == 'completed' and saved['step']['stopGroupId'] == stop2['groupId'], saved)
        session.send_line('step-cancel step/1')
        after = session.receive('response')
        ok(after['step']['state'] == 'completed', after)

        session.send_line(f"continue {stop2['id']} {stop2['stateRevision']}")
        released = session.receive('response')
        ok(released['release']['result'] == 'continued' and Wait(done, 5000) == WAIT_OBJECT, released)

        session.send_line('step sideways X 1 t 1 1')
        bad_mode = session.receive('error')
        ok(bad_mode['errorId'] == 'invalid-step', bad_mode)
        session.send_line('step-status step/7')
        unknown = session.receive('error')
        ok(unknown['errorId'] == 'step-replay-expired', unknown)

        session.send_line('quit')
        summary = session.receive('summary')
        closed = summary['control']
        ok(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['clean'] and
           not closed['attached'] and closed['breakpoint']['state'] == 'retired', summary)
        ok(session.process.wait(timeout=8) == 0 and not attached(child), 'REPL quit did not clean up')
        drain_rounds(trigger, done, 2)
        code = win.DWORD()
        ok(Wait(child, 8000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code)) and code.value == 0,
           'fixture exit code')
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            for handle in events.values():
                CloseHandle(handle)


def pair_negative(log):
    """A cooperative pair session must reject the step entry while idle."""
    global CHECKS
    name = 'pair-reject'
    prefix = r'Local\KSwordProductPair-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_BREAKPOINT_PAIR_EVENTS=prefix)
    events = []
    children = []
    session = None
    try:
        configured = CreateEvent(None, True, False, f'{prefix}-configured')
        require(configured, 'CreateEvent configured failed')
        events.append(configured)
        session = Session(env, log, AUX_TARGET, ['--export', 'ExportedTick'], cooperative_pair=True)
        hello = session.receive('hello')
        control = hello['control']
        members = control['members']
        ok(control['mode'] == 'cooperative-pair' and control['frozen'] and len(members) == 2, hello)
        identities = [(member['pid'], member['creationFileTime']) for member in members]
        triggers, completions = [], []
        for pid, creation in identities:
            children.append(checked_target(dict(targetPid=pid, targetCreationFileTime=creation)))
            triggers.append(CreateEvent(None, False, False, f'{prefix}-{pid}-trigger'))
            completions.append(CreateEvent(None, False, False, f'{prefix}-{pid}-done'))
            events.extend([triggers[-1], completions[-1]])
        require(SetEvent(configured), 'allow cooperative workloads to initialize')
        deadline = time.monotonic() + 8
        while True:
            report = session.status()
            if report['state'] == 'running' and all(
                    member['gateOpened'] and member['control']['breakpoint']['state'] == 'armed'
                    for member in report['members']):
                break
            require(report['state'] in ('starting', 'running') and time.monotonic() < deadline, report)
            time.sleep(0.01)
        # hello advertises the protocol shape, but dispatch must reject the entry for pair sessions.
        rejection = error_step(session, 1, dict(mode='into', threadId='x', tid=1, threadCreationFileTime='1'),
                               stop=None, expected=False)
        ok(rejection['errorId'] == 'step-mode-unavailable', rejection)
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        closed = summary['control']
        ok(summary['exitCode'] == 0 and closed['state'] == 'closed' and closed['endReason'] == 'requested' and
           closed['clean'] and len(closed['members']) == 2 and
           all(member['control']['clean'] and not member['control']['attached'] for member in closed['members']),
           summary)
        ok(session.process.wait(timeout=8) == 0 and
           all(not attached(child) for child in children), 'pair shutdown did not detach')
        for index in range(ROUNDS):
            for trigger, completion in zip(triggers, completions):
                require(SetEvent(trigger), f'pair trigger {index}')
            for completion in completions:
                require(Wait(completion, 8000) == WAIT_OBJECT, f'pair round {index} did not complete')
        codes = []
        for child in children:
            code = win.DWORD()
            require(Wait(child, 8000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code)), 'pair child exit')
            codes.append(code.value)
        ok(codes == [0, 0], f'pair children exit codes: {codes}')
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            for child in children:
                cleanup_child(child)
            for handle in events:
                CloseHandle(handle)


def data_negative(log):
    """A data-write session reports a null step protocol and rejects the entry."""
    global CHECKS
    name = 'data-reject'
    prefix = r'Local\KSwordProductBreakpoint-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_BREAKPOINT_EVENTS=prefix, KSWORD_PRODUCT_BREAKPOINT_WRITE_WATCH='1',
               KSWORD_PRODUCT_BREAKPOINT_WATCH_WIDTH='4')
    events = []
    child = session = None
    try:
        for suffix in ('ready', 'trigger', 'done'):
            handle = CreateEvent(None, False, False, f'{prefix}-{suffix}')
            require(handle, f'CreateEvent {suffix} failed: {ct.get_last_error()}')
            events.append(handle)
        ready, trigger, done = events
        session = Session(env, log, AUX_TARGET, ['--export', 'WatchedData', '--watch-write-bytes', '4'])
        hello = session.receive('hello')
        ok(hello['stepProtocol'] is None, hello)
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_armed(identity)
        ok(armed['breakpoint']['watchedBytes'] == 4, armed)
        rejection = error_step(session, 1, dict(mode='into', threadId='x', tid=1, threadCreationFileTime='1'),
                               stop=None, expected=False)
        ok(rejection['errorId'] == 'step-mode-unavailable', rejection)
        # The first round writes the same value, so no data stop is expected.
        require(SetEvent(trigger) and Wait(done, 8000) == WAIT_OBJECT, 'same-value write did not complete')
        # The second round really changes the watched byte and must not project an execution observation.
        require(SetEvent(trigger), 'trigger the real data change')
        held = session.wait_held(identity)
        ok(held['hit']['phase'] == 'data-write-observed' and held['hit']['changedByteMask'] == 1, held)
        check_no_execution(held, 'data write stop must not project an execution observation')
        ok(Wait(done, 0) == WAIT_TIMEOUT, 'data write completed before release')
        stop = held['stop']
        released = session.request('continue/1', 'control.continue',
                                   expected=dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 8000) == WAIT_OBJECT, released)
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        closed = summary['control']
        ok(summary['exitCode'] == 0 and closed['clean'] and not closed['attached'] and
           closed['breakpoint']['state'] == 'retired', summary)
        ok(session.process.wait(timeout=8) == 0 and not attached(child), 'data shutdown did not detach')
        drain_rounds(trigger, done, 2)
        code = win.DWORD()
        ok(Wait(child, 8000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code)) and code.value == 0,
           'fixture exit code')
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            for handle in events:
                CloseHandle(handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutex-timeout-ms', type=int, default=30000)
    parser.add_argument('--suite', choices=('focused', 'full'), default='focused',
                        help='focused: fast + slow-cancel; full: every legacy case')
    parser.add_argument('--skip-build', action='store_true',
                        help='reuse the formal CLI built once by the batch; still report its actual SHA')
    parser.add_argument('--case', action='append', default=None,
                        help='Run only the named case (repeatable): fast, slow-cancel, slow-out, condition, repl, pair-reject, data-reject')
    args = parser.parse_args()
    cases = {'fast': fast_session, 'slow-cancel': lambda log: slow_session(log, True),
             'slow-out': lambda log: slow_session(log, False), 'condition': condition_session,
             'repl': repl_session, 'pair-reject': pair_negative, 'data-reject': data_negative}
    focused = ('fast', 'slow-cancel')
    names = args.case or (list(focused) if args.suite == 'focused' else list(cases))
    selected = [(name, cases[name]) for name in names]
    mutex = acquire_mutex(args.mutex_timeout_ms)
    started = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
    log_path = REPO / '.codex-build-logs' / f'action-analyze-cli-step-{datetime.now():%Y%m%d-%H%M%S}.log'
    try:
        with log_path.open('w', encoding='utf-8', buffering=1) as log:
            log.write(f'CLI_STEP_VALIDATION started={started} mutex={MUTEX_NAME} held by pid={os.getpid()} '
                      f'suite={args.suite} cases={",".join(name for name, _ in selected)}\n')
            if args.skip_build:
                build_properties = {'skipped': 'true'}
                log.write('CLI_BUILD=skipped (shared batch build)\n')
            else:
                build_properties = build_cli(log)
            cli_sha = fingerprint(CLI)
            log.write(f'CLI_SHA256={cli_sha}\n')
            with installed_fixtures(log):
                fixture_sha = fingerprint(STEP_TARGET)
                aux_sha = fingerprint(AUX_TARGET)
                for case_name, case in selected:
                    case(log)
            receipt = {
                'generatedAt': datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds'),
                'mutex': MUTEX_NAME,
                'suite': args.suite,
                'cli': {'sha256': cli_sha, 'size': CLI.stat().st_size},
                'build': {'script': str(BUILD_SCRIPT), 'skipped': args.skip_build,
                          'intDir': build_properties.get('IntDir'),
                          'outDir': build_properties.get('OutDir'),
                          'compiler': build_properties.get('VC_ExecutablePath_x64'),
                          'priority': build_properties.get('Priority'),
                          'exitCode': None if args.skip_build else 0},
                'fixtures': {'stepChild': {'path': str(STEP_TARGET), 'sha256': fixture_sha},
                             'auxChild': {'path': str(AUX_TARGET), 'sha256': aux_sha},
                             'intDir': str(INT_DIR)},
                'cases': [name for name, _ in selected],
                'assertions': CHECKS,
                'log': str(log_path),
            }
            RECEIPT.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
            log.write(f'RECEIPT={RECEIPT} ASSERTIONS={CHECKS} RESULT=PASS\n')
        print(f'PASS assertions={CHECKS} receipt={RECEIPT} log={log_path}')
    finally:
        release_mutex(mutex)


if __name__ == '__main__':
    main()
