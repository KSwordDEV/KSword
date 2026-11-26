"""Formal CLI native execution archive validation.

Covers the formal Release ``KswordCLI`` native execution project wiring only:

  * ``--project`` / ``--sample`` write lease; single-target execution scope only
  * REPL ``execution-save`` and JSONL ``control.execution.save`` at a real DR0 stop
  * idempotent save of the same native event (same coordinates, no second segment)
  * exact stale / wrong / missing session and non-canonical revision rejection
  * Into TF step producing the next saved segment
  * ``analyze execution read`` per segment, default ordinal, SHA-256 and endpoints
  * session close then a new session continuing the same sample
  * writer lease conflict rejects the launch before the target starts
  * bad tail / missing middle segment / existing later segment reject the launch
  * feasible failed write keeps raw.written/raw.flushed and blocks later segments
  * ``analyze execution correlate`` positives and negatives over a real native archive
  * static 4096 session save limit boundary (documented, not executed to the limit)

Owned targets are the repository step fixtures rebuilt into this script's own
fixed ``IntDir`` and output names; the runtime is never copied.  The caller
holds ``Local\\KSword.ActionAnalyze.CliValidation`` for the whole CLI build +
run batch; this script acquires it itself (in <=60 s waits, recording the
wait) and releases it on the same (main) thread in ``finally``.
"""

import ctypes as ct
from ctypes import wintypes as win
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
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
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent))

from api_evidence import archive_line
from api_transfer_archive import injection_packet
from continuous_etw import shutdown as controller_shutdown
from live_etw import call as controller_call
from live_etw import controller as open_controller
from passive_api_session import CREATION, SESSION_ID, wait_for_segment

REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
STEP_TARGET = RELEASE / 'ActionAnalyzeNativeExecutionChild.exe'
AUX_TARGET = RELEASE / 'ActionAnalyzeNativeExecutionAuxChild.exe'
INT_DIR = REPO / 'KswordCLI' / 'x64' / 'Release' / 'NativeExecutionValidation'
WORK = Path(__file__).with_name('native-execution-project')
STEP_C = Path(__file__).with_name('product_step_child.c')
STEP_ASM = Path(__file__).with_name('product_step_child.asm')
STEP_DEF = Path(__file__).with_name('product_step_child.def')
AUX_C = Path(__file__).with_name('product_breakpoint_child.c')
BUILD_SCRIPT = REPO / 'tools' / 'Invoke-KSwordNativeBuildCheck.ps1'
LOG_DIR = REPO / '.codex-build-logs'
MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
SEGMENT_LIMIT = 4096
WAIT_OBJECT = 0
WAIT_ABANDONED = 128
WAIT_TIMEOUT = 258
BELOW_NORMAL = 0x4000
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_TERMINATE = 0x1
SYNCHRONIZE = 0x100000
SEGMENT_HEADER_BYTES = 96
BLOCK_HEADER_BYTES = 80
RECORD_HEADER_BYTES = 32


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
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
GetThreadTimes = api('GetThreadTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetExitCode = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetImagePath = api('QueryFullProcessImageNameW', win.BOOL, win.HANDLE, win.DWORD, win.LPWSTR, ct.POINTER(win.DWORD))
CheckDebugger = api('CheckRemoteDebuggerPresent', win.BOOL, win.HANDLE, ct.POINTER(win.BOOL))
TerminateProcess = api('TerminateProcess', win.BOOL, win.HANDLE, win.UINT)
ReadMemory = api('ReadProcessMemory', win.BOOL, win.HANDLE, ct.c_void_p, win.LPVOID, ct.c_size_t,
                 ct.POINTER(ct.c_size_t))
CreateMutex = api('CreateMutexW', win.HANDLE, ct.c_void_p, win.BOOL, win.LPCWSTR)

CHECKS = 0


def ok(condition, detail):
    """One recorded assertion; failures abort the current case."""
    global CHECKS
    CHECKS += 1
    require(condition, detail)
    return condition


def crc32c(data):
    """Independent CRC-32C (Castagnoli) reference used to verify fixture bytes."""
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def uuid_bytes(text):
    """RFC 4122 text order used by the segment header identity."""
    return bytes.fromhex(text.replace('-', ''))


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
    started = time.monotonic()
    result = Wait(handle, timeout_ms)
    waited = int((time.monotonic() - started) * 1000)
    if result not in (WAIT_OBJECT, WAIT_ABANDONED):
        CloseHandle(handle)
        raise Blocked(f'{MUTEX_NAME} busy after {timeout_ms} ms (WaitForSingleObject={result})')
    return handle, waited


def release_mutex(handle):
    CloseHandle(handle)


def build_cli(log):
    """One necessary BelowNormal HostX64 incremental build of the formal CLI."""
    started = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
    host = next((candidate for candidate in ('pwsh', 'powershell') if shutil.which(candidate)), None)
    require(host is not None, 'No PowerShell host is available for the repository build check')
    result = subprocess.run(
        [host, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(BUILD_SCRIPT), '-Product', 'CLI'],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800,
    )
    log.write(result.stdout)
    if result.stderr:
        log.write('STDERR ' + result.stderr)
    require(result.returncode == 0, f'CLI build failed: exit {result.returncode}')
    properties = {}
    for line in result.stdout.splitlines():
        for key in ('IntDir', 'OutDir', 'VC_ExecutablePath_x64', 'Priority', 'SHA256'):
            if line.startswith(key + '='):
                properties[key] = line[len(key) + 1:]
    ok(properties.get('OutDir') == str(RELEASE), f'unexpected OutDir: {properties}')
    ok('HostX64' in properties.get('VC_ExecutablePath_x64', ''), f'unexpected compiler host: {properties}')
    ok(properties.get('Priority') == 'BelowNormal', f'unexpected build priority: {properties}')
    ok(properties.get('SHA256', '').lower() == fingerprint(CLI).lower(),
        'build script SHA does not match the tested artifact')
    log.write(f'CLI_BUILD_EXIT={result.returncode} HOST={host} STARTED={started}\n')
    log.flush()
    return properties


def build_fixtures(log):
    """Rebuild only the owned fixture targets into this script's own fixed IntDir."""
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
        f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 /c /FoNativeExecC.obj "{STEP_C}"',
        f'{initialize} && "{assembler}" /nologo /c /FoNativeExecAsm.obj "{STEP_ASM}"',
        f'{initialize} && "{compiler}" /nologo NativeExecC.obj NativeExecAsm.obj /link /OUT:"{STEP_TARGET}" '
        f'/DEF:"{STEP_DEF}" /IMPLIB:NativeExecChild.lib /MACHINE:X64',
        f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 "{AUX_C}" /link /OUT:"{AUX_TARGET}" '
        f'/IMPLIB:NativeExecAux.lib /MACHINE:X64',
    ]
    for command in commands:
        log.write('RUN ' + command + '\n')
        log.flush()
        subprocess.run(shell + command, cwd=INT_DIR, stdout=log, stderr=subprocess.STDOUT,
                       creationflags=BELOW_NORMAL, timeout=120, check=True)
    log.write('STEP_CHILD_SHA256=' + fingerprint(STEP_TARGET) + '\nAUX_CHILD_SHA256=' + fingerprint(AUX_TARGET) + '\n')
    log.flush()


@contextmanager
def install_fixtures(log):
    """Own the fixture outputs for this run and remove them afterwards."""
    require(not STEP_TARGET.exists() and not AUX_TARGET.exists() and not INT_DIR.exists(),
            f'Fixture outputs already exist: {STEP_TARGET}, {AUX_TARGET}, {INT_DIR}')
    INT_DIR.mkdir(parents=True)
    try:
        build_fixtures(log)
        yield
    finally:
        STEP_TARGET.unlink(missing_ok=True)
        AUX_TARGET.unlink(missing_ok=True)
        shutil.rmtree(INT_DIR, ignore_errors=True)


class Session:
    """Breakpoint session client; JSONL or REPL input, optional project archive."""

    def __init__(self, env, log, exe, site, *, input_mode='jsonl', project=None, sample=None, extra=()):
        self.log = log
        self.lines = queue.Queue()
        self.session = None
        self.sequence = 0
        self.query_sequence = 0
        mode = ['--input', input_mode]
        archive = []
        if project is not None:
            archive += ['--project', str(project)]
        if sample is not None:
            archive += ['--sample', str(sample)]
        self.argv = [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(exe), *site,
                     '--confirm', '--disposition', 'resume-detach', *mode, *archive, *extra]
        self.process = subprocess.Popen(
            self.argv, cwd=RELEASE, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
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
        line = self.lines.get(timeout=15)
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

    def send_raw(self, payload):
        line = json.dumps(payload, separators=(',', ':')) + '\n'
        self.log.write('TX ' + line)
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def send_line(self, text):
        self.log.write('TX ' + text + '\n')
        self.process.stdin.write(text + '\n')
        self.process.stdin.flush()

    def send(self, request_id, method, params=None, expected=None, session=None):
        request = dict(schemaVersion=1, requestId=request_id, method=method,
                       params=params if params is not None else {})
        if session is not False:
            request['session'] = session if session is not None else self.session
        if expected is not None:
            request['expected'] = expected
        self.send_raw(request)

    def request(self, request_id, method, params=None, expected=None, kind='response', session=None):
        self.send(request_id, method, params, expected, session)
        return self.receive(kind, request_id)

    def status(self):
        self.query_sequence += 1
        return self.request(f'query/{self.query_sequence}', 'control.query')

    def wait_armed(self, identity):
        deadline = time.monotonic() + 10
        while True:
            result = self.status()
            require((result['pid'], result['creationFileTime'], result['processInstanceId']) == identity, result)
            binding = result['breakpoint']['state']
            if binding == 'armed' and result.get('attached'):
                return result
            require(binding in ('installing', 'armed') and time.monotonic() < deadline, result)
            time.sleep(0.01)

    def wait_held(self, identity):
        deadline = time.monotonic() + 10
        while True:
            result = self.status()
            require((result['pid'], result['creationFileTime'], result['processInstanceId']) == identity, result)
            binding = result['breakpoint']['state']
            if binding == 'held' and 'stop' in result:
                return result
            require(binding in ('installing', 'armed', 'held') and time.monotonic() < deadline, result)
            time.sleep(0.01)

    def poll_step(self, request_id, states, timeout=15, after_stop_id=None):
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
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=8)
        self.reader.join(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()


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


def checked_target(hello):
    """Only keep the real owned process object matching this CLI receipt and fixture path."""
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, False, hello['targetPid'])
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


def cleanup_child(child):
    try:
        if Wait(child, 0) == WAIT_TIMEOUT:
            require(TerminateProcess(child, 3) and Wait(child, 5000) == WAIT_OBJECT,
                    'test target could not be stopped after failure')
    finally:
        CloseHandle(child)


def drain_rounds(trigger, done, count=1):
    for _ in range(count):
        require(SetEvent(trigger), 'trigger detached round')
        require(Wait(done, 8000) == WAIT_OBJECT, 'detached round did not complete')


def fixture_events(prefix):
    """Create the three owned fixture handshake events for one child run."""
    events = {}
    for suffix in ('ready', 'trigger', 'done'):
        events[suffix] = CreateEvent(None, False, False, f'{prefix}-{suffix}')
        require(events[suffix], f'CreateEvent {suffix} failed: {ct.get_last_error()}')
    return events


def close_events(events):
    for handle in events.values():
        CloseHandle(handle)


def cleanup_controller(controller):
    """Release one owned JSONL controller process."""
    try:
        if controller.process.poll() is None:
            controller.process.stdin.close()
            controller.process.wait(timeout=12)
    except Exception:
        pass
    finally:
        controller.stop()


def project_cli(*args, timeout=90):
    """Run a formal one-shot CLI command and return (exit code, stdout, stderr)."""
    result = subprocess.run([str(CLI), *args], capture_output=True, text=True, encoding='utf-8',
                            errors='replace', timeout=timeout, cwd=RELEASE,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    return result.returncode, result.stdout, result.stderr


def json_command(*args, timeout=90):
    """Run a formal one-shot CLI command and return its JSON data document."""
    code, stdout, stderr = project_cli(*args, '--json', timeout=timeout)
    require(code == 0, f'command {args} failed: exit {code} stdout={stdout} stderr={stderr}')
    start = stdout.find('{')
    require(start >= 0, f'command {args} produced no JSON: {stdout!r}')
    envelope, _ = json.JSONDecoder().raw_decode(stdout[start:])
    require(isinstance(envelope, dict) and 'data' in envelope, f'command {args} produced no data: {envelope}')
    return envelope['data']


def segment_files(sample_dir):
    native = Path(sample_dir) / 'raw-native'
    if not native.is_dir():
        return []
    return sorted(native.glob('*.ksaseg'))


def project_create(path, title='Native execution archive fixture'):
    """Create the offline project and one frozen sample with the formal controller."""
    with ExitStack() as children:
        controller = open_controller('offline')
        children.callback(cleanup_controller, controller)
        created = controller_call(controller, 'create', 'project.create',
                                  {'path': str(path), 'settings': {'title': title, 'notes': ''}})
        saved = controller_call(controller, 'save', 'project.save',
                                {'projectId': created['projectId'], 'expectedRevisionId': created['revisionId'],
                                 'settings': {'title': title, 'notes': '', 'breakpointDefinitions': []}})
        sample = controller_call(controller, 'sample', 'sample.create',
                                 {'projectId': created['projectId'], 'expectedRevisionId': saved['revisionId'],
                                  'title': 'Native execution sample'})
        controller_call(controller, 'close', 'project.close', {'projectId': created['projectId']})
        require(controller_shutdown(controller) == 0, 'offline controller shutdown')
    return created['projectId'], sample['sampleId']


def api_follow(project, source, title, write_packet, create_packet):
    """Import one owned API archive into a new sample of the given project."""
    with ExitStack() as children:
        controller = open_controller('r3')
        children.callback(cleanup_controller, controller)
        opened = controller_call(controller, 'open', 'project.open',
                                 {'path': str(project), 'access': 'read-write'})
        identity = {'projectId': opened['projectId']}
        api = {'path': str(source), 'sessionIdentity': str(SESSION_ID), 'authorized': True}
        options = dict(identity, title=title, pid=42, creationFileTime=CREATION, apiArchive=api)
        session = controller_call(controller, 'open-sample', 'session.open', options,
                                  expected={'revisionId': opened['revisionId']})
        owner = {'session': session['session']}
        sample = Path(project) / 'samples' / session['sampleId']
        wait_for_segment(sample / 'checkpoints', 1)
        with Path(source).open('ab') as stream:
            stream.write(archive_line(2, create_packet, pid=42, processCreation100ns=CREATION))
        wait_for_segment(sample / 'checkpoints', 2)
        active = controller_call(controller, 'status', 'session.query', {}, **owner)
        stopped = controller_call(controller, 'stop', 'session.stop', {},
                                  expected={'stateRevision': active['stateRevision']}, **owner)
        require(stopped['capture'] == 'stopped', stopped)
        controller_call(controller, 'close', 'session.close', {},
                        expected={'stateRevision': stopped['stateRevision']}, **owner)
        require(controller_shutdown(controller) == 0, 'API follow controller shutdown')
    return session['sampleId']


def write_api_archive(path, write_packet):
    """Write the first owned API packet of one archive file."""
    with Path(path).open('wb') as stream:
        stream.write(archive_line(1, write_packet, pid=42, processCreation100ns=CREATION))


def write_fields(address, completed, target_pid, target_creation):
    """Owned write packet fields: actor identity, target identity and the actual range."""
    flags = (1 << 0) | (1 << 1) | (1 << 6) | (1 << 4) | (1 << 3)
    return [1, flags, 1000, target_pid, target_creation, 0, 0,
            address, completed, completed, 0, 100, 110, 0]


def thread_fields(start_address, target_pid, target_creation, target_tid, thread_creation,
                  with_identity=True):
    """Owned create request fields; the thread identity bit is optional on purpose."""
    flags = (1 << 0) | (1 << 1) | (1 << 6) | (1 << 5)
    if with_identity:
        flags |= (1 << 2)
    return [2, flags, 1000, target_pid, target_creation, target_tid, thread_creation,
            0, 0, 0, start_address, 200, 210, 0]


def relocate_native_segment(source, target_path, old_sample, new_sample):
    """Copy one verified native segment into another sample of the same project.

    The segment header binds project and sample identity, and the stored native
    document repeats the sample id.  Only those two bindings and the four
    affected CRC-32C values change; the observed bytes stay untouched.
    """
    data = bytearray(source.read_bytes())
    require(len(data) >= SEGMENT_HEADER_BYTES + BLOCK_HEADER_BYTES + RECORD_HEADER_BYTES, 'short native segment')
    data[48:64] = uuid_bytes(new_sample)
    data[92:96] = struct.pack('<I', crc32c(bytes(data[0:92])))
    block = SEGMENT_HEADER_BYTES
    record = block + BLOCK_HEADER_BYTES
    payload_bytes, = struct.unpack_from('<I', data, record + 12)
    payload = bytearray(data[record + RECORD_HEADER_BYTES:record + RECORD_HEADER_BYTES + payload_bytes])
    json_bytes, = struct.unpack_from('<I', payload, 0)
    document = payload[4:4 + json_bytes].decode('utf-8')
    marker = f'"sampleId":"{old_sample}"'
    require(marker in document, document[:400])
    replaced = document.replace(marker, f'"sampleId":"{new_sample}"')
    require(len(replaced) == len(document), 'the relocated document changed length')
    payload[4:4 + json_bytes] = replaced.encode('utf-8')
    data[record + RECORD_HEADER_BYTES:record + RECORD_HEADER_BYTES + payload_bytes] = payload
    data[record + 24:record + 28] = struct.pack('<I', crc32c(bytes(payload)))
    data[record + 28:record + 32] = struct.pack('<I', crc32c(bytes(data[record:record + 28])))
    decoded, = struct.unpack_from('<I', data, block + 40)
    block_crc = crc32c(bytes(data[block + BLOCK_HEADER_BYTES:block + BLOCK_HEADER_BYTES + decoded]))
    data[block + 64:block + 72] = struct.pack('<II', block_crc, block_crc)
    data[block + 76:block + 80] = struct.pack('<I', crc32c(bytes(data[block:block + 76])))
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(bytes(data))
    return len(data)


def execution_identity(held):
    """Real native identity of one owned stop: process, thread and instruction."""
    origin = held['originThread']
    execution = held['execution']
    return {
        'pid': int(execution['pid']),
        'creationFileTime': int(execution['processCreationFileTime']),
        'tid': int(execution['tid']),
        'threadCreationFileTime': int(execution['threadCreationFileTime']),
        'address': int(execution['instructionAddress'], 16),
        'threadId': origin['threadId'],
    }


def save_stop(session, stop):
    """One exact JSONL control.execution.save against the current owned stop."""
    return session.request('save/1', 'control.execution.save', {},
                           expected=dict(stopId=stop['id'], stateRevision=stop['stateRevision']))


def save_rejected(session, request_id, expected, *, session_override=None, omit_session=False, params=None):
    """One control.execution.save expected to fail with a protocol error."""
    if omit_session:
        override = False
    elif session_override is not None:
        override = session_override
    else:
        override = None
    session.send(request_id, 'control.execution.save', params if params is not None else {}, expected, override)
    return session.receive('error', request_id)


def native_save_case(log):
    """Main session: exact rejections, idempotent save, Into TF next segment."""
    global CHECKS
    name = 'native-save'
    project = WORK / 'main'
    project_id, sample = project_create(project)
    prefix = r'Local\KSwordNativeExecution-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = fixture_events(prefix)
    ready, trigger, done = events['ready'], events['trigger'], events['done']
    session = child = None
    try:
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], project=project, sample=sample)
        hello = session.receive('hello')
        archive = hello['executionArchive']
        ok(archive['projectId'] == project_id and archive['sampleId'] == sample, archive)
        ok(archive['stream'] == 'raw-native' and archive['nextOrdinal'] == '1', archive)
        ok(archive['sessionSaveLimit'] == str(SEGMENT_LIMIT) and archive['writerLeaseHeld'] is True, archive)
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        armed = session.wait_armed(identity)
        address = int(armed['breakpoint']['address'], 16)

        require(SetEvent(trigger), 'trigger the first round')
        held = session.wait_held(identity)
        stop = held['stop']
        origin = held['originThread']
        ok(held['execution']['kind'] == 'execution-enter-attempt', held)
        ok(int(held['execution']['instructionAddress'], 16) == address, held)

        # ---- exact protocol rejections; none of them may move the owned stop ----
        wrong_id = dict(id=str(uuid4()), epoch=session.session['epoch'])
        wrong_epoch = dict(id=session.session['id'], epoch='0')
        rejections = [
            ('wrong-session', 'breakpoint-control', save_rejected(session, 'neg/1',
                                            dict(stopId=stop['id'], stateRevision=stop['stateRevision']),
                                            session_override=wrong_id)),
            ('wrong-session', 'breakpoint-control', save_rejected(session, 'neg/2',
                                            dict(stopId=stop['id'], stateRevision=stop['stateRevision']),
                                            session_override=wrong_epoch)),
            ('invalid-execution-save', 'native-execution-save',
             save_rejected(session, 'neg/3',
                           dict(stopId=stop['id'], stateRevision=stop['stateRevision']),
                           omit_session=True)),
            ('invalid-execution-save', 'native-execution-save',
             save_rejected(session, 'neg/4',
                           dict(stopId=stop['id'], stateRevision='not-a-number'))),
            ('invalid-execution-save', 'native-execution-save',
             save_rejected(session, 'neg/5',
                           dict(stopId=stop['id'], stateRevision='01'))),
            ('invalid-execution-save', 'native-execution-save',
             save_rejected(session, 'neg/6',
                           dict(stopId=stop['id'], stateRevision=stop['stateRevision'], extra='x'))),
            ('invalid-execution-save', 'native-execution-save',
             save_rejected(session, 'neg/7',
                           dict(stopId=stop['id'], stateRevision=stop['stateRevision']),
                           params={'unexpected': 'value'})),
            ('stale-execution-stop', 'native-execution-save',
             save_rejected(session, 'neg/8',
                           dict(stopId=stop['id'] + '0', stateRevision=stop['stateRevision']))),
            ('stale-execution-stop', 'native-execution-save',
             save_rejected(session, 'neg/9',
                           dict(stopId=stop['id'],
                                stateRevision=str(int(stop['stateRevision']) + 1)))),
        ]
        for index, (expected_error, expected_stage, result) in enumerate(rejections):
            ok(result['errorId'] == expected_error, (index, result))
            ok(result['stage'] == expected_stage, (index, result))
        ok(session.status()['stop'] == stop and Wait(done, 0) == WAIT_TIMEOUT,
           'a rejected save moved the owned stop')

        # ---- positive save; the same native event must not create a second segment ----
        receipt = save_stop(session, stop)
        ok(receipt['ordinal'] == '1' and receipt['segmentVerified'] is True, receipt)
        ok(receipt['sampleId'] == sample and receipt['stream'] == 'raw-native', receipt)
        ok(isinstance(receipt['sha256'], str) and len(receipt['sha256']) == 64, receipt)
        ok(receipt['stopId'] == stop['id'] and receipt['stateRevision'] == stop['stateRevision'], receipt)
        ok(receipt['raw']['written'] is not None and receipt['raw']['flushed'] is not None, receipt)
        ok(receipt['raw']['written']['lastSequence'] == receipt['raw']['flushed']['lastSequence'], receipt)
        ok(receipt['raw']['status'] == 0 and receipt['raw']['issue'] == 0 and receipt['raw']['win32Error'] == 0,
           receipt)
        ok(receipt['error'] is None and receipt['appendBlocked'] is False, receipt)
        ok(int(receipt['event']['serial']) > 0 and receipt['event']['backendInstanceId'], receipt)
        first_sha = receipt['sha256']
        again = save_stop(session, stop)
        ok(again == receipt, 'the same native event produced a different receipt')
        ok(again['ordinal'] == '1' and again['sha256'] == first_sha, again)
        written = segment_files(Path(project) / 'samples' / sample)
        ok(len(written) == 1, f'one native event wrote {len(written)} segments')
        ok(int(receipt['raw']['flushed']['byteOffset']) == written[0].stat().st_size,
           (receipt['raw']['flushed'], written[0].stat().st_size))

        # ---- Into TF produces the next stop and the next saved segment ----
        step = session.request('step/1', 'control.step',
                               dict(mode='into', threadId=origin['threadId'], tid=origin['tid'],
                                    threadCreationFileTime=origin['creationFileTime']),
                               expected=dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
        ok(step['step']['state'] == 'running' and step['step']['requestId'] == 'step/1', step)
        result, step_receipt = session.poll_step('step/1', ('completed',), after_stop_id=stop['id'])
        stop2 = result['stop']
        ok(result['execution']['kind'] == 'instruction-completed', result)
        ok(int(result['execution']['instructionAddress'], 16) == address and
           int(result['execution']['nextInstructionAddress'], 16) == address + 1, result)
        second = save_stop(session, stop2)
        ok(second['ordinal'] == '2' and second['segmentVerified'] is True, second)
        ok(second['sha256'] != first_sha, 'the second segment reused the first digest')
        ok(second['stopId'] == stop2['id'] and second['stopId'] != stop['id'], second)
        written = segment_files(Path(project) / 'samples' / sample)
        ok(len(written) == 2, f'the Into TF stop wrote {len(written)} segments')

        released = session.request('continue/1', 'control.continue', {},
                                   expected=dict(stopId=stop2['id'], stateRevision=stop2['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 8000) == WAIT_OBJECT, released)

        # ---- the third round saves the third segment of the same sample ----
        require(SetEvent(trigger), 'trigger the third round')
        held = session.wait_held(identity)
        third = save_stop(session, held['stop'])
        ok(third['ordinal'] == '3' and third['segmentVerified'] is True, third)
        released = session.request('continue/2', 'control.continue', {},
                                   expected=dict(stopId=held['stop']['id'], stateRevision=held['stop']['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 8000) == WAIT_OBJECT, released)

        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        closed = summary['control']
        ok(summary['reason'] == 'requested' and summary['exitCode'] == 0 and closed['clean'] and
           not closed['attached'], summary)
        ok(session.process.wait(timeout=10) == 0, 'formal CLI exit code')
        require(not attached(child), 'shutdown did not detach the owned target')
        drain_rounds(trigger, done, 1)
        code = win.DWORD()
        ok(Wait(child, 8000) == WAIT_OBJECT and GetExitCode(child, ct.byref(code)) and code.value == 0,
           'fixture exit code')
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
        return project, sample, project_id
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            close_events(events)


def repl_save_case(log, project, sample):
    """The human REPL form must accept the same stop and revision."""
    global CHECKS
    name = 'repl-save'
    prefix = r'Local\KSwordNativeExecutionRepl-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = fixture_events(prefix)
    ready, trigger, done = events['ready'], events['trigger'], events['done']
    session = child = None
    try:
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], input_mode='repl',
                          project=project, sample=sample)
        hello = session.receive('hello')
        ok(hello['executionArchive']['nextOrdinal'] == '5', hello)
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        session.wait_armed(identity)
        session.send_line('help')
        usage = session.receive('response')
        ok('execution-save STOP_ID STATE_REVISION' in usage, usage)
        require(SetEvent(trigger), 'trigger the round')
        held = session.wait_held(identity)
        stop = held['stop']
        session.send_line(f"execution-save {stop['id']} {stop['stateRevision']}")
        receipt = session.receive('response')
        ok(receipt['ordinal'] == '5' and receipt['segmentVerified'] is True, receipt)
        ok(receipt['stopId'] == stop['id'] and receipt['stateRevision'] == stop['stateRevision'], receipt)
        session.send_line(f"execution-save {stop['id']} {stop['stateRevision']}")
        again = session.receive('response')
        ok(again == receipt, 'the REPL save was not idempotent')
        session.send_line('execution-save')
        bad = session.receive('error')
        ok(bad['errorId'] == 'invalid-execution-save', bad)
        session.send_line('quit')
        summary = session.receive('summary')
        ok(summary['exitCode'] == 0 and summary['control']['clean'], summary)
        session.process.wait(timeout=10)
        drain_rounds(trigger, done, 1)
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            close_events(events)


def history_read_case(log, project, sample, project_id):
    """analyze execution read: per segment, default ordinal, digest and endpoints."""
    global CHECKS
    name = 'history-read'
    sample_dir = Path(project) / 'samples' / sample
    segments = segment_files(sample_dir)
    ok(len(segments) == 3, f'expected three native segments, found {len(segments)}')
    previous = 0
    for ordinal in (1, 2, 3):
        report = json_command('analyze', 'execution', 'read', '--project', str(project),
                              '--sample', sample, '--ordinal', str(ordinal))
        ok(report['projectId'] == project_id and report['sampleId'] == sample, report)
        ok(report['stream'] == 'raw-native' and report['ordinal'] == str(ordinal), report)
        ok(report['segmentVerified'] is True and report['historical'] is True, report)
        digest = report['sha256']
        ok(isinstance(digest, str) and len(digest) == 64, report)
        segment = sample_dir / 'raw-native' / f'{ordinal:020d}.ksaseg'
        raw = segment.read_bytes()
        end = int(report['endOffset'])
        ok(end == len(raw), (ordinal, end, len(raw)))
        ok(hashlib.sha256(raw[:end]).hexdigest() == digest.lower(), f'segment {ordinal} digest mismatch')
        ok(int(report['lastSequence']) > 0 and int(report['blockOrdinal']) > 0, report)
        document = report['document']
        ok(document['kind'] == 'native-execution-v1', document)
        ok(document['projectId'] == project_id and document['sampleId'] == sample, document)
        ok(document['historical'] is True and document['source'] == 'native-debug-owner', document)
        ok(document['observation'] in ('execution-enter-attempt', 'instruction-completed'), document)
        ok(document['target']['pid'] > 0 and document['thread']['tid'] > 0, document)
        ok(document['stopId'] and int(document['stateRevision']) > 0, document)
        ok(document['instructionAddress'] and int(document['instructionAddress']) > 0, document)
        ok(int(report['lastSequence']) > previous, (ordinal, report['lastSequence'], previous))
        previous = int(report['lastSequence'])
    default = json_command('analyze', 'execution', 'read', '--project', str(project), '--sample', sample)
    ok(default['ordinal'] == '1', default)
    ok(default['sha256'] == json_command('analyze', 'execution', 'read', '--project', str(project),
                                         '--sample', sample, '--ordinal', '1')['sha256'], default)
    ok(default['document']['observation'] == 'execution-enter-attempt', default)
    code, stdout, stderr = project_cli('analyze', 'execution', 'read', '--project', str(project),
                                        '--sample', sample, '--ordinal', '0', '--json')
    ok(code != 0, (code, stdout, stderr))
    # 拒绝以结构化错误信封回报（与 json_command 同约定）：校验拒绝原因，不要求 stdout 为空。
    envelope = {}
    if '{' in stdout:
        envelope, _ = json.JSONDecoder().raw_decode(stdout[stdout.find('{'):])
    ok(envelope.get('status') == 'failed' and
       any('positive uint64' in str(item) for item in envelope.get('diagnostics', [])),
       (code, stdout, stderr))
    log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')


def reuse_session_case(log, project, sample):
    """A closed sample can be continued by a new session on the same project."""
    global CHECKS
    name = 'reuse-session'
    prefix = r'Local\KSwordNativeExecutionReuse-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = fixture_events(prefix)
    ready, trigger, done = events['ready'], events['trigger'], events['done']
    session = child = None
    try:
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], project=project, sample=sample)
        hello = session.receive('hello')
        ok(hello['executionArchive']['nextOrdinal'] == '4', hello)
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        session.wait_armed(identity)
        require(SetEvent(trigger), 'trigger the round')
        held = session.wait_held(identity)
        receipt = save_stop(session, held['stop'])
        ok(receipt['ordinal'] == '4' and receipt['segmentVerified'] is True, receipt)
        released = session.request('continue/1', 'control.continue', {},
                                   expected=dict(stopId=held['stop']['id'], stateRevision=held['stop']['stateRevision']))
        ok(released['release']['result'] == 'continued' and Wait(done, 8000) == WAIT_OBJECT, released)
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        ok(summary['exitCode'] == 0 and summary['control']['clean'], summary)
        session.process.wait(timeout=10)
        drain_rounds(trigger, done, 1)
        segments = segment_files(Path(project) / 'samples' / sample)
        ok(len(segments) == 4, f'reuse wrote {len(segments)} segments')
        report = json_command('analyze', 'execution', 'read', '--project', str(project), '--sample', sample,
                              '--ordinal', '4')
        ok(report['ordinal'] == '4' and report['segmentVerified'] is True, report)
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            close_events(events)


def lease_conflict_case(log, project, sample):
    """A second writer must be rejected before the owned target starts."""
    global CHECKS
    name = 'lease-conflict'
    prefix = r'Local\KSwordNativeExecutionLease-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    holder = None
    try:
        holder = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], project=project, sample=sample)
        hello = holder.receive('hello')
        ok(hello['executionArchive']['writerLeaseHeld'] is True, hello)
        child = checked_target(hello)
        try:
            code, stdout, stderr = project_cli('analyze', 'breakpoint', 'session', '--exe', str(STEP_TARGET),
                                               '--export', 'StepSite', '--confirm', '--disposition', 'resume-detach',
                                               '--input', 'jsonl', '--project', str(project), '--sample', sample,
                                               timeout=90)
            ok(code != 0, (code, stdout, stderr))
            ok('writerBusy' in stderr, stderr)
            ok('writerBusy' not in stdout, stdout)
            code2, stdout2, stderr2 = project_cli('analyze', 'breakpoint', 'session', '--exe', str(STEP_TARGET),
                                                   '--export', 'StepSite', '--confirm', '--disposition',
                                                   'resume-detach', '--input', 'jsonl', '--project', str(project),
                                                   '--sample', sample, timeout=90)
            ok(code2 != 0 and 'writerBusy' in stderr2, (code2, stderr2))
        finally:
            cleanup_child(child)
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        if holder is not None:
            holder.close_pipes()


def startup_reject_case(log, project, sample):
    """Project evidence is refused for data watch and cooperative pair scopes."""
    global CHECKS
    name = 'scope-reject'
    code, stdout, stderr = project_cli('analyze', 'breakpoint', 'session', '--exe', str(AUX_TARGET),
                                       '--export', 'WatchedData', '--watch-write-bytes', '4', '--confirm',
                                       '--disposition', 'resume-detach', '--input', 'jsonl',
                                       '--project', str(project), '--sample', sample, timeout=90)
    ok(code != 0, (code, stdout, stderr))
    ok('single-target execution breakpoint' in stderr, stderr)
    code, stdout, stderr = project_cli('analyze', 'breakpoint', 'session', '--exe', str(AUX_TARGET),
                                       '--export', 'ExportedTick', '--cooperative-pair', '--confirm',
                                       '--disposition', 'resume-detach', '--input', 'jsonl',
                                       '--project', str(project), '--sample', sample, timeout=90)
    ok(code != 0, (code, stdout, stderr))
    ok('single-target execution breakpoint' in stderr, stderr)
    log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')


def unavailable_save_cases(log):
    """Sessions without a project archive, data watch and pair must refuse the save."""
    global CHECKS
    name = 'save-unavailable'
    # 1. no project archive at all
    prefix = r'Local\KSwordNativeExecutionNone-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = fixture_events(prefix)
    ready, trigger, done = events['ready'], events['trigger'], events['done']
    session = child = None
    try:
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'])
        hello = session.receive('hello')
        ok(hello['executionArchive'] is None, hello)
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        session.wait_armed(identity)
        require(SetEvent(trigger), 'trigger the round')
        held = session.wait_held(identity)
        rejection = save_rejected(session, 'save/1',
                                  dict(stopId=held['stop']['id'], stateRevision=held['stop']['stateRevision']))
        ok(rejection['errorId'] == 'execution-save-unavailable', rejection)
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        ok(summary['exitCode'] == 0 and summary['control']['clean'], summary)
        session.process.wait(timeout=10)
        drain_rounds(trigger, done, 1)
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            close_events(events)

    # 2. data write watch scope
    prefix = r'Local\KSwordNativeExecutionWatch-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_BREAKPOINT_EVENTS=prefix,
               KSWORD_PRODUCT_BREAKPOINT_WRITE_WATCH='1', KSWORD_PRODUCT_BREAKPOINT_WATCH_WIDTH='4')
    events = fixture_events(prefix)
    ready, trigger, done = events['ready'], events['trigger'], events['done']
    session = child = None
    try:
        session = Session(env, log, AUX_TARGET, ['--export', 'WatchedData', '--watch-write-bytes', '4'])
        hello = session.receive('hello')
        ok(hello['executionArchive'] is None, hello)
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        session.wait_armed(identity)
        require(SetEvent(trigger) and Wait(done, 8000) == WAIT_OBJECT, 'the same-value write must complete')
        require(SetEvent(trigger), 'trigger the real data change')
        held = session.wait_held(identity)
        ok(held['hit']['phase'] == 'data-write-observed', held)
        rejection = save_rejected(session, 'save/1',
                                  dict(stopId=held['stop']['id'], stateRevision=held['stop']['stateRevision']))
        ok(rejection['errorId'] == 'execution-save-unavailable', rejection)
        session.request('continue/1', 'control.continue', {},
                        expected=dict(stopId=held['stop']['id'], stateRevision=held['stop']['stateRevision']))
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        ok(summary['exitCode'] == 0 and summary['control']['clean'], summary)
        session.process.wait(timeout=10)
        drain_rounds(trigger, done, 2)
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            close_events(events)

    # 3. cooperative pair scope
    prefix = r'Local\KSwordNativeExecutionPair-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_BREAKPOINT_PAIR_EVENTS=prefix)
    configured = CreateEvent(None, True, False, f'{prefix}-configured')
    require(configured, 'CreateEvent configured failed')
    session = None
    children = []
    try:
        session = Session(env, log, AUX_TARGET, ['--export', 'ExportedTick'], extra=['--cooperative-pair'])
        hello = session.receive('hello')
        ok(hello['executionArchive'] is None, hello)
        ok(hello['control']['mode'] == 'cooperative-pair', hello)
        for member in hello['control']['members']:
            children.append(checked_target(dict(targetPid=member['pid'],
                                                targetCreationFileTime=member['creationFileTime'])))
        require(SetEvent(configured), 'allow cooperative workloads to initialize')
        deadline = time.monotonic() + 10
        while True:
            report = session.status()
            if report['state'] == 'running' and all(member['gateOpened'] and
                                                    member['control']['breakpoint']['state'] == 'armed'
                                                    for member in report['members']):
                break
            require(report['state'] in ('starting', 'running') and time.monotonic() < deadline, report)
            time.sleep(0.01)
        rejection = save_rejected(session, 'save/1', dict(stopId='0' * 32, stateRevision='1'))
        ok(rejection['errorId'] == 'execution-save-unavailable', rejection)
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        ok(summary['exitCode'] == 0 and summary['control']['clean'], summary)
        session.process.wait(timeout=10)
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            for handle in children:
                cleanup_child(handle)
            CloseHandle(configured)
    log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')


def failed_write_case(log):
    """A refused segment write keeps its receipt and blocks every later segment."""
    global CHECKS
    name = 'failed-write'
    project = WORK / 'failure'
    project_id, sample = project_create(project, 'Native execution failed write fixture')
    prefix = r'Local\KSwordNativeExecutionFail-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = fixture_events(prefix)
    ready, trigger, done = events['ready'], events['trigger'], events['done']
    session = child = None
    native_dir = Path(project) / 'samples' / sample / 'raw-native'
    try:
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], project=project, sample=sample)
        hello = session.receive('hello')
        ok(hello['executionArchive']['nextOrdinal'] == '1', hello)
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        session.wait_armed(identity)

        # The segment writer only creates a new file; an existing name refuses the write.
        native_dir.mkdir(parents=True, exist_ok=True)
        blocker = native_dir / f'{1:020d}.ksaseg'
        blocker.write_bytes(b'occupied-by-the-negative-control')
        require(SetEvent(trigger), 'trigger the round')
        held = session.wait_held(identity)
        stop = held['stop']
        rejected = save_rejected(session, 'save/1',
                                 dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
        ok(rejected['ordinal'] == '1', rejected)
        ok(rejected['segmentVerified'] is False and rejected['appendBlocked'] is True, rejected)
        ok(rejected['sha256'] is None, rejected)
        ok('written' in rejected['raw'] and 'flushed' in rejected['raw'], rejected)
        ok(rejected['raw']['status'] != 0 and rejected['raw']['win32Error'] != 0, rejected)
        ok(rejected['error'] is not None and rejected['error']['errorId'] == 'ioError', rejected)
        again = save_rejected(session, 'save/2',
                              dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
        ok(again == rejected, 'the refused write did not keep its first receipt')
        ok(segment_files(Path(project) / 'samples' / sample) == [blocker], 'the refused write added a segment')
        blocker.unlink()
        blocked = save_rejected(session, 'save/3',
                                dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
        ok(blocked == rejected, 'the refused write did not block the later segment')
        ok(segment_files(Path(project) / 'samples' / sample) == [], 'a blocked write published a segment')
        ok(session.status()['stop'] == stop, 'the refused write moved the owned stop')

        session.request('continue/1', 'control.continue', {},
                        expected=dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
        ok(Wait(done, 8000) == WAIT_OBJECT, 'round did not complete')
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        ok(summary['exitCode'] == 0 and summary['control']['clean'], summary)
        session.process.wait(timeout=10)
        drain_rounds(trigger, done, 1)
        log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            close_events(events)


def broken_archive_cases(log, project, sample):
    """Bad tail, missing middle segment and existing later segment refuse the launch."""
    global CHECKS
    name = 'broken-archive'
    source = Path(project)
    copies = WORK / 'copies'
    copies.mkdir(parents=True, exist_ok=True)
    segments = sorted((source / 'samples' / sample / 'raw-native').glob('*.ksaseg'))
    ok(len(segments) >= 3, f'need three native segments, found {len(segments)}')

    def probe(case_root, expected):
        """The launch must fail before the owned target starts."""
        prefix = r'Local\KSwordNativeExecutionBroken-' + uuid4().hex
        env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
        events = fixture_events(prefix)
        try:
            code, stdout, stderr = project_cli('analyze', 'breakpoint', 'session', '--exe', str(STEP_TARGET),
                                               '--export', 'StepSite', '--confirm', '--disposition',
                                               'resume-detach', '--input', 'jsonl', '--project', str(case_root),
                                               '--sample', sample, timeout=90)
            ok(code != 0, (case_root, code, stdout, stderr))
            ok(expected in stderr, (case_root, stderr))
            ok(Wait(events['ready'], 0) == WAIT_TIMEOUT, f'{case_root} started the owned target')
            return stderr
        finally:
            close_events(events)

    # 1. the last segment carries a broken tail
    bad_tail = copies / 'bad-tail'
    shutil.copytree(source, bad_tail)
    target = bad_tail / 'samples' / sample / 'raw-native' / segments[-1].name
    raw = bytearray(target.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    target.write_bytes(bytes(raw))
    probe(bad_tail, 'corrupt')

    # 2. the middle segment is missing while a later segment still exists
    missing = copies / 'missing-middle'
    shutil.copytree(source, missing)
    (missing / 'samples' / sample / 'raw-native' / segments[1].name).unlink()
    probe(missing, 'recoveryRequired')

    # 3. a later segment exists without its predecessor
    later = copies / 'existing-later'
    shutil.copytree(source, later)
    (later / 'samples' / sample / 'raw-native' / segments[0].name).unlink()
    probe(later, 'recoveryRequired')

    # 4. the untouched project still opens and continues
    code, stdout, stderr = project_cli('analyze', 'breakpoint', 'session', '--exe', str(STEP_TARGET),
                                       '--export', 'StepSite', '--confirm', '--disposition', 'resume-detach',
                                       '--input', 'jsonl', '--project', str(source), '--sample', sample,
                                       timeout=90)
    ok(code != 0, (code, stdout, stderr))
    ok('writerBusy' in stderr, stderr)
    log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')


def limit_boundary_case(log, project, sample):
    """Static and CLI level checks of the 4096 session save limit."""
    global CHECKS
    name = 'limit-boundary'
    header = (REPO / 'KswordCLI' / 'ActionAnalyze' / 'Cli' / 'NativeExecutionJournal.h').read_text(encoding='utf-8')
    body = (REPO / 'KswordCLI' / 'ActionAnalyze' / 'Cli' / 'NativeExecutionJournal.cpp').read_text(encoding='utf-8')
    ok('kNativeExecutionSessionSaveLimit = 4096' in header, 'the session save limit constant is missing')
    ok('saved_.size() >= kNativeExecutionSessionSaveLimit' in body, 'the session save limit check is missing')
    ok('"execution-save-limit"' in body, 'the session save limit error id is missing')
    report = json_command('analyze', 'execution', 'read', '--project', str(project), '--sample', sample,
                          '--ordinal', '1')
    ok(report['ordinal'] == '1', report)
    code, stdout, stderr = project_cli('analyze', 'execution', 'correlate', '--project', str(project),
                                       '--sample', sample, '--api-ordinal', '1', '--native-ordinal',
                                       str(SEGMENT_LIMIT + 1), '--json')
    ok(code != 0, (code, stdout, stderr))
    ok('--native-ordinal' in stderr, stderr)
    code, stdout, stderr = project_cli('analyze', 'execution', 'correlate', '--project', str(project),
                                       '--sample', sample, '--api-ordinal', '129', '--native-ordinal', '1',
                                       '--json')
    ok(code != 0, (code, stdout, stderr))
    ok('--api-ordinal' in stderr, stderr)
    log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')


def correlate_case(log):
    """analyze execution correlate over a real native archive and owned API archives."""
    global CHECKS
    name = 'correlate'
    project = WORK / 'correlate'
    project_id, _ = project_create(project, 'Native execution correlate fixture')

    # 1. one owned native session produces the real execution archive and identity.
    prefix = r'Local\KSwordNativeExecutionCorrelate-' + uuid4().hex
    env = dict(os.environ, KSWORD_PRODUCT_STEP_EVENTS=prefix, KSWORD_PRODUCT_STEP_MODE='fast')
    events = fixture_events(prefix)
    ready, trigger, done = events['ready'], events['trigger'], events['done']
    session = child = None
    real = None
    native_sample = None
    try:
        session = Session(env, log, STEP_TARGET, ['--export', 'StepSite'], project=project)
        hello = session.receive('hello')
        native_sample = hello['executionArchive']['sampleId']
        child = checked_target(hello)
        identity = (hello['targetPid'], hello['targetCreationFileTime'], hello['control']['processInstanceId'])
        ok(Wait(ready, 5000) == WAIT_OBJECT, 'fixture did not signal ready')
        session.wait_armed(identity)
        require(SetEvent(trigger), 'trigger the round')
        held = session.wait_held(identity)
        real = execution_identity(held)
        receipt = save_stop(session, held['stop'])
        ok(receipt['ordinal'] == '1' and receipt['segmentVerified'] is True, receipt)
        session.request('continue/1', 'control.continue', {},
                        expected=dict(stopId=held['stop']['id'], stateRevision=held['stop']['stateRevision']))
        ok(Wait(done, 8000) == WAIT_OBJECT, 'round did not complete')
        session.send('shutdown', 'controller.shutdown')
        summary = session.receive('summary')
        ok(summary['exitCode'] == 0 and summary['control']['clean'], summary)
        session.process.wait(timeout=10)
        drain_rounds(trigger, done, 1)
    finally:
        try:
            if session is not None:
                session.close_pipes()
        finally:
            if child:
                cleanup_child(child)
            close_events(events)
    ok(real is not None and real['address'] > 0, real)
    native_segment = Path(project) / 'samples' / native_sample / 'raw-native' / f'{1:020d}.ksaseg'
    ok(native_segment.is_file(), native_segment)

    # 2. owned API archives over the same real identity, one per variant.
    plans = {
        'match': dict(write_address=real['address'] - 4, write_bytes=8, start=real['address'],
                      target_creation=real['creationFileTime'], thread_creation=real['threadCreationFileTime'],
                      with_identity=True),
        'creation-mismatch': dict(write_address=real['address'] - 4, write_bytes=8, start=real['address'],
                                   target_creation=real['creationFileTime'] + 1,
                                   thread_creation=real['threadCreationFileTime'], with_identity=True),
        'thread-creation-mismatch': dict(write_address=real['address'] - 4, write_bytes=8, start=real['address'],
                                         target_creation=real['creationFileTime'],
                                         thread_creation=real['threadCreationFileTime'] + 1, with_identity=True),
        'half-open-end': dict(write_address=real['address'] - 4, write_bytes=4, start=real['address'] - 2,
                              target_creation=real['creationFileTime'],
                              thread_creation=real['threadCreationFileTime'], with_identity=True),
        'no-thread-identity': dict(write_address=real['address'] - 4, write_bytes=8, start=real['address'],
                                    target_creation=real['creationFileTime'],
                                    thread_creation=real['threadCreationFileTime'], with_identity=False),
    }
    samples = {}
    for index, (key, plan) in enumerate(plans.items()):
        source = WORK / f'correlate-archive-{index}.jsonl'
        write_packet = injection_packet('KernelBase', 'WriteProcessMemory', 8,
                                        write_fields(plan['write_address'], plan['write_bytes'],
                                                     real['pid'], plan['target_creation']))
        create_packet = injection_packet('Kernel32.dll', 'CreateRemoteThread', 9,
                                         thread_fields(plan['start'], real['pid'], plan['target_creation'],
                                                       real['tid'], plan['thread_creation'],
                                                       with_identity=plan['with_identity']))
        write_api_archive(source, write_packet)
        samples[key] = api_follow(project, source, f'Correlate {key}', write_packet, create_packet)
        source.unlink()
        ok(samples[key] != native_sample, samples[key])
        # The verified native observation moves into the same sample as the API archive.
        size = relocate_native_segment(native_segment,
                                       Path(project) / 'samples' / samples[key] / 'raw-native' / f'{1:020d}.ksaseg',
                                       native_sample, samples[key])
        ok(size == native_segment.stat().st_size, (size, native_segment.stat().st_size))

    def correlate(key):
        report = json_command('analyze', 'execution', 'correlate', '--project', str(project),
                              '--sample', samples[key], '--api-ordinal', '2', '--native-ordinal', '1')
        ok(report['projectId'] == project_id and report['sampleId'] == samples[key], report)
        ok(report['apiOrdinal'] == '2' and report['nativeOrdinal'] == '1', report)
        ok(report['historical'] is True, report)
        ok(isinstance(report['apiSha256'], str) and len(report['apiSha256']) == 64, report)
        ok(isinstance(report['nativeSha256'], str) and len(report['nativeSha256']) == 64, report)
        for flag in ('sourceAuthenticated', 'regionVersionVerified', 'causalityConfirmed', 'commonClockVerified'):
            ok(report[flag] is False, (flag, report))
        ok(report['candidateCount'] == str(len(report['candidates'])), report)
        return report

    matched = correlate('match')
    ok(matched['candidateCount'] == '1', matched)
    ok(matched['transferCandidateCount'] == '1', matched)
    ok(matched['retainedTransferCandidates'] == '1', matched)
    ok(matched['evictedTransferWrites'] == '0', matched)
    ok(matched['transferCandidatesTruncated'] is False, matched)
    candidate = matched['candidates'][0]
    ok(candidate['kind'] == 'native-transfer-consistency-candidate', candidate)
    ok(candidate['observation'] == 'execution-enter-attempt', candidate)
    ok(candidate['write']['stream'] == 'raw' and candidate['write']['segmentOrdinal'] == '1', candidate)
    ok(candidate['write']['recordSequence'] == '2', candidate)
    ok(candidate['threadCreate']['segmentOrdinal'] == '2' and candidate['threadCreate']['recordSequence'] == '2',
       candidate)
    ok(candidate['native']['stream'] == 'raw-native' and candidate['native']['segmentOrdinal'] == '1', candidate)
    ok(candidate['native']['sha256'] == matched['nativeSha256'], candidate)
    ok(candidate['actorPid'] == 42 and candidate['targetPid'] == real['pid'], candidate)
    ok(candidate['targetCreationFileTime'] == str(real['creationFileTime']), candidate)
    ok(candidate['tid'] == real['tid'] and candidate['threadCreationFileTime'] == str(real['threadCreationFileTime']),
       candidate)
    ok(candidate['instructionAddress'] == str(real['address']), candidate)
    ok(candidate['writtenAddress'] == str(real['address'] - 4), candidate)
    ok(candidate['writtenBytes'] == '8', candidate)
    ok(candidate['requestedStartAddress'] == str(real['address']), candidate)
    ok(candidate['apiClock']['createEnterQpc'] == '200' and candidate['apiClock']['createReturnQpc'] == '210',
       candidate)
    ok(candidate['nativeClock']['observedQpc'] is not None, candidate)
    ok(candidate['nativeClock']['qpcFrequency'] is not None, candidate)
    for flag in ('sourceAuthenticated', 'regionVersionVerified', 'causalityConfirmed', 'commonClockVerified'):
        ok(candidate[flag] is False, (flag, candidate))

    for key in ('creation-mismatch', 'thread-creation-mismatch', 'half-open-end', 'no-thread-identity'):
        report = correlate(key)
        ok(report['transferCandidateCount'] == '1', (key, report))
        ok(report['candidateCount'] == '0', (key, report))
        ok(report['candidates'] == [], (key, report))

    # A wrong sample must fail the whole query instead of returning partial candidates.
    code, stdout, stderr = project_cli('analyze', 'execution', 'correlate', '--project', str(project),
                                       '--sample', str(uuid4()), '--api-ordinal', '2', '--native-ordinal', '1',
                                       '--json')
    ok(code != 0, (code, stdout, stderr))
    ok('"candidates"' not in stdout, stdout)
    log.write(f'CASE={name} ASSERTIONS_SO_FAR={CHECKS}\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutex-timeout-ms', type=int, default=30000)
    parser.add_argument('--suite', choices=('focused', 'full'), default='focused',
                        help='focused: native-save + history-read + failed-write; full: every legacy case')
    parser.add_argument('--skip-build', action='store_true',
                        help='reuse the formal CLI built once by the batch; still report its actual SHA')
    args = parser.parse_args()
    all_cases = ('native-save', 'history-read', 'reuse-session', 'repl-save', 'lease-conflict',
                 'scope-reject', 'save-unavailable', 'failed-write', 'broken-archive',
                 'limit-boundary', 'correlate')
    focused = ('native-save', 'history-read', 'failed-write')
    selected = set(focused if args.suite == 'focused' else all_cases)
    mutex, waited = acquire_mutex(args.mutex_timeout_ms)
    started = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
    stamp = f'{datetime.now():%Y%m%d-%H%M%S}'
    log_path = LOG_DIR / f'action-analyze-native-execution-cli-{stamp}.log'
    receipt_path = LOG_DIR / f'action-analyze-native-execution-cli-{stamp}-receipt.json'
    try:
        with log_path.open('w', encoding='utf-8', buffering=1) as log:
            log.write(f'NATIVE_EXECUTION_CLI started={started} mutex={MUTEX_NAME} '
                      f'held_by_pid={os.getpid()} mutex_wait_ms={waited} suite={args.suite}\n')
            if args.skip_build:
                build_properties = {'skipped': 'true'}
                log.write('CLI_BUILD=skipped (shared batch build)\n')
            else:
                build_properties = build_cli(log)
            cli_sha = fingerprint(CLI)
            log.write(f'CLI_SHA256={cli_sha}\n')
            executed = []
            with install_fixtures(log):
                fixture_sha = fingerprint(STEP_TARGET)
                aux_sha = fingerprint(AUX_TARGET)
                WORK.mkdir(parents=True, exist_ok=True)
                try:
                    project, sample, project_id = native_save_case(log)
                    executed.append('native-save')
                    if 'history-read' in selected:
                        history_read_case(log, project, sample, project_id)
                        executed.append('history-read')
                    if 'reuse-session' in selected:
                        reuse_session_case(log, project, sample)
                        executed.append('reuse-session')
                    if 'repl-save' in selected:
                        repl_save_case(log, project, sample)
                        executed.append('repl-save')
                    if 'lease-conflict' in selected:
                        lease_conflict_case(log, project, sample)
                        executed.append('lease-conflict')
                    if 'scope-reject' in selected:
                        startup_reject_case(log, project, sample)
                        executed.append('scope-reject')
                    if 'save-unavailable' in selected:
                        unavailable_save_cases(log)
                        executed.append('save-unavailable')
                    if 'failed-write' in selected:
                        failed_write_case(log)
                        executed.append('failed-write')
                    if 'broken-archive' in selected:
                        broken_archive_cases(log, project, sample)
                        executed.append('broken-archive')
                    if 'limit-boundary' in selected:
                        limit_boundary_case(log, project, sample)
                        executed.append('limit-boundary')
                    if 'correlate' in selected:
                        correlate_case(log)
                        executed.append('correlate')
                finally:
                    shutil.rmtree(WORK, ignore_errors=True)
            receipt = {
                'generatedAt': datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds'),
                'mutex': MUTEX_NAME,
                'mutexWaitMs': waited,
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
                'workDir': str(WORK),
                'cases': executed,
                'assertions': CHECKS,
                'log': str(log_path),
            }
            receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
            log.write(f'RECEIPT={receipt_path} ASSERTIONS={CHECKS} RESULT=PASS\n')
        print(f'PASS assertions={CHECKS} receipt={receipt_path} log={log_path}')
    finally:
        release_mutex(mutex)


if __name__ == '__main__':
    main()
