"""Focused product validation for `analyze execution-group session` append of live members.

Drives the formal Release KswordCLI.exe over JSONL:
  1. hold original member A, append B to the same collection/sample, verify A unchanged,
     B gets an independent owner on the same sample, then actually hit B's breakpoint.
  2. replay the identical execution/N request: original receipt, no re-attach, no new member.
  3. duplicate PID and an unparsable sites file are rejected while A's stop stays readable.
  4. wrong collection ID, confirm:false and a stale hello identity are rejected without
     changing members.
  5. a real unknown frozen definition reports memberSetupError, keeps the original writer,
     and A's original execution observation still saves into the same sample.
  6. controller.shutdown closes all original owners clean while both are held; the owned
     targets then finish their fixed rounds and exit 0.

Owned AMD64 target is built from the existing product_step_child source into the fixed
IntDir tools/action_analyze_validation/cli/obj/execution-group-append and the unified
Ksword5.1/x64/Release. No GUI, driver, system process or copy of the runtime is used.
"""

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
TARGET = RELEASE / 'ActionAnalyzeAppendGroupChild.exe'
WORK = REPO / 'tools' / 'action_analyze_validation' / 'cli' / 'obj' / 'execution-group-append'
PROJECT = WORK / 'project'
SOURCE_C = Path(__file__).with_name('product_step_child.c')
SOURCE_ASM = Path(__file__).with_name('product_step_child.asm')
SOURCE_DEF = Path(__file__).with_name('product_step_child.def')
LOG_DIR = Path(os.environ.get('KSWORD_EXECUTION_GROUP_LOG_DIR',
                              str(REPO / '.codex-build-logs' / 'codebuddy-three-tests' / 'append')))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG = (LOG_DIR / 'run.log').open('w', encoding='utf-8')
RECEIPT = LOG_DIR / 'receipt.json'
BELOW_NORMAL = 0x4000
CREATE_NO_WINDOW = 0x08000000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
CHECKS = 0
SCENARIOS = []


class Blocked(Exception):
    """Real environment blocker; never reported as a product pass."""


def ok(condition, detail):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise RuntimeError(f'#{CHECKS} {detail}')
    print(f'PASS #{CHECKS} {detail}')
    LOG.write(f'PASS #{CHECKS} {detail}\n')
    return True


def note(text):
    print(text)
    LOG.write(text + '\n')


def fingerprint(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def api(name, result, *args):
    function = getattr(KERNEL, name)
    function.restype = result
    function.argtypes = args
    return function


KERNEL = ct.WinDLL('kernel32', use_last_error=True)
CreateEvent = api('CreateEventW', win.HANDLE, ct.c_void_p, win.BOOL, win.BOOL, win.LPCWSTR)
OpenProcess = api('OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
OpenEvent = api('OpenEventW', win.HANDLE, win.DWORD, win.BOOL, win.LPCWSTR)
SetEvent = api('SetEvent', win.BOOL, win.HANDLE)
CloseHandle = api('CloseHandle', win.BOOL, win.HANDLE)
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
GetExitCode = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetProcessTimes = api('GetProcessTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
TerminateProcess = api('TerminateProcess', win.BOOL, win.HANDLE, win.UINT)


class FileTime(ct.Structure):
    _fields_ = [('low', win.DWORD), ('high', win.DWORD)]

    def value(self):
        return (self.high << 32) | self.low


def creation_filetime(pid):
    handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not handle:
        raise Blocked(f'OpenProcess({pid}) failed: {ct.get_last_error()}')
    try:
        creation, exit_time, kernel, user = win.FILETIME(), win.FILETIME(), win.FILETIME(), win.FILETIME()
        if not GetProcessTimes(handle, ct.byref(creation), ct.byref(exit_time), ct.byref(kernel), ct.byref(user)):
            raise Blocked(f'GetProcessTimes({pid}) failed: {ct.get_last_error()}')
        return str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
    finally:
        CloseHandle(handle)


def process_running(pid):
    handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        return Wait(handle, 0) == WAIT_TIMEOUT
    finally:
        CloseHandle(handle)


def exit_code(pid):
    handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        if Wait(handle, 5000) == WAIT_TIMEOUT:
            return None
        code = win.DWORD()
        return code.value if GetExitCode(handle, ct.byref(code)) else None
    finally:
        CloseHandle(handle)


@contextmanager
def built_target(log):
    """One BelowNormal HostX64 build of the owned target into the fixed IntDir/Release."""
    if TARGET.exists() or WORK.exists():
        raise Blocked(f'Owned fixture already exists: {TARGET} or {WORK}')
    choices = [Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'), Path(r'D:\Software\VS')]
    setup = next((base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat' for base in choices
                  if (base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat').is_file()), None)
    if setup is None:
        raise Blocked('MSVC vcvars64.bat is required')
    WORK.mkdir(parents=True)
    initialize = f'call "{setup}" >nul'
    shell = f'"{os.environ["ComSpec"]}" /d /c '
    paths = subprocess.check_output(shell + initialize + ' && where cl.exe', cwd=WORK,
                                    creationflags=BELOW_NORMAL, text=True, timeout=30).splitlines()
    compiler = next((Path(path) for path in paths if path.lower().endswith(r'\hostx64\x64\cl.exe')), None)
    if compiler is None or not compiler.is_file():
        raise Blocked(f'HostX64 compiler required: {paths}')
    assembler = compiler.with_name('ml64.exe')
    if not assembler.is_file():
        raise Blocked(f'HostX64 ml64 required next to {compiler}')
    log.write(f'TARGET_INTDIR={WORK}\nTARGET_OUTDIR={RELEASE}\nHOSTX64={compiler}\nPRIORITY=BelowNormal\n')
    commands = [
        f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 /c /Foappend_child_c.obj "{SOURCE_C}"',
        f'{initialize} && "{assembler}" /nologo /c /Foappend_child_asm.obj "{SOURCE_ASM}"',
        f'{initialize} && "{compiler}" /nologo append_child_c.obj append_child_asm.obj /link /OUT:"{TARGET}" '
        f'/DEF:"{SOURCE_DEF}" /IMPLIB:append_child.lib /MACHINE:X64',
    ]
    try:
        for command in commands:
            log.write('RUN ' + command + '\n')
            log.flush()
            subprocess.run(shell + initialize + ' && ' + command, cwd=WORK, stdout=log, stderr=subprocess.STDOUT,
                           creationflags=BELOW_NORMAL, timeout=180, check=True)
        log.write(f'TARGET_SHA256={fingerprint(TARGET)}\n')
        yield
    finally:
        # 自有目标仍可能映射映像；由调用者在关闭子进程后统一清理固定位置。
        log.write(f'BUILD_FINISHED={TARGET.exists()}\n')


class Child:
    """One owned target with its own event trio and a real creation identity."""

    def __init__(self):
        self.prefix = f'Local\\KSwordAppendGroup-{uuid4().hex}'
        self.handles = {
            'ready': CreateEvent(None, False, False, self.prefix + '-ready'),
            'trigger': CreateEvent(None, False, False, self.prefix + '-trigger'),
            'done': CreateEvent(None, False, False, self.prefix + '-done'),
        }
        for name, handle in self.handles.items():
            if not handle:
                raise Blocked(f'CreateEvent({name}) failed: {ct.get_last_error()}')
        env = dict(os.environ)
        env['KSWORD_PRODUCT_STEP_EVENTS'] = self.prefix
        self.process = subprocess.Popen([str(TARGET)], env=env, cwd=RELEASE,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
        self.pid = self.process.pid
        try:
            self.creation = creation_filetime(self.pid)
            if Wait(self.handles['ready'], 10000) != WAIT_OBJECT_0:
                raise Blocked(f'target {self.pid} did not signal ready')
        except BaseException:
            self.close()
            raise

    def fire(self):
        if not SetEvent(self.handles['trigger']):
            raise RuntimeError(f'SetEvent(trigger) failed for {self.pid}')

    def await_round(self, timeout=10000):
        return Wait(self.handles['done'], timeout) == WAIT_OBJECT_0

    def site(self, **extra):
        value = {'pid': self.pid, 'creationFileTime': self.creation, 'module': str(TARGET),
                 'exactExport': 'StepSite'}
        value.update(extra)
        return value

    def close(self):
        if getattr(self, 'closed', False):
            return
        self.closed = True
        for handle in self.handles.values():
            CloseHandle(handle)
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                TerminateProcess(self.process._handle, 1)


class Cli:
    def __init__(self, sites_path, project=None, stderr=None):
        args = [str(CLI), 'analyze', 'execution-group', 'session', '--sites', str(sites_path),
                '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl', '--backend', 'r3']
        if project is not None:
            args += ['--project', str(project)]
        self.lines = queue.Queue()
        self.session = None
        self.sequence = 0
        self.query_sequence = 0
        self.process = subprocess.Popen(args, cwd=RELEASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=LOG if stderr is None else stderr,
                                        encoding='utf-8', errors='replace',
                                        creationflags=subprocess.CREATE_NO_WINDOW)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        self.hello = self.receive('hello', None)

    def read(self):
        try:
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def receive(self, kind, request_id, timeout=15):
        line = self.lines.get(timeout=timeout)
        if line is None:
            raise RuntimeError(f'CLI closed stdout (exit={self.process.poll()})')
        LOG.write(f'[{datetime.now():%H:%M:%S.%f}] RX ' + line)
        frame = json.loads(line)
        self.sequence += 1
        ok(frame['schemaVersion'] == 1 and frame['streamSequence'] == str(self.sequence),
           f'frame sequence and schema for {kind}')
        ok(frame['type'] == kind, f'frame type {kind}, got {frame["type"]}')
        if kind != 'summary':
            ok(frame['requestId'] == request_id, f'frame requestId {request_id}')
        if self.session is None:
            self.session = frame['session']
        ok(frame['session'] == self.session, 'frame carries the same hello session')
        return frame['result']

    def send(self, request_id, method, params=None, expected=None, session=None):
        request = {'schemaVersion': 1, 'requestId': request_id, 'method': method,
                   'session': session if session is not None else self.session,
                   'params': params if params is not None else {}}
        if expected is not None:
            request['expected'] = expected
        line = json.dumps(request, separators=(',', ':')) + '\n'
        LOG.write(f'[{datetime.now():%H:%M:%S.%f}] TX ' + line)
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def request(self, request_id, method, params=None, expected=None, session=None, kind='response', timeout=15):
        self.send(request_id, method, params, expected, session)
        return self.receive(kind, request_id, timeout=timeout)

    def status(self):
        self.query_sequence += 1
        return self.request(f'query/{self.query_sequence}', 'control.query')

    def wait_held(self, pid, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.status()
            member = next((item for item in result['members'] if item['site']['pid'] == pid), None)
            if member and member['stopToken'] is not None:
                return result, member
            time.sleep(0.05)
        raise RuntimeError(f'member {pid} did not become held')

    def wait_armed(self, pid, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.status()
            member = next((item for item in result['members'] if item['site']['pid'] == pid), None)
            if member:
                binding = member['control'].get('breakpoint')
                if member['stopToken'] is not None:
                    return result, member
                if binding and binding['state'] == 1:
                    return result, member
            time.sleep(0.05)
        raise RuntimeError(f'member {pid} did not report an armed breakpoint')

    def finish(self):
        return self.process.wait(20)


def write_sites(path, sites):
    path.write_text(json.dumps({'schemaVersion': 1, 'sites': sites}, ensure_ascii=False), encoding='utf-8')
    return path


def member_of(result, pid):
    return next(item for item in result['members'] if item['site']['pid'] == pid)


def scenario(title):
    SCENARIOS.append({'name': title, 'checksStart': CHECKS + 1})
    note(f'=== {title}')


def end_scenario():
    SCENARIOS[-1]['checks'] = CHECKS - SCENARIOS[-1]['checksStart'] + 1


def run():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG.write(f'START={datetime.now(timezone.utc).isoformat()} CLI={CLI} SHA256={fingerprint(CLI)} '
              f'MTIME={datetime.fromtimestamp(CLI.stat().st_mtime, timezone.utc).isoformat()}\n')
    child_a = child_b = child_c = cli = None
    sites_a = WORK / 'sites-a.json'
    sites_b = WORK / 'sites-b.json'
    sites_dup = WORK / 'sites-duplicate.json'
    sites_bad = WORK / 'sites-invalid.json'
    sites_def = WORK / 'sites-definition.json'
    try:
        with built_target(LOG):
            note(f'TARGET_SHA256={fingerprint(TARGET)}')
            child_a = Child()
            note(f'CHILD_A pid={child_a.pid} creation={child_a.creation}')
            sites_a = write_sites(sites_a, [child_a.site()])

            scenario('1 append explicit instance B to a live collection')
            cli = Cli(sites_a, PROJECT)
            hello = cli.hello
            collection = hello['control']['collectionId']
            sample = hello['sampleId']
            ok(bool(collection) and bool(sample), 'hello advertises collection and sample identity')
            initial = cli.status()
            ok(initial['executionArchive']['writerLeaseHeld'] is True, 'project writer lease is held before attach')
            ok(initial['executionArchive']['setupError'] is None, 'initial project/sample setup succeeded')
            ok(len(initial['members']) == 1 and initial['members'][0]['site']['pid'] == child_a.pid,
               'start attached exactly the original member A')

            child_a.fire()
            _, a_held = cli.wait_held(child_a.pid)
            ok(a_held['held'] is True and a_held['stopToken'] is not None, 'A holds a real execution stop')
            ok(a_held['control']['state'] == 'held', 'A native control state is held')
            a_owner = json.dumps(a_held['owner'], sort_keys=True)
            a_stop = json.dumps(a_held['stopToken'], sort_keys=True)
            a_site = json.dumps(a_held['site'], sort_keys=True)
            a_binding = json.dumps(a_held['control']['breakpoint'], sort_keys=True)
            ok(a_held['owner']['sampleId'] == sample, 'A owner uses the frozen round sample')
            ok(bool(a_held['control']['breakpoint']['address']) and a_held['control']['breakpoint']['rangeBytes'] == '0',
               'A reports its original image execution site and zero dynamic range')

            child_b = Child()
            note(f'CHILD_B pid={child_b.pid} creation={child_b.creation}')
            sites_b = write_sites(sites_b, [child_b.site()])
            appended = cli.request('execution/1', 'control.members.append',
                                   {'sites': str(sites_b), 'confirm': True},
                                   {'collectionId': collection})
            ok(appended['operation']['action'] == 'members-append' and appended['operation']['admitted'] is True,
               'append operation is admitted')
            ok(len(appended['members']) == 2, 'member directory grows from 1 to 2')
            a_after = member_of(appended, child_a.pid)
            ok(json.dumps(a_after['owner'], sort_keys=True) == a_owner, 'A owner did not change')
            ok(json.dumps(a_after['stopToken'], sort_keys=True) == a_stop, 'A stop token byte-identical after append')
            ok(json.dumps(a_after['site'], sort_keys=True) == a_site, 'A frozen site did not change')
            ok(json.dumps(a_after['control']['breakpoint'], sort_keys=True) == a_binding, 'A binding/range unchanged')
            b_after = member_of(appended, child_b.pid)
            ok(b_after['owner']['sampleId'] == sample, 'B joins the same sample')
            ok(b_after['owner']['sessionId'] != a_held['owner']['sessionId'] and
               b_after['owner']['epoch'] != a_held['owner']['epoch'] and
               b_after['owner']['backendInstanceId'] != a_held['owner']['backendInstanceId'],
               'B has an independent session/epoch/backend owner')
            ok(b_after['attachAccepted'] is True, 'B attach accepted')
            outcome = next((item for item in appended['operation']['outcomes'] if item['pid'] == child_b.pid), None)
            ok(outcome is not None and outcome['actionAttempted'] is True, 'B outcome attempted its own attach')

            armed_result, armed_member = cli.wait_armed(child_b.pid)
            if armed_member['stopToken'] is None:
                child_b.fire()  # 只在确认真实breakpoint已Armed后触发本轮执行。
                _, b_held = cli.wait_held(child_b.pid)
            else:
                b_held = armed_member
            ok(b_held['stopToken'] is not None and b_held['control']['state'] == 'held',
               'B actually hits its own execution stop')
            ok(b_held['control']['nativeSnapshot']['group']['sampleId'] == sample,
               'B native stop group uses the same sample')
            a_still = member_of(cli.status(), child_a.pid)
            ok(json.dumps(a_still['stopToken'], sort_keys=True) == a_stop, 'A stop still unchanged after B hits')
            end_scenario()

            scenario('2 identical execution/N replay attaches nothing')
            replay = cli.request('execution/1', 'control.members.append',
                                 {'sites': str(sites_b), 'confirm': True},
                                 {'collectionId': collection})
            ok(json.dumps(replay, sort_keys=True) == json.dumps(appended, sort_keys=True),
               'replay returns the original append receipt unchanged')
            after_replay = cli.status()
            ok(len(after_replay['members']) == 2, 'replay did not add a member')
            ok(json.dumps(member_of(after_replay, child_b.pid)['owner']['sessionId']) ==
               json.dumps(b_after['owner']['sessionId']), 'B owner identity survived replay')
            end_scenario()

            scenario('3 duplicate PID and invalid configuration are rejected')
            sites_dup = write_sites(sites_dup, [child_a.site()])
            duplicate = cli.request('execution/2', 'control.members.append',
                                    {'sites': str(sites_dup), 'confirm': True},
                                    {'collectionId': collection})
            ok(duplicate['operation']['action'] == 'members-append' and duplicate['operation']['admitted'] is False,
               'duplicate PID batch is rejected')
            ok(duplicate['operation']['win32Error'] == 87 and
               duplicate['operation']['stage'] == 'execution-group-invalid-or-duplicate-site',
               'duplicate rejection carries the explicit site error')
            sites_bad.write_text('{"schemaVersion":1,"sites":[{"pid":', encoding='utf-8')
            invalid = cli.request('execution/3', 'control.members.append',
                                  {'sites': str(sites_bad), 'confirm': True},
                                  {'collectionId': collection})
            ok(invalid.get('errorId') == 'invalid-append-sites', 'invalid configuration reports invalid-append-sites')
            after_reject = cli.status()
            ok(len(after_reject['members']) == 2, 'rejected appends leave the member count unchanged')
            ok(json.dumps(member_of(after_reject, child_a.pid)['stopToken'], sort_keys=True) == a_stop,
               'A original stop remains readable after rejections')
            end_scenario()

            scenario('4 wrong collection, missing confirmation and stale identity are rejected')
            wrong_collection = cli.request('execution/5', 'control.members.append',
                                           {'sites': str(sites_b), 'confirm': True},
                                           {'collectionId': str(uuid4())}, kind='error')
            ok(wrong_collection.get('errorId') == 'invalid-append-members', 'wrong collection ID is rejected')
            unconfirmed = cli.request('execution/6', 'control.members.append',
                                      {'sites': str(sites_b), 'confirm': False},
                                      {'collectionId': collection}, kind='error')
            ok(unconfirmed.get('errorId') == 'invalid-append-members', 'confirm:false is rejected')
            stale = dict(cli.session)
            stale['epoch'] = str(uuid4()) + '-stale'
            stale_result = cli.request('execution/7', 'control.members.append',
                                       {'sites': str(sites_b), 'confirm': True},
                                       {'collectionId': collection}, session=stale, kind='error')
            ok(stale_result.get('errorId') == 'wrong-session', 'stale hello epoch is rejected')
            after_identities = cli.status()
            ok(len(after_identities['members']) == 2, 'identity rejections did not change members')
            ok(json.dumps(member_of(after_identities, child_a.pid)['stopToken'], sort_keys=True) == a_stop,
               'A stop remains the original after identity rejections')
            end_scenario()

            scenario('5 frozen definition failure keeps writer and original observation')
            child_c = Child()
            note(f'CHILD_C pid={child_c.pid} creation={child_c.creation}')
            sites_def = write_sites(sites_def, [{'pid': child_c.pid, 'creationFileTime': child_c.creation,
                                                 'module': str(TARGET), 'rva': 4096,
                                                 'definitionId': str(uuid4())}])
            definition = cli.request('execution/8', 'control.members.append',
                                     {'sites': str(sites_def), 'confirm': True},
                                     {'collectionId': collection})
            archive = definition['executionArchive']
            ok(definition['operation']['admitted'] is False, 'definition failure does not attach any member')
            ok(len(definition['members']) == 2, 'definition failure leaves the directory at two members')
            ok(archive['setupError'] is None and archive['memberSetupError'] is not None,
               'definition failure is reported separately as memberSetupError')
            ok(archive['writerLeaseHeld'] is True, 'definition failure retains the original project writer')
            saved = cli.request('execution/9', 'control.execution.save', {},
                                {'collectionId': collection,
                                 'stops': [member_of(definition, child_a.pid)['stopToken']]})
            saved_view = saved['executionArchive']
            ok(saved_view['saved'] is not None and saved_view['saved']['segmentVerified'] is True,
               'A original execution observation saved and verified on the same sample')
            ok(saved_view['saved']['owner']['sampleId'] == sample, 'saved segment belongs to the frozen sample')
            ok(saved_view['firstFailure'] is None, 'save did not report an append failure')
            ok(len(saved['members']) == 2 and json.dumps(member_of(saved, child_a.pid)['stopToken'], sort_keys=True) == a_stop,
               'save left A original stop and member directory unchanged')
            end_scenario()

            scenario('6 shutdown restores every original owner clean and targets exit normally')
            shutdown = cli.request('execution/10', 'controller.shutdown', {})
            ok(shutdown['clean'] is True and shutdown['state'] == 'closed', 'shutdown closes the collection clean')
            ok(all(member['control']['clean'] is True for member in shutdown['members']),
               'every original owner reports clean detach')
            summary = cli.receive('summary', None)
            ok(summary['reason'] == 'requested' and summary['exitCode'] == 0, 'summary reports requested exit code 0')
            ok(summary['control']['clean'] is True, 'final summary retains a clean collection')
            code = cli.finish()
            ok(code == 0, f'formal CLI exited 0, got {code}')
            cli = None
            for child in (child_a, child_b):
                ok(child.await_round(5000), f'target {child.pid} finished the held round after detach')
                for _ in range(2):
                    child.fire()
                    ok(child.await_round(5000), f'target {child.pid} finished a remaining round')
                code = exit_code(child.pid)
                ok(code == 0, f'target {child.pid} ended normally with code 0, got {code}')
            end_scenario()
    finally:
        for child in (child_a, child_b, child_c):
            if child is not None:
                child.close()
        if cli is not None:
            try:
                cli.process.kill()
            except Exception:
                pass
        target_sha = fingerprint(TARGET) if TARGET.exists() else None
        cleanup = {}
        for path in (sites_a, sites_b, sites_dup, sites_bad, sites_def, PROJECT, TARGET, WORK):
            if path is None:
                continue
            for _ in range(40):
                try:
                    if not path.exists():
                        break
                    if path.is_dir():
                        shutil.rmtree(path, ignore_errors=False)
                    else:
                        path.unlink(missing_ok=True)
                    break
                except (PermissionError, OSError):
                    time.sleep(0.25)
            cleanup[str(path)] = not path.exists()
        LOG.write('CLEANUP=' + json.dumps(cleanup) + '\n')
        RECEIPT.write_text(json.dumps({
            'cli': {'path': str(CLI), 'sha256': fingerprint(CLI),
                    'mtime': datetime.fromtimestamp(CLI.stat().st_mtime, timezone.utc).isoformat()},
            'target': {'path': str(TARGET), 'sha256': target_sha},
            'checks': CHECKS, 'scenarios': SCENARIOS,
            'cleanup': cleanup,
            'finished': datetime.now(timezone.utc).isoformat(),
        }, indent=2), encoding='utf-8')


if __name__ == '__main__':
    try:
        run()
        print(f'RESULT=PASS checks={CHECKS}')
        LOG.write(f'RESULT=PASS checks={CHECKS}\n')
    except Blocked as error:
        print(f'RESULT=BLOCKED {error}')
        LOG.write(f'RESULT=BLOCKED {error}\n')
        raise SystemExit(77)
    finally:
        LOG.close()
