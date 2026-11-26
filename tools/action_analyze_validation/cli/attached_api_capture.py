"""Acceptance host for the explicit R3 attachment path of ActionAnalyze.

One persistent process holds ``Local\\KSword.ActionAnalyze.CliValidation`` from
before the build until every case has finished, builds the Release CLI with the
repository script, compiles one owned x64 windowless target into the unified
Release output and then runs the positive and negative cases of this batch.

Only this host's own target processes are started. No driver, Sysmon, GUI or
foreign user process is touched.
"""

import argparse
import ctypes as ct
from ctypes import wintypes as win
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid


REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
AGENT = RELEASE / 'APIMonitor_x64.dll'
INT_DIR = REPO / 'KswordCLI' / 'x64' / 'Release' / 'AttachedApiCaptureValidation'
WORK = INT_DIR / 'work'
PROJECT = WORK / 'project'
TARGET = RELEASE / 'ActionAnalyzeAttachedApiCaptureTarget.exe'
SOURCE = Path(__file__).with_name('attached_api_capture_target.c')
LOG_DIR = REPO / '.codex-build-logs'
MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
COOPERATIVE_ENV = 'KSWORD_APIMON_COOPERATIVE_SESSION_V1'
STOP_ENV = 'KSWORD_ATTACHED_VALIDATION_STOP'

BELOW_NORMAL = 0x00004000
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_SUSPENDED_UNUSED = 0x00000004
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ct.c_void_p(-1).value
WAIT_TIMEOUT = 258
WAIT_OBJECT_0 = 0
WAIT_ABANDONED = 0x80
ERROR_ALREADY_EXISTS = 183
PACKET_SIZE = 1000
PACKET_VERSION = 0x20261003
SESSION_OFFSET = 896

RECORDS = []
FAILED = []
TARGET_PIDS = []
LIVE_TARGETS = []


class Tee:
    """Mirror every printed receipt line into the retained text log."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def check(section, name, condition, detail=''):
    ok = bool(condition)
    RECORDS.append((section, name, ok, detail))
    if not ok:
        FAILED.append(f'{section}: {name} {detail}'.strip())
    print(f"[{'PASS' if ok else 'FAIL'}] {section} | {name}" + (f' | {detail}' if detail else ''), flush=True)
    return ok


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


# --------------------------------------------------------------------------- Win32


_kernel = ct.WinDLL('kernel32', use_last_error=True)
_psapi = ct.WinDLL('psapi', use_last_error=True)


def _api(dll, name, result, *args):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, args
    return function


CreateMutexW = _api(_kernel, 'CreateMutexW', win.HANDLE, ct.c_void_p, win.BOOL, win.LPCWSTR)
ReleaseMutex = _api(_kernel, 'ReleaseMutex', win.BOOL, win.HANDLE)
WaitForSingleObject = _api(_kernel, 'WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
OpenProcess = _api(_kernel, 'OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
CloseHandle = _api(_kernel, 'CloseHandle', win.BOOL, win.HANDLE)
GetProcessTimes = _api(_kernel, 'GetProcessTimes', win.BOOL, win.HANDLE, *([ct.POINTER(win.FILETIME)] * 4))
CreateEventW = _api(_kernel, 'CreateEventW', win.HANDLE, ct.c_void_p, win.BOOL, win.BOOL, win.LPCWSTR)
SetEvent = _api(_kernel, 'SetEvent', win.BOOL, win.HANDLE)
TerminateProcess = _api(_kernel, 'TerminateProcess', win.BOOL, win.HANDLE, win.UINT)
GetExitCodeProcess = _api(_kernel, 'GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
CreateToolhelp32Snapshot = _api(_kernel, 'CreateToolhelp32Snapshot', win.HANDLE, win.DWORD, win.DWORD)
Module32FirstW = _api(_kernel, 'Module32FirstW', win.BOOL, win.HANDLE, ct.c_void_p)
Module32NextW = _api(_kernel, 'Module32NextW', win.BOOL, win.HANDLE, ct.c_void_p)
GetTempPathW = _api(_kernel, 'GetTempPathW', win.DWORD, win.DWORD, win.LPWSTR)


class MODULEENTRY32W(ct.Structure):
    _fields_ = [('dwSize', win.DWORD), ('th32ModuleID', win.DWORD), ('th32ProcessID', win.DWORD),
                ('GlblcntUsage', win.DWORD), ('ProccntUsage', win.DWORD),
                ('modBaseAddr', ct.POINTER(ct.c_byte)), ('modBaseSize', win.DWORD),
                ('hModule', win.HMODULE), ('szModule', win.WCHAR * 256), ('szExePath', win.WCHAR * 260)]


def process_alive(handle):
    return WaitForSingleObject(handle, 0) == WAIT_TIMEOUT


def process_creation(pid):
    handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not handle:
        raise RuntimeError(f'OpenProcess {pid} failed: {ct.get_last_error()}')
    try:
        times = [win.FILETIME() for _ in range(4)]
        if not GetProcessTimes(handle, *(ct.byref(item) for item in times)):
            raise RuntimeError(f'GetProcessTimes {pid} failed: {ct.get_last_error()}')
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    finally:
        CloseHandle(handle)


def loaded_modules(pid):
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        raise RuntimeError(f'module snapshot failed: {ct.get_last_error()}')
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ct.sizeof(entry)
        names = []
        ok = Module32FirstW(snapshot, ct.byref(entry))
        while ok:
            names.append(entry.szModule)
            ok = Module32NextW(snapshot, ct.byref(entry))
        return names
    finally:
        CloseHandle(snapshot)


def temp_session_file(name):
    # 产品按机器级 %WINDIR%\Temp 解析会话文件，不跟随调用者的 TEMP。
    windows = Path(os.environ['WINDIR']) / 'Temp' / 'KswordApiMon'
    return windows / name


# --------------------------------------------------------------------------- mutex


@contextmanager
def cli_validation_mutex(log):
    handle = CreateMutexW(None, False, MUTEX_NAME)
    require(handle, f'CreateMutex failed: {ct.get_last_error()}')
    acquired = False
    try:
        print(f'MUTEX_HANDLE={handle:#x}', flush=True)
        status = WaitForSingleObject(handle, 0)
        if status == WAIT_TIMEOUT:
            print('MUTEX=held-by-other; waiting up to 900s without touching that process', flush=True)
            status = WaitForSingleObject(handle, 900000)
        if status == WAIT_ABANDONED:
            print('MUTEX=acquired-after-abandon', flush=True)
        require(status == WAIT_OBJECT_0 or status == WAIT_ABANDONED,
                f'could not acquire {MUTEX_NAME}: wait status {status}')
        acquired = True
        print('MUTEX=acquired', flush=True)
        yield
    finally:
        # 显式释放所有权，避免后续宿主在旧进程存活时无限等待。
        if acquired:
            ReleaseMutex(handle)
        CloseHandle(handle)
        print('MUTEX=released', flush=True)


# --------------------------------------------------------------------------- build


def build_cli(log):
    script = REPO / 'tools' / 'Invoke-KSwordCliBuildCheck.ps1'
    require(script.is_file(), f'missing build script: {script}')
    # 一次适用构建；失败立即中止本轮，不自动重试，也不使用已有旧二进制继续实测。
    started = time.monotonic()
    process = subprocess.run(['pwsh', '-NoProfile', '-File', str(script)], cwd=REPO,
                             capture_output=True, creationflags=BELOW_NORMAL, timeout=2400)
    elapsed = time.monotonic() - started
    text = (process.stdout + process.stderr).decode('utf-8', 'replace')
    print(text, flush=True)
    print(f'BUILD_EXIT_CODE={process.returncode} BUILD_SECONDS={elapsed:.1f} '
          f'STDOUT_BYTES={len(process.stdout)} STDERR_BYTES={len(process.stderr)}', flush=True)
    check('build', 'exit code 0', process.returncode == 0, f'code={process.returncode}')
    check('build', 'BUILD_RESULT=SUCCESS', 'BUILD_RESULT=SUCCESS' in text)
    check('build', 'EXIT_CODE=0', 'EXIT_CODE=0' in text)
    int_dir = next((line.split('=', 1)[1] for line in text.splitlines() if line.startswith('IntDir=')), '')
    out_dir = next((line.split('=', 1)[1] for line in text.splitlines() if line.startswith('OutDir=')), '')
    host = next((line.split('=', 1)[1] for line in text.splitlines() if line.startswith('VC_ExecutablePath_x64=')), '')
    check('build', 'IntDir is the fixed CLI Release directory',
          Path(int_dir).resolve() == (REPO / 'KswordCLI' / 'x64' / 'Release').resolve(), int_dir)
    check('build', 'OutDir is the unified Release directory',
          Path(out_dir).resolve() == RELEASE.resolve(), out_dir)
    check('build', 'HostX64 compiler host', 'hostx64\\x64' in host.lower(), host)
    check('build', 'CLI artifact exists', CLI.is_file() and CLI.stat().st_size > 0)
    if process.returncode != 0:
        raise RuntimeError(f'CLI build failed with {process.returncode}; refusing to test a stale binary')
    return text


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def msvc_vcvars():
    choices = [Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'), Path(r'D:\Software\VS')]
    setup = next((base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat' for base in choices
                  if (base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat').is_file()), None)
    require(setup is not None, 'MSVC vcvars64.bat is required')
    return setup


def build_target(log):
    setup = msvc_vcvars()
    initialize = f'call "{setup}" >nul'
    shell = f'"{os.environ["ComSpec"]}" /d /c '
    paths = subprocess.check_output(shell + initialize + ' && where cl.exe', cwd=INT_DIR,
                                    creationflags=BELOW_NORMAL, text=True, timeout=60).splitlines()
    compiler = next((Path(path) for path in paths if path.lower().endswith(r'\hostx64\x64\cl.exe')), None)
    require(compiler is not None and compiler.is_file(), f'HostX64 compiler required: {paths}')
    log.write(f'FIXTURE_INTDIR={INT_DIR}\nFIXTURE_OUTDIR={TARGET}\nFIXTURE_HOSTX64={compiler}\n'
              f'FIXTURE_PRIORITY=BelowNormal\n')
    log.flush()
    print(f'FIXTURE_HOSTX64={compiler}', flush=True)
    command = (f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 "{SOURCE}" '
               f'/Fd:"{INT_DIR}\\target.pdb" '
               f'/link /OUT:"{TARGET}" /IMPLIB:"{INT_DIR}\\target.lib" /MACHINE:X64')
    process = subprocess.run(shell + command, cwd=INT_DIR, capture_output=True,
                             creationflags=BELOW_NORMAL, timeout=180)
    text = (process.stdout + process.stderr).decode('utf-8', 'replace')
    print(text, flush=True)
    check('fixture', 'target compiled', process.returncode == 0 and TARGET.is_file(),
          f'code={process.returncode}')
    text_source = SOURCE.read_text(encoding='utf-8')
    check('fixture', 'fixture source never loads a library', 'LoadLibrary' not in text_source)
    if TARGET.is_file():
        check('fixture', 'fixture binary does not import the product Agent',
              b'APIMonitor' not in TARGET.read_bytes())
    else:
        raise RuntimeError('fixture target was not produced')


# --------------------------------------------------------------------------- CLI helpers


def run_cli(args, timeout=180, new_group=False):
    flags = CREATE_NO_WINDOW | (CREATE_NEW_PROCESS_GROUP if new_group else 0)
    process = subprocess.run([str(CLI), *args], cwd=RELEASE, capture_output=True,
                             creationflags=flags, timeout=timeout)
    data = None
    try:
        data = json.loads(process.stdout)['data'] if process.stdout.strip() else None
    except (ValueError, KeyError):
        data = None
    return process.returncode, data, process.stdout, process.stderr


GenerateConsoleCtrlEvent = _api(_kernel, 'GenerateConsoleCtrlEvent', win.BOOL, win.DWORD, win.DWORD)


def send_break(pid):
    if not GenerateConsoleCtrlEvent(1, pid):  # CTRL_BREAK_EVENT
        raise OSError(ct.get_last_error(), 'GenerateConsoleCtrlEvent failed')


def as_int(value):
    return int(str(value))


def create_project(path, title):
    result = subprocess.run([str(CLI), 'analyze', 'session'],
                            input=f'project create "{path}" "{title}"\nquit\n'.encode(),
                            cwd=RELEASE, capture_output=True, timeout=60,
                            creationflags=CREATE_NO_WINDOW)
    require((path / 'project.ksaproj').is_file(), f'project create failed: {result.stdout} {result.stderr}')
    return json.loads((path / 'project.ksaproj').read_bytes())['projectId']


def sample_ids(path):
    root = path / 'samples'
    return sorted(item.name for item in root.iterdir()) if root.is_dir() else []


def parse_packet(hex_text):
    raw = bytes.fromhex(hex_text)
    require(len(raw) == PACKET_SIZE, f'packet length {len(raw)}')
    size, version, pid, tid = struct.unpack_from('<IIII', raw, 0)
    timestamp, = struct.unpack_from('<Q', raw, 16)
    category, result_code = struct.unpack_from('<Ii', raw, 24)
    module = raw[32:96].decode('utf-16-le').split('\x00')[0]
    api = raw[96:224].decode('utf-16-le').split('\x00')[0]
    session, = struct.unpack_from('<Q', raw, SESSION_OFFSET)
    return dict(size=size, version=version, pid=pid, tid=tid, timestamp=timestamp,
                category=category, resultCode=result_code, module=module, api=api, session=session)


# --------------------------------------------------------------------------- target


class Target:
    def __init__(self, hold_seconds, log):
        self.events = []
        env = dict(os.environ)
        env.pop(COOPERATIVE_ENV, None)
        self.stop_name = r'Local\KSwordAttachedValidation-' + uuid.uuid4().hex + '-stop'
        # Create the named event, leave it non-signalled and release our handle so the
        # target can open it by name and the host can signal it later.
        seed = CreateEventW(None, True, False, self.stop_name)
        require(seed, f'CreateEvent failed: {ct.get_last_error()}')
        CloseHandle(seed)
        env[STOP_ENV] = self.stop_name
        self.process = subprocess.Popen([str(TARGET), str(hold_seconds)], cwd=RELEASE, env=env,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=log, creationflags=CREATE_NO_WINDOW)
        self.identity = json.loads(self.process.stdout.readline().decode('utf-8'))
        self.identity['creation'] = int(self.identity['creation'])
        self.closed = False
        TARGET_PIDS.append(self.identity['pid'])
        LIVE_TARGETS.append(self)
        self.handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, self.identity['pid'])
        require(self.handle, f'OpenProcess target failed: {ct.get_last_error()}')
        self.log = log

    def alive(self):
        return process_alive(self.handle)

    def modules(self):
        return loaded_modules(self.identity['pid'])

    def agent_loaded(self):
        return any(name.lower() == AGENT.name.lower() for name in self.modules())

    def stop(self, timeout=20):
        signal_event = CreateEventW(None, True, False, self.stop_name)
        if signal_event:
            SetEvent(signal_event)
            CloseHandle(signal_event)
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            TerminateProcess(self.handle, 1)
            code = self.process.wait(timeout=10)
        tail = self.process.stdout.read().decode('utf-8', 'replace').strip()
        if not self.closed:
            CloseHandle(self.handle)
            self.closed = True
        self.exit_code, self.tail = code, tail
        return code, tail

    def ensure_stopped(self):
        """Leave no owned target behind, including after a failed case."""
        if self.process.poll() is None:
            try:
                self.stop(timeout=15)
            except Exception:  # noqa: BLE001
                TerminateProcess(self.handle, 1)
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
        if not self.closed:
            CloseHandle(self.handle)
            self.closed = True


# --------------------------------------------------------------------------- positive cases


def replay_page(project, sample, after=0, limit=100):
    args = ['analyze', 'api-evidence', 'replay', '--project', str(project), '--sample', sample,
            '--limit', str(limit), '--packet', '1']
    if after:
        args += ['--after', str(after)]
    return run_cli(args + ['--json'])


def positive_finite(log):
    section = 'attach-1000ms'
    target = Target(30, log)
    check(section, 'target never preloaded the Agent', not target.agent_loaded())
    check(section, 'target identity matches GetProcessTimes',
          target.identity['creation'] == process_creation(target.identity['pid']))
    code, data, out, err = run_cli(['analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                                    '--title', 'Attached explicit R3 finite',
                                    '--pid', str(target.identity['pid']),
                                    '--creation-filetime', str(target.identity['creation']),
                                    '--confirm', '--duration-ms', '1000', '--json'])
    print(f'ATTACH_FINITE_EXIT={code} DATA={json.dumps(data, sort_keys=True)}', flush=True)
    check(section, 'exit code is 0 or 6 (partial allowed)', code in (0, 6), f'code={code}')
    require(data is not None, f'attach produced no JSON: {out!r} {err!r}')
    check(section, 'status is capture-complete/partial',
          data.get('status') in ('capture-complete', 'capture-partial'), str(data.get('status')))
    check(section, 'captureMode is explicit-r3-attachment',
          data.get('captureMode') == 'explicit-r3-attachment', str(data.get('captureMode')))
    check(section, 'attachmentIdentityVerified', data.get('attachmentIdentityVerified') is True)
    check(section, 'agentLoadAttempted (module was not resident)', data.get('agentLoadAttempted') is True)
    check(section, 'agentModuleVerified', data.get('agentModuleVerified') is True)
    check(section, 'agentPath is the Release product Agent',
          str(data.get('agentPath', '')) and Path(data['agentPath']).resolve() == AGENT.resolve(),
          str(data.get('agentPath')))
    check(section, 'agentReady', data.get('agentReady') is True)
    check(section, 'sessionReady reported by the same pipe', data.get('sessionReady') is True)
    check(section, 'hooksInstalled', data.get('hooksInstalled') is True)
    check(section, 'current complete coverage snapshot', data.get('coverageSnapshotCurrent') is True)
    check(section, 'configPublished', data.get('configPublished') is True)
    check(section, 'connected', data.get('connected') is True)
    check(section, 'covered revision published at ready',
          as_int(data.get('readyCoverageRevision') or 0) > 0, str(data.get('readyCoverageRevision')))
    check(section, 'ordinaryPackets observed', as_int(data.get('ordinaryPackets') or 0) > 0,
          str(data.get('ordinaryPackets')))
    check(section, 'archivedPackets equals verified ordinary packets',
          as_int(data.get('archivedPackets') or 0) == as_int(data.get('ordinaryPackets') or 0),
          f"{data.get('archivedPackets')} vs {data.get('ordinaryPackets')}")
    archive = data.get('archive') or {}
    committed = as_int(archive.get('committedSegments') or 0)
    check(section, 'multiple committed segments', committed >= 2, str(committed))
    check(section, 'no omitted clues', as_int(data.get('omittedClues') or 0) == 0)
    check(section, 'cleanupComplete', data.get('cleanupComplete') is True)
    check(section, 'stopMarkerWritten', data.get('stopMarkerWritten') is True)
    check(section, 'hooksRemoved', data.get('hooksRemoved') is True)
    check(section, 'cleanPipeEof', data.get('cleanPipeEof') is True)
    check(section, 'targetExited is false (target still alive)', data.get('targetExited') is False)
    check(section, 'target process still alive after capture', target.alive())
    check(section, 'CLI loaded the Agent into the frozen target', target.agent_loaded())
    check(section, 'terminal segment published', archive.get('finalSegment') is True)
    check(section, 'archive source is the cooperative pipe',
          archive.get('archiveSource') == 'cooperative-pipe', str(archive.get('archiveSource')))
    check(section, 'readback status is readback-verified',
          archive.get('status') == 'readback-verified', str(archive.get('status')))

    sample = data['sampleId']
    checkpoints = PROJECT / 'samples' / sample / 'checkpoints'
    markers = sorted(checkpoints.glob('*.json'))
    check(section, 'checkpoint files cover every committed segment', len(markers) == committed,
          f'{len(markers)} files vs {committed} segments')
    last_marker = json.loads(markers[-1].read_bytes())
    check(section, 'last checkpoint is the terminal segment', last_marker.get('finalSegment') is True)
    check(section, 'replay sourceRows equals the final checkpoint watermark',
          as_int(archive.get('sourceRows') or -1) == as_int(last_marker['lastSourceSequence']),
          f"{archive.get('sourceRows')} vs {last_marker['lastSourceSequence']}")

    code, replay, out, err = replay_page(PROJECT, sample, limit=100)
    print(f'REPLAY_EXIT={code} ROWS={len((replay or {}).get("rows") or [])}', flush=True)
    check(section, 'replay exit code 0', code == 0, f'code={code}')
    require(replay is not None, f'replay produced no JSON: {out!r} {err!r}')
    check(section, 'replay committedSegments equals capture',
          as_int(replay['committedSegments']) == committed, f"{replay['committedSegments']} vs {committed}")
    rows = replay.get('rows') or []
    check(section, 'replay returned archived rows', len(rows) > 0, str(len(rows)))
    check(section, 'replay returned every archived clue row',
          len(rows) == as_int(archive.get('clueRows') or -1),
          f"{len(rows)} vs {archive.get('clueRows')}")
    sessions = {as_int(data['sourceSessionIdentity'])}
    creation = target.identity['creation']
    window_end = creation + (as_int(data['elapsedMs']) + 5000) * 10000
    previous = (0, 0)
    ordered = True
    identity_ok = True
    timestamps_ok = True
    for row in rows:
        packet = parse_packet(row['packet'])
        segment = as_int(row['rawSegment'])
        raw = as_int(row['rawSequence'])
        ordered &= 1 <= segment <= committed and raw > 1
        ordered &= segment >= previous[0]
        ordered &= segment > previous[0] or raw > previous[1]
        identity_ok &= (packet['size'] == PACKET_SIZE and packet['version'] == PACKET_VERSION
                        and packet['pid'] == target.identity['pid'] and packet['tid'] == target.identity['tid']
                        and packet['session'] in sessions
                        and as_int(row['sourceSessionIdentity']) == packet['session']
                        and as_int(row['pid']) == target.identity['pid']
                        and bool(packet['module']) and bool(packet['api']))
        timestamps_ok &= creation <= packet['timestamp'] <= window_end
        previous = (segment, raw)
    check(section, 'replayed coordinates are real and strictly ordered', ordered)
    check(section, 'replayed packets keep the same sample identity and target coordinates', identity_ok)
    check(section, 'replayed packet timestamps fall inside the frozen instance window', timestamps_ok)
    check(section, 'last replayed coordinate sits in the terminal segment', previous[0] == committed,
          str(previous))

    code, again, out, err = replay_page(PROJECT, sample, limit=100)
    again_rows = (again or {}).get('rows') or []
    same = (code == 0 and len(again_rows) == len(rows)
            and all(a['rawSegment'] == b['rawSegment'] and a['rawSequence'] == b['rawSequence']
                    and a['packet'] == b['packet'] and a['sourceSequence'] == b['sourceSequence']
                    for a, b in zip(rows, again_rows)))
    check(section, 'a second replay returns the identical same-sample raw packets', same)

    exit_code, tail = target.stop()
    print(f'TARGET_EXIT={exit_code} TAIL={tail}', flush=True)
    check(section, 'target exits normally after the capture', exit_code == 0, str(exit_code))
    check(section, 'target kept the injected Agent until exit', '"agentLoaded":true' in tail.replace(' ', ''), tail)
    return data


def positive_continuous(log):
    section = 'attach-duration0'
    target = Target(30, log)
    check(section, 'fresh target never preloaded the Agent', not target.agent_loaded())
    # 新进程组与共享控制台：CtrlBreak 只能投递给同一控制台中的目标组。
    flags = CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen([str(CLI), 'analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                                '--title', 'Attached explicit R3 continuous',
                                '--pid', str(target.identity['pid']),
                                '--creation-filetime', str(target.identity['creation']),
                                '--confirm', '--duration-ms', '0', '--json'],
                               cwd=RELEASE, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=log, creationflags=flags)
    time.sleep(5.0)
    if process.poll() is not None:
        early_out, early_err = process.communicate()
        print(f'EARLY_EXIT={process.returncode} OUT={early_out!r} ERR={early_err!r}', flush=True)
        raise RuntimeError(f'continuous CLI exited before the stop request: {process.returncode}')
    break_sent = True
    try:
        send_break(process.pid)
    except OSError as error:
        break_sent = False
        print(f'CTRL_BREAK_UNAVAILABLE={error}; ending the capture through the owned target exit', flush=True)
        target.stop()
    try:
        out, err = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        print('CTRL_BREAK_NO_EFFECT=1; ending the capture through the owned target exit', flush=True)
        break_sent = False
        target.stop()
        out, err = process.communicate(timeout=120)
    code = process.returncode
    data = None
    try:
        data = json.loads(out)['data'] if out.strip() else None
    except (ValueError, KeyError):
        data = None
    print(f'ATTACH_CONTINUOUS_EXIT={code} DATA={json.dumps(data, sort_keys=True)}', flush=True)
    check(section, 'continuous capture ends with exit code 6', code == 6, f'code={code}')
    require(data is not None, f'continuous attach produced no JSON: {out!r} {err!r}')
    check(section, 'status is capture-partial', data.get('status') == 'capture-partial', str(data.get('status')))
    check(section, 'cancellation flag matches the stop path used',
          data.get('cancelled') is break_sent, f"cancelled={data.get('cancelled')} breakSent={break_sent}")
    check(section, 'completedInterval stays false for duration 0', data.get('completedInterval') is False)
    check(section, 'captureMode is explicit-r3-attachment',
          data.get('captureMode') == 'explicit-r3-attachment')
    check(section, 'attachment/admission evidence kept', data.get('attachmentIdentityVerified') is True
          and data.get('agentLoadAttempted') is True and data.get('agentModuleVerified') is True)
    check(section, 'continuous run archived activity', as_int(data.get('ordinaryPackets') or 0) > 0,
          str(data.get('ordinaryPackets')))
    check(section, 'several committed segments before the stop',
          as_int((data.get('archive') or {}).get('committedSegments') or 0) >= 2,
          str((data.get('archive') or {}).get('committedSegments')))
    check(section, 'final segment committed on cancellation',
          (data.get('archive') or {}).get('finalSegment') is True)
    check(section, 'cleanupComplete after cancellation', data.get('cleanupComplete') is True)
    check(section, 'hooksRemoved after cancellation', data.get('hooksRemoved') is True)
    check(section, 'cleanPipeEof after cancellation', data.get('cleanPipeEof') is True)
    if break_sent:
        check(section, 'target survived the CtrlBreak cancellation',
              target.alive() and data.get('targetExited') is False)
        exit_code, tail = target.stop()
    else:
        exit_code, tail = target.exit_code, target.tail
    check(section, 'target exits normally afterwards', exit_code == 0, str(exit_code))
    check(section, 'target kept the injected Agent until exit', '"agentLoaded":true' in tail.replace(' ', ''), tail)
    return data


# --------------------------------------------------------------------------- negative cases


def negative_controls(log):
    section = 'negatives'
    created_before = set(sample_ids(PROJECT))

    # 1. Missing --confirm must be rejected before any project or target side effect.
    target = Target(20, log)
    config = temp_session_file(f"config_{target.identity['pid']}.ini")
    config.unlink(missing_ok=True)
    code, data, out, err = run_cli(['analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                                    '--title', 'Attach without confirmation',
                                    '--pid', str(target.identity['pid']),
                                    '--creation-filetime', str(target.identity['creation']),
                                    '--duration-ms', '1000', '--json'])
    print(f'MISSING_CONFIRM_EXIT={code} DATA={json.dumps(data)}', flush=True)
    check(section, 'missing --confirm is rejected with exit 1', code == 1, f'code={code}')
    check(section, 'missing --confirm reports invalid-attachment-scope',
          (data or {}).get('status') == 'invalid-attachment-scope', str((data or {}).get('status')))
    check(section, 'missing --confirm did not load the Agent', not target.agent_loaded())
    check(section, 'missing --confirm did not publish config', not config.exists(), str(config))
    check(section, 'missing --confirm did not create a sample', set(sample_ids(PROJECT)) == created_before)

    # 2. Wrong creation FILETIME must fail after identity verification, without loading or publishing.
    wrong = target.identity['creation'] ^ 0x1000
    code, data, out, err = run_cli(['analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                                    '--title', 'Attach with wrong creation time',
                                    '--pid', str(target.identity['pid']),
                                    '--creation-filetime', str(wrong),
                                    '--confirm', '--duration-ms', '1000', '--json'])
    print(f'WRONG_FILETIME_EXIT={code} DATA={json.dumps(data)}', flush=True)
    check(section, 'wrong FILETIME fails with exit 3', code == 3, f'code={code}')
    check(section, 'wrong FILETIME reports capture-failed',
          (data or {}).get('status') == 'capture-failed', str((data or {}).get('status')))
    check(section, 'wrong FILETIME leaves identity unverified', (data or {}).get('attachmentIdentityVerified') is False)
    check(section, 'wrong FILETIME did not load the Agent', not target.agent_loaded())
    check(section, 'wrong FILETIME did not publish config', not config.exists(), str(config))
    check(section, 'wrong FILETIME did not commit a segment',
          as_int((data or {}).get('committedSegments') or 0) == 0)

    # 3. R0 backend selection and explicit R0 injection are both rejected.
    code, data, out, err = run_cli(['analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                                    '--title', 'Attach on r0 backend',
                                    '--pid', str(target.identity['pid']),
                                    '--creation-filetime', str(target.identity['creation']),
                                    '--confirm', '--duration-ms', '1000', '--backend', 'r0', '--json'])
    print(f'BACKEND_R0_EXIT={code} DATA={json.dumps(data)}', flush=True)
    check(section, '--backend r0 is rejected before the command runs', code == 1, f'code={code}')
    check(section, '--backend r0 reports unsupported backend',
          'unsupported backend' in str((data or {}).get('diagnostics')) + str(parse_diagnostics(out, err)),
          parse_diagnostics(out, err))
    code, data, out, err = run_cli(['analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                                    '--title', 'Attach with explicit R0 injection',
                                    '--pid', str(target.identity['pid']),
                                    '--creation-filetime', str(target.identity['creation']),
                                    '--confirm', '--duration-ms', '1000', '--r0-inject', '1', '--json'])
    print(f'R0_INJECT_EXIT={code} DATA={json.dumps(data)}', flush=True)
    check(section, 'explicit R0 injection is rejected', code == 1, f'code={code}')
    check(section, 'explicit R0 injection reports an unknown option',
          'unknown option' in parse_diagnostics(out, err), parse_diagnostics(out, err))
    check(section, 'rejected R0 selections left the target unloaded', not target.agent_loaded())
    code, tail = target.stop()
    check(section, 'negative-control target exits normally', code == 0, str(code))

    # 4. The legacy monitor entry still rejects duration 0.
    legacy = Target(20, log)
    code, data, out, err = run_cli(['monitor', 'api', 'capture', '--pid', str(legacy.identity['pid']),
                                    '--confirm', '--duration-ms', '0', '--json'])
    print(f'MONITOR_DURATION0_EXIT={code} DATA={json.dumps(data)}', flush=True)
    check(section, 'ordinary monitor api capture still rejects duration 0', code == 1, f'code={code}')
    check(section, 'ordinary monitor rejection names the duration bound',
          'duration-ms' in parse_diagnostics(out, err), parse_diagnostics(out, err))
    check(section, 'ordinary monitor rejection left the Agent unloaded', not legacy.agent_loaded())
    code, tail = legacy.stop()
    check(section, 'legacy negative-control target exits normally', code == 0, str(code))


def parse_diagnostics(out, err):
    text = (out or b'').decode('utf-8', 'replace') + (err or b'').decode('utf-8', 'replace')
    try:
        payload = json.loads(out)
        return text + ' ' + ' '.join(str(item) for item in payload.get('diagnostics') or [])
    except (ValueError, AttributeError):
        return text


# --------------------------------------------------------------------------- source gates


def source_gates():
    section = 'source-gate'
    capture = (REPO / 'shared' / 'ApiMonitorCapture.cpp').read_text(encoding='utf-8')
    check(section, 'strict observation rejects behavior options',
          '(!strict && behavioral.count(key))' in capture)
    check(section, 'incomplete attach opt-in cannot fall back to the legacy path',
          'if (attached || request.attachConfirmed || request.strictReadOnlyObservation)' in capture
          and 'request.attachConfirmed && request.strictReadOnlyObservation' in capture)
    check(section, 'strict admission refuses descendant injection and R0',
          'valid = valid && !request.autoChildren && !request.useR0Injection' in capture)
    check(section, 'COOPERATIVE_ONLY build rejects explicit attachment',
          'valid = valid && resident && !attached;' in capture)
    desktop = (REPO / 'Ksword5.1' / 'Ksword5.1' / 'Ksword5.1.vcxproj').read_text(encoding='utf-8')
    light = (REPO / 'KswordARKLight' / 'KswordARKLight.vcxproj').read_text(encoding='utf-8')
    cli = (REPO / 'KswordCLI' / 'KswordCLI.vcxproj').read_text(encoding='utf-8')
    check(section, 'desktop and Light compile the cooperative-only gate',
          'KSWORD_APIMON_COOPERATIVE_ONLY' in desktop and 'KSWORD_APIMON_COOPERATIVE_ONLY' in light)
    check(section, 'CLI keeps the attachment path compiled in',
          'KSWORD_APIMON_COOPERATIVE_ONLY' not in cli)
    preprocess_gate(capture)


def preprocess_gate(capture_text):
    """Preprocess the real translation unit with the desktop define and verify the gate."""
    section = 'source-gate'
    setup = msvc_vcvars()
    initialize = f'call "{setup}" >nul'
    shell = f'"{os.environ["ComSpec"]}" /d /c '
    shared = REPO / 'shared'
    outputs = {}
    for tag, define in (('plain', ''), ('desktop', ' /DKSWORD_APIMON_COOPERATIVE_ONLY')):
        out_file = INT_DIR / f'gate_{tag}.i'
        command = (f'{initialize} && cl.exe /nologo /P /TP{define} /I"{shared}" '
                   f'"{shared / "ApiMonitorCapture.cpp"}" /Fi"{out_file}"')
        process = subprocess.run(shell + command, cwd=INT_DIR, capture_output=True,
                                 creationflags=BELOW_NORMAL, timeout=180)
        text = (process.stdout + process.stderr).decode('utf-8', 'replace')
        if process.returncode != 0 or not out_file.is_file():
            check(section, f'preprocess with define {tag!r} works', False, text[-400:])
            return
        outputs[tag] = out_file.read_text(encoding='utf-8', errors='replace')
        out_file.unlink(missing_ok=True)
    gate = 'valid = valid && resident && !attached;'
    check(section, 'preprocessor keeps the COOPERATIVE_ONLY attachment rejection',
          gate in outputs['desktop'] and gate not in outputs['plain'])
    check(section, 'preprocessor keeps the CLI attachment admission',
          'request.attachCreationFileTime' in outputs['plain'])


# --------------------------------------------------------------------------- cleanup


def cleanup_targets(pids):
    for target in list(LIVE_TARGETS):
        target.ensure_stopped()
    for pid in pids:
        for name in (f'config_{pid}.ini', f'stop_{pid}.flag'):
            path = temp_session_file(name)
            if path.exists():
                path.unlink()
                print(f'CLEANED={path}', flush=True)


def cleanup_outputs(keep):
    if keep:
        print('CLEANUP=skipped by --keep', flush=True)
        return
    target = TARGET.resolve()
    require(target.parent == RELEASE.resolve(), f'unexpected target path {target}')
    target.unlink(missing_ok=True)
    for suffix in ('.pdb', '.lib', '.exp'):
        (RELEASE / (TARGET.stem + suffix)).unlink(missing_ok=True)
    root = INT_DIR.resolve()
    require(root.is_relative_to((REPO / 'KswordCLI' / 'x64' / 'Release').resolve()), f'unexpected {root}')
    shutil.rmtree(root, ignore_errors=True)
    print(f'CLEANUP=removed {root}', flush=True)
    require(not root.exists(), f'leftover intermediate directory {root}')
    require(not target.exists(), f'leftover target {target}')


# --------------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--keep', action='store_true')
    parser.add_argument('--log', default=None)
    args = parser.parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    log_path = Path(args.log) if args.log else LOG_DIR / f'action-analyze-attached-api-capture-{stamp}.log'
    with log_path.open('w', encoding='utf-8', newline='\n') as log:
        previous_stdout = sys.stdout
        sys.stdout = Tee(sys.stdout, log)

        def emit(text):
            print(text, flush=True)

        try:
            emit(f'LOG={log_path}')
            emit(f'REPO={REPO}')
            emit(f'RELEASE={RELEASE}')
            emit(f'INT_DIR={INT_DIR}')
            emit(f'PROJECT={PROJECT}')
            emit(f'TARGET={TARGET}')
            # 构建、编译、实测与清理全程持同一个命名互斥。
            with cli_validation_mutex(log):
                try:
                    if not args.skip_build:
                        build_cli(log)
                    else:
                        check('build', 'reused existing CLI artifact', CLI.is_file())
                    emit(f'CLI_SHA256={sha256(CLI)}')
                    emit(f'AGENT_SHA256={sha256(AGENT)}')
                    emit(f'CLI_SIZE={CLI.stat().st_size}')

                    cli_digest = sha256(CLI)
                    require(not INT_DIR.exists(), f'intermediate directory already exists: {INT_DIR}')
                    INT_DIR.mkdir(parents=True)
                    build_target(log)
                    emit(f'TARGET_SHA256={sha256(TARGET)}')

                    WORK.mkdir(parents=True, exist_ok=True)
                    require(not PROJECT.exists(), f'test project already exists: {PROJECT}')
                    emit(f'PROJECT_ID={create_project(PROJECT, "Attached API acceptance")}')

                    positive_finite(log)
                    positive_continuous(log)
                    negative_controls(log)
                    source_gates()
                    stable = sha256(CLI) == cli_digest
                    check('artifact', 'tested CLI bytes stayed identical for the whole run', stable,
                          f'{cli_digest} -> {sha256(CLI)}')
                    emit('RESULT=summary')
                except Exception as error:  # noqa: BLE001 - the receipt must record the first failure.
                    FAILED.append(f'host-abort: {type(error).__name__}: {error}')
                    emit(f'FAILURE={type(error).__name__}: {error}')
                finally:
                    # 清理必须在互斥退出之前完成，且清理失败本身计入最终结果。
                    try:
                        cleanup_targets(TARGET_PIDS)
                        cleanup_outputs(args.keep)
                    except Exception as error:  # noqa: BLE001
                        FAILED.append(f'cleanup-failure: {type(error).__name__}: {error}')
                        emit(f'CLEANUP_FAILURE={type(error).__name__}: {error}')
                passed = sum(1 for item in RECORDS if item[2])
                emit(f'ASSERTIONS={len(RECORDS)} PASS={passed} FAIL={len(RECORDS) - passed}')
                for item in RECORDS:
                    if not item[2]:
                        emit(f'FAILED_ASSERTION={item[0]} | {item[1]} | {item[3]}')
                emit('FINAL=' + ('PASS' if not FAILED else 'FAIL'))
        finally:
            sys.stdout = previous_stdout
    return 0 if not FAILED else 1


if __name__ == '__main__':
    sys.exit(main())
