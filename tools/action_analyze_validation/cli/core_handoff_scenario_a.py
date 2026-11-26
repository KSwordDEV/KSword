"""Scenario A: formal CLI `analyze breakpoint session --launch-suspended` on an owned plain EXE.

The fixture is a self-owned AMD64 image with no exports and no cooperative
handshake.  The CLI creates it with CREATE_SUSPENDED, attaches the original
native owner, arms the entry DR0 and only then releases the single initial
suspend.  The driver verifies the real hello receipt, waits for the real entry
stop, continues it explicitly, and closes the session cleanly.

Nothing here proves earliest TLS coverage or Agent readiness: the CLI reports
earliestTlsCovered=false and apiAgentReady=null and this driver asserts those
exact values instead of treating them as passed.

The owned fixture is built into the fixed IntDir
tools/action_analyze_validation/cli/obj/core-handoff and the unified
Ksword5.1/x64/Release output.  No GUI, no driver, no third-party process.
"""

import argparse
import ctypes as ct
from ctypes import wintypes as win
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time

REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
TARGET = RELEASE / 'ActionAnalyzeCoreHandoffSuspendedTarget.exe'
INT_DIR = REPO / 'tools' / 'action_analyze_validation' / 'cli' / 'obj' / 'core-handoff'
SOURCE = Path(__file__).with_name('core_handoff_suspended_target.c')
RUNTIME = REPO / 'tools' / 'action_analyze_validation' / 'runtime' / 'core-handoff'
LOG_DIR = REPO / '.codex-build-logs' / 'codebuddy-five-tests' / 'core-handoff'
BELOW_NORMAL = 0x4000
CREATE_NO_WINDOW = 0x08000000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
CHECKS = 0
STEPS = []


class Failed(Exception):
    """A real product or environment failure; never reported as a pass."""


def require(condition, detail):
    global CHECKS
    if not condition:
        raise Failed(str(detail))
    CHECKS += 1


def api(name, result, *args):
    function = getattr(KERNEL, name)
    function.restype = result
    function.argtypes = args
    return function


KERNEL = ct.WinDLL('kernel32', use_last_error=True)
OpenProcess = api('OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
CloseHandle = api('CloseHandle', win.BOOL, win.HANDLE)
GetProcessTimes = api('GetProcessTimes', win.BOOL, win.HANDLE, *[ct.POINTER(win.FILETIME)] * 4)
GetExitCodeProcess = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetImagePath = api('QueryFullProcessImageNameW', win.BOOL, win.HANDLE, win.DWORD, win.LPWSTR, ct.POINTER(win.DWORD))
CheckDebugger = api('CheckRemoteDebuggerPresent', win.BOOL, win.HANDLE, ct.POINTER(win.BOOL))
Wait = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
TerminateProcess = api('TerminateProcess', win.BOOL, win.HANDLE, win.UINT)


def fingerprint(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def build_fixture(log):
    """Build the owned plain EXE into the fixed IntDir and the unified Release."""
    choices = [Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'), Path(r'D:\Software\VS')]
    setup = next((base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat' for base in choices
                  if (base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat').is_file()), None)
    require(setup is not None, 'MSVC vcvars64.bat is required')
    initialize = f'call "{setup}" >nul'
    shell = f'"{os.environ["ComSpec"]}" /d /c '
    paths = subprocess.check_output(shell + initialize + ' && where cl.exe', cwd=INT_DIR,
                                    creationflags=BELOW_NORMAL, text=True, timeout=60).splitlines()
    compiler = next((Path(path) for path in paths if path.lower().endswith(r'\hostx64\x64\cl.exe')), None)
    require(compiler is not None and compiler.is_file(), f'HostX64 compiler required: {paths}')
    log.write(f'INTDIR={INT_DIR}\nOUTDIR={RELEASE}\nHOSTX64={compiler}\nPRIORITY=BelowNormal\n')
    log.flush()
    command = (f'{initialize} && "{compiler}" /nologo /W4 /WX /O2 /MT /utf-8 '
               f'"{SOURCE}" /link /OUT:"{TARGET}" /MACHINE:X64')
    result = subprocess.run(shell + command, cwd=INT_DIR, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, creationflags=BELOW_NORMAL, timeout=120)
    log.write(result.stdout.decode('utf-8', errors='replace'))
    log.flush()
    require(result.returncode == 0, f'fixture build failed: {result.stdout.decode("utf-8", errors="replace")}')
    require(TARGET.is_file() and TARGET.stat().st_size, 'fixture EXE missing')


class Session:
    """Drives the formal CLI JSONL session over its own stdin/stdout."""

    def __init__(self, environment, log):
        self.log = log
        self.lines = queue.Queue()
        self.session = None
        self.sequence = 0
        self.query_sequence = 0
        self.process = subprocess.Popen(
            [str(CLI), 'analyze', 'breakpoint', 'session', '--exe', str(TARGET), '--launch-suspended',
             '--confirm', '--disposition', 'resume-detach', '--input', 'jsonl'],
            cwd=RELEASE, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
            encoding='utf-8', creationflags=CREATE_NO_WINDOW)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def receive(self, kind, request_id=None):
        line = self.lines.get(timeout=30)
        require(line is not None, f'CLI closed stdout (exit={self.process.poll()})')
        self.log.write('RX ' + line)
        self.log.flush()
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
        self.log.flush()
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def request(self, request_id, method, expected=None, kind='response'):
        self.send(request_id, method, expected)
        return self.receive(kind, request_id)

    def status(self):
        self.query_sequence += 1
        return self.request(f'query/{self.query_sequence}', 'control.query')

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
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()


def owned_handle(hello):
    """Open the exact owned target instance and verify its identity and image."""
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, False, hello['targetPid'])
    require(handle, f'OpenProcess failed: {ct.get_last_error()}')
    try:
        created, exited, kernel, user = (win.FILETIME() for _ in range(4))
        require(GetProcessTimes(handle, ct.byref(created), ct.byref(exited), ct.byref(kernel), ct.byref(user)),
                f'GetProcessTimes failed: {ct.get_last_error()}')
        stamp = str((created.dwHighDateTime << 32) | created.dwLowDateTime)
        require(stamp == hello['targetCreationFileTime'], (stamp, hello))
        length = win.DWORD(32768)
        path = ct.create_unicode_buffer(length.value)
        require(GetImagePath(handle, 0, path, ct.byref(length)) and Path(path.value) == TARGET, path.value)
        return handle
    except BaseException:
        CloseHandle(handle)
        raise


def run(log):
    marker = RUNTIME / 'scenario-a-target-marker.txt'
    if marker.exists():
        marker.unlink()
    environment = os.environ | {'CORE_HANDOFF_TARGET_MARKER': str(marker)}
    session = Session(environment, log)
    try:
        hello = session.receive('hello')
        require(hello['targetMode'] == 'launched-suspended-image', hello)
        control = hello['control']
        launch = control['launch']
        # The four launch facts must all be true in the real hello receipt.
        for field in ('createdSuspended', 'ownerAttachedBeforeResume',
                      'breakpointArmedBeforeResume', 'initialSuspendReleased'):
            require(launch[field] is True, (field, launch))
        require(launch['stage'] == 'image-launch-entry-armed-initial-suspend-released', launch)
        require(launch['win32Error'] == 0, launch)
        require(launch['initialThreadId'] > 0 and launch['entryRva'] > 0, launch)
        # These two are explicitly NOT covered; the receipt must keep them false/null.
        require(launch['earliestTlsCovered'] is False, launch)
        require(launch['apiAgentReady'] is None, launch)
        require(control['clean'] is False and control['attached'] is True, control)
        require(control['breakpoint']['state'] == 'armed', control)
        require(control['breakpoint']['siteKind'] == 'image-execution', control)
        require(int(control['breakpoint']['address'], 16) > 0xffffffff, control)
        STEPS.append('hello-launch-receipt')

        handle = owned_handle(hello)
        try:
            # Wait for the real entry stop.  The target is already running past
            # the entry point, so the DR0 hit is the expected first stop.
            deadline = time.monotonic() + 30
            held = None
            while time.monotonic() < deadline:
                state = session.status()
                if state.get('stop') and state.get('hit'):
                    held = state
                    break
                require(state['breakpoint']['state'] in ('installing', 'armed', 'held'), state)
                time.sleep(0.02)
            require(held is not None, 'no real entry stop was observed')
            stop = held['stop']
            require(stop['stateRevision'] and stop['id'], held)
            require(held['hit']['address'] == control['breakpoint']['address'], (held['hit'], control))
            require(held['stopReason'] == 'breakpoint', held)
            require(int(held['hit']['tid']) > 0, held)
            require(held['execution']['kind'] == 'execution-enter-attempt', held)
            require(not marker.exists(), 'the target ran its body before the entry stop was continued')
            STEPS.append('entry-stop-observed')

            # Explicit continue on the exact current stop token.
            released = session.request('continue/1', 'control.continue',
                                       dict(stopId=stop['id'], stateRevision=stop['stateRevision']))
            require(released['release']['result'] == 'continued', released)
            require(released['release']['win32Error'] in (None, 0), released)
            STEPS.append('entry-stop-continued')

            # The target body must really run after the continue.
            body_deadline = time.monotonic() + 20
            while time.monotonic() < body_deadline and not marker.exists():
                time.sleep(0.02)
            require(marker.exists() and 'executed-after-entry-stop' in marker.read_text(), 'target body did not run')
            STEPS.append('target-body-executed')

            # Explicit close must retire the binding and confirm cleanup.
            session.send('shutdown', 'controller.shutdown')
            summary = session.receive('summary')
            closed = summary['control']
            require(summary['exitCode'] == 0, summary)
            require(closed['clean'] is True and closed['attached'] is False, closed)
            require(closed['breakpoint']['state'] == 'retired', closed)
            require(closed['breakpoint']['enrolledThreads'] == '0', closed)
            require(session.process.wait(timeout=10) == 0, 'CLI did not exit 0')
            STEPS.append('session-closed-clean')

            # The detached owned target must finish on its own with exit code 0.
            require(Wait(handle, 20000) == WAIT_OBJECT_0, 'detached owned target did not exit')
            code = win.DWORD()
            require(GetExitCodeProcess(handle, ct.byref(code)) and code.value == 0,
                    f'owned target exit code: {code.value}')
            STEPS.append('detached-target-exited-zero')
        finally:
            if Wait(handle, 0) == WAIT_TIMEOUT:
                TerminateProcess(handle, 0xDEAD)
                Wait(handle, 5000)
            CloseHandle(handle)
    finally:
        session.close_pipes()
    return {
        'scenario': 'A',
        'name': 'analyze breakpoint session --launch-suspended',
        'result': 'PASS',
        'steps': list(STEPS),
        'checks': CHECKS,
        'marker': str(marker),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-build', action='store_true', help='reuse the already built owned fixture')
    args = parser.parse_args()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / 'scenario-a.log'
    with log_path.open('w', encoding='utf-8') as log:
        log.write(f'CLI={CLI}\nCLI_SHA256={fingerprint(CLI) if CLI.is_file() else "MISSING"}\n')
        try:
            if not args.skip_build:
                require(not TARGET.exists() and not INT_DIR.exists(),
                        f'fixture outputs already exist: {TARGET}, {INT_DIR}')
                INT_DIR.mkdir(parents=True)
                try:
                    build_fixture(log)
                finally:
                    if INT_DIR.exists():
                        shutil.rmtree(INT_DIR, ignore_errors=True)
            else:
                require(TARGET.is_file(), f'owned fixture missing: {TARGET}')
            receipt = run(log)
            receipt['targetSha256'] = fingerprint(TARGET)
            log.write('SCENARIO_A=PASS\n')
            print(json.dumps(receipt, indent=2))
        except Failed as failure:
            log.write(f'SCENARIO_A=FAIL {failure}\n')
            print(json.dumps({'scenario': 'A', 'result': 'FAIL', 'detail': str(failure),
                              'checks': CHECKS, 'steps': list(STEPS)}, indent=2))
            raise SystemExit(1)


if __name__ == '__main__':
    main()
