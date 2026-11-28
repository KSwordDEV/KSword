"""Self-owned target for one real Strong-hook debugger-query capture."""

import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import sys
from threading import Event, Thread
import time


ROOT = Path(__file__).resolve().parents[3]
AGENT = ROOT / 'Ksword5.1' / 'x64' / 'Release' / 'APIMonitor_x64.dll'
SESSION_ENV = 'KSWORD_APIMON_COOPERATIVE_SESSION_V1'
ERROR_NOT_READY = 21
INVALID_HANDLE = W.HANDLE(0)


def bind(dll, name, result, *args):
    function = getattr(dll, name)
    function.restype = result
    function.argtypes = args
    return function


def run_target():
    kernel = C.WinDLL('kernel32', use_last_error=True)
    times = [W.FILETIME() for _ in range(4)]
    get_times = bind(kernel, 'GetProcessTimes', W.BOOL, W.HANDLE,
                     C.POINTER(W.FILETIME), C.POINTER(W.FILETIME),
                     C.POINTER(W.FILETIME), C.POINTER(W.FILETIME))
    if not get_times(kernel.GetCurrentProcess(), *(C.byref(value) for value in times)):
        raise C.WinError(C.get_last_error())
    creation = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime

    agent = C.WinDLL(str(AGENT))
    enable = bind(agent, 'KSwordApiMonitorEnableCooperativeCapture', W.DWORD)
    deadline = time.monotonic() + 5
    status = enable()
    while status == ERROR_NOT_READY and time.monotonic() < deadline:
        time.sleep(.025)
        status = enable()
    if status:
        raise C.WinError(status)

    base = C.WinDLL('KernelBase', use_last_error=True)
    is_debugger_present = bind(base, 'IsDebuggerPresent', W.BOOL)
    check_remote = bind(base, 'CheckRemoteDebuggerPresent', W.BOOL, W.HANDLE, C.POINTER(W.BOOL))
    identity = dict(pid=os.getpid(), creation=creation, agentLoaded=bool(agent._handle))
    print(json.dumps(identity), flush=True)

    stopping = Event()

    def wait_for_controller():
        sys.stdin.buffer.read()
        stopping.set()

    Thread(target=wait_for_controller, daemon=True).start()
    counts = dict(isDebuggerPresent=0, checkRemoteSuccess=0, checkRemoteFailure=0)
    first = None
    while not stopping.is_set():
        C.set_last_error(0)
        local = is_debugger_present()
        local_error = C.get_last_error()

        local_output = W.BOOL(1)
        C.set_last_error(0)
        remote_ok = check_remote(kernel.GetCurrentProcess(), C.byref(local_output))
        remote_error = C.get_last_error()

        failed_output = W.BOOL(1)
        C.set_last_error(0)
        remote_failed = check_remote(INVALID_HANDLE, C.byref(failed_output))
        failed_error = C.get_last_error()

        observed = dict(isDebuggerPresent=bool(local), isDebuggerPresentLastError=local_error,
                        checkRemoteSucceeded=bool(remote_ok), checkRemoteOutput=bool(local_output.value),
                        checkRemoteLastError=remote_error, failedQuerySucceeded=bool(remote_failed),
                        failedQueryLastError=failed_error, failedQueryOutput=bool(failed_output.value))
        if first is None:
            first = observed
        counts['isDebuggerPresent'] += 1
        counts['checkRemoteSuccess'] += 1
        counts['checkRemoteFailure'] += 1
        stopping.wait(.025)

    print(json.dumps(dict(counts=counts, first=first)), flush=True)


if __name__ == '__main__':
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        raise SystemExit('Windows x64 Python is required')
    run_target()
