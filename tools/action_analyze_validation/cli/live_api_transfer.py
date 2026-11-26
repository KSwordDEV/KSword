"""AA-04 / AA-09: formal CLI live API-transfer candidate chain on an owned parent/child target.

The parent is a self-owned Python worker that loads the formal Release Agent and
opts into cooperative capture.  The child is a second self-owned worker that owns
the write buffer and loads a tiny helper DLL exporting the remote-thread entry.
The parent performs WriteProcessMemory and CreateRemoteThread at two distinct
checkpoints.  Checkpoints are segmented by the *published checkpoint watermark*
of the CLI sample; no fixed sleep is used as a readiness guess.

The caller holds Local\\KSword.ActionAnalyze.CliValidation for the whole
build + run batch.  This script acquires it itself when run standalone and
releases it on the same (main) thread in finally.
"""

import argparse
import configparser
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import struct
import subprocess
import sys
from threading import Thread
import time
from uuid import UUID

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[3]
RELEASE = ROOT / 'Ksword5.1/x64/Release'
CLI = RELEASE / 'KswordCLI.exe'
AGENT = RELEASE / 'APIMonitor_x64.dll'
HELPER = RELEASE / 'LiveApiTransferHelper.dll'
BUILD_SCRIPT = ROOT / 'tools/Invoke-KSwordNativeBuildCheck.ps1'
SESSION_ENV = 'KSWORD_APIMON_COOPERATIVE_SESSION_V1'
MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
WAIT_OBJECT_0 = 0
WAIT_ABANDONED = 0x80
WAIT_TIMEOUT = 258
ERROR_ALREADY_EXISTS = 183
ERROR_NOT_READY = 21
CTRL_BREAK_EVENT = 1
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
THREAD_ALL_ACCESS = 0x001F03FF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
CHECKPOINT_RE = re.compile(r'^\d{20}\.json$')
# Position-independent x64 thread routine: mov eax, 0x4C545241 ; ret.
# Written into the child's executable region so the requested entry truly lies
# inside the completed write range and the thread returns normally.
THREAD_CODE = bytes((0xB8, 0x41, 0x52, 0x54, 0x4C, 0xC3))
THREAD_RETURN = 0x4C545241


class Blocked(Exception):
    """A real environment blocker; never reported as a product pass."""


def winapi(dll, name, result, *args):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, args
    return function


def kernel32():
    return C.WinDLL('kernel32', use_last_error=True)


def filetime():
    kernel = kernel32()
    query = winapi(kernel, 'GetProcessTimes', W.BOOL, W.HANDLE, *([C.POINTER(W.FILETIME)] * 4))
    pseudo = winapi(kernel, 'GetCurrentProcess', W.HANDLE)()
    times = [W.FILETIME() for _ in range(4)]
    if not query(pseudo, *(C.byref(value) for value in times)):
        raise C.WinError(C.get_last_error())
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def acquire_mutex(timeout_ms=540000):
    kernel = kernel32()
    create = winapi(kernel, 'CreateMutexW', W.HANDLE, C.c_void_p, W.BOOL, W.LPCWSTR)
    wait = winapi(kernel, 'WaitForSingleObject', W.DWORD, W.HANDLE, W.DWORD)
    handle = create(None, False, MUTEX_NAME)
    if not handle:
        raise Blocked(f'Cannot open {MUTEX_NAME}: {C.get_last_error()}')
    result = wait(handle, timeout_ms)
    # WAIT_ABANDONED means a prior fixture host died before releasing ownership;
    # taking it here restores exclusive ownership for this batch.
    if result not in (WAIT_OBJECT_0, WAIT_ABANDONED):
        winapi(kernel, 'CloseHandle', W.BOOL, W.HANDLE)(handle)
        raise Blocked(f'{MUTEX_NAME} busy (WaitForSingleObject={result})')
    if result == WAIT_ABANDONED:
        print('CLI_VALIDATION_MUTEX_ABANDONED_RECOVERED=True', flush=True)
    return kernel, handle


def release_mutex(kernel, handle):
    # ReleaseMutex must run on the same thread that acquired it.
    winapi(kernel, 'ReleaseMutex', W.BOOL, W.HANDLE)(handle)
    winapi(kernel, 'CloseHandle', W.BOOL, W.HANDLE)(handle)


def create_session_directory(directory):
    class SecurityAttributes(C.Structure):
        _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit_handle', W.BOOL)]

    sid = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                          '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],
                         capture_output=True, timeout=15, check=True).stdout.decode('ascii').strip()
    assert sid.startswith('S-1-') and all(part.isdecimal() for part in sid[2:].split('-')), sid
    assert sid != 'S-1-5-18', 'Run this fixture as a regular Windows user, not LocalSystem'
    kernel = kernel32()
    advapi = C.WinDLL('advapi32', use_last_error=True)
    convert = winapi(advapi, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', W.BOOL,
                     W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD))
    create = winapi(kernel, 'CreateDirectoryW', W.BOOL, W.LPCWSTR, C.POINTER(SecurityAttributes))
    free = winapi(kernel, 'LocalFree', C.c_void_p, C.c_void_p)
    descriptor = C.c_void_p()
    if not convert(f'O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)', 1, C.byref(descriptor), None):
        raise C.WinError(C.get_last_error())
    try:
        attributes = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor.value, False)
        if not create(str(directory), C.byref(attributes)):
            raise C.WinError(C.get_last_error())
    finally:
        free(descriptor)


def cleanup_session(directory, identities, controller_pid):
    paths = []
    for pid, creation in identities:
        paths.extend(path for path in (directory / f'config_{pid}_{creation}.ini',
                                       directory / f'stop_{pid}_{creation}.flag') if path.exists())
    if not paths:
        return 0
    for path in paths:
        assert path.is_file() and not path.is_symlink(), path
        if path.suffix == '.flag':
            assert path.read_bytes() == b'stop', path
            continue
        raw = path.read_bytes()
        if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
            text = raw.decode('utf-16')
        else:
            text = raw.decode('utf-8-sig')
        ini = configparser.ConfigParser(interpolation=None)
        ini.read_string(text)
        assert ini['monitor']['session_id'].startswith(f'cli_{controller_pid}_'), path
    for path in paths:
        path.unlink()
    return len(paths)


def child_role():
    """Owned child: publish an executable entry region plus the self-owned export and a data buffer.

    The executable region receives position-independent thread code written by the
    parent (the positive candidate).  The helper export is a second, legitimate
    executable entry used for the out-of-range negative case; no data address is
    ever used as a thread entry.
    """
    C.WinDLL(str(HELPER))  # The self-owned export must be present in this process.
    kernel = kernel32()
    get_module = winapi(kernel, 'GetModuleHandleW', W.HMODULE, W.LPCWSTR)
    base = get_module(HELPER.name)
    assert base, f'{HELPER.name} not loaded in owned child'
    allocate = winapi(kernel, 'VirtualAlloc', C.c_void_p, C.c_void_p, C.c_size_t, W.DWORD, W.DWORD)
    executable = allocate(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    assert executable, C.WinError(C.get_last_error())
    data = allocate(None, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    assert data, C.WinError(C.get_last_error())
    print(json.dumps(dict(pid=os.getpid(), creation=filetime(), helperBase=base,
                          executable=executable, buffer=data)), flush=True)
    sys.stdin.buffer.read()  # Parent/controller closes this to release the owned child.


def parent_role(session_dir):
    """Owned parent: opt into cooperative capture, then run command-driven transfer APIs.

    Real protocol order: the formal CLI controller publishes the per-PID session
    config first; only then may the owned target load the formal Agent and opt in.
    Every thread entry below is legitimate executable code that returns normally:
      T    entry written by this process in the executable region (positive link)
      OOB  self-owned helper export, outside the written range (negative link)
    No data address is ever used as a thread entry.
    """
    C.WinDLL(str(HELPER))  # Both roles map the self-owned export for RVA consistency.
    kernel = kernel32()
    open_process = winapi(kernel, 'OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
    close_handle = winapi(kernel, 'CloseHandle', W.BOOL, W.HANDLE)
    write_memory = winapi(C.WinDLL('KernelBase', use_last_error=True), 'WriteProcessMemory', W.BOOL,
                          W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t))
    create_thread = winapi(kernel, 'CreateRemoteThread', W.HANDLE, W.HANDLE, W.HANDLE, C.c_size_t,
                           C.c_void_p, C.c_void_p, W.DWORD, C.POINTER(W.DWORD))
    read_memory = winapi(kernel, 'ReadProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p,
                         C.c_size_t, C.POINTER(C.c_size_t))
    wait_single = winapi(kernel, 'WaitForSingleObject', W.DWORD, W.HANDLE, W.DWORD)
    exit_code = winapi(kernel, 'GetExitCodeThread', W.BOOL, W.HANDLE, C.POINTER(W.DWORD))
    get_proc = winapi(kernel, 'GetProcAddress', C.c_void_p, W.HMODULE, C.c_char_p)
    get_module = winapi(kernel, 'GetModuleHandleW', W.HMODULE, W.LPCWSTR)

    print(json.dumps(dict(pid=os.getpid(), creation=filetime(), role='parent')), flush=True)
    agent = None
    child = None
    child_info = None
    process_handle = None
    limited_handle = None
    pattern = b'AAIP1-live-transfer-pattern'
    written = C.c_size_t()
    tid = W.DWORD()
    try:
        for raw in sys.stdin:
            command = raw.strip()
            if command.startswith('L '):
                path = command[2:]
                agent = C.WinDLL(path)
                enable = winapi(agent, 'KSwordApiMonitorEnableCooperativeCapture', W.DWORD)
                status = enable()
                deadline = time.monotonic() + 5
                while status == ERROR_NOT_READY and time.monotonic() < deadline:
                    time.sleep(0.025)
                    status = enable()
                assert status == 0, f'cooperative opt-in failed: {status}'
                print('LOADED', flush=True)
            elif command == 'R':
                # 真实协议：控制器发布配置后，目标等待正式 Agent 安装 Hook 并发布覆盖。
                wait_startup = winapi(agent, 'KSwordApiMonitorWaitForCooperativeStartup', W.DWORD, W.DWORD)
                ready = wait_startup(30000)
                assert ready == 0, f'cooperative startup not ready: {ready}'
                print('READY', flush=True)
            elif command == 'S':
                environment = os.environ | {SESSION_ENV: str(session_dir)}
                child = subprocess.Popen([sys.executable, '-B', SCRIPT, '--child'],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, env=environment,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                child_info = json.loads(child.stdout.readline())
                print('CHILD ' + json.dumps(child_info), flush=True)
            elif command == 'O':
                process_handle = open_process(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ |
                                              PROCESS_QUERY_INFORMATION, False, child_info['pid'])
                assert process_handle, C.WinError(C.get_last_error())
                limited_handle = open_process(PROCESS_QUERY_INFORMATION, False, child_info['pid'])
                assert limited_handle, C.WinError(C.get_last_error())
                print('OPENED', flush=True)
            elif command == 'W':
                # Positive case: write executable thread code into the region that
                # will be used as the requested thread entry on the next checkpoint.
                entry = child_info['executable']
                ok = write_memory(process_handle, C.c_void_p(entry), THREAD_CODE, len(THREAD_CODE), C.byref(written))
                assert ok and written.value == len(THREAD_CODE), (ok, written.value, C.get_last_error())
                check = (C.c_byte * len(THREAD_CODE))()
                got = C.c_size_t()
                assert read_memory(process_handle, C.c_void_p(entry), check, len(THREAD_CODE), C.byref(got))
                assert bytes(check) == THREAD_CODE, 'executable entry bytes not verified in child'
                print(f'WRITE {entry:x} {written.value}', flush=True)
            elif command == 'F':
                written.value = 0
                ok = write_memory(limited_handle, C.c_void_p(child_info['buffer'] + 0x300),
                                  pattern, len(pattern), C.byref(written))
                assert not ok and written.value == 0, (ok, written.value)
                print(f'WRITE_FAILED {C.get_last_error()}', flush=True)
            elif command == 'T':
                # Positive thread: entry is exactly the first byte of the write range.
                entry = child_info['executable']
                handle = create_thread(process_handle, None, 0, C.c_void_p(entry), None, 0, C.byref(tid))
                assert handle, C.WinError(C.get_last_error())
                assert wait_single(handle, 10000) == 0, 'positive thread did not return normally'
                code = W.DWORD()
                assert exit_code(handle, C.byref(code)) and code.value == THREAD_RETURN, (
                    code.value, C.get_last_error())
                close_handle(handle)
                print(f'THREAD {entry:x} {tid.value} RETURN={code.value:x}', flush=True)
            elif command == 'OOB':
                # Negative thread: a legitimate self-owned export, but its address
                # lies outside the write range; the thread still returns normally.
                module = get_module(HELPER.name)
                assert module, 'helper missing in parent'
                proc = get_proc(module, b'LiveTransferThreadProc')
                assert proc, 'export missing in parent'
                entry = child_info['helperBase'] + (proc - module)
                handle = create_thread(process_handle, None, 0, C.c_void_p(entry), None, 0, C.byref(tid))
                assert handle, C.WinError(C.get_last_error())
                assert wait_single(handle, 10000) == 0, 'out-of-range thread did not return normally'
                code = W.DWORD()
                assert exit_code(handle, C.byref(code)) and code.value == THREAD_RETURN, (
                    code.value, C.get_last_error())
                close_handle(handle)
                print(f'OOB_THREAD {entry:x} {tid.value} RETURN={code.value:x}', flush=True)
            elif command == 'Q':
                print('DONE', flush=True)
                return
    finally:
        for handle in (process_handle, limited_handle):
            if handle:
                close_handle(handle)
        if child is not None:
            if child.poll() is None:
                child.stdin.close()
                child.wait(timeout=10)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()


def published_watermark(sample_dir, previous=0):
    """Return the highest fully published checkpoint ordinal, waiting only on real file events."""
    checkpoint_dir = sample_dir / 'checkpoints'
    deadline = time.monotonic() + 40
    best = previous
    while time.monotonic() < deadline:
        if checkpoint_dir.is_dir():
            ordinals = [int(path.stem) for path in checkpoint_dir.iterdir()
                        if CHECKPOINT_RE.match(path.name)]
            best = max([best, *ordinals]) if ordinals else best
        if best > previous:
            return best
        time.sleep(0.02)
    markers = sorted(path for path in checkpoint_dir.iterdir() if CHECKPOINT_RE.match(path.name)) \
        if checkpoint_dir.is_dir() else []
    detail = [(path.name, path.read_text(encoding='utf-8', errors='replace')[:400]) for path in markers]
    raise Blocked(f'No new published checkpoint after watermark {previous}: {checkpoint_dir}: {detail}')


def wait_sample(project):
    deadline = time.monotonic() + 30
    seen = set()
    while time.monotonic() < deadline:
        samples = project / 'samples'
        if samples.is_dir():
            entries = [entry for entry in samples.iterdir() if entry.is_dir()]
            fresh = [entry for entry in entries if entry.name not in seen]
            if len(fresh) == 1:
                return fresh[0], {entry.name for entry in entries}
            seen = {entry.name for entry in entries}
        time.sleep(0.02)
    raise Blocked(f'No new sample directory appeared under {project / "samples"}')


def latest_checkpoint(sample_dir):
    directory = sample_dir / 'checkpoints'
    markers = sorted(path for path in directory.iterdir() if CHECKPOINT_RE.match(path.name))
    assert markers, directory
    return json.loads(markers[-1].read_bytes()), int(markers[-1].stem)


def replay_packet(project, sample_id, raw_sequence):
    result = subprocess.run([CLI, 'analyze', 'api-evidence', 'replay', '--project', str(project),
                             '--sample', sample_id, '--packet', '1', '--after', str(raw_sequence - 1),
                             '--limit', '1', '--json'], capture_output=True, timeout=20)
    assert result.returncode == 0, (result.stdout, result.stderr)
    data = json.loads(result.stdout)['data']
    assert len(data['rows']) == 1, data
    return data['rows'][0]


def verify_transfer_receipt(project, captured, parent, child):
    transfers = captured['apiTransfers']
    assert transfers and transfers['evidence'] == 'reported-api-write-to-thread-create', captured
    assert transfers['execution'] == 'unknown', transfers
    # 一次成功写入 + 范围内入口，失败写入与区间外合法入口均不得形成候选。
    assert int(transfers['candidateCount']) == 1, transfers
    assert int(transfers['evictedWrites']) == 0, transfers
    assert len(transfers['recent']) == 1 and transfers['windowTruncated'] is False, transfers
    sample_dir = project / 'samples' / captured['sampleId']
    marker, ordinal = latest_checkpoint(sample_dir)
    link, = transfers['recent']
    write, create = link['write'], link['threadCreate']
    assert write['segmentOrdinal'] and create['segmentOrdinal'], link
    assert int(create['segmentOrdinal']) >= int(write['segmentOrdinal']), link
    assert int(create['sourceSequence']) > int(write['sourceSequence']), link
    assert int(link['actorPid']) == parent['pid'] and int(link['targetPid']) == child['pid'], link
    assert int(link['actorCreationFileTime']) == parent['creation'], link
    assert int(link['targetCreationFileTime']) == child['creation'], link
    assert int(link['writtenBytes']) == len(THREAD_CODE), link
    assert int(link['writtenAddress']) == child['executable'], link
    assert int(link['requestedStartAddress']) == child['executable'], link
    # 以同一采样的 archive.inspect / replay 原始坐标为唯一核对源。
    packet = replay_packet(project, captured['sampleId'], int(write['rawSequence']))
    assert (int(packet['rawSegment']), int(packet['rawSequence']), int(packet['sourceSequence'])) == (
        int(write['segmentOrdinal']), int(write['rawSequence']), int(write['sourceSequence'])), (link, packet)
    assert packet['family'] == 'memory-write', packet
    # archive.inspect graph 从同一已发布 raw 段重新投影候选，坐标须与 CLI 报告一致。
    from smoke import invoke as method_invoke, line, request, SESSION

    project_id = json.loads((project / 'project.ksaproj').read_bytes())['projectId']

    def graph_page(ordinal, after=None):
        params = {'projectId': project_id, 'sampleId': captured['sampleId'], 'stream': 'raw',
                  'ordinal': str(ordinal), 'view': 'graph'}
        if after is not None:
            params['afterSequence'] = str(after)
        commands = [request('open', 'project.open',
                            {'path': str(project / 'project.ksaproj'), 'access': 'read-only'}),
                    request('graph', 'archive.inspect', params),
                    request('shutdown', 'controller.shutdown')]
        stdout, _ = method_invoke(SESSION, b''.join(map(line, commands)))
        responses = {frame['requestId']: frame for frame in
                     (json.loads(raw) for raw in stdout.splitlines()) if frame.get('type') == 'response'}
        assert responses['graph']['error'] is None, responses['graph']
        return responses['graph']['result']

    # 候选在“线程创建所在段”的图中形成：图读侧连续核验前序段以保留写入。
    write_page = graph_page(int(create['segmentOrdinal']))
    candidates = write_page['apiTransferCandidates']
    assert int(candidates['count']) >= 1, write_page
    links = candidates['links']
    assert links, write_page
    matched = [item for item in links
               if int(item['write']['recordSequence']) == int(write['rawSequence'])]
    assert matched, (write, links)
    item = matched[0]
    assert int(item['write']['segmentOrdinal']) == int(write['segmentOrdinal']), (write, item)
    assert int(item['threadCreate']['recordSequence']) == int(create['rawSequence']), (create, item)
    assert int(item['threadCreate']['segmentOrdinal']) == int(create['segmentOrdinal']), (create, item)
    assert item['execution'] is None, item
    print(f'LIVE_TRANSFER_GRAPH=PASS GRAPH_LINKS={len(links)}', flush=True)
    print(f'LIVE_TRANSFER_RECEIPT=PASS CANDIDATES={transfers["candidateCount"]} '
          f'RECENT={len(transfers["recent"])} WATERMARK={ordinal} '
          f'WRITE_RAW={write["segmentOrdinal"]}/{write["rawSequence"]} '
          f'CREATE_RAW={create["segmentOrdinal"]}/{create["rawSequence"]}', flush=True)
    return marker


def build_if_requested(cli=False, helper=False):
    if not (cli or helper):
        return
    candidates = [Path(r'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'),
                  Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe')]
    msbuild = next((path for path in candidates if path.is_file()), None)
    assert msbuild, '64-bit HostX64 MSBuild not found'
    common = ['/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64',
              '/p:PROCESSOR_ARCHITEW6432=AMD64', '/nologo', '/m:1', '/v:minimal']
    if cli:
        result = None
        for shell in ('pwsh', 'powershell.exe'):
            result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(BUILD_SCRIPT), '-Product', 'CLI'], capture_output=True, timeout=600)
            print(result.stdout.decode('utf-8', errors='replace'), flush=True)
            if result.returncode == 0:
                break
        assert result is not None and result.returncode == 0, (
            result.returncode if result else None,
            result.stderr.decode('utf-8', errors='replace') if result else 'no shell')
    if helper:
        project = SCRIPT.with_name('live_api_transfer_helper.vcxproj')
        result = subprocess.run([str(msbuild), str(project), '/t:Build', '/p:Configuration=Release',
                                 '/p:Platform=x64', f'/p:SolutionDir={ROOT / "Ksword5.1"}\\',
                                 '/p:BuildProjectReferences=false', *common], capture_output=True, timeout=300)
        print(result.stdout.decode('utf-8', errors='replace'), flush=True)
        assert result.returncode == 0, (result.returncode, result.stderr.decode('utf-8', errors='replace'))


def preflight(strict=True):
    for path in (CLI, AGENT, HELPER):
        assert path.is_file() and path.stat().st_size, f'Formal artifact missing: {path}'
    agent_bytes = AGENT.read_bytes()
    fresh = 'AAIP1|'.encode('utf-16-le') in agent_bytes
    for path in (CLI, AGENT, HELPER):
        print(f'{path.name}_SHA256={sha256(path)}', flush=True)
    if not fresh:
        if strict:
            raise Blocked(f'Formal Agent at {AGENT} predates ApiInjectionFieldsV1; product candidate capture is '
                          f'blocked until the source author rebuilds it. SHA256={sha256(AGENT)}')
        print(f'AGENT_FIELDS_BLOCKED=True SHA256={sha256(AGENT)}', flush=True)
    return fresh


def create_project(project):
    from cooperative_api_capture import create_project as create
    # Another HostX64 task may be replacing KswordCLI.exe under the shared mutex;
    # retry only the transient Win32 file-in-use / not-found window.
    for attempt in range(12):
        try:
            create(project, 'AA-04 live API transfer candidate chain')
            return
        except (PermissionError, FileNotFoundError) as error:
            if attempt == 11:
                raise
            time.sleep(0.5)


def run_capture(project, directory, build=False, protocol_only=False):
    from project_v1 import regular_identity

    build_if_requested(cli=build)
    agent_fresh = preflight(strict=not protocol_only)
    original = regular_identity(directory)
    environment = os.environ | {SESSION_ENV: str(directory)}
    parent = subprocess.Popen([sys.executable, '-B', SCRIPT, '--parent', str(directory)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
    controller = None
    lines = queue.Queue()

    def pump():
        for line in parent.stdout:
            lines.put(line)

    Thread(target=pump, daemon=True).start()
    identities = []
    try:
        first = lines.get(timeout=15)
        parent_identity = json.loads(first)
        assert parent_identity['pid'] == parent.pid and parent_identity['creation'] > 0, parent_identity
        identities.append((parent.pid, parent_identity['creation']))
        def drive(line):
            parent.stdin.write((line + '\n').encode())
            parent.stdin.flush()
            try:
                return lines.get(timeout=20).decode().strip()
            except queue.Empty:
                detail = parent.stderr.read() if parent.poll() is not None else b''
                raise Blocked(f'Parent worker did not reply to {line!r} (exit={parent.poll()}): '
                              f'{detail.decode("utf-8", errors="replace")}')
        # 真实协议：目标先加载正式 Agent 并显式 opt-in，控制器才核验驻留并发布会话配置。
        assert drive('L ' + str(AGENT)) == 'LOADED'
        # 有界时长只限制整体采集；两个动作由发布水位分段，不靠固定睡眠猜测。
        command = [CLI, 'analyze', 'api-evidence', 'capture', '--project', str(project),
                   '--title', 'AA-04 live API transfer', '--pid', str(parent.pid),
                   '--creation-filetime', str(parent_identity['creation']), '--confirm',
                   '--duration-ms', '20000', '--json']
        controller = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
        sample_dir, _ = wait_sample(project)
        config = directory / f'config_{parent.pid}_{parent_identity["creation"]}.ini'
        deadline = time.monotonic() + 20
        while not config.is_file() and time.monotonic() < deadline:
            if controller.poll() is not None:
                out, err = controller.communicate(timeout=10)
                raise Blocked(f'CLI exited before publishing cooperative config ({controller.returncode}): '
                              f'{out.decode("utf-8", errors="replace")} / {err.decode("utf-8", errors="replace")}')
            time.sleep(0.02)
        assert config.is_file(), f'CLI did not publish cooperative config: {config}'
        assert drive('R') == 'READY', 'formal Agent did not publish cooperative startup coverage'
        child_reply = drive('S')
        assert child_reply.startswith('CHILD '), child_reply
        child = json.loads(child_reply[6:])
        assert child['pid'] > 4 and child['creation'] and child['helperBase'] and child['buffer'], child
        assert child['executable'], child
        identities.append((child['pid'], child['creation']))
        drive('O')  # opens owned child handles; replies are informational.
        # 预热 API：失败写入会产生一个真实普通包，使钩子与归档水位可被独立确认。
        failed_reply = drive('F')
        assert failed_reply.startswith('WRITE_FAILED '), failed_reply
        watermark = published_watermark(sample_dir, 0)
        # 发布水位握手：写与线程创建必须落在不同检查点。
        write_reply = drive('W')
        assert write_reply.startswith('WRITE '), write_reply
        write_entry = int(write_reply.split()[1], 16)
        assert write_entry == child['executable'], (write_reply, child)
        after_write = published_watermark(sample_dir, watermark)
        assert after_write > watermark, 'Write was not followed by a newly published checkpoint'
        thread_reply = drive('T')
        assert thread_reply.startswith('THREAD ') and f'RETURN={THREAD_RETURN:x}' in thread_reply, thread_reply
        after_thread = published_watermark(sample_dir, after_write)
        assert after_thread > after_write, 'Thread creation was not followed by a newly published checkpoint'
        oob_reply = drive('OOB')  # legitimate export outside the write range must not link
        assert oob_reply.startswith('OOB_THREAD ') and f'RETURN={THREAD_RETURN:x}' in oob_reply, oob_reply
        # 保持自有父进程存活到采集区间自然结束；目标退出只能由关闭 stdin 触发。
        output, error = controller.communicate(timeout=90)
        print(f'CLI_CAPTURE_EXIT={controller.returncode} '
              f'{output.decode("utf-8", errors="replace").strip()}', flush=True)
        result = json.loads(output)['data']
        assert controller.returncode in (0, 6), (controller.returncode, error.decode('utf-8', errors='replace'))
        assert result['completedInterval'] and not result['cancelled'], result
        assert result['connected'] and result['cleanupComplete'], result
        tail, parent_error = parent.communicate(timeout=15)
        assert parent.returncode == 0, (parent.returncode, tail, parent_error)
        # 诊断：导出本次采样的全部线索行，确认写入与线程创建均被归类。
        all_rows = subprocess.run([CLI, 'analyze', 'api-evidence', 'replay', '--project', str(project),
                                   '--sample', result['sampleId'], '--limit', '100', '--json'],
                                  capture_output=True, timeout=20)
        if all_rows.returncode == 0:
            for row in json.loads(all_rows.stdout)['data']['rows']:
                print(f"CLUE raw/{row['rawSegment']}#{row['rawSequence']} src={row['sourceSequence']} "
                      f"{row['family']} {row['api']} status={row['reportedStatusCode']} "
                      f"bits={row['reportedReturnBits']}", flush=True)
                detail = subprocess.run([CLI, 'analyze', 'api-evidence', 'replay', '--project', str(project),
                                         '--sample', result['sampleId'], '--packet', '1',
                                         '--after', str(int(row['rawSequence']) - 1), '--limit', '1', '--json'],
                                        capture_output=True, timeout=20)
                if detail.returncode == 0:
                    packet = bytes.fromhex(json.loads(detail.stdout)['data']['rows'][0]['packet'])
                    coverage = struct.unpack_from('<I', packet, 876)[0]
                    text = packet[224:864].decode('utf-16-le', errors='replace').split('\0', 1)[0]
                    print(f"  FIELDS coverage=0x{coverage:08x} detail={text[:120]!r}", flush=True)
        if agent_fresh:
            verify_transfer_receipt(project, result, parent_identity, child)
            print('LIVE_API_TRANSFER=PASS', flush=True)
        else:
            # 旧 Agent 无版本化字段：只核对正式 CLI 端确实公开了空候选，不宣称串链通过。
            transfers = result['apiTransfers']
            assert transfers and transfers['candidateCount'] == '0' and not transfers['recent'], transfers
            print(f'LIVE_API_TRANSFER_PROTOCOL_ONLY=PASS CANDIDATE_ASSERT=DEFERRED '
                  f'REASON=agent-predates-ApiInjectionFieldsV1', flush=True)
    finally:
        if controller is not None and controller.poll() is None:
            # Error recovery uses EOF only; never terminate an owned process.
            try:
                controller.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                pass
        if parent.poll() is None:
            if not parent.stdin.closed:
                parent.stdin.close()
            parent.wait(timeout=15)
        for stream in (parent.stdin, parent.stdout, parent.stderr):
            stream.close()
        removed = cleanup_session(directory, identities, controller.pid if controller else None)
        print(f'OWNED_SESSION_FILES_REMOVED={removed}', flush=True)
        assert regular_identity(directory) == original, directory
        assert not any(directory.iterdir()), f'Session directory residue: {list(directory.iterdir())}'
        directory.rmdir()
        print('COOPERATIVE_SESSION_DIRECTORY_REMOVED=True', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true', help='run the HostX64 CLI increment first')
    parser.add_argument('--build-helper', action='store_true', help='build the owned helper DLL increment')
    parser.add_argument('--protocol-only', action='store_true',
                        help='validate protocol/handshake/cleanup with a pre-fields Agent; candidate assertion deferred')
    parser.add_argument('--project', help='existing local project directory')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parent', nargs='?', const='', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        parser.error('Windows x64 Python is required')
    if not __debug__:
        parser.error('fixture assertions must be enabled (do not run with -O)')
    if args.child:
        child_role()
        return
    if args.parent is not None:
        parent_role(Path(args.parent))
        return
    from project_v1 import owned_project_path

    # Hold the named mutex for the whole build + run batch, on this same thread.
    kernel, handle = acquire_mutex()
    try:
        with owned_project_path() as owned:
            project = Path(args.project).resolve() if args.project else owned
            build_if_requested(cli=args.build)
            if not args.project:
                create_project(project)
            assert project.is_dir(), project
            # Agent 只接受末段名为 KswordApiMonCooperative 的私有会话目录。
            directory = project.parent / 'KswordApiMonCooperative'
            create_session_directory(directory)
            build_if_requested(helper=args.build_helper)
            run_capture(project, directory, build=args.build, protocol_only=args.protocol_only)
    finally:
        release_mutex(kernel, handle)


if __name__ == '__main__':
    main()
