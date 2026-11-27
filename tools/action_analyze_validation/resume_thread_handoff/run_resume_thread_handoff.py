"""ResumeThread handoff fixture. Default invocation is source-only.

--execute builds only the owned x64 target at fixed paths and runs one owned
two-process scenario against the existing formal Release CLI and Agent.
"""
import argparse
import ctypes as ct
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid

REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
AGENT = RELEASE / 'APIMonitor_x64.dll'
TARGET = RELEASE / 'ActionAnalyzeResumeThreadHandoffTarget.exe'
INTDIR = REPO / 'tools' / 'action_analyze_validation' / 'resume_thread_handoff' / 'obj' / 'Release'
SOURCE = Path(__file__).with_name('resume_thread_handoff_target.cpp')
EVIDENCE = REPO / '.codex-build-logs' / 'action-analyze-resume-thread-handoff' / 'run-01'
PROJECT = RELEASE / 'action-analyze-resume-thread-handoff' / 'run-01' / 'project'
LOG = EVIDENCE / 'run.log'
RECEIPT = EVIDENCE / 'receipt.md'
STRONG = EVIDENCE / 'strong-criteria.json'
OBJECT = REPO / 'tools' / 'action_analyze_validation' / 'resume_thread_handoff' / 'obj' / 'Release' / 'ActionAnalyzeResumeThreadHandoffTarget.obj'

BELOW_NORMAL = 0x00004000
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
EXEC_BITS = 0xF0
FILE_MAP_ALL_ACCESS = 0x000F001F
THREAD_QUERY_INFORMATION = 0x0040
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
SYNCHRONIZE = 0x00100000
THREAD_ACCESS = (THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                 THREAD_SUSPEND_RESUME | SYNCHRONIZE)
PROCESS_QUERY_INFORMATION = 0x0400
INVALID_HANDLE_VALUE = ct.c_void_p(-1).value

CHECKS, BOUNDARIES, EVID, CHILDREN, OWNED_PIDS = [], [], {}, [], []
STATE = None


class FixtureBlocked(RuntimeError):
    """A required local prerequisite is unavailable, so the scenario cannot start."""


class SharedState(ct.Structure):
    _fields_ = [
        ('ready', w.LONG), ('goWin32', w.LONG), ('goNt', w.LONG), ('stop', w.LONG),
        ('win32Result', w.LONG), ('win32LastError', w.LONG), ('win32Previous', w.LONG),
        ('ntStatus', w.LONG), ('ntLastError', w.LONG), ('ntPrevious', w.LONG),
        ('counter1', w.LONG), ('counter2', w.LONG),
        ('fPid', ct.c_int64), ('fCreation', ct.c_int64), ('aPid', ct.c_int64), ('aCreation', ct.c_int64),
        ('tid1', ct.c_int64), ('tid2', ct.c_int64),
        ('threadCreation1', ct.c_int64), ('threadCreation2', ct.c_int64),
        ('page1', ct.c_int64), ('page2', ct.c_int64), ('stub1', ct.c_int64), ('stub2', ct.c_int64),
    ]


kernel = ct.WinDLL('kernel32', use_last_error=True)


def bind(name, result, *args):
    f = getattr(kernel, name)
    f.restype, f.argtypes = result, args
    return f


CreateFileMappingW = bind('CreateFileMappingW', w.HANDLE, w.HANDLE, ct.c_void_p, w.DWORD,
                          w.DWORD, w.DWORD, w.LPCWSTR)
MapViewOfFile = bind('MapViewOfFile', ct.c_void_p, w.HANDLE, w.DWORD, w.DWORD, w.DWORD, ct.c_size_t)
UnmapViewOfFile = bind('UnmapViewOfFile', w.BOOL, ct.c_void_p)
OpenProcess = bind('OpenProcess', w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
OpenThread = bind('OpenThread', w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
GetProcessTimes = bind('GetProcessTimes', w.BOOL, w.HANDLE, *([ct.POINTER(w.FILETIME)] * 4))
GetThreadTimes = bind('GetThreadTimes', w.BOOL, w.HANDLE, *([ct.POINTER(w.FILETIME)] * 4))
GetThreadContext = bind('GetThreadContext', w.BOOL, w.HANDLE, ct.c_void_p)
VirtualQueryEx = bind('VirtualQueryEx', ct.c_size_t, w.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t)
CloseHandle = bind('CloseHandle', w.BOOL, w.HANDLE)


class Context64(ct.Structure):
    _fields_ = [('P1', ct.c_ulonglong), ('P2', ct.c_ulonglong), ('P3', ct.c_ulonglong),
                ('P4', ct.c_ulonglong), ('P5', ct.c_ulonglong), ('P6', ct.c_ulonglong),
                ('ContextFlags', w.DWORD), ('MxCsr', w.DWORD),
                ('SegCs', w.WORD), ('SegDs', w.WORD), ('SegEs', w.WORD), ('SegFs', w.WORD),
                ('SegGs', w.WORD), ('SegSs', w.WORD), ('EFlags', w.DWORD),
                ('Dr0', ct.c_ulonglong), ('Dr1', ct.c_ulonglong), ('Dr2', ct.c_ulonglong),
                ('Dr3', ct.c_ulonglong), ('Dr6', ct.c_ulonglong), ('Dr7', ct.c_ulonglong),
                ('Rax', ct.c_ulonglong), ('Rcx', ct.c_ulonglong), ('Rdx', ct.c_ulonglong),
                ('Rbx', ct.c_ulonglong), ('Rsp', ct.c_ulonglong), ('Rbp', ct.c_ulonglong),
                ('Rsi', ct.c_ulonglong), ('Rdi', ct.c_ulonglong), ('R8', ct.c_ulonglong),
                ('R9', ct.c_ulonglong), ('R10', ct.c_ulonglong), ('R11', ct.c_ulonglong),
                ('R12', ct.c_ulonglong), ('R13', ct.c_ulonglong), ('R14', ct.c_ulonglong),
                ('R15', ct.c_ulonglong), ('Rip', ct.c_ulonglong), ('Tail', ct.c_byte * 1024)]


class MBI64(ct.Structure):
    _fields_ = [('BaseAddress', ct.c_ulonglong), ('AllocationBase', ct.c_ulonglong),
                ('AllocationProtect', w.DWORD), ('PartitionId', w.WORD), ('pad', w.WORD),
                ('RegionSize', ct.c_ulonglong), ('State', w.DWORD), ('Protect', w.DWORD), ('Type', w.DWORD)]


def emit(text):
    print(text, flush=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    with LOG.open('a', encoding='utf-8') as f:
        f.write(text + '\n')


def check(name, ok, detail=''):
    CHECKS.append((name, 'PASS' if ok else 'FAIL', str(detail)))
    emit(f'CHECK {CHECKS[-1][1]} {name} :: {detail}')
    return bool(ok)


def blocked(name, detail):
    CHECKS.append((name, 'BLOCKED', str(detail)))
    emit(f'CHECK BLOCKED {name} :: {detail}')


def ft_value(ft):
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)


def identity(api, handle):
    values = [w.FILETIME() for _ in range(4)]
    return ft_value(values[0]) if api(handle, *[ct.byref(x) for x in values]) else 0


def process_creation(handle):
    return identity(GetProcessTimes, handle)


def thread_creation(handle):
    return identity(GetThreadTimes, handle)


def pump(stream):
    result = queue.Queue()
    def read_lines():
        for raw in stream:
            try:
                result.put(json.loads(raw.decode('utf-8', errors='replace')))
            except json.JSONDecodeError:
                emit('NON_JSON=' + raw.decode('utf-8', errors='replace').rstrip())
        result.put(None)
    threading.Thread(target=read_lines, daemon=True).start()
    return result


def next_line(lines, timeout, label):
    try:
        value = lines.get(timeout=timeout)
    except queue.Empty as e:
        raise RuntimeError(f'timeout waiting for {label}') from e
    if value is None:
        raise RuntimeError(f'process ended before {label}')
    return value


def create_project():
    if PROJECT.parent.exists():
        raise FixtureBlocked(f'fixed project parent already exists; refusing overwrite: {PROJECT.parent}')
    PROJECT.parent.mkdir(parents=True, exist_ok=True)
    p = subprocess.run([str(CLI), 'analyze', 'session'], cwd=RELEASE,
                       input=f'project create "{PROJECT}" "ResumeThread handoff"\nquit\n'.encode(),
                       capture_output=True, timeout=120)
    emit(f'PROJECT_CREATE_EXIT={p.returncode}')
    if not (PROJECT / 'project.ksaproj').is_file():
        raise RuntimeError('formal CLI project creation failed')


def build_fixture():
    if TARGET.exists():
        raise FixtureBlocked(f'fixed fixture executable already exists; refusing overwrite: {TARGET}')
    if INTDIR.exists():
        raise FixtureBlocked(f'fixed fixture object directory already exists; refusing reuse: {INTDIR}')
    candidates = [Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'),
                  Path(r'D:\Software\VS')]
    setup = next((x / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat' for x in candidates
                  if (x / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat').is_file()), None)
    if setup is None:
        raise FixtureBlocked('64-bit MSVC vcvars64.bat unavailable')
    INTDIR.mkdir(parents=True, exist_ok=False)
    shell_command = f'call "{setup}" >nul && where cl.exe'
    found = subprocess.check_output(shell_command, cwd=INTDIR, creationflags=BELOW_NORMAL,
                                    text=True, timeout=120, shell=True).splitlines()
    compiler = next((Path(x) for x in found if x.lower().endswith(r'\hostx64\x64\cl.exe')), None)
    if not compiler:
        raise FixtureBlocked(f'HostX64 compiler unavailable: {found}')
    emit(f'INTDIR={INTDIR.resolve()}'); emit(f'OUTDIR={RELEASE.resolve()}'); emit(f'HOSTX64={compiler}')
    command = (f'call "{setup}" >nul && "{compiler}" /nologo /W4 /O2 /MT /utf-8 '
               f'"{SOURCE}" /Fo"{OBJECT}" /link /OUT:"{TARGET}" /MACHINE:X64')
    built = subprocess.run(command, cwd=INTDIR, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, creationflags=BELOW_NORMAL,
                           timeout=180, shell=True)
    emit(built.stdout.decode('utf-8', errors='replace'))
    if built.returncode or not TARGET.is_file():
        raise RuntimeError(f'fixture build failed ({built.returncode})')


def protection(process, address):
    info = MBI64()
    if not VirtualQueryEx(process, ct.c_void_p(address), ct.byref(info), ct.sizeof(info)):
        return None
    return {'base': int(info.BaseAddress), 'region': int(info.RegionSize), 'state': int(info.State),
            'protect': int(info.Protect), 'type': int(info.Type)}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest().upper()


def crc32c(data):
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def parse_raw_metadata(raw):
    if not raw or len(raw) > 4 * 1024 * 1024 or raw.startswith(b'\xef\xbb\xbf'):
        raise ValueError('invalid raw metadata length or BOM')

    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate raw metadata key')
            value[key] = item
        return value

    def parse_integer(text):
        number = int(text)
        if len(text.lstrip('-')) > 10 or number < -2147483648 or number > 4294967295:
            raise ValueError('raw metadata integer is out of range')
        return number

    value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=object_pairs,
                       parse_int=parse_integer,
                       parse_float=lambda text: (_ for _ in ()).throw(ValueError('floating point rejected')),
                       parse_constant=lambda text: (_ for _ in ()).throw(ValueError(text)))
    if not isinstance(value, dict):
        raise ValueError('raw metadata root is not an object')
    pending = [(value, 0)]
    nodes = 1
    while pending:
        current, depth = pending.pop()
        if depth > 32:
            raise ValueError('raw metadata nesting exceeds limit')
        children = list(current.values()) if isinstance(current, dict) else current
        if len(children) > 1 << 20:
            raise ValueError('raw metadata container exceeds item limit')
        if isinstance(current, dict):
            for key in current:
                if len(key.encode('utf-8')) > 64 * 1024:
                    raise ValueError('raw metadata key exceeds limit')
        for item in children:
            nodes += 1
            if nodes > 1 << 19:
                raise ValueError('raw metadata node limit exceeded')
            if isinstance(item, str):
                if len(item.encode('utf-8')) > 64 * 1024:
                    raise ValueError('raw metadata string exceeds limit')
            elif isinstance(item, (dict, list)):
                pending.append((item, depth + 1))
    return value


def archive_prefix_digest(path, project_id, sample_id):
    """Hash the last formally framed prefix, retaining a valid prefix on a bad tail."""
    data = path.read_bytes()
    try:
        expected_ordinal = int(path.stem)
        expected_project = uuid.UUID(project_id).bytes
        expected_sample = uuid.UUID(sample_id).bytes
    except (ValueError, AttributeError) as exc:
        raise ValueError(f'invalid expected archive identity: {path}') from exc
    if (len(data) < 96 or data[:8] != b'KSAASEG\x00' or
            int.from_bytes(data[92:96], 'little') != crc32c(data[:92]) or
            int.from_bytes(data[8:10], 'little') != 1 or
            int.from_bytes(data[10:12], 'little') != 0 or
            int.from_bytes(data[12:16], 'little') != 96 or
            int.from_bytes(data[16:20], 'little') != 0 or
            int.from_bytes(data[20:24], 'little') != 1 or
            int.from_bytes(data[24:32], 'little') == 0 or
            int.from_bytes(data[24:32], 'little') != expected_ordinal or
            data[32:48] != expected_project or data[48:64] != expected_sample or
            any(data[72:92])):
        raise ValueError(f'invalid segment header: {path}')
    end = 96
    last_block_ordinal = 0
    last_sequence = None
    while end < len(data):
        header = data[end:end + 80]
        if len(header) != 80:
            if end == 96:
                raise ValueError(f'truncated first block header at {end}: {path}')
            break
        if (header[:4] != b'AAB1' or
                int.from_bytes(header[76:80], 'little') != crc32c(header[:76])):
            if end == 96:
                raise ValueError(f'invalid first block header at {end}: {path}')
            break
        header_length = int.from_bytes(header[4:6], 'little')
        version = int.from_bytes(header[6:8], 'little')
        codec = int.from_bytes(header[8:10], 'little')
        flags = int.from_bytes(header[10:12], 'little')
        record_count = int.from_bytes(header[12:16], 'little')
        block_ordinal = int.from_bytes(header[16:24], 'little')
        first_sequence = int.from_bytes(header[24:32], 'little')
        block_last_sequence = int.from_bytes(header[32:40], 'little')
        decoded_bytes = int.from_bytes(header[40:44], 'little')
        stored_bytes = int.from_bytes(header[44:48], 'little')
        qpc_min = int.from_bytes(header[48:56], 'little')
        qpc_max = int.from_bytes(header[56:64], 'little')
        if (header_length != 80 or version != 1 or codec != 0 or flags & ~1 or
                int.from_bytes(header[72:76], 'little') != 0 or not stored_bytes or
                decoded_bytes > 8 * 1024 * 1024 or stored_bytes > 9 * 1024 * 1024 or
                decoded_bytes != stored_bytes or record_count == 0 or record_count > 32768 or
                record_count > decoded_bytes // 32 or block_ordinal <= last_block_ordinal or
                 first_sequence > block_last_sequence or
                 (last_sequence is not None and first_sequence != last_sequence + 1) or
                block_last_sequence - first_sequence < record_count - 1 or
                (flags & 1 and qpc_min > qpc_max)):
            if end == 96:
                raise ValueError(f'invalid first block framing at {end}: {path}')
            break
        block_end = end + header_length + stored_bytes
        if block_end > 1024 * 1024 * 1024 or block_end > len(data):
            if end == 96:
                raise ValueError(f'truncated first block at {end}: {path}')
            break
        payload = data[end + 80:block_end]
        payload_crc = crc32c(payload)
        if (int.from_bytes(header[64:68], 'little') != payload_crc or
                int.from_bytes(header[68:72], 'little') != payload_crc):
            if end == 96:
                raise ValueError(f'invalid first block payload at {end}: {path}')
            break

        # SegmentReader advances framedBytes only after every record header,
        # length, sequence, and payload CRC in this block have been checked.
        cursor = 0
        previous_record_sequence = None
        valid_records = True
        for index in range(record_count):
            if len(payload) - cursor < 32:
                valid_records = False
                break
            record = payload[cursor:cursor + 32]
            total_bytes = int.from_bytes(record[0:4], 'little')
            record_type = int.from_bytes(record[4:6], 'little')
            schema_version = int.from_bytes(record[6:8], 'little')
            flags = int.from_bytes(record[8:12], 'little')
            payload_bytes = int.from_bytes(record[12:16], 'little')
            sequence = int.from_bytes(record[16:24], 'little')
            body = payload[cursor + 32:cursor + total_bytes] if total_bytes >= 32 else b''
            metadata_bytes = int.from_bytes(body[:4], 'little') if len(body) >= 4 else -1
            metadata_end = 4 + metadata_bytes if metadata_bytes >= 0 else -1
            try:
                if metadata_bytes < 0 or metadata_end > len(body):
                    raise ValueError('raw metadata length exceeds record')
                parse_raw_metadata(body[4:metadata_end])
                metadata_valid = True
            except (UnicodeDecodeError, UnicodeEncodeError, ValueError, json.JSONDecodeError, RecursionError):
                metadata_valid = False
            if (int.from_bytes(record[28:32], 'little') != crc32c(record[:28]) or
                    record_type != 3 or schema_version != 1 or
                    flags & ~1 or
                    total_bytes < 32 or total_bytes > len(payload) - cursor or
                    total_bytes - 32 != payload_bytes or
                    metadata_bytes < 0 or metadata_end > len(body) or not metadata_valid or
                    (index == 0 and sequence != first_sequence) or
                    (previous_record_sequence is not None and sequence != previous_record_sequence + 1) or
                    (index == record_count - 1 and sequence != block_last_sequence) or
                    int.from_bytes(record[24:28], 'little') !=
                    crc32c(body)):
                valid_records = False
                break
            previous_record_sequence = sequence
            cursor += total_bytes
        if not valid_records or cursor != len(payload):
            if end == 96:
                raise ValueError(f'invalid first block records at {end}: {path}')
            break
        end = block_end
        last_block_ordinal = block_ordinal
        last_sequence = block_last_sequence
    if end == 96:
        raise ValueError(f'no complete archive block: {path}')
    return hashlib.sha256(data[:end]).hexdigest().upper()


def archive_hashes(sample_id):
    root = PROJECT / 'samples' / sample_id
    project_id = json.loads((PROJECT / 'project.ksaproj').read_text(encoding='utf-8'))['projectId']
    result = {}
    for path in root.glob('raw-native/*.ksaseg'):
        try:
            result[int(path.stem)] = archive_prefix_digest(path, project_id, sample_id)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            pass
    return result


def main():
    global STATE
    if EVIDENCE.exists():
        print(f'BLOCKED: fixed evidence directory already exists; refusing overwrite: {EVIDENCE}', flush=True)
        return 2
    if PROJECT.parent.exists():
        print(f'BLOCKED: fixed project parent already exists; refusing overwrite: {PROJECT.parent}', flush=True)
        return 2
    if TARGET.exists():
        print(f'BLOCKED: fixed fixture executable already exists; refusing overwrite: {TARGET}', flush=True)
        return 2
    if INTDIR.exists():
        print(f'BLOCKED: fixed fixture object directory already exists; refusing reuse: {INTDIR}', flush=True)
        return 2
    EVIDENCE.mkdir(parents=True, exist_ok=False)
    LOG.touch()
    abort = None
    mapping = view = None
    process_handles = []
    f_proc = a_proc = None
    cli = None
    pumps = []
    try:
        for path in (CLI, AGENT):
            if not path.is_file():
                raise FixtureBlocked(f'formal Release prerequisite missing: {path}')
        EVID['cli_sha256'] = digest(CLI); EVID['agent_sha256'] = digest(AGENT)
        build_fixture()
        EVID['fixture_sha256'] = digest(TARGET)
        create_project()
        section = f'Local\\KSwordResumeThreadHandoff-{os.getpid()}'
        mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0,
                                     ct.sizeof(SharedState), section)
        if not mapping:
            raise RuntimeError(f'CreateFileMappingW failed: {ct.get_last_error()}')
        view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, ct.sizeof(SharedState))
        if not view:
            raise RuntimeError(f'MapViewOfFile failed: {ct.get_last_error()}')
        STATE = ct.cast(view, ct.POINTER(SharedState)).contents

        f_proc = subprocess.Popen([str(TARGET), 'f', section], cwd=RELEASE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        CHILDREN.append(f_proc); OWNED_PIDS.append(f_proc.pid)
        f_lines = pump(f_proc.stdout); pumps.append(f_lines)
        f = next_line(f_lines, 30, 'F ready')
        if f.get('stage') != 'ready':
            raise RuntimeError(f'F readiness missing: {f}')
        fpid, fcreation = int(f['pid']), int(f['creation'])
        ip1, ip2 = int(f['stub1']), int(f['stub2'])
        EVID.update(f=f, f_pid=fpid, f_creation=fcreation)
        check('f-process-identity', fpid == f_proc.pid and fcreation > 0, f)
        check('distinct-private-stub-addresses', ip1 != ip2 and ip1 == int(f['page1']) + 0x100 and
              ip2 == int(f['page2']) + 0x100, f)
        check('f-published-protection-and-readiness', int(f.get('protection1', 0)) == PAGE_EXECUTE_READWRITE and
              int(f.get('protection2', 0)) == PAGE_EXECUTE_READWRITE and
              int(f.get('state1', 0)) == MEM_COMMIT and int(f.get('state2', 0)) == MEM_COMMIT and
              int(STATE.ready) == 1, f)

        a_proc = subprocess.Popen([str(TARGET), 'a', section], cwd=RELEASE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        CHILDREN.append(a_proc); OWNED_PIDS.append(a_proc.pid)
        a_lines = pump(a_proc.stdout); pumps.append(a_lines)
        a = next_line(a_lines, 30, 'A waiting')
        if a.get('stage') != 'waiting':
            raise RuntimeError(f'A did not publish readiness: {a}')
        apid, acreation = int(a['pid']), int(a['creation'])
        EVID.update(a=a, a_pid=apid, a_creation=acreation)
        check('a-target-identity', int(a['targetPid']) == fpid and
              str(a['targetCreation']) == str(fcreation), a)
        check('thread-rights', int(a['access']) == THREAD_ACCESS, hex(int(a['access'])))
        ah = OpenProcess(PROCESS_QUERY_INFORMATION, False, apid)
        fh = OpenProcess(PROCESS_QUERY_INFORMATION, False, fpid)
        if not ah or not fh:
            raise RuntimeError(f'OpenProcess identity handle failed: {ct.get_last_error()}')
        process_handles.extend([ah, fh])
        check('a-creation-identity', process_creation(ah) == acreation, acreation)
        check('f-creation-identity', process_creation(fh) == fcreation, fcreation)

        baseline = [protection(fh, ip1), protection(fh, ip2)]
        EVID['baseline'] = baseline
        check('private-rwx-committed-pages', all(p and p['protect'] == PAGE_EXECUTE_READWRITE and
              p['state'] == MEM_COMMIT and p['type'] == MEM_PRIVATE for p in baseline), baseline)
        for index, (tid_key, creation_key, ip) in enumerate((('tid1', 'threadCreation1', ip1),
                                                              ('tid2', 'threadCreation2', ip2)), 1):
            thread = OpenThread(THREAD_ACCESS, False, int(a[tid_key]))
            if not thread:
                raise RuntimeError(f'OpenThread {index} failed: {ct.get_last_error()}')
            process_handles.append(thread)
            ctx = Context64(); ctx.ContextFlags = 0x00100001
            check(f'thread-{index}-creation-identity', thread_creation(thread) == int(a[creation_key]),
                  f'tid={a[tid_key]} creation={a[creation_key]}')
            check(f'thread-{index}-pre-resume-rip', bool(GetThreadContext(thread, ct.byref(ctx))) and ctx.Rip == ip,
                  f'expected=0x{ip:X} observed=0x{ctx.Rip:X}')

        command = [str(CLI), 'analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                   '--title', 'ResumeThread handoff', '--pid', str(apid), '--creation-filetime', str(acreation),
                   '--confirm', '--auto-transfer', '--duration-ms', '120000', '--startup-progress', '1', '--json']
        emit('CLI_COMMAND=' + subprocess.list2cmdline(command))
        cli = subprocess.Popen(command, cwd=RELEASE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, creationflags=CREATE_NEW_PROCESS_GROUP)
        CHILDREN.append(cli)
        err_lines, out_chunks = [], []
        def drain_err():
            for raw in cli.stderr:
                text = raw.decode('utf-8', errors='replace').strip(); err_lines.append(text); emit('CLI_STDERR=' + text)
        def drain_out(): out_chunks.append(cli.stdout.read())
        threading.Thread(target=drain_err, daemon=True).start()
        threading.Thread(target=drain_out, daemon=True).start()
        deadline = time.monotonic() + 120
        ready = False
        ready_record = None
        while cli.poll() is None and time.monotonic() < deadline:
            for line in err_lines:
                try:
                    progress = json.loads(line)
                    if (progress.get('stage') == 'ready' and int(progress.get('pid', 0)) == apid and
                            str(progress.get('creationFileTime')) == str(acreation) and
                            progress.get('attachmentIdentityVerified') is True and
                            progress.get('agentModuleVerified') is True and
                            int(progress.get('sessionIdentity') or 0) > 0 and
                            int(progress.get('coverageRevision') or 0) > 0):
                        ready_record = progress
                        ready = True
                        break
                except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
                    pass
            if ready:
                break
            time.sleep(.2)
        EVID['formal_ready'] = ready_record
        if not ready:
            blocked('formal-agent-ready-before-resume',
                    ready_record or 'no matching verified Ready progress record')
            raise FixtureBlocked('formal Agent readiness was not observed')
        check('formal-agent-ready-before-resume', True, ready_record)

        STATE.goWin32 = 1
        win32 = next_line(a_lines, 60, 'ResumeThread result')
        EVID['win32'] = win32
        check('win32-original-previous-count', win32.get('api') == 'ResumeThread' and
              int(win32.get('previous', -1)) == 1 and STATE.win32Result == 1, win32)
        check('win32-result-preserved', int(win32.get('lastError', -1)) == STATE.win32LastError, win32)
        STATE.goNt = 1
        native = next_line(a_lines, 60, 'NtResumeThread result')
        EVID['nt'] = native
        check('nt-original-status-and-previous-count', native.get('api') == 'NtResumeThread' and
              native.get('module') == 'ntdll.dll' and int(native.get('status', 1)) == 0 and
              int(native.get('previous', -1)) == 1 and STATE.ntStatus == 0 and STATE.ntPrevious == 1, native)
        check('nt-result-preserved', int(native.get('lastError', -1)) == STATE.ntLastError, native)
        final_f = next_line(f_lines, 60, 'F execution counters')
        EVID['f_final'] = final_f
        check('both-stubs-executed-exactly-once', int(final_f.get('counter1', -1)) == 1 and
              int(final_f.get('counter2', -1)) == 1 and STATE.counter1 == 1 and STATE.counter2 == 1, final_f)

        try:
            cli.wait(timeout=270)
        except subprocess.TimeoutExpired:
            raise RuntimeError('formal CLI did not naturally finish')
        check('formal-cli-exit-success', cli.returncode == 0, cli.returncode)
        stdout = (out_chunks[0] if out_chunks else b'').decode('utf-8', errors='replace')
        (EVIDENCE / 'cli-stdout.json').write_text(stdout, encoding='utf-8')
        receipt = json.loads(stdout)
        data = receipt.get('data', receipt)
        if not isinstance(data, dict):
            raise RuntimeError('formal CLI receipt data is not an object')
        handoff = data.get('transferHandoff')
        if isinstance(handoff, str):
            handoff = json.loads(handoff)
        if not isinstance(handoff, dict):
            raise RuntimeError('formal CLI transferHandoff receipt is missing or invalid')
        EVID['transferHandoff'] = handoff
        sample_id = str(data.get('sampleId') or '')
        admissions = (handoff or {}).get('admissions') or []
        kind6 = [x for x in admissions if int(x.get('handoffKind', 0)) == 6]
        selected = [x for x in kind6 if int(x.get('sourcePid', 0)) == apid and
                    int(x.get('targetPid', 0)) == fpid and
                    str(x.get('sourceCreationFileTime')) == str(acreation) and
                    str(x.get('targetCreationFileTime')) == str(fcreation)]
        check('exactly-two-kind6-admissions', len(selected) == 2 and len(kind6) == 2, selected)
        expected = [(int(a['tid1']), int(a['threadCreation1']), ip1),
                    (int(a['tid2']), int(a['threadCreation2']), ip2)]
        matched = []
        for tid, thread_creation_value, ip in expected:
            row = next((x for x in selected if int(x.get('address', 0)) == ip), None)
            matched.append(row)
            check(f'kind6-exact-address-{tid}', row is not None, row)
            if row is None:
                continue
            check(f'kind6-phase-{tid}', row.get('handoffPhase') == 'before-execution-dispatch',
                  row.get('handoffPhase'))
            check(f'kind6-source-target-identity-{tid}', int(row.get('sourcePid', 0)) == apid and
                  str(row.get('sourceCreationFileTime')) == str(acreation) and
                  int(row.get('targetPid', 0)) == fpid and
                  str(row.get('targetCreationFileTime')) == str(fcreation), row)
            check(f'kind6-address-is-precreated-rip-{tid}', int(row.get('address', 0)) == ip, row.get('address'))
            check(f'kind6-completed-without-owner-error-{tid}', row.get('completed') is True and
                  int(row.get('error', -1)) == 0 and int(row.get('nativeOwnerError', -1)) == 0, row)
            obs = row.get('entryObservation')
            check(f'kind6-entry-observation-{tid}', isinstance(obs, dict), obs)
            if isinstance(obs, dict):
                ordinal = int(obs.get('segmentOrdinal', 0))
                hashes = archive_hashes(sample_id) if sample_id else {}
                check(f'observation-thread-and-segment-{tid}', int(obs.get('pid', 0)) == fpid and
                      str(obs.get('creationFileTime')) == str(fcreation) and int(obs.get('tid', 0)) == tid and
                      str(obs.get('threadCreationFileTime')) == str(thread_creation_value) and ordinal > 0,
                      obs)
                check(f'observation-address-and-archive-hash-{tid}', int(obs.get('instructionAddress', 0)) == ip and
                      bool(hashes.get(ordinal)) and str(obs.get('sha256', '')).upper() == hashes.get(ordinal),
                      f'observation={obs} archive={hashes.get(ordinal)}')
                check(f'observation-same-sample-{tid}', bool(sample_id) and
                      str(data.get('sampleId')) == sample_id, sample_id)
        if all(matched):
            opids = [str(x.get('requestOperationId', '')) for x in matched]
            try:
                numeric_opids = [int(x) for x in opids]
            except (TypeError, ValueError):
                numeric_opids = []
            check('distinct-nonzero-operation-ids', len(numeric_opids) == 2 and
                  all(x > 0 for x in numeric_opids) and numeric_opids[0] != numeric_opids[1], opids)
        sources, targets = handoff.get('sources', []), handoff.get('targets', [])
        a_source = next((x for x in sources if int(x.get('pid', 0)) == apid and
                         str(x.get('creationFileTime')) == str(acreation)), None)
        f_source = next((x for x in sources if int(x.get('pid', 0)) == fpid and
                         str(x.get('creationFileTime')) == str(fcreation)), None)
        f_target = next((x for x in targets if int(x.get('targetPid', 0)) == fpid and
                         str(x.get('targetCreationFileTime')) == str(fcreation)), None)
        check('shared-owner-agent-sample', a_source is not None and a_source.get('original') is True and
              a_source.get('ready') is True and a_source.get('failed') is not True and
              f_source is not None and f_source.get('ready') is True and
              f_source.get('failed') is not True and
              f_source.get('attachmentIdentityVerified') is True and
              f_source.get('agentModuleVerified') is True and
              f_source.get('cleanupComplete') is True and f_target is not None and
              bool(f_target.get('backendInstanceId')) and f_target.get('clean') is True and
              bool(sample_id) and str(f_target.get('sampleId')) == sample_id and
              handoff.get('clean') is True, f'source={a_source} target={f_target} sample={sample_id}')
        check('formal-cleanup', data.get('cleanupComplete') is True and data.get('hooksRemoved') is True and
              data.get('cleanPipeEof') is True and handoff.get('clean') is True and
              f_target is not None and f_target.get('clean') is True,
              {k: data.get(k) for k in ('cleanupComplete', 'hooksRemoved', 'cleanPipeEof')})

        after = [protection(fh, ip1), protection(fh, ip2)]
        EVID['after'] = after
        check('original-protections-restored', all(x and x['protect'] == y['protect'] for x, y in zip(baseline, after)),
              f'baseline={baseline} after={after}')
    except Exception as exc:
        abort = f'{type(exc).__name__}: {exc}'
        emit('ABORT=' + abort)
        if isinstance(exc, FixtureBlocked):
            blocked('scenario-prerequisite', abort)
    finally:
        if STATE is not None:
            STATE.stop = 1
        for process in CHILDREN:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                    check('child-process-cleanup', False,
                          f'pid={process.pid} remains unconfirmed: {cleanup_error}')
            if process.poll() is not None:
                check('child-process-cleanup', True, f'pid={process.pid} exit={process.returncode}')
            elif not any(name == 'child-process-cleanup' and status == 'FAIL' and
                         f'pid={process.pid} ' in detail for name, status, detail in CHECKS):
                check('child-process-cleanup', False, f'pid={process.pid} remains alive')
        if abort is None:
            check('f-target-exit-success', f_proc is not None and f_proc.returncode == 0,
                  f_proc.returncode if f_proc is not None else None)
            check('a-target-exit-success', a_proc is not None and a_proc.returncode == 0,
                  a_proc.returncode if a_proc is not None else None)
        for handle in process_handles:
            CloseHandle(handle)
        if view: UnmapViewOfFile(view)
        if mapping: CloseHandle(mapping)
    failures = [x for x in CHECKS if x[1] == 'FAIL']
    blocks = [x for x in CHECKS if x[1] == 'BLOCKED']
    verdict = 'FAIL' if failures or (abort and not blocks) else ('BLOCKED' if blocks else 'PASS')
    emit(f'VERDICT={verdict} FAILURES={len(failures)} BLOCKED={len(blocks)}')
    lines = ['# ResumeThread handoff fixture receipt', '', f'- Verdict: **{verdict}**',
             f'- Abort: `{abort}`', f'- Evidence: `{EVID}`', '', '## Checks', '']
    lines += [f'- {s} {n}: {d}' for n, s, d in CHECKS]
    RECEIPT.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    STRONG.write_text(json.dumps({'verdict': verdict, 'evidence': EVID,
                                  'checks': [{'name': n, 'status': s, 'detail': d} for n, s, d in CHECKS],
                                  'abort': abort}, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return 0 if verdict == 'PASS' else (2 if verdict == 'BLOCKED' else 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='build owned fixture and run the scenario')
    parser.add_argument('--attempt', type=int, default=1,
                        help='fixed evidence/project attempt number (1 keeps run-01; 2 uses run-02)')
    args = parser.parse_args()
    if args.attempt < 1:
        parser.error('--attempt must be >= 1')
    if args.attempt != 1:
        suffix = f'run-{args.attempt:02d}'
        EVIDENCE = REPO / '.codex-build-logs' / 'action-analyze-resume-thread-handoff' / suffix
        PROJECT = RELEASE / 'action-analyze-resume-thread-handoff' / suffix / 'project'
        LOG = EVIDENCE / 'run.log'
        RECEIPT = EVIDENCE / 'receipt.md'
        STRONG = EVIDENCE / 'strong-criteria.json'
    if not args.execute:
        print('FIXTURE_ONLY=1 BUILD=NOT_RUN RUN=NOT_RUN PRODUCT_REBUILD=NEVER')
        sys.exit(0)
    sys.exit(main())
