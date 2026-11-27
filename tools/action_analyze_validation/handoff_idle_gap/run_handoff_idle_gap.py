"""【夹具｜跨空档接管单次场景】A -> B（B 自然退出）-> 空档 >=500ms -> 同一 A -> 新进程 C。

只写夹具与驱动，不构建产品、不改产品/记忆/规范、不提交、不推送、不 GUI、不 ETW、不探针。

场景目标：证明“全部旧目标 clean 之后仍能接管下一目标”，不能用 B/C 同时存活的重叠链冒充。
驱动流程：
  1. 起自有 B，读取其私有 stub 与真实 PID/creation；
  2. 起自有 A，attach 正式 Release CLI（--auto-transfer，有限 duration）；
  3. Agent Ready 后置 goHop1，A 发真实 NtQueueApcThreadEx 到 B 私有 stub；
  4. B 真实 stub 执行（stubRan/counter=1）并自然 exit 0；用进程句柄确认已结束；
  5. 至少 500ms 空档后，才创建全新进程 C（不同 PID/creation），复制其线程句柄给 A；
  6. A 再发第二次真实 APC 到 C 私有 stub，C 真实执行并自然 exit 0；
  7. 同一 attach 会话/同一 collection/sample 下，CLI 有限时长自然完成 exit 0；
  8. A 由 stop 标志自然 exit 0，核对无残留保护/自有进程。

默认（不带 --execute）只打印说明。整个脚本只允许执行一次；失败留证即停，不修不重跑。
日志、完整项目根、strong-criteria 默认保存在
.codex-build-logs/codebuddy-resumed-10/handoff-idle-gap/；可用 --evidence-root 指向新的
独立证据目录，避免覆盖旧证据。--skip-build 复用统一 Release 中的既有夹具，不重新编译。
"""

import argparse
import ctypes as ct
from ctypes import wintypes as win
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
import traceback

MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
TARGET = RELEASE / 'ActionAnalyzeHandoffIdleGapTarget.exe'
INT_DIR = HERE / 'obj' / 'Release'          # 固定 IntDir，唯一一次编译
SOURCE = HERE / 'handoff_idle_gap_target.cpp'
OUT = REPO / '.codex-build-logs' / 'codebuddy-resumed-10' / 'handoff-idle-gap'
PROJECT = OUT / 'project-root'
LOG_PATH = OUT / 'run.log'
STRONG_PATH = OUT / 'strong-criteria.json'


def configure_outputs(evidence_root):
    """证据目录可切换，旧目录内容保持不动。"""
    global OUT, PROJECT, LOG_PATH, STRONG_PATH
    OUT = Path(evidence_root).resolve()
    PROJECT = OUT / 'project-root'
    LOG_PATH = OUT / 'run.log'
    STRONG_PATH = OUT / 'strong-criteria.json'

INVALID_HANDLE_VALUE = ct.c_void_p(-1)
WAIT_OBJECT_0 = 0
WAIT_ABANDONED = 0x80
BELOW_NORMAL = 0x00004000
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
PAGE_READWRITE = 0x04
FILE_MAP_ALL_ACCESS = 0x000F001F
CTRL_BREAK_EVENT = 1
SE_DEBUG_NAME = 'SeDebugPrivilege'
SE_PRIVILEGE_ENABLED = 0x0002
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
DUPLICATE_SAME_ACCESS = 0x00000002
THREAD_ALL_ACCESS = 0x1F03FF
MIN_IDLE_GAP_SECONDS = 0.5
IDLE_GAP_TARGET_SECONDS = 0.7
CLI_DURATION_MS = 20000

CHILDREN = []
STDOUT_TAILS = []
HARD = []
OWNED_PIDS = []
COLLECTED = False
CTRL_BREAK_SENT = 0

NATIVE_SEGMENT_HEADER_BYTES = 96
NATIVE_BLOCK_HEADER_BYTES = 80
NATIVE_RECORD_HEADER_BYTES = 32
NATIVE_RECORD_KIND = 3
NATIVE_RECORD_VERSION = 1
NATIVE_OBSERVATIONS = ('execution-enter-attempt', 'instruction-completed')


class GapState(ct.Structure):
    """逐字段对齐 handoff_idle_gap_target.cpp 的 GapState。"""
    _fields_ = [
        ('goHop1', win.LONG), ('goHop2', win.LONG),
        ('resultHop1', win.LONG), ('resultHop2', win.LONG),
        ('stubRanB', win.LONG), ('stubRanC', win.LONG),
        ('counterB', win.LONG), ('counterC', win.LONG),
        ('stop', win.LONG), ('pad', win.LONG),
        ('stubB', ct.c_int64), ('threadB', ct.c_int64),
        ('stubC', ct.c_int64), ('threadC', ct.c_int64),
    ]


class LUID(ct.Structure):
    _fields_ = [('LowPart', win.DWORD), ('HighPart', win.LONG)]


class LUID_AND_ATTRIBUTES(ct.Structure):
    _fields_ = [('Luid', LUID), ('Attributes', win.DWORD)]


class TOKEN_PRIVILEGES(ct.Structure):
    _fields_ = [('PrivilegeCount', win.DWORD), ('Privileges', LUID_AND_ATTRIBUTES * 1)]


KERNEL = ct.WinDLL('kernel32', use_last_error=True)
ADVAPI32 = ct.WinDLL('advapi32', use_last_error=True)


def api(name, result, *args, library=None):
    function = getattr(library or KERNEL, name)
    function.restype = result
    function.argtypes = args
    return function


CreateMutexW = api('CreateMutexW', win.HANDLE, ct.c_void_p, win.BOOL, win.LPCWSTR)
WaitForSingleObject = api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
ReleaseMutex = api('ReleaseMutex', win.BOOL, win.HANDLE)
CloseHandle = api('CloseHandle', win.BOOL, win.HANDLE)
UnmapViewOfFile = api('UnmapViewOfFile', win.BOOL, ct.c_void_p)
GenerateConsoleCtrlEvent = api('GenerateConsoleCtrlEvent', win.BOOL, win.DWORD, win.DWORD)
OpenProcess = api('OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
OpenThread = api('OpenThread', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
DuplicateHandle = api('DuplicateHandle', win.BOOL, win.HANDLE, win.HANDLE, win.HANDLE,
                      ct.POINTER(win.HANDLE), win.DWORD, win.BOOL, win.DWORD)
GetExitCodeProcess = api('GetExitCodeProcess', win.BOOL, win.HANDLE, ct.POINTER(win.DWORD))
GetCurrentProcess = api('GetCurrentProcess', win.HANDLE)
OpenProcessToken = api('OpenProcessToken', win.BOOL, win.HANDLE, win.DWORD,
                       ct.POINTER(win.HANDLE), library=ADVAPI32)
LookupPrivilegeValueW = api('LookupPrivilegeValueW', win.BOOL, win.LPCWSTR, win.LPCWSTR,
                            ct.c_void_p, library=ADVAPI32)
AdjustTokenPrivileges = api('AdjustTokenPrivileges', win.BOOL, win.HANDLE, win.BOOL, ct.c_void_p,
                            win.DWORD, ct.POINTER(win.DWORD), library=ADVAPI32)
CreateFileMappingW = KERNEL.CreateFileMappingW
CreateFileMappingW.restype = win.HANDLE
CreateFileMappingW.argtypes = [win.HANDLE, ct.c_void_p, win.DWORD, win.DWORD, win.DWORD, win.LPCWSTR]
MapViewOfFile = api('MapViewOfFile', ct.c_void_p, win.HANDLE, win.DWORD, win.DWORD, win.DWORD,
                    ct.c_size_t)


def emit(message):
    line = message if message.endswith('\n') else message + '\n'
    sys.stdout.write(line)
    sys.stdout.flush()
    with LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(line)


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def enable_debug_privilege():
    token = win.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                            ct.byref(token)):
        return False, f'open-token:{ct.get_last_error()}'
    luid = LUID()
    if not LookupPrivilegeValueW(None, SE_DEBUG_NAME, ct.byref(luid)):
        CloseHandle(token)
        return False, f'lookup:{ct.get_last_error()}'
    privileges = TOKEN_PRIVILEGES()
    privileges.PrivilegeCount = 1
    privileges.Privileges[0].Luid = luid
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    ok = AdjustTokenPrivileges(token, False, ct.byref(privileges), ct.sizeof(privileges), None)
    error = ct.get_last_error()
    CloseHandle(token)
    return bool(ok), f'lastError={error}'


def build_fixture():
    """HostX64 cl.exe，BelowNormal 宿主，写固定 IntDir 与统一 Release，唯一一次编译。"""
    choices = [Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'),
               Path(r'D:\Software\VS')]
    setup = next((base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat' for base in choices
                  if (base / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat').is_file()), None)
    if setup is None:
        raise RuntimeError('MSVC vcvars64.bat is required')
    INT_DIR.mkdir(parents=True, exist_ok=True)
    shell = f'"{os.environ["ComSpec"]}" /d /c '
    paths = subprocess.check_output(shell + f'call "{setup}" >nul && where cl.exe', cwd=INT_DIR,
                                    creationflags=BELOW_NORMAL, text=True, timeout=120).splitlines()
    compiler = next((Path(path) for path in paths if path.lower().endswith(r'\hostx64\x64\cl.exe')), None)
    if compiler is None or not compiler.is_file():
        raise RuntimeError(f'HostX64 compiler required: {paths}')
    emit(f'INTDIR={INT_DIR}')
    emit(f'OUTDIR={RELEASE}')
    emit(f'HOSTX64={compiler}')
    emit('PRIORITY=BelowNormal')
    command = (f'call "{setup}" >nul && "{compiler}" /nologo /W4 /O2 /MT /utf-8 '
               f'"{SOURCE}" /link /OUT:"{TARGET}" /MACHINE:X64')
    result = subprocess.run(shell + command, cwd=INT_DIR, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, creationflags=BELOW_NORMAL, timeout=180)
    emit(result.stdout.decode('utf-8', errors='replace'))
    if result.returncode != 0 or not TARGET.is_file():
        raise RuntimeError('fixture build failed')
    emit(f'FIXTURE_SHA256={digest(TARGET)}')


def reuse_fixture():
    """复用统一 Release 中既有夹具，不编译、不覆盖产物。"""
    if not TARGET.is_file():
        raise RuntimeError(f'fixture missing: {TARGET}')
    emit(f'INTDIR={INT_DIR}')
    emit(f'OUTDIR={RELEASE}')
    emit('BUILD=SKIPPED (reuse existing formal fixture)')
    emit(f'FIXTURE_SHA256={digest(TARGET)}')


def spawn(role, section):
    process = subprocess.Popen([str(TARGET), role, section], cwd=str(RELEASE),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    CHILDREN.append((role, process))
    OWNED_PIDS.append(process.pid)
    return process


def read_json_line(stream, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = stream.readline()
        if not raw:
            time.sleep(0.05)
            continue
        text = raw.decode('utf-8', errors='replace').strip()
        if not text:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            emit(f'NON_JSON_STDOUT {text}')
    return None


def create_project():
    result = subprocess.run([str(CLI), 'analyze', 'session'], cwd=str(RELEASE),
                            input=(f'project create "{PROJECT}" "handoff idle gap acceptance"\n'
                                   'quit\n').encode('utf-8'),
                            capture_output=True, timeout=120)
    emit(f'PROJECT_CREATE_EXIT={result.returncode}')
    if not (PROJECT / 'project.ksaproj').is_file():
        raise RuntimeError('project create failed')


def duplicate_thread_into(source_thread, target_pid):
    target_process = OpenProcess(PROCESS_DUP_HANDLE, False, target_pid)
    if not target_process:
        raise RuntimeError(f'OpenProcess(dup pid={target_pid}) failed: {ct.get_last_error()}')
    duplicated = win.HANDLE()
    ok = DuplicateHandle(GetCurrentProcess(), source_thread, target_process,
                         ct.byref(duplicated), 0, False, DUPLICATE_SAME_ACCESS)
    error = ct.get_last_error()
    CloseHandle(target_process)
    if not ok:
        raise RuntimeError(f'DuplicateHandle -> pid {target_pid} failed: {error}')
    return duplicated.value


def wait_shared(state, predicate, timeout, label):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(state):
            emit(f'HANDSHAKE_OK {label}')
            return True
        time.sleep(0.02)
    emit(f'HANDSHAKE_TIMEOUT {label}')
    return False


def wait_process_exit(pid, timeout_ms):
    """用独立进程句柄确认自然退出，保留句柄事实；不 terminate 自有目标。"""
    handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False, None, f'open:{ct.get_last_error()}'
    try:
        wait = WaitForSingleObject(handle, timeout_ms)
        if wait != WAIT_OBJECT_0:
            return False, None, f'wait:{wait}'
        code = win.DWORD()
        if not GetExitCodeProcess(handle, ct.byref(code)):
            return False, None, f'code:{ct.get_last_error()}'
        return True, code.value, 'ok'
    finally:
        CloseHandle(handle)


def process_alive(pid):
    handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        code = win.DWORD()
        if not GetExitCodeProcess(handle, ct.byref(code)):
            return True
        return code.value == 259  # STILL_ACTIVE
    finally:
        CloseHandle(handle)


def collect_children():
    global COLLECTED
    if COLLECTED:
        return
    COLLECTED = True
    for role, process in CHILDREN:
        try:
            out, err = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            emit(f'CHILD_WAIT_TIMEOUT role={role} pid={process.pid}')
            HARD.append(f'child-timeout-{process.pid}')
            try:
                process.kill()
            except Exception:
                pass
            try:
                out, err = process.communicate(timeout=5)
            except Exception:
                out, err = b'', b''
        stdout = out.decode('utf-8', errors='replace')
        stderr = err.decode('utf-8', errors='replace')
        STDOUT_TAILS.append({'role': role, 'pid': process.pid, 'args': process.args,
                             'returncode': process.returncode,
                             'stdout': stdout, 'stderr': stderr})
        emit(f'CHILD_EXIT role={role} pid={process.pid} code={process.returncode}')
        for line in stdout.splitlines():
            emit(f'CHILD_STDOUT role={role} pid={process.pid} :: {line}')
        if stderr.strip():
            emit(f'CHILD_STDERR role={role} pid={process.pid} :: {stderr.strip()}')


def decode_native_documents(path):
    """按 Stored v1 记录头的长度字段定位 JSON；地址只能作为字段读出。"""
    data = Path(path).read_bytes()
    ordinal = int(Path(path).stem)
    documents = []
    record = NATIVE_SEGMENT_HEADER_BYTES + NATIVE_BLOCK_HEADER_BYTES
    limit = len(data)
    while record + NATIVE_RECORD_HEADER_BYTES <= limit:
        total, kind, version, _, body, sequence = struct.unpack_from('<IHHIIQ', data, record)
        if kind != NATIVE_RECORD_KIND or version != NATIVE_RECORD_VERSION:
            break
        if total != NATIVE_RECORD_HEADER_BYTES + body:
            break
        payload = record + NATIVE_RECORD_HEADER_BYTES
        if payload + 4 > limit:
            break
        metadata_size, = struct.unpack_from('<I', data, payload)
        if payload + 4 + metadata_size > limit:
            break
        document = json.loads(data[payload + 4:payload + 4 + metadata_size].decode('utf-8'))
        documents.append({'segmentOrdinal': ordinal, 'recordSequence': sequence,
                          'document': document})
        record += total
    return documents


def scan_samples(samples_root, specs):
    """逐 sample 目录解 raw-native；同一 sample 内两目标都必须命中真实入口。"""
    samples = []
    if not samples_root.is_dir():
        return samples
    for sample in sorted(samples_root.iterdir()):
        if not sample.is_dir():
            continue
        documents = []
        for segment in sorted((sample / 'raw-native').glob('*.ksaseg')):
            documents.extend(decode_native_documents(segment))
        ranges = {}
        for spec in specs:
            base = int(spec['base'])
            size = int(spec.get('bytes') or 0x1000)
            matched = []
            for entry in documents:
                document = entry['document']
                try:
                    address = int(document.get('instructionAddress'))
                except (TypeError, ValueError):
                    continue
                if not base <= address < base + size:
                    continue
                if document.get('observation') not in NATIVE_OBSERVATIONS:
                    continue
                target = document.get('target') or {}
                thread = document.get('thread') or {}
                if not target.get('pid') or not target.get('creationFileTime'):
                    continue
                if not thread.get('tid') or not thread.get('creationFileTime'):
                    continue
                if int(target['pid']) != int(spec['targetPid']):
                    continue
                if spec.get('expectedTid') is not None and int(thread['tid']) != int(spec['expectedTid']):
                    continue
                matched.append({
                    'segmentOrdinal': entry['segmentOrdinal'],
                    'recordSequence': entry['recordSequence'],
                    'instructionAddress': address,
                    'exactEntry': address == base,
                    'observation': document.get('observation'),
                    'kind': document.get('kind'),
                    'targetPid': int(target['pid']),
                    'targetCreationFileTime': target['creationFileTime'],
                    'threadTid': int(thread['tid']),
                    'threadCreationFileTime': thread['creationFileTime'],
                })
            matched.sort(key=lambda item: (not item['exactEntry'], item['segmentOrdinal']))
            ranges[spec['name']] = {
                'base': base, 'bytes': size, 'targetPid': int(spec['targetPid']),
                'expectedTid': spec.get('expectedTid'),
                'matchedCount': len(matched),
                'exactEntryMatched': any(item['exactEntry'] for item in matched),
                'documents': matched,
            }
            for item in matched:
                emit(f'RAW_NATIVE_EXEC sample={sample.name} name={spec["name"]} '
                     f'segmentOrdinal={item["segmentOrdinal"]} recordSequence={item["recordSequence"]} '
                     f'instructionAddress={item["instructionAddress"]} observation={item["observation"]} '
                     f'targetPid={item["targetPid"]} targetCreate={item["targetCreationFileTime"]} '
                     f'threadTid={item["threadTid"]} threadCreate={item["threadCreationFileTime"]} '
                     f'exactEntry={item["exactEntry"]}')
            if not matched:
                emit(f'RAW_NATIVE_EXEC sample={sample.name} name={spec["name"]} NO_MATCH '
                     f'base={base} bytes={size}')
        samples.append({'sampleId': sample.name, 'documentCount': len(documents), 'ranges': ranges})
    return samples


def cleanup_exact_session_files():
    session_dir = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Temp' / 'KswordApiMon'
    if not session_dir.is_dir():
        emit(f'SESSION_DIR_ABSENT={session_dir}')
        return 0
    exact_names = []
    for pid in OWNED_PIDS:
        exact_names.extend([f'config_{pid}.ini', f'stop_{pid}.flag'])
    removed = 0
    for name in exact_names:
        path = session_dir / name
        if not path.exists():
            continue
        try:
            path.unlink()
            removed += 1
            emit(f'SESSION_FILE_REMOVED={path}')
        except OSError as error:
            emit(f'SESSION_FILE_REMOVE_FAILED={path} :: {error}')
    left = [name for name in exact_names if (session_dir / name).exists()]
    emit(f'SESSION_FILE_REMOVED_COUNT={removed}')
    emit(f'SESSION_FILE_LEFT_OWNED_COUNT={len(left)}')
    for name in left:
        emit(f'SESSION_FILE_LEFT_OWNED={name}')
    return len(left)


def finalize(ctx):
    """异常路径：只有失败/超时才 CtrlBreak；项目根按用户要求保留，不删除。"""
    global CTRL_BREAK_SENT
    emit('--- finalize: (failure only) formal-cancel -> stop -> collect -> cleanup ---')
    cli = ctx.get('cli')
    if cli is not None and cli.poll() is None:
        try:
            sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, cli.pid)
            CTRL_BREAK_SENT += 1
            emit(f'FINAL_CTRL_BREAK_SENT={sent} pid={cli.pid}')
            if not sent:
                HARD.append('ctrl-break-rejected')
        except Exception as error:
            emit(f'FINAL_CTRL_BREAK_EXCEPTION={error}')
            HARD.append('ctrl-break-exception')
        try:
            cli.wait(timeout=30)
            emit(f'CLI_FINAL_EXIT={cli.returncode}')
        except subprocess.TimeoutExpired:
            emit('CLI_CANCEL_TIMEOUT')
            HARD.append('cli-cancel-timeout')
    state = ctx.get('state')
    if state is not None:
        try:
            state.stop = 1
            emit('FINAL_STOP_SET=1')
        except Exception as error:
            emit(f'FINAL_STOP_EXCEPTION={error}')
    collect_children()
    cleanup_exact_session_files()
    for key in ('b_thread', 'c_thread'):
        handle = ctx.get(key)
        if handle:
            try:
                CloseHandle(handle)
            except Exception:
                pass
    if ctx.get('view'):
        try:
            UnmapViewOfFile(ctx['view'])
        except Exception:
            pass
    if ctx.get('mapping'):
        try:
            CloseHandle(ctx['mapping'])
        except Exception:
            pass
    emit(f'HARD_FAILURES={json.dumps(HARD)}')


def admission_for(admissions, source_pid, target_pid, address):
    for entry in admissions:
        if (int(entry.get('sourcePid') or 0) == int(source_pid)
                and int(entry.get('targetPid') or 0) == int(target_pid)
                and int(entry.get('address') or 0) == int(address)):
            return entry
    return None


def final_line(role, required_fields):
    found = None
    for tail in STDOUT_TAILS:
        if tail['role'] != role:
            continue
        for line in tail['stdout'].splitlines():
            line = line.strip()
            if not line.startswith('{'):
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if parsed.get('role') == role and all(field in parsed for field in required_fields):
                found = parsed
    return found


def execute(skip_build=False):
    LOG_PATH.write_text('', encoding='utf-8')
    emit('=== handoff idle gap: A -> B (natural exit) -> >=500ms gap -> A -> C (new process) ===')
    emit(f'REPO={REPO}')
    emit(f'RUN_COUNT=1')
    if not CLI.is_file():
        raise RuntimeError(f'formal CLI missing: {CLI}')
    cli_hash = digest(CLI)
    emit(f'CLI={CLI} SHA256={cli_hash}')
    emit(f'AGENT_X64_SHA256={digest(RELEASE / "APIMonitor_x64.dll")}')
    enabled, detail = enable_debug_privilege()
    emit(f'SEDEBUG_ENABLED_IN_DRIVER={enabled} :: {detail}')

    if PROJECT.exists():
        raise RuntimeError(f'pre-existing project root, refusing to overwrite evidence: {PROJECT}')

    ctx = {}
    abnormal = None
    try:
        emit('--- fixture: single compile, fixed IntDir ---' if not skip_build
             else '--- fixture: reuse existing formal Release build ---')
        if skip_build:
            reuse_fixture()
        else:
            build_fixture()

        emit('--- create-owned-project (kept in .codex-build-logs) ---')
        create_project()

        emit('--- create-shared-section ---')
        section = f'Local\\KswordHandoffIdleGap-{os.getpid()}'
        mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, 256, section)
        if not mapping:
            raise RuntimeError(f'CreateFileMappingW failed: {ct.get_last_error()}')
        view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 256)
        if not view:
            raise RuntimeError(f'MapViewOfFile failed: {ct.get_last_error()}')
        state = ct.cast(view, ct.POINTER(GapState)).contents
        ctx.update(mapping=mapping, view=view, state=state)

        emit('--- start-owned-B (first target) ---')
        b_proc = spawn('b', section)
        b_line = read_json_line(b_proc.stdout, 30)
        emit(f'B_WAITING={json.dumps(b_line)}')
        if not b_line or not b_line.get('stub'):
            raise RuntimeError('B did not report identity/stub')
        ctx['b_proc'] = b_proc
        ctx['b_line'] = b_line

        emit('--- start-owned-A (source stays alive) ---')
        a_proc = spawn('a', section)
        a_line = read_json_line(a_proc.stdout, 30)
        emit(f'A_WAITING={json.dumps(a_line)}')
        if not a_line:
            raise RuntimeError('A did not report identity')
        ctx['a_proc'] = a_proc
        ctx['a_line'] = a_line

        emit('--- duplicate-B-thread-handle-into-A ---')
        b_thread = OpenThread(THREAD_ALL_ACCESS, False, b_line['tid'])
        if not b_thread:
            raise RuntimeError(f'OpenThread(B) failed: {ct.get_last_error()}')
        ctx['b_thread'] = b_thread
        state.threadB = duplicate_thread_into(b_thread, a_proc.pid)
        emit(f'THREADB_IN_A={state.threadB} B_STUB={b_line["stub"]}')

        emit('--- run-formal-CLI-attach-auto-transfer (finite duration, natural completion) ---')
        command = [str(CLI), 'analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                   '--title', 'handoff idle gap acceptance', '--pid', str(a_proc.pid),
                   '--creation-filetime', str(a_line['creation']), '--confirm', '--auto-transfer',
                   '--duration-ms', str(CLI_DURATION_MS), '--startup-progress', '1', '--json']
        emit('CLI_COMMAND=' + subprocess.list2cmdline(command))
        stderr_lines = []
        stdout_chunks = []
        cli = subprocess.Popen(command, cwd=str(RELEASE), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                               creationflags=CREATE_NEW_PROCESS_GROUP)
        ctx['cli'] = cli

        def drain_stderr():
            for raw in cli.stderr:
                text = raw.decode('utf-8', errors='replace').rstrip()
                stderr_lines.append(text)
                emit('CLI_STDERR=' + text)

        def drain_stdout():
            stdout_chunks.append(cli.stdout.read())

        stderr_reader = threading.Thread(target=drain_stderr, daemon=True)
        stdout_reader = threading.Thread(target=drain_stdout, daemon=True)
        stderr_reader.start()
        stdout_reader.start()

        emit('--- wait-for-agent-ready ---')
        ready = False
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and cli.poll() is None:
            for text in list(stderr_lines):
                try:
                    if json.loads(text).get('stage') == 'ready':
                        ready = True
                except json.JSONDecodeError:
                    continue
            if ready:
                break
            time.sleep(0.2)
        emit(f'AGENT_READY_STAGE_SEEN={ready}')
        if not ready:
            raise RuntimeError('Agent Ready stage not seen; refusing to dispatch hop1')
        ctx['agent_ready_at'] = time.monotonic()

        emit('--- hop1: A dispatches real APC into B private stub (address auto-resolved) ---')
        state.goHop1 = 1
        hop1 = wait_shared(state, lambda s: s.stubRanB == 1 and s.counterB == 1 and s.resultHop1 == 0,
                           90, 'B-stub-executed-with-status-0')
        if not hop1:
            raise RuntimeError('A -> B did not complete with status 0 and real B stub ran')

        emit('--- confirm B natural exit BEFORE any C exists ---')
        b_exit_ok, b_exit_code, b_exit_detail = wait_process_exit(b_line['pid'], 30000)
        b_exit_confirmed_at = time.monotonic()
        emit(f'B_EXIT_HANDLE_WAIT={b_exit_ok} code={b_exit_code} detail={b_exit_detail} '
             f'confirmedAtMono={b_exit_confirmed_at:.6f}')
        if not b_exit_ok or b_exit_code != 0:
            raise RuntimeError(f'B did not exit naturally with 0: {b_exit_detail}/{b_exit_code}')
        ctx['b_exit'] = {'handleWait': b_exit_ok, 'code': b_exit_code,
                         'confirmedAtMono': b_exit_confirmed_at}

        gap_until = b_exit_confirmed_at + IDLE_GAP_TARGET_SECONDS
        while time.monotonic() < gap_until:
            time.sleep(0.01)
        measured_gap = time.monotonic() - b_exit_confirmed_at
        emit(f'IDLE_GAP_SECONDS={measured_gap:.3f} (min required {MIN_IDLE_GAP_SECONDS})')
        if measured_gap < MIN_IDLE_GAP_SECONDS:
            raise RuntimeError('idle gap shorter than 500ms')
        ctx['measured_gap'] = measured_gap

        emit('--- start-owned-C (NEW process, different PID/creation; B already gone) ---')
        c_spawn_at = time.monotonic()
        c_proc = spawn('c', section)
        c_line = read_json_line(c_proc.stdout, 30)
        emit(f'C_WAITING={json.dumps(c_line)}')
        if not c_line or not c_line.get('stub'):
            raise RuntimeError('C did not report identity/stub')
        ctx['c_proc'] = c_proc
        ctx['c_line'] = c_line
        emit(f'C_START_AFTER_B_EXIT={c_spawn_at > b_exit_confirmed_at} '
             f'deltaAfterGap={c_spawn_at - b_exit_confirmed_at:.3f}')
        if int(c_line['pid']) == int(b_line['pid']):
            raise RuntimeError('C reused B PID; not an independent target process')
        if str(c_line['creation']) == str(b_line['creation']):
            raise RuntimeError('C reused B creation time; not an independent target process')

        emit('--- duplicate-C-thread-handle-into-A (A still alive) ---')
        c_thread = OpenThread(THREAD_ALL_ACCESS, False, c_line['tid'])
        if not c_thread:
            raise RuntimeError(f'OpenThread(C) failed: {ct.get_last_error()}')
        ctx['c_thread'] = c_thread
        state.threadC = duplicate_thread_into(c_thread, a_proc.pid)
        emit(f'THREADC_IN_A={state.threadC} C_STUB={c_line["stub"]}')

        emit('--- hop2: same A dispatches real APC into C private stub after B clean ---')
        state.goHop2 = 1
        hop2 = wait_shared(state, lambda s: s.stubRanC == 1 and s.counterC == 1 and s.resultHop2 == 0,
                           90, 'C-stub-executed-with-status-0')
        if not hop2:
            raise RuntimeError('A -> C did not complete with status 0 and real C stub ran')

        emit('--- confirm C natural exit ---')
        c_exit_ok, c_exit_code, c_exit_detail = wait_process_exit(c_line['pid'], 30000)
        emit(f'C_EXIT_HANDLE_WAIT={c_exit_ok} code={c_exit_code} detail={c_exit_detail}')
        if not c_exit_ok or c_exit_code != 0:
            raise RuntimeError(f'C did not exit naturally with 0: {c_exit_detail}/{c_exit_code}')
        ctx['c_exit'] = {'handleWait': c_exit_ok, 'code': c_exit_code}

        emit('--- await-formal-cli-natural-completion (finite duration; no cancel) ---')
        if cli.poll() is not None:
            raise RuntimeError(f'CLI exited before the second transfer finished: {cli.returncode}')
        try:
            cli.wait(timeout=180)
        except subprocess.TimeoutExpired:
            raise RuntimeError('CLI did not complete within its finite duration')
        stderr_reader.join(timeout=15)
        stdout_reader.join(timeout=15)
        cli_stdout = (stdout_chunks[0] if stdout_chunks else b'').decode('utf-8', errors='replace')
        ctx['cli_stdout'] = cli_stdout
        ctx['cli_exit'] = cli.returncode
        emit(f'CLI_EXIT_CODE={cli.returncode}')
        emit('CLI_STDOUT=' + cli_stdout.strip())

        emit('--- stop A only after CLI natural completion; A returns 0 naturally ---')
        state.stop = 1
        try:
            a_proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            HARD.append('a-exit-timeout')
        emit(f'A_PROC_EXIT={a_proc.returncode}')
    except Exception as error:
        abnormal = error
        emit(f'ABNORMAL={error!r}')
        traceback.print_exc()
    finally:
        if abnormal is not None:
            finalize(ctx)
        else:
            collect_children()
            cleanup_exact_session_files()
            for key in ('b_thread', 'c_thread'):
                handle = ctx.get(key)
                if handle:
                    try:
                        CloseHandle(handle)
                    except Exception:
                        pass
            if ctx.get('view'):
                try:
                    UnmapViewOfFile(ctx['view'])
                except Exception:
                    pass
            if ctx.get('mapping'):
                try:
                    CloseHandle(ctx['mapping'])
                except Exception:
                    pass

    if abnormal is not None:
        raise abnormal

    # ---- strong criteria ----
    cli_stdout = ctx.get('cli_stdout', '')
    cli_exit = ctx.get('cli_exit')
    receipt = None
    try:
        receipt = json.loads(cli_stdout)
    except json.JSONDecodeError:
        pass
    data = (receipt or {}).get('data', (receipt or {}))
    handoff = data.get('transferHandoff')
    if isinstance(handoff, str):
        try:
            handoff = json.loads(handoff)
        except json.JSONDecodeError:
            handoff = None
    handoff = handoff or {}
    admissions = handoff.get('admissions') or []
    collection_id = handoff.get('collectionId')

    a_line = ctx['a_line']; b_line = ctx['b_line']; c_line = ctx['c_line']
    a2b = admission_for(admissions, a_line['pid'], b_line['pid'], b_line['stub'])
    a2c = admission_for(admissions, a_line['pid'], c_line['pid'], c_line['stub'])

    b_final = final_line('b', ('stubRan', 'counter', 'exit', 'pid', 'creation'))
    c_final = final_line('c', ('stubRan', 'counter', 'exit', 'pid', 'creation'))
    a_final = final_line('a', ('resultHop1', 'resultHop2', 'exit', 'pid', 'creation'))

    specs = [
        {'name': 'b-stub', 'base': b_line['stub'], 'bytes': 0x1000,
         'targetPid': b_line['pid'], 'expectedTid': b_line['tid']},
        {'name': 'c-stub', 'base': c_line['stub'], 'bytes': 0x1000,
         'targetPid': c_line['pid'], 'expectedTid': c_line['tid']},
    ]
    samples = scan_samples(PROJECT / 'samples', specs)
    same_sample = next((sample for sample in samples
                        if all(sample['ranges'][spec['name']]['exactEntryMatched'] for spec in specs)),
                       None)
    for sample in samples:
        for spec in specs:
            item = sample['ranges'][spec['name']]
            emit(f'RAW_NATIVE_RANGE sample={sample["sampleId"]} name={spec["name"]} '
                 f'base={item["base"]} bytes={item["bytes"]} targetPid={item["targetPid"]} '
                 f'expectedTid={item["expectedTid"]} matched={item["matchedCount"]} '
                 f'exactEntryMatched={item["exactEntryMatched"]}')

    def completed(entry):
        return bool(entry and entry.get('completed') is True and int(entry.get('error') or 0) == 0)

    by_role = {tail['role']: tail for tail in STDOUT_TAILS}
    a_exit = by_role.get('a', {}).get('returncode')
    b_exit = by_role.get('b', {}).get('returncode')
    c_exit = by_role.get('c', {}).get('returncode')

    sources = handoff.get('sources') or []
    source_by_pid = {int(item.get('pid') or 0): item for item in sources}
    b_source = source_by_pid.get(int(b_line['pid']))
    c_source = source_by_pid.get(int(c_line['pid']))
    a_source = source_by_pid.get(int(a_line['pid']))

    def source_clean(item):
        if not item:
            return False
        procs = item.get('processes') or []
        return (item.get('ended') is True and item.get('failed') is False
                and int(item.get('error') or 0) == 0 and item.get('cleanupComplete') is True
                and all(proc.get('removed') is True or proc.get('exited') is True for proc in procs)
                and all(proc.get('cleanPipeEof') is True for proc in procs))

    session_left = cleanup_exact_session_files()  # 幂等复核
    alive = {pid: process_alive(pid) for pid in OWNED_PIDS}
    project_retained = (PROJECT / 'project.ksaproj').is_file()

    range_summary = {
        key: {'matched': value['matchedCount'], 'exact': value['exactEntryMatched']}
        for key, value in (same_sample or {}).get('ranges', {}).items()
    }

    criteria = [
        ('two-distinct-target-processes',
         int(b_line['pid']) != int(c_line['pid'])
         and str(b_line['creation']) != str(c_line['creation']),
         f'B(pid={b_line["pid"]},create={b_line["creation"]}) '
         f'C(pid={c_line["pid"]},create={c_line["creation"]})'),
        ('b-exited-naturally-before-c-existed',
         ctx['b_exit']['handleWait'] and ctx['b_exit']['code'] == 0
         and ctx.get('measured_gap', 0) >= MIN_IDLE_GAP_SECONDS
         and ctx.get('measured_gap', 0) > 0,
         f'B_handle_wait={ctx["b_exit"]["handleWait"]} B_code={ctx["b_exit"]["code"]} '
         f'gap={ctx.get("measured_gap", 0):.3f}s'),
        ('a-to-b-admission-completed', completed(a2b) and collection_id,
         f'source={a_line["pid"]} target={b_line["pid"]} address={b_line["stub"]} '
         f'collection={collection_id} -> {json.dumps(a2b)}'),
        ('a-to-c-admission-completed-after-b-exit', completed(a2c) and collection_id,
         f'source={a_line["pid"]} target={c_line["pid"]} address={c_line["stub"]} '
         f'collection={collection_id} (only B natural exit observed, no intermediate clean) '
         f'-> {json.dumps(a2c)}'),
        ('raw-native-same-sample-both-exact-entry',
         same_sample is not None
         and all(same_sample['ranges'][spec['name']]['exactEntryMatched'] for spec in specs),
         f'sample={same_sample["sampleId"] if same_sample else None} '
         f'ranges={json.dumps(range_summary)}'),
        ('original-api-returns-zero',
         bool(a_final) and a_final.get('resultHop1') == 0 and a_final.get('resultHop2') == 0,
         json.dumps(a_final, ensure_ascii=False)),
        ('real-stub-side-effects-one-each',
         bool(b_final) and b_final.get('stubRan') is True and b_final.get('counter') == 1
         and bool(c_final) and c_final.get('stubRan') is True and c_final.get('counter') == 1,
         f'B={json.dumps(b_final, ensure_ascii=False)} C={json.dumps(c_final, ensure_ascii=False)}'),
        ('all-three-natural-exit-0',
         a_exit == 0 and b_exit == 0 and c_exit == 0 and not HARD,
         f'A={a_exit} B={b_exit} C={c_exit} hard={json.dumps(HARD)}'),
        ('cli-natural-exit-0-no-cancel',
         cli_exit == 0 and CTRL_BREAK_SENT == 0,
         f'exit={cli_exit} status={data.get("status")} ctrlBreakSent={CTRL_BREAK_SENT}'),
        ('handoff-clean-with-both-members-ended',
         handoff.get('clean') is True and handoff.get('activeAgents') is False
         and int(handoff.get('members') or 0) == 2
         and source_clean(b_source) and source_clean(c_source)
         and a_source is not None,
         f'clean={handoff.get("clean")} members={handoff.get("members")} '
         f'activeAgents={handoff.get("activeAgents")} '
         f'B_clean={source_clean(b_source)} C_clean={source_clean(c_source)}'),
        ('no-residual-protection-or-owned-process',
         data.get('hooksRemoved') is True and data.get('cleanupComplete') is True
         and data.get('cleanPipeEof') is True
         and session_left == 0 and not any(alive.values()),
         f'hooksRemoved={data.get("hooksRemoved")} cleanupComplete={data.get("cleanupComplete")} '
         f'cleanPipeEof={data.get("cleanPipeEof")} sessionLeft={session_left} alive={alive} '
         f'projectRetained={project_retained}'),
    ]

    emit('=== STRONG_CRITERIA ===')
    failed = []
    for name, ok, detail in criteria:
        emit(f'STRONG {"PASS" if ok else "FAIL"} {name} :: {detail}')
        if not ok:
            failed.append(name)
    emit(f'STRONG_CHECKS={len(criteria)}')
    emit(f'STRONG_FAILED={len(failed)}')
    for name in failed:
        emit(f'STRONG_FAILED_ITEM={name}')
    emit('=== RAW ===')
    emit(f'COLLECTION_ID={collection_id}')
    emit(f'ADMISSIONS={json.dumps(admissions, ensure_ascii=False)}')
    emit(f'A_FINAL={json.dumps(a_final, ensure_ascii=False)}')
    emit(f'B_FINAL={json.dumps(b_final, ensure_ascii=False)}')
    emit(f'C_FINAL={json.dumps(c_final, ensure_ascii=False)}')
    emit(f'B_EXIT={json.dumps(ctx["b_exit"], ensure_ascii=False)}')
    emit(f'C_EXIT={json.dumps(ctx["c_exit"], ensure_ascii=False)}')
    emit(f'IDLE_GAP={ctx.get("measured_gap", 0):.3f}')
    verdict = 'PASS' if not failed else 'FAIL'
    emit(f'STRONG_VERDICT={verdict}')

    try:
        STRONG_PATH.write_text(json.dumps({
            'verdict': verdict,
            'run_count': 1,
            'fixture_build': 'skipped-existing-fixture' if skip_build else 'built-once',
            'fixture_sha256': digest(TARGET),
            'cli_sha256': cli_hash,
            'cli_exit': cli_exit,
            'criteria': [{'name': n, 'ok': bool(o), 'detail': d} for n, o, d in criteria],
            'handoff': handoff,
            'admissions': admissions,
            'collection_id': collection_id,
            'samples': samples,
            'same_sample_id': same_sample['sampleId'] if same_sample else None,
            'targets': {'a': a_final, 'b': b_final, 'c': c_final},
            'target_identity': {
                'a': {'pid': a_line['pid'], 'creation': a_line['creation']},
                'b': {'pid': b_line['pid'], 'creation': b_line['creation'], 'stub': b_line['stub']},
                'c': {'pid': c_line['pid'], 'creation': c_line['creation'], 'stub': c_line['stub']},
            },
            'target_exits': {'a': a_exit, 'b': b_exit, 'c': c_exit},
            'b_exit_handle': ctx['b_exit'],
            'c_exit_handle': ctx['c_exit'],
            'idle_gap_seconds': ctx.get('measured_gap', 0),
            'owned_pids_alive': alive,
            'session_files_left': session_left,
            'project_root': str(PROJECT),
            'hard_failures': HARD,
            'unverified': [
                'intermediate product-level per-target clean is not dynamically queryable; '
                'only B natural exit 0 via process handle plus final receipt are observed',
            ],
        }, indent=2, ensure_ascii=False), encoding='utf-8')
    except Exception as error:
        emit(f'STRONG_WRITE_FAILED={error}')

    return 0 if not failed else 1


def main():
    parser = argparse.ArgumentParser(description='handoff idle gap fixture (fixture-only by default)')
    parser.add_argument('--execute', action='store_true',
                        help='actually build and run once; default is fixture-only')
    parser.add_argument('--evidence-root', default=None,
                        help='log/project/receipt directory; defaults to the original evidence path')
    parser.add_argument('--skip-build', action='store_true',
                        help='reuse the existing formal Release fixture instead of compiling it')
    args = parser.parse_args()
    if args.evidence_root:
        configure_outputs(args.evidence_root)
    if not args.execute:
        print('FIXTURE_ONLY=1 BUILD=NOT_RUN RUN=NOT_RUN')
        print('Single authorized run: python -B run_handoff_idle_gap.py --execute')
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text('', encoding='utf-8')
    handle = CreateMutexW(None, True, MUTEX_NAME)
    if not handle:
        emit(f'MUTEX_CREATE_FAILED={ct.get_last_error()}')
        return 3
    state = 'held'
    try:
        wait = WaitForSingleObject(handle, 120000)
        if wait == WAIT_ABANDONED:
            state = 'abandoned-recovered'
        elif wait != WAIT_OBJECT_0:
            emit(f'MUTEX_WAIT_FAILED={wait}')
            return 3
        emit(f'MUTEX={state}')
        emit(f'FIXTURE_SOURCE={SOURCE}')
        code = execute(skip_build=args.skip_build)
        emit(f'SCENARIO_EXIT={code}')
        return code
    except Exception:
        traceback.print_exc()
        return 4
    finally:
        ReleaseMutex(handle)
        CloseHandle(handle)
        emit('MUTEX=released')


if __name__ == '__main__':
    raise SystemExit(main())
