"""【夹具｜456连续接管】A -> B -> C 连续两跳 + B 第二范围/新线程 的正式 CLI 验收夹具。

只写夹具，不构建、不运行、不改产品、不提交、不派发、不 GUI。
默认（不带 --execute）只打印入口说明并返回 0；下一批显式授权后
`python -B run_api_handoff_chain.py --execute` 才编译夹具并调用正式 Release CLI。

A 只在真实 Agent Ready 后向 B 私有 block1 发一次真实 APC；B 在 block1 导出例程中
对 C 发真实跨进程 APC，且由 B 自己的 CreateThread 直接以 block2 私有入口启动第二范围；
A 不对 block2 设防、没有 launcher。产物 raw/raw-native/checkpoints 在清理前复制到
固定 evidence 目录；所有句柄与进程在 try/finally 中管理。成功路径由有限 duration
自然完成（完成前不发取消，CLI 退出码 0 为硬判据），只有失败/超时才正式 CtrlBreak + 协作 stop。
"""

import argparse
import ctypes as ct
from ctypes import wintypes as win
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback

MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]              # api_handoff_chain -> action_analyze_validation -> tools -> repo
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
TARGET = RELEASE / 'ActionAnalyzeApiHandoffChainTarget.exe'
INT_DIR = HERE / 'obj' / 'Release'   # 固定 IntDir
SOURCE = HERE / 'api_handoff_chain_target.cpp'
SCRATCH = RELEASE / 'action-analyze-api-handoff-chain'
PROJECT = SCRATCH / 'project'
LOG_PATH = HERE / 'chain-run.log'
STRONG_PATH = HERE / 'strong-criteria.json'
EVIDENCE = HERE / 'evidence' / 'latest'   # 固定取证位置（项目独有证据，不放 .codex-build-logs）

INVALID_HANDLE_VALUE = ct.c_void_p(-1)     # page-file mapping 必须用 INVALID_HANDLE_VALUE
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
DUPLICATE_SAME_ACCESS = 0x00000002
THREAD_ALL_ACCESS = 0x1F03FF
THREAD_SUSPEND_RESUME = 0x0002

CHILDREN = []
STDOUT_TAILS = []
HARD = []                 # 兜底/超时/正式取消失败，使结果明确失败
OWNED_PIDS = []
COLLECTED = False
OFFLINE = False           # 离线核验：不改写运行记录 chain-run.log

# Stored v1 归档布局，沿用仓库既有读侧（cli/product_native_execution.py 的段/块/记录头常量，
# light/archive_network_project_preview.py 的记录头解包），不另造格式假设。
NATIVE_SEGMENT_HEADER_BYTES = 96
NATIVE_BLOCK_HEADER_BYTES = 80
NATIVE_RECORD_HEADER_BYTES = 32
NATIVE_RECORD_KIND = 3
NATIVE_RECORD_VERSION = 1
NATIVE_OBSERVATIONS = ('execution-enter-attempt', 'instruction-completed')


class ChainState(ct.Structure):
    """逐字段对齐 api_handoff_chain_target.cpp 的 ChainState。"""
    _fields_ = [
        ('goHop1', win.LONG), ('resultHop1', win.LONG), ('resultHopC', win.LONG),
        ('counterB1', win.LONG), ('counterB2', win.LONG), ('counterC', win.LONG),
        ('stubRanB1', win.LONG), ('stubRanB2', win.LONG), ('stubRanC', win.LONG),
        ('newThreadB', win.LONG), ('stop', win.LONG), ('pad', win.LONG),
        ('block1B', ct.c_int64), ('block2B', ct.c_int64),
        ('threadB', ct.c_int64), ('stubC', ct.c_int64), ('threadC', ct.c_int64),
    ]


class LUID(ct.Structure):
    _fields_ = [('LowPart', win.DWORD), ('HighPart', win.LONG)]


class LUID_AND_ATTRIBUTES(ct.Structure):
    _fields_ = [('Luid', LUID), ('Attributes', win.DWORD)]


class TOKEN_PRIVILEGES(ct.Structure):
    _fields_ = [('PrivilegeCount', win.DWORD), ('Privileges', LUID_AND_ATTRIBUTES * 1)]


def api(name, result, *args, library=None):
    function = getattr(library or KERNEL, name)
    function.restype = result
    function.argtypes = args
    return function


KERNEL = ct.WinDLL('kernel32', use_last_error=True)
ADVAPI32 = ct.WinDLL('advapi32', use_last_error=True)
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
SuspendThread = api('SuspendThread', win.DWORD, win.HANDLE)
ResumeThread = api('ResumeThread', win.DWORD, win.HANDLE)
GetCurrentProcess = api('GetCurrentProcess', win.HANDLE)
OpenProcessToken = api('OpenProcessToken', win.BOOL, win.HANDLE, win.DWORD, ct.POINTER(win.HANDLE), library=ADVAPI32)
LookupPrivilegeValueW = api('LookupPrivilegeValueW', win.BOOL, win.LPCWSTR, win.LPCWSTR,
                            ct.c_void_p, library=ADVAPI32)
AdjustTokenPrivileges = api('AdjustTokenPrivileges', win.BOOL, win.HANDLE, win.BOOL, ct.c_void_p,
                            win.DWORD, ct.POINTER(win.DWORD), library=ADVAPI32)
CreateFileMappingW = KERNEL.CreateFileMappingW
CreateFileMappingW.restype = win.HANDLE
CreateFileMappingW.argtypes = [win.HANDLE, ct.c_void_p, win.DWORD, win.DWORD, win.DWORD, win.LPCWSTR]
MapViewOfFile = api('MapViewOfFile', ct.c_void_p, win.HANDLE, win.DWORD, win.DWORD, win.DWORD, ct.c_size_t)


def emit(message):
    line = message if message.endswith('\n') else message + '\n'
    sys.stdout.write(line)
    sys.stdout.flush()
    if OFFLINE:
        # 离线核验不改写运行记录 chain-run.log。
        return
    with LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(line)


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def enable_debug_privilege():
    token = win.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ct.byref(token)):
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
    """使用 HostX64 cl.exe、BelowNormal 宿主，构建到固定 IntDir 与统一 Release。"""
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


def spawn(role, section):
    process = subprocess.Popen([str(TARGET), role, section], cwd=str(RELEASE),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    CHILDREN.append(process)
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
                            input=f'project create "{PROJECT}" "456 chain handoff acceptance"\nquit\n'.encode('utf-8'),
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
    """以共享内存为显式握手通道轮询，不盲 Sleep 假定 Ready。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(state):
            emit(f'HANDSHAKE_OK {label}')
            return True
        time.sleep(0.02)
    emit(f'HANDSHAKE_TIMEOUT {label}')
    return False


def collect_children():
    """正常/兜底路径收集三目标完整 stdout 与真实退出码；超时仅兜底自有 PID。"""
    global COLLECTED
    if COLLECTED:
        return
    COLLECTED = True
    for process in CHILDREN:
        try:
            out, err = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            emit(f'CHILD_WAIT_TIMEOUT pid={process.pid}')
            HARD.append(f'child-timeout-{process.pid}')
            try:
                process.terminate()
                process.wait(timeout=10)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except Exception:
                    HARD.append(f'child-unreaped-{process.pid}')
            continue
        stdout = out.decode('utf-8', errors='replace')
        stderr = err.decode('utf-8', errors='replace')
        STDOUT_TAILS.append({'pid': process.pid, 'args': process.args,
                             'returncode': process.returncode,
                             'stdout': stdout, 'stderr': stderr})
        emit(f'CHILD_EXIT pid={process.pid} code={process.returncode}')
        for line in stdout.splitlines():
            emit(f'CHILD_STDOUT pid={process.pid} :: {line}')
        if stderr.strip():
            emit(f'CHILD_STDERR pid={process.pid} :: {stderr.strip()}')


def preserve_evidence_from_project():
    """清理 scratch 前，把项目独有 raw/raw-native/checkpoints/sample.json 复制到固定 evidence。"""
    samples_root = PROJECT / 'samples'
    if not samples_root.is_dir():
        emit(f'EVIDENCE_SOURCE_ABSENT={samples_root}')
        return
    if EVIDENCE.exists():
        shutil.rmtree(EVIDENCE)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    count = 0
    for sample in sorted(samples_root.iterdir()):
        if not sample.is_dir():
            continue
        for path in sorted(sample.rglob('*')):
            if path.is_file():
                relative = Path(sample.name) / path.relative_to(sample)
                target = EVIDENCE / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
                count += 1
                emit(f'EVIDENCE_FILE={relative}')
    (EVIDENCE / 'evidence-manifest.json').write_text(json.dumps({
        'source': str(samples_root), 'fileCount': count,
    }, indent=2), encoding='utf-8')
    emit(f'EVIDENCE_FILE_COUNT={count}')


def decode_native_documents(path):
    """按 Stored v1 结构解出 raw-native 段里的原生执行文档。

    记录位置只由记录头的长度字段决定；地址只能作为 JSON 字段读出，
    不允许按原始字节包含地址就算命中。
    """
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


def raw_native_has_addresses(ranges):
    """按真实字段核验每个私有范围在正式归档中的执行证据。

    计入条件：原生文档顶层 `instructionAddress` 落在该范围内、`observation` 是执行观察、
    `target`/`thread` 身份齐全（必要时线程 tid 必须匹配该范围的实际执行线程）。
    `binding.executionRanges` 只是当时的绑定历史，可能同时列出多个范围，不作命中依据。
    """
    documents = []
    for segment in sorted(EVIDENCE.rglob('raw-native/*.ksaseg')):
        documents.extend(decode_native_documents(segment))
    results = []
    for spec in ranges:
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
            if spec.get('targetPid') is not None and int(target['pid']) != int(spec['targetPid']):
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
        results.append({
            'name': spec.get('name'), 'base': base, 'bytes': size,
            'targetPid': spec.get('targetPid'), 'expectedTid': spec.get('expectedTid'),
            'matchedCount': len(matched),
            'exactEntryMatched': any(item['exactEntry'] for item in matched),
            'documents': matched,
        })
        for item in matched:
            emit(f'RAW_NATIVE_EXEC name={spec.get("name")} segmentOrdinal={item["segmentOrdinal"]} '
                 f'recordSequence={item["recordSequence"]} instructionAddress={item["instructionAddress"]} '
                 f'observation={item["observation"]} targetPid={item["targetPid"]} '
                 f'targetCreate={item["targetCreationFileTime"]} threadTid={item["threadTid"]} '
                 f'threadCreate={item["threadCreationFileTime"]} exactEntry={item["exactEntry"]}')
        if not matched:
            emit(f'RAW_NATIVE_EXEC name={spec.get("name")} NO_MATCH base={base} bytes={size}')
    return results


def offline_verify():
    """用已有归档样本离线核验 raw-native 执行证据：不构建、不运行、不改写运行记录。"""
    global OFFLINE
    OFFLINE = True
    facts = json.loads((HERE / 'strong-criteria.json').read_text(encoding='utf-8'))
    targets = facts.get('targets') or {}
    pids = {role: int((targets.get(role) or {}).get('pid') or 0) for role in 'abc'}
    admissions = facts.get('admissions') or []

    def pick(source, target):
        for entry in admissions:
            if (int(entry.get('sourcePid') or 0) == pids[source]
                    and int(entry.get('targetPid') or 0) == pids[target]):
                return entry
        return None

    a2b, b2c, b2b = pick('a', 'b'), pick('b', 'c'), pick('b', 'b')
    if not (a2b and b2c and b2b):
        emit('OFFLINE_ADMISSIONS_INCOMPLETE')
        return 1
    b_final = targets.get('b') or {}
    ranges = [
        {'name': 'block1', 'base': int(a2b['address']),
         'bytes': int(a2b.get('rangeBytes') or 4096), 'targetPid': pids['b']},
        {'name': 'block2', 'base': int(b2b['address']),
         'bytes': int(b2b.get('rangeBytes') or 4096), 'targetPid': pids['b'],
         'expectedTid': b_final.get('newThreadB')},
        {'name': 'c-stub', 'base': int(b2c['address']),
         'bytes': int(b2c.get('rangeBytes') or 4096), 'targetPid': pids['c']},
    ]
    results = raw_native_has_addresses(ranges)
    for item in results:
        emit(f'RAW_NATIVE_RANGE name={item["name"]} base={item["base"]} bytes={item["bytes"]} '
             f'targetPid={item["targetPid"]} expectedTid={item["expectedTid"]} '
             f'matched={item["matchedCount"]} exactEntryMatched={item["exactEntryMatched"]}')
    ok = bool(results) and all(item['matchedCount'] > 0 for item in results)
    emit(f'RAW_NATIVE_VERDICT={"PASS" if ok else "FAIL"}')
    return 0 if ok else 1


def guarded_scratch_cleanup():
    """核对绝对路径边界与自有 owner 标记后才删，绝不递归删不明旧 SCRATCH。"""
    if not SCRATCH.exists():
        emit(f'SCRATCH_ABSENT={SCRATCH}')
        return
    try:
        if SCRATCH.parent.resolve() != RELEASE.resolve():
            emit(f'SCRATCH_REFUSE_BOUNDARY={SCRATCH.parent}'); return
        if SCRATCH.name != 'action-analyze-api-handoff-chain':
            emit(f'SCRATCH_REFUSE_NAME={SCRATCH.name}'); return
        marker = SCRATCH / 'owner.json'
        if not marker.is_file():
            emit(f'SCRATCH_REFUSE_NO_OWNER_MARKER={marker}'); return
        owner = json.loads(marker.read_text(encoding='utf-8')).get('driverPid')
        if owner != os.getpid():
            emit(f'SCRATCH_REFUSE_OTHER_OWNER={owner}'); return
    except Exception as error:
        emit(f'SCRATCH_REFUSE_ERROR={error}')
        return
    shutil.rmtree(SCRATCH)
    emit(f'SCRATCH_REMOVED={not SCRATCH.exists()}')


def cleanup_exact_session_files():
    """按精确 config_PID.ini / stop_PID.flag 删除，不用裸 PID 前缀影响他人文件。"""
    session_dir = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Temp' / 'KswordApiMon'
    if not session_dir.is_dir():
        emit(f'SESSION_DIR_ABSENT={session_dir}')
        return
    exact_names = []
    for pid in OWNED_PIDS:
        exact_names.extend([f'config_{pid}.ini', f'stop_{pid}.flag'])
    for name in exact_names:
        path = session_dir / name
        if not path.exists():
            continue
        try:
            path.unlink()
            emit(f'SESSION_FILE_REMOVED={path}')
        except OSError as error:
            emit(f'SESSION_FILE_REMOVE_FAILED={path} :: {error}')
    left = [name for name in exact_names if (session_dir / name).exists()]
    emit(f'SESSION_FILE_LEFT_OWNED_COUNT={len(left)}')
    for name in left:
        emit(f'SESSION_FILE_LEFT_OWNED={name}')


def finalize(ctx):
    """异常/正常统一收尾：先正式 CtrlBreak，再协作 stop，取证，最后有边界清理。"""
    emit('--- finalize: formal-cancel(if still running) -> cooperative-stop -> evidence -> cleanup ---')
    cli = ctx.get('cli')
    if cli is not None and cli.poll() is None:
        try:
            sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, cli.pid)
            emit(f'FINAL_CTRL_BREAK_SENT={sent} pid={cli.pid}')
            if not sent:
                HARD.append('ctrl-break-rejected')
        except Exception as error:
            emit(f'FINAL_CTRL_BREAK_EXCEPTION={error}')
            HARD.append('ctrl-break-exception')
        try:
            cli.wait(timeout=30)
            emit(f'CLI_FINAL_EXIT={cli.returncode}')
            ctx['cli_exit'] = cli.returncode
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
    preserve_evidence_from_project()
    guarded_scratch_cleanup()
    cleanup_exact_session_files()
    for key in ('a_main', 'b_thread', 'c_thread'):
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


def execute():
    LOG_PATH.write_text('', encoding='utf-8')
    emit('=== 456 continuous hand-off chain: A -> B -> C ===')
    emit(f'REPO={REPO}')
    if not CLI.is_file():
        raise RuntimeError(f'formal CLI missing: {CLI}')
    emit(f'CLI={CLI} SHA256={digest(CLI)}')
    emit(f'AGENT_X64_SHA256={digest(RELEASE / "APIMonitor_x64.dll")}')
    enabled, detail = enable_debug_privilege()
    emit(f'SEDEBUG_ENABLED_IN_DRIVER={enabled} :: {detail}')

    ctx = {}
    abnormal = None
    try:
        emit('--- build-owned-fixture ---')
        build_fixture()

        emit('--- create-owned-project ---')
        if SCRATCH.exists():
            # 不明旧 SCRATCH 不认领、不递归删除；只有本夹具 owner 标记可复用。
            if not (SCRATCH / 'owner.json').is_file() and any(SCRATCH.iterdir()):
                raise RuntimeError(f'pre-existing unmarked SCRATCH, refusing: {SCRATCH}')
            emit(f'SCRATCH_PREEXISTING_OWNED={SCRATCH}')
        SCRATCH.mkdir(parents=True, exist_ok=True)
        (SCRATCH / 'owner.json').write_text(
            json.dumps({'driverPid': os.getpid(), 'kind': '456-chain-fixture'}), encoding='utf-8')
        create_project()

        emit('--- create-shared-section ---')
        section = f'Local\\KswordApiHandoffChain-{os.getpid()}'
        mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, 256, section)
        if not mapping:
            raise RuntimeError(f'CreateFileMappingW failed: {ct.get_last_error()}')
        view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 256)
        if not view:
            raise RuntimeError(f'MapViewOfFile failed: {ct.get_last_error()}')
        state = ct.cast(view, ct.POINTER(ChainState)).contents
        ctx.update(mapping=mapping, view=view, state=state)

        emit('--- start-owned-c ---')
        c_proc = spawn('c', section)
        c_line = read_json_line(c_proc.stdout, 30)
        emit(f'C_WAITING={json.dumps(c_line)}')
        if not c_line:
            raise RuntimeError('C did not report identity')

        emit('--- start-owned-b ---')
        b_proc = spawn('b', section)
        b_line = read_json_line(b_proc.stdout, 30)
        emit(f'B_WAITING={json.dumps(b_line)}')
        if not b_line:
            raise RuntimeError('B did not report identity')

        emit('--- start-owned-a-and-suspend-main ---')
        a_proc = spawn('a', section)
        a_line = read_json_line(a_proc.stdout, 30)
        emit(f'A_WAITING={json.dumps(a_line)}')
        if not a_line:
            raise RuntimeError('A did not report identity')
        a_main = OpenThread(THREAD_SUSPEND_RESUME, False, a_line['tid'])
        if not a_main:
            raise RuntimeError(f'OpenThread(A main) failed: {ct.get_last_error()}')
        ctx['a_main'] = a_main
        emit(f'A_MAIN_SUSPEND_COUNT={SuspendThread(a_main)}')

        emit('--- duplicate-owned-thread-handles ---')
        b_thread = OpenThread(THREAD_ALL_ACCESS, False, b_line['tid'])
        c_thread = OpenThread(THREAD_ALL_ACCESS, False, c_line['tid'])
        if not b_thread or not c_thread:
            raise RuntimeError(f'OpenThread(B/C) failed: {ct.get_last_error()}')
        ctx['b_thread'] = b_thread
        ctx['c_thread'] = c_thread
        state.threadB = duplicate_thread_into(b_thread, a_proc.pid)   # A -> B (block1 only)
        state.threadC = duplicate_thread_into(c_thread, b_proc.pid)   # B -> C
        emit(f'THREADB_IN_A={state.threadB} THREADC_IN_B={state.threadC} STUBC={state.stubC}')
        ctx.update(a_proc=a_proc, b_proc=b_proc, c_proc=c_proc,
                   a_line=a_line, b_line=b_line, c_line=c_line)

        emit('--- run-formal-cli-attach-auto-transfer (finite duration, natural completion) ---')
        command = [str(CLI), 'analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                   '--title', '456 chain handoff acceptance', '--pid', str(a_proc.pid),
                   '--creation-filetime', str(a_line['creation']), '--confirm', '--auto-transfer',
                   '--duration-ms', '10000', '--startup-progress', '1', '--json']
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

        emit('--- dispatch-hop1 (after real Ready); A never arms block2 ---')
        state.goHop1 = 1
        emit(f'A_MAIN_RESUME_COUNT={ResumeThread(a_main)}')
        hop1 = wait_shared(state, lambda s: s.counterB1 == 1 and s.stubRanB1 == 1
                           # resultHopC 是 NtQueueApcThreadEx 的 NTSTATUS：0 才是成功。
                           and s.resultHopC == 0 and s.counterC == 1
                           and s.counterB2 == 1 and s.stubRanB2 == 1,
                           90, 'B-block1-B-to-C-and-B-CreateThread-block2')
        if not hop1:
            raise RuntimeError('chain (B block1 -> C, B CreateThread -> block2) did not complete')

        emit('--- await-formal-cli-natural-completion (finite duration; no cancel) ---')
        if cli.poll() is not None:
            raise RuntimeError(f'CLI exited before the chain finished: {cli.returncode}')
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
    except Exception as error:
        abnormal = error
        emit(f'ABNORMAL={error!r}')
        traceback.print_exc()
    finally:
        finalize(ctx)

    if abnormal is not None:
        raise abnormal

    # ---- strong criteria: admission identity + archived native execution + CLI receipt ----
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
    a_line = ctx['a_line']; b_line = ctx['b_line']; c_line = ctx['c_line']
    a2b = admission_for(admissions, a_line['pid'], b_line['pid'], b_line['block1'])
    b2c = admission_for(admissions, b_line['pid'], c_line['pid'], c_line['stub'])
    b2b = admission_for(admissions, b_line['pid'], b_line['pid'], b_line['block2'])
    native = (b2b or {}).get('nativePageAdvance') or {}
    native_ok = bool(native.get('stage')) and native.get('resourcesRestored') is True

    addresses = [b_line['block1'], b_line['block2'], c_line['stub']]

    b_final = final_line('b', ('stubRan', 'counter1', 'counter2', 'exit', 'pid', 'creation'))
    c_final = final_line('c', ('stubRan', 'counter', 'exit', 'pid', 'creation'))
    a_final = final_line('a', ('exit', 'pid', 'creation'))

    # B 的 block2 必须由 B 自己新建的线程执行：期望线程取 B 自报的 newThreadB，
    # 不使用 binding.executionRanges / startIp / 列表匹配。
    ranges = [
        {'name': 'block1', 'base': b_line['block1'], 'bytes': 0x1000, 'targetPid': b_line['pid']},
        {'name': 'block2', 'base': b_line['block2'], 'bytes': 0x1000, 'targetPid': b_line['pid'],
         'expectedTid': (b_final or {}).get('newThreadB')},
        {'name': 'c-stub', 'base': c_line['stub'], 'bytes': 0x1000, 'targetPid': c_line['pid']},
    ]
    native_ranges = raw_native_has_addresses(ranges)
    ranges_ok = bool(native_ranges) and all(item['matchedCount'] > 0 for item in native_ranges)
    by_pid = {tail['pid']: tail for tail in STDOUT_TAILS}
    a_pid = ctx['a_proc'].pid; b_pid = ctx['b_proc'].pid; c_pid = ctx['c_proc'].pid
    a_exit = by_pid.get(a_pid, {}).get('returncode')
    b_exit = by_pid.get(b_pid, {}).get('returncode')
    c_exit = by_pid.get(c_pid, {}).get('returncode')
    log_text = LOG_PATH.read_text(encoding='utf-8', errors='replace')
    removed = log_text.count('SESSION_FILE_REMOVED=')
    remove_failed = log_text.count('SESSION_FILE_REMOVE_FAILED=')
    left_owned = 0
    for line in log_text.splitlines():
        if line.startswith('SESSION_FILE_LEFT_OWNED_COUNT='):
            left_owned = int(line.split('=', 1)[1])
    evidence_count = log_text.count('EVIDENCE_FILE=')
    scratch_removed = f'SCRATCH_REMOVED=True' in log_text

    def completed(entry):
        return bool(entry and entry.get('completed') is True and int(entry.get('error') or 0) == 0)

    criteria = [
        ('admission-a-to-b-completed', completed(a2b),
         f'sourcePid={a_pid} targetPid={b_pid} address={b_line["block1"]} -> {json.dumps(a2b)}'),
        ('admission-b-to-c-completed', completed(b2c),
         f'sourcePid={b_pid} targetPid={c_pid} address={c_line["stub"]} -> {json.dumps(b2c)}'),
        ('admission-b-to-b-native-second-range', completed(b2b) and native_ok,
         f'sourcePid={b_pid} targetPid={b_pid} address={b_line["block2"]} native={json.dumps(native)}'),
        ('raw-native-execution-three-ranges', ranges_ok,
         f'addresses={addresses} ranges={json.dumps(native_ranges, ensure_ascii=False)}'),
        ('three-target-real-side-effects',
         bool(b_final and b_final.get('counter1') == 1 and b_final.get('counter2') == 1
              and c_final and c_final.get('counter') == 1),
         f'B={json.dumps(b_final, ensure_ascii=False)} C={json.dumps(c_final, ensure_ascii=False)}'),
        ('cli-exit-0', cli_exit == 0, f'exit={cli_exit} status={data.get("status")}'),
        ('agent-hooks-cleaned',
         handoff.get('clean') is True and data.get('hooksRemoved') is True
         and data.get('cleanupComplete') is True and data.get('cleanPipeEof') is True,
         f'clean={handoff.get("clean")} hooksRemoved={data.get("hooksRemoved")}'),
        ('evidence-preserved-and-cleanup',
         evidence_count > 0 and scratch_removed and removed >= 6 and remove_failed == 0 and left_owned == 0,
         f'evidenceFiles={evidence_count} scratch={scratch_removed} removed={removed} '
         f'failed={remove_failed} leftOwned={left_owned}'),
        ('three-targets-normal-exit-no-leftover',
         a_exit == 0 and b_exit == 0 and c_exit == 0 and not HARD,
         f'A={a_exit} B={b_exit} C={c_exit} hard={json.dumps(HARD)}'),
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
    emit(f'ADMISSIONS={json.dumps(admissions, ensure_ascii=False)}')
    emit(f'A_FINAL={json.dumps(a_final, ensure_ascii=False)}')
    emit(f'B_FINAL={json.dumps(b_final, ensure_ascii=False)}')
    emit(f'C_FINAL={json.dumps(c_final, ensure_ascii=False)}')
    verdict = 'PASS' if not failed else 'FAIL'
    emit(f'STRONG_VERDICT={verdict}')

    try:
        STRONG_PATH.write_text(json.dumps({
            'verdict': verdict,
            'criteria': [{'name': n, 'ok': bool(o), 'detail': d} for n, o, d in criteria],
            'cli_exit': cli_exit, 'handoff': handoff, 'admissions': admissions,
            'raw_native_ranges': native_ranges,
            'targets': {'a': a_final, 'b': b_final, 'c': c_final},
            'target_exits': {'a': a_exit, 'b': b_exit, 'c': c_exit},
            'evidence_dir': str(EVIDENCE), 'hard_failures': HARD,
        }, indent=2, ensure_ascii=False), encoding='utf-8')
    except Exception as error:
        emit(f'STRONG_WRITE_FAILED={error}')

    return 0 if not failed else 1


def main():
    parser = argparse.ArgumentParser(description='456 chain handoff fixture (fixture-only by default)')
    parser.add_argument('--execute', action='store_true',
                        help='actually build and run; default is fixture-only (no build, no run)')
    args = parser.parse_args()
    if not args.execute:
        print('FIXTURE_ONLY=1 BUILD=NOT_RUN RUN=NOT_RUN')
        print('Next authorized batch: python -B run_api_handoff_chain.py --execute')
        return 0

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
        emit(f'FIXTURE_SOURCE={HERE / "api_handoff_chain_target.cpp"}')
        code = execute()
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
