"""Accept the official Release CLI memory snapshot/read/export commands.

One persistent host holds ``Local\\KSword.ActionAnalyze.CliValidation`` from
before the formal CLI build until every case has finished.  The host also owns
the authorized memory target: one windowless child process keeps a committed,
page aligned range alive with deterministic non-zero bytes and one protected
page in the middle, so the official CLI reads a live owned process without any
injection, driver or third party target.

Only this host's own target process and its own temporary projects are used.
The script never touches a formal user project and never copies a runtime.
"""

import argparse
import ctypes as ct
from ctypes import wintypes as win
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
WORK = REPO / 'KswordCLI' / 'x64' / 'Release' / 'MemorySnapshotCliValidation'
LOG_DIR = REPO / '.codex-build-logs'
MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
DOC = REPO / 'docs' / 'CLI使用文档.md'

PAGE_SIZE = 4096
READABLE_PAGES = 2          # readable pages before the protected page
GAP_PAGE = 2                # the protected page inside the range
TRAILING_PAGES = 2          # readable pages after the protected page
TOTAL_PAGES = READABLE_PAGES + 1 + TRAILING_PAGES
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000
PAGE_READWRITE = 0x04
PAGE_NOACCESS = 0x01
WAIT_OBJECT_0 = 0
WAIT_ABANDONED = 0x80
BELOW_NORMAL = 0x00004000
CREATE_NO_WINDOW = 0x08000000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000

RESULTS = []
FAILURES = []


def check(section, name, condition, detail=''):
    ok = bool(condition)
    RESULTS.append({'section': section, 'name': name, 'ok': ok, 'detail': detail})
    if not ok:
        FAILURES.append(f'{section}: {name} :: {detail}')
    print(f"[{'PASS' if ok else 'FAIL'}] {section} | {name}" + (f' | {detail}' if detail else ''), flush=True)
    return ok


def note(section, name, detail):
    RESULTS.append({'section': section, 'name': name, 'ok': True, 'detail': detail})
    print(f"[INFO] {section} | {name} | {detail}", flush=True)


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def number(value, fallback=-1):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def page_pattern(page, count):
    """Deterministic, non-zero content that both the target and the host compute."""
    return bytes(((page * 37 + index * 11 + 5) % 254) + 1 for index in range(count))


# --------------------------------------------------------------------------- Win32

kernel32 = ct.WinDLL('kernel32', use_last_error=True)


def _api(name, result, *args):
    fn = getattr(kernel32, name)
    fn.restype, fn.argtypes = result, args
    return fn


CreateMutexW = _api('CreateMutexW', win.HANDLE, ct.c_void_p, win.BOOL, win.LPCWSTR)
WaitForSingleObject = _api('WaitForSingleObject', win.DWORD, win.HANDLE, win.DWORD)
ReleaseMutex = _api('ReleaseMutex', win.BOOL, win.HANDLE)
CloseHandle = _api('CloseHandle', win.BOOL, win.HANDLE)
SetPriorityClass = _api('SetPriorityClass', win.BOOL, win.HANDLE, win.DWORD)
GetCurrentProcess = _api('GetCurrentProcess', win.HANDLE)
GetProcessTimes = _api('GetProcessTimes', win.BOOL, win.HANDLE,
                       ct.POINTER(win.FILETIME), ct.POINTER(win.FILETIME),
                       ct.POINTER(win.FILETIME), ct.POINTER(win.FILETIME))
OpenProcess = _api('OpenProcess', win.HANDLE, win.DWORD, win.BOOL, win.DWORD)
VirtualAlloc = _api('VirtualAlloc', ct.c_void_p, ct.c_void_p, ct.c_size_t, win.DWORD, win.DWORD)
VirtualProtect = _api('VirtualProtect', win.BOOL, ct.c_void_p, ct.c_size_t, win.DWORD, ct.POINTER(win.DWORD))
VirtualFree = _api('VirtualFree', win.BOOL, ct.c_void_p, ct.c_size_t, win.DWORD)


def filetime_value(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


def own_creation_filetime():
    created, exited, kernel, user = (win.FILETIME() for _ in range(4))
    require(GetProcessTimes(GetCurrentProcess(), ct.byref(created), ct.byref(exited),
                            ct.byref(kernel), ct.byref(user)), 'GetProcessTimes failed')
    return filetime_value(created)


def process_creation_filetime(pid):
    handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    require(handle, f'OpenProcess {pid} failed: {ct.get_last_error()}')
    try:
        created, exited, kernel, user = (win.FILETIME() for _ in range(4))
        require(GetProcessTimes(handle, ct.byref(created), ct.byref(exited), ct.byref(kernel),
                                ct.byref(user)), 'GetProcessTimes failed')
        return filetime_value(created)
    finally:
        CloseHandle(handle)


# --------------------------------------------------------------------------- mutex


def acquire_mutex(timeout_ms=30000):
    handle = CreateMutexW(None, False, MUTEX_NAME)
    require(handle, f'CreateMutexW failed: {ct.get_last_error()}')
    result = WaitForSingleObject(handle, timeout_ms)
    if result not in (WAIT_OBJECT_0, WAIT_ABANDONED):
        CloseHandle(handle)
        raise SystemExit(f'{MUTEX_NAME} busy after {timeout_ms} ms (WaitForSingleObject={result})')
    return handle, result


def release_mutex(handle):
    ReleaseMutex(handle)
    CloseHandle(handle)


# --------------------------------------------------------------------------- target


def target_mode():
    """Own a live committed range with a protected middle page and report it."""
    pattern = bytearray()
    for page in range(TOTAL_PAGES):
        pattern.extend(page_pattern(page, PAGE_SIZE))
    base = VirtualAlloc(None, len(pattern), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    require(base, f'VirtualAlloc failed: {ct.get_last_error()}')
    base = int(base)
    ct.memmove(base, bytes(pattern), len(pattern))
    previous = win.DWORD()
    require(VirtualProtect(base + GAP_PAGE * PAGE_SIZE, PAGE_SIZE, PAGE_NOACCESS,
                            ct.byref(previous)), 'VirtualProtect failed')
    seed = {'pid': os.getpid(), 'creation': own_creation_filetime(), 'base': base,
            'pageSize': PAGE_SIZE, 'pages': TOTAL_PAGES, 'gapPage': GAP_PAGE,
            'pattern': bytes(pattern).hex()}
    print(json.dumps(seed), flush=True)
    try:
        for line in sys.stdin:
            if line.strip() == 'exit':
                break
    except KeyboardInterrupt:
        pass
    VirtualFree(base, 0, MEM_RELEASE)


def build_target():
    """Start one windowless owned child process with the deterministic live range."""
    require(sys.maxsize > 2 ** 32, 'the host must be 64-bit')
    child = subprocess.Popen(
        [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--target'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding='utf-8', creationflags=CREATE_NO_WINDOW)
    line = child.stdout.readline()
    require(line, 'target did not report its live range')
    seed = json.loads(line)
    require(seed.get('pid') == child.pid, 'target pid mismatch')
    require(seed.get('pages') == TOTAL_PAGES, 'target page count mismatch')
    require(seed.get('creation') == process_creation_filetime(child.pid),
            'target creation time mismatch')
    seed['pattern'] = bytes.fromhex(seed['pattern'])
    return child, seed


# --------------------------------------------------------------------------- CLI


def cli(*args, timeout=300):
    result = subprocess.run([str(CLI), *args], capture_output=True, timeout=timeout,
                            creationflags=CREATE_NO_WINDOW)
    stdout = result.stdout.decode('utf-8', errors='replace')
    stderr = result.stderr.decode('utf-8', errors='replace')
    payload = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
    return result.returncode, payload, stdout, stderr


def data_of(payload):
    return (payload or {}).get('data') or {}


def repl(*commands, timeout=300):
    """Run one offline REPL session and return the JSON documents it printed."""
    script = ''.join(f'{command}\n' for command in commands) + 'quit\n'
    result = subprocess.run([str(CLI), 'analyze', 'session'], input=script.encode('utf-8'),
                            capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    text = result.stdout.decode('utf-8', errors='replace')
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return result.returncode, rows, text, result.stderr.decode('utf-8', errors='replace')


# --------------------------------------------------------------------------- build


def build_cli(stamp):
    script = REPO / 'tools' / 'Invoke-KSwordNativeBuildCheck.ps1'
    command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
               '-File', str(script), '-Product', 'CLI']
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, timeout=1800, cwd=str(REPO))
    stdout = result.stdout.decode('utf-8', errors='replace')
    stderr = result.stderr.decode('utf-8', errors='replace')
    (LOG_DIR / f'action-analyze-memory-snapshot-cli-build-{stamp}.log').write_text(
        f'COMMAND={" ".join(command)}\n{stdout}\n=== STDERR ===\n{stderr}', encoding='utf-8')
    facts = {}
    for line in stdout.splitlines():
        if '=' in line:
            key, _, value = line.partition('=')
            facts[key.strip()] = value.strip()
    facts['EXIT_CODE'] = str(result.returncode)
    facts['DURATION_SECONDS'] = f'{time.monotonic() - started:.1f}'
    return facts


# --------------------------------------------------------------------------- project


def create_project(name):
    """Create a project through the official REPL so the CLI owns the project format."""
    path = WORK / name
    if path.exists():
        shutil.rmtree(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    code, rows, text, stderr = repl(f'project create "{path}" MemorySnapshotValidation')
    require(code == 0, f'project create failed: {text[:300]} {stderr[:300]}')
    project_id = ''
    for row in rows:
        project_id = row.get('projectId') or project_id
    require(project_id, f'project create reported no project id: {text[:300]}')
    return path, project_id


def project_status(path):
    code, rows, text, stderr = repl(f'project open "{path}"', 'project status')
    require(code == 0, f'project status failed: {text[:300]} {stderr[:300]}')
    for row in rows:
        if row.get('revisionId'):
            return row
    raise RuntimeError(f'project status reported no revision: {text[:300]}')


def sample_status(path, sample):
    code, rows, text, stderr = repl(f'project open "{path}"', f'sample status {sample}')
    require(code == 0, f'sample status failed: {text[:300]} {stderr[:300]}')
    for row in rows:
        if row.get('sampleId') == sample:
            return row
    raise RuntimeError(f'sample status reported no sample: {text[:300]}')


def sample_dirs(project):
    samples = project / 'samples'
    return sorted(p.name for p in samples.glob('*')) if samples.is_dir() else []


def memory_segments(project, sample):
    directory = project / 'samples' / sample / 'raw-memory'
    return sorted(directory.glob('*.ksaseg')) if directory.is_dir() else []


# --------------------------------------------------------------------------- cases


def case_help_and_docs():
    section = 'help'
    for command in ('snapshot', 'read', 'export'):
        code, _, stdout, stderr = cli('help', 'analyze', 'memory', command)
        check(section, f'help analyze memory {command} exits 0', code == 0,
              f'exit={code} stderr={stderr.strip()[:200]}')
        check(section, f'help analyze memory {command} prints a syntax', 'Syntax:' in stdout,
              stdout[:160])
    rows = {}
    for line in DOC.read_text(encoding='utf-8').splitlines():
        if not line.startswith('| `analyze memory'):
            continue
        cells = [cell.strip() for cell in line.strip('|').split('|')]
        rows[cells[0].strip('`')] = cells[1].strip().strip('`')
    for command in ('snapshot', 'read', 'export'):
        _, _, stdout, _ = cli('help', 'analyze', 'memory', command)
        syntax = ''
        lines = stdout.splitlines()
        for index, line in enumerate(lines):
            if line.strip() == 'Syntax:' and index + 1 < len(lines):
                syntax = lines[index + 1].strip()
                break
        documented = rows.get(f'analyze memory {command}', '')
        check(section, f'the CLI document has a row for {command}', bool(documented), documented)
        check(section, f'the documented syntax matches the built-in help for {command}',
              syntax == documented, f'help={syntax!r} doc={documented!r}')


def case_snapshot_roundtrip(seed):
    section = 'snapshot'
    project, project_id = create_project('roundtrip')
    before = project_status(project)
    base = seed['base']
    size = seed['pageSize'] * READABLE_PAGES
    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project),
        '--pid', str(seed['pid']), '--creation-filetime', str(seed['creation']),
        '--base', hex(base), '--bytes', str(size), '--confirm',
        '--title', 'CLI memory snapshot validation', '--json')
    check(section, 'snapshot exits 0', code == 0,
          f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    data = data_of(payload)
    sample = data.get('sampleId')
    check(section, 'snapshot created a new sample', bool(sample), json.dumps(data)[:400])
    check(section, 'snapshot verified the archived segment', data.get('segmentVerified') is True,
          json.dumps(data)[:400])
    check(section, 'snapshot is not an atomic process snapshot',
          data.get('atomicProcessSnapshot') is False, str(data.get('atomicProcessSnapshot')))
    check(section, 'snapshot covered the complete range', data.get('completeRange') is True,
          str(data.get('completeRange')))
    check(section, 'snapshot reports no unavailable page', data.get('unavailablePages') == '0',
          str(data.get('unavailablePages')))
    check(section, 'snapshot captured every requested byte', data.get('capturedBytes') == str(size),
          f"{data.get('capturedBytes')} vs {size}")
    check(section, 'snapshot names the raw-memory lane', data.get('stream') == 'raw-memory',
          str(data.get('stream')))
    pages = data.get('pages') or []
    check(section, 'snapshot listed every page', len(pages) == READABLE_PAGES, str(len(pages)))
    sha = data.get('sha256')
    check(section, 'snapshot reported a segment hash', isinstance(sha, str) and len(sha) == 64, str(sha))

    # The new sample must freeze the project revision that was current at capture time.
    after = project_status(project)
    check(section, 'the project revision is unchanged by the capture',
          before.get('revisionId') == after.get('revisionId'),
          f"{before.get('revisionId')} -> {after.get('revisionId')}")
    frozen = sample_status(project, sample)
    check(section, 'the sample froze the captured project revision',
          frozen.get('revisionId') == before.get('revisionId'),
          f"{frozen.get('revisionId')} vs {before.get('revisionId')}")
    check(section, 'the sample froze the project configuration',
          frozen.get('frozenSettings') == before.get('settings'),
          json.dumps(frozen.get('frozenSettings'))[:200])
    check(section, 'the sample carries the captured identity',
          frozen.get('sampleId') == sample, str(frozen.get('sampleId')))

    code, payload, stdout, stderr = cli('analyze', 'memory', 'read', '--project', str(project),
                                        '--sample', sample, '--ordinal', '1', '--json')
    check(section, 'read exits 0', code == 0, f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    read = data_of(payload)
    check(section, 'read confirmed the segment', read.get('segmentVerified') is True,
          json.dumps(read)[:400])
    check(section, 'read reported the same ordinal', read.get('ordinal') == '1', str(read.get('ordinal')))
    check(section, 'read reported the same segment hash', read.get('sha256') == sha, str(read.get('sha256')))
    check(section, 'read reported the complete range', read.get('completeRange') is True,
          str(read.get('completeRange')))
    read_pages = read.get('pages') or []
    check(section, 'read listed every page', len(read_pages) == READABLE_PAGES, str(len(read_pages)))
    coordinates = lengths = qpc = hashes = True
    for index, page in enumerate(read_pages):
        observation = page.get('observation') or {}
        expected_base = base + index * seed['pageSize']
        if number(observation.get('pageBase')) != expected_base:
            coordinates = False
        if number((observation.get('range') or {}).get('base')) != expected_base:
            coordinates = False
        if number((observation.get('range') or {}).get('bytes')) != seed['pageSize']:
            lengths = False
        if number(page.get('validLength')) != seed['pageSize']:
            lengths = False
        if number(observation.get('returnedBytes')) != seed['pageSize']:
            lengths = False
        begin, end = observation.get('readBeginQpc'), observation.get('readEndQpc')
        if not (begin and end and number(end) >= number(begin)):
            qpc = False
        if observation.get('sha256') != hashlib.sha256(page_pattern(index, seed['pageSize'])).hexdigest():
            hashes = False
    check(section, 'read reported the real raw-memory coordinates', coordinates, json.dumps(read_pages)[:500])
    check(section, 'read reported the real valid lengths', lengths, json.dumps(read_pages)[:500])
    check(section, 'read reported monotonic QPC windows', qpc, json.dumps(read_pages)[:500])
    check(section, 'read reported the original page hashes', hashes, json.dumps(read_pages)[:500])

    out = WORK / 'roundtrip.bin'
    if out.exists():
        out.unlink()
    code, payload, stdout, stderr = cli('analyze', 'memory', 'export', '--project', str(project),
                                        '--sample', sample, '--ordinal', '1', '--out', str(out), '--json')
    check(section, 'export exits 0', code == 0, f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    exported = data_of(payload)
    check(section, 'export reported the source segment hash', exported.get('sourceSha256') == sha,
          f"{exported.get('sourceSha256')} vs {sha}")
    check(section, 'export reported the exported length', exported.get('validLength') == str(size),
          str(exported.get('validLength')))
    check(section, 'export created the output file', out.is_file(), str(out))
    if out.is_file():
        content = out.read_bytes()
        check(section, 'export bytes equal the live target bytes', content == seed['pattern'][:size],
              f'{len(content)} vs {size}')
        check(section, 'export hash equals the live target hash',
              exported.get('sha256') == hashlib.sha256(content).hexdigest(), str(exported.get('sha256')))
    return project, project_id, sample, sha, data


def case_rejections(seed, generation_only=False):
    section = 'reject'
    project, _ = create_project('rejects')
    before = sample_dirs(project)
    wrong = seed['creation'] + 1
    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project),
        '--pid', str(seed['pid']), '--creation-filetime', str(wrong),
        '--base', hex(seed['base']), '--bytes', str(seed['pageSize']), '--confirm', '--json')
    check(section, 'a wrong creation time is rejected', code != 0,
          f'exit={code} stdout={stdout[:300]}')
    check(section, 'a wrong creation time names the instance mismatch',
          'target-instance-mismatch' in stdout, stdout[:300])
    check(section, 'a wrong creation time creates no sample', before == sample_dirs(project),
          f'{before} -> {sample_dirs(project)}')
    check(section, 'a wrong creation time creates no memory segment',
          not any((project / 'samples' / name / 'raw-memory').exists() for name in sample_dirs(project)),
          str(list((project / 'samples').glob('*'))))
    # 缩减批次只保留这一次错代次无读取检查，其余同类型负控留给 --suite full。
    if generation_only:
        return

    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project),
        '--pid', str(seed['pid']), '--creation-filetime', str(seed['creation']),
        '--base', hex(seed['base']), '--bytes', str(seed['pageSize'] * 65), '--confirm', '--json')
    check(section, 'a range over 64 pages is rejected', code != 0, f'exit={code} stdout={stdout[:300]}')
    check(section, 'an over-long range creates no sample', before == sample_dirs(project),
          f'{before} -> {sample_dirs(project)}')

    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project),
        '--pid', str(seed['pid']), '--creation-filetime', str(seed['creation']),
        '--base', hex(seed['base']), '--bytes', str(seed['pageSize']), '--json')
    check(section, 'a missing --confirm is rejected', code != 0, f'exit={code} stdout={stdout[:300]}')
    check(section, 'a missing --confirm explains the requirement',
          'confirm' in (stdout + stderr).lower(), (stdout + stderr)[:300])
    check(section, 'a missing --confirm creates no sample', before == sample_dirs(project),
          f'{before} -> {sample_dirs(project)}')

    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project),
        '--pid', str(os.getpid()), '--creation-filetime', str(seed['creation']),
        '--base', hex(seed['base']), '--bytes', str(seed['pageSize']), '--confirm', '--json')
    check(section, 'an unrelated process identity is rejected', code != 0,
          f'exit={code} stdout={stdout[:300]}')
    check(section, 'an unrelated process identity creates no sample', before == sample_dirs(project),
          f'{before} -> {sample_dirs(project)}')


def case_append_segment(seed, project, sample, first_data):
    section = 'append'
    segments = memory_segments(project, sample)
    check(section, 'the first memory segment exists', len(segments) == 1, str(segments))
    first_hash = hashlib.sha256(segments[0].read_bytes()).hexdigest() if segments else ''

    # A second snapshot into the same sample must append ordinal 2 and keep ordinal 1 intact.
    tail_base = seed['base'] + (GAP_PAGE + 1) * seed['pageSize']
    size = seed['pageSize'] * TRAILING_PAGES
    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project), '--sample', sample,
        '--pid', str(seed['pid']), '--creation-filetime', str(seed['creation']),
        '--base', hex(tail_base), '--bytes', str(size), '--confirm', '--json')
    check(section, 'the second snapshot exits 0', code == 0,
          f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    data = data_of(payload)
    check(section, 'the second snapshot uses ordinal 2', data.get('ordinal') == '2',
          str(data.get('ordinal')))
    check(section, 'the second snapshot keeps the same sample', data.get('sampleId') == sample,
          str(data.get('sampleId')))
    after = memory_segments(project, sample)
    check(section, 'the second snapshot appended a new segment', len(after) == 2, str(after))
    check(section, 'the first segment file is byte identical',
          first_hash == hashlib.sha256(segments[0].read_bytes()).hexdigest(), first_hash)
    check(section, 'the second segment continues the record sequence',
          number(data.get('lastSequence')) > number(first_data.get('lastSequence')),
          f"{data.get('lastSequence')} vs {first_data.get('lastSequence')}")

    code, payload, stdout, stderr = cli('analyze', 'memory', 'read', '--project', str(project),
                                        '--sample', sample, '--ordinal', '2', '--json')
    check(section, 'reading ordinal 2 exits 0', code == 0, f'exit={code} stdout={stdout[:400]}')
    second = data_of(payload)
    check(section, 'ordinal 2 has its own segment hash',
          second.get('sha256') not in (None, '', first_hash), str(second.get('sha256')))
    check(section, 'ordinal 2 reports the continued record sequence',
          number(second.get('lastSequence')) > number(first_data.get('lastSequence')),
          f"{second.get('lastSequence')} vs {first_data.get('lastSequence')}")
    pages = second.get('pages') or []
    check(section, 'ordinal 2 listed both pages', len(pages) == TRAILING_PAGES, str(len(pages)))
    hashes = True
    for index, page in enumerate(pages):
        observation = page.get('observation') or {}
        expected = hashlib.sha256(page_pattern(GAP_PAGE + 1 + index, seed['pageSize'])).hexdigest()
        if observation.get('sha256') != expected:
            hashes = False
    check(section, 'ordinal 2 reported the original page hashes', hashes, json.dumps(pages)[:500])

    out = WORK / 'append.bin'
    if out.exists():
        out.unlink()
    code, payload, stdout, stderr = cli('analyze', 'memory', 'export', '--project', str(project),
                                        '--sample', sample, '--ordinal', '2', '--out', str(out), '--json')
    check(section, 'exporting ordinal 2 exits 0', code == 0, f'exit={code} stdout={stdout[:400]}')
    if out.is_file():
        expected = b''.join(page_pattern(GAP_PAGE + 1 + index, seed['pageSize'])
                            for index in range(TRAILING_PAGES))
        check(section, 'ordinal 2 export equals the live target bytes', out.read_bytes() == expected,
              str(out.stat().st_size))
    return project, sample


def api_archive_bytes():
    """Build a legal closed API Monitor archive with the existing test generator."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    module = importlib.import_module('api_evidence')
    cases = (
        ('memory-write', 'WriteProcessMemory',
         module.packet('KernelBase', 'WriteProcessMemory', 8, 0x52545631, status=299),
         {'processCreation100ns': '134400565183024180'}),
        ('apc-queue', 'NtQueueApcThread',
         module.packet('NTDLL.DLL', 'NtQueueApcThread', 9, result_kind=1), {}),
        ('thread-create', 'CreateRemoteThreadEx',
         module.packet('Kernel32.dll', 'CreateRemoteThreadEx', 9, 0x52545631, returned=20), {}),
        ('thread-context', 'SetThreadContext',
         module.packet('KernelBase', 'SetThreadContext', 9), {}),
        ('section-map', 'NtMapViewOfSection',
         module.packet('ntdll', 'NtMapViewOfSection', 8), {}),
    )
    rows = [module.archive_line(index, wire, **extra)
            for index, (_, _, wire, extra) in enumerate(cases, 1)]
    return b''.join(rows)


def case_api_raw_preserved(seed, project):
    section = 'api-raw'
    archive = WORK / 'api-events.jsonl'
    archive.write_bytes(api_archive_bytes())
    code, payload, stdout, stderr = cli('analyze', 'api-evidence', 'import', '--archive', str(archive),
                                        '--project', str(project), '--title', 'API raw', '--json')
    check(section, 'api-evidence import exits 0', code == 0,
          f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    data = data_of(payload)
    api_sample = data.get('sampleId')
    check(section, 'api-evidence import created a sample', bool(api_sample), json.dumps(data)[:400])
    check(section, 'api-evidence import verified its rows', data.get('status') == 'readback-verified',
          str(data.get('status')))
    api_raw = project / 'samples' / api_sample / 'raw'
    require(api_raw.is_dir(), f'{api_raw} is missing')
    api_segments = sorted(api_raw.glob('*.ksaseg'))
    check(section, 'api-evidence import wrote a primary raw segment', len(api_segments) == 1,
          str(api_segments))
    before = hashlib.sha256(api_segments[0].read_bytes()).hexdigest()

    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project), '--sample', api_sample,
        '--pid', str(seed['pid']), '--creation-filetime', str(seed['creation']),
        '--base', hex(seed['base']), '--bytes', str(seed['pageSize']), '--confirm', '--json')
    check(section, 'snapshot into the API sample exits 0', code == 0,
          f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    check(section, 'snapshot into the API sample keeps the sample',
          data_of(payload).get('sampleId') == api_sample, str(data_of(payload).get('sampleId')))
    after = hashlib.sha256(api_segments[0].read_bytes()).hexdigest()
    check(section, 'the API raw segment is byte identical', before == after, f'{before} -> {after}')
    memory_dir = project / 'samples' / api_sample / 'raw-memory'
    check(section, 'the memory lane is a separate directory',
          memory_dir.is_dir() and len(list(memory_dir.glob('*.ksaseg'))) == 1, str(memory_dir))

    code, payload, stdout, stderr = cli('analyze', 'api-evidence', 'replay', '--project', str(project),
                                        '--sample', api_sample, '--json')
    check(section, 'api-evidence replay still verifies the raw stream', code == 0,
          f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    check(section, 'api-evidence replay reports verified rows',
          data_of(payload).get('status') == 'readback-verified', json.dumps(data_of(payload))[:300])
    return api_sample


def case_gap(seed):
    section = 'gap'
    project, _ = create_project('gap')
    size = seed['pageSize'] * TOTAL_PAGES
    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'snapshot', '--project', str(project),
        '--pid', str(seed['pid']), '--creation-filetime', str(seed['creation']),
        '--base', hex(seed['base']), '--bytes', str(size), '--confirm', '--json')
    check(section, 'the gap snapshot reports a partial result', code == 6,
          f'exit={code} stdout={stdout[:500]} stderr={stderr[:300]}')
    data = data_of(payload)
    check(section, 'the gap snapshot is not complete', data.get('completeRange') is False,
          str(data.get('completeRange')))
    check(section, 'the gap snapshot counts the unavailable page', data.get('unavailablePages') == '1',
          str(data.get('unavailablePages')))
    expected_captured = seed['pageSize'] * (TOTAL_PAGES - 1)
    check(section, 'the gap snapshot captured only the readable pages',
          data.get('capturedBytes') == str(expected_captured),
          f"{data.get('capturedBytes')} vs {expected_captured}")
    pages = data.get('pages') or []
    check(section, 'the gap snapshot listed every page', len(pages) == TOTAL_PAGES, str(len(pages)))
    denied = [page for page in pages
              if number((page.get('observation') or {}).get('pageBase'))
              == seed['base'] + GAP_PAGE * seed['pageSize']]
    check(section, 'the denied page kept its metadata', len(denied) == 1, json.dumps(pages)[:500])
    if denied:
        observation = denied[0].get('observation') or {}
        check(section, 'the denied page archived no bytes', number(denied[0].get('validLength')) == 0,
              str(denied[0].get('validLength')))
        check(section, 'the denied page kept its state', observation.get('state') not in (None, 'sampled'),
              str(observation.get('state')))
    sample = data.get('sampleId')

    code, payload, stdout, stderr = cli('analyze', 'memory', 'read', '--project', str(project),
                                        '--sample', sample, '--ordinal', '1', '--json')
    check(section, 'reading the gap segment reports a partial result', code == 6,
          f'exit={code} stdout={stdout[:400]}')
    check(section, 'reading the gap segment keeps the unavailable page count',
          data_of(payload).get('unavailablePages') == '1', str(data_of(payload).get('unavailablePages')))

    out = WORK / 'gap-full.bin'
    if out.exists():
        out.unlink()
    code, payload, stdout, stderr = cli('analyze', 'memory', 'export', '--project', str(project),
                                        '--sample', sample, '--ordinal', '1', '--out', str(out), '--json')
    check(section, 'the default export across the gap is rejected', code != 0,
          f'exit={code} stdout={stdout[:400]}')
    check(section, 'the rejected export created no output file', not out.exists(), str(out))

    out = WORK / 'gap-subrange.bin'
    if out.exists():
        out.unlink()
    code, payload, stdout, stderr = cli(
        'analyze', 'memory', 'export', '--project', str(project), '--sample', sample, '--ordinal', '1',
        '--out', str(out), '--base', hex(seed['base']),
        '--bytes', str(seed['pageSize'] * READABLE_PAGES), '--json')
    check(section, 'the covered subrange export exits 0', code == 0,
          f'exit={code} stdout={stdout[:400]} stderr={stderr[:300]}')
    if out.is_file():
        expected = b''.join(page_pattern(index, seed['pageSize']) for index in range(READABLE_PAGES))
        check(section, 'the covered subrange export equals the live target bytes',
              out.read_bytes() == expected, str(out.stat().st_size))
    check(section, 'the covered subrange export reports its length',
          data_of(payload).get('validLength') == str(seed['pageSize'] * READABLE_PAGES),
          str(data_of(payload).get('validLength')))
    return project, sample


def case_corruption(project, sample):
    section = 'corrupt'
    segments = memory_segments(project, sample)
    require(segments, 'no memory segment to damage')
    segment = segments[0]
    original = segment.read_bytes()
    try:
        segment.write_bytes(original[:-16])
        code, payload, stdout, stderr = cli('analyze', 'memory', 'read', '--project', str(project),
                                            '--sample', sample, '--ordinal', '1', '--json')
        check(section, 'a truncated segment is refused by read', code != 0,
              f'exit={code} stdout={stdout[:400]}')
        out = WORK / 'corrupt.bin'
        if out.exists():
            out.unlink()
        code, payload, stdout, stderr = cli('analyze', 'memory', 'export', '--project', str(project),
                                            '--sample', sample, '--ordinal', '1', '--out', str(out),
                                            '--json')
        check(section, 'a truncated segment is refused by export', code != 0,
              f'exit={code} stdout={stdout[:400]}')
        check(section, 'the refused export created no output file', not out.exists(), str(out))

        damaged = bytearray(original)
        damaged[len(damaged) // 2] ^= 0xFF
        segment.write_bytes(bytes(damaged))
        code, payload, stdout, stderr = cli('analyze', 'memory', 'read', '--project', str(project),
                                            '--sample', sample, '--ordinal', '1', '--json')
        check(section, 'a damaged segment body is refused by read', code != 0,
              f'exit={code} stdout={stdout[:400]}')
    finally:
        segment.write_bytes(original)
    code, payload, stdout, stderr = cli('analyze', 'memory', 'read', '--project', str(project),
                                        '--sample', sample, '--ordinal', '1', '--json')
    check(section, 'the restored segment reads again', code == 0, f'exit={code} stdout={stdout[:400]}')

    out = WORK / 'existing.bin'
    out.write_bytes(b'keep-me')
    code, payload, stdout, stderr = cli('analyze', 'memory', 'export', '--project', str(project),
                                        '--sample', sample, '--ordinal', '1', '--out', str(out), '--json')
    check(section, 'an existing output file is refused', code != 0, f'exit={code} stdout={stdout[:400]}')
    check(section, 'the existing output file is untouched', out.read_bytes() == b'keep-me', str(out))

    link = WORK / 'outlink'
    target = WORK / 'reparse-target'
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    if link.exists():
        subprocess.run(['cmd', '/c', 'rmdir', str(link)], capture_output=True,
                       creationflags=CREATE_NO_WINDOW)
    created = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)],
                              capture_output=True, creationflags=CREATE_NO_WINDOW)
    if created.returncode == 0:
        code, payload, stdout, stderr = cli('analyze', 'memory', 'export', '--project', str(project),
                                            '--sample', sample, '--ordinal', '1',
                                            '--out', str(link / 'x.bin'), '--json')
        check(section, 'a reparse point output path is refused', code != 0,
              f'exit={code} stdout={stdout[:400]}')
        subprocess.run(['cmd', '/c', 'rmdir', str(link)], capture_output=True,
                       creationflags=CREATE_NO_WINDOW)
    else:
        note(section, 'a reparse point output path', 'junction creation is unavailable, check skipped')
    shutil.rmtree(target, ignore_errors=True)


# --------------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', action='store_true', help=__doc__)
    parser.add_argument('--suite', choices=('focused', 'full'), default='focused',
                        help='focused: roundtrip + gap + corruption; full: every legacy case')
    parser.add_argument('--skip-build', action='store_true',
                        help='reuse the formal CLI built once by the batch; still report its actual SHA')
    args = parser.parse_args()
    if args.target:
        target_mode()
        return 0

    LOG_DIR.mkdir(exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    handle, mutex_result = acquire_mutex()
    note('mutex', 'acquired', f'{MUTEX_NAME} result={mutex_result}')
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL)
    target = None
    facts = {}
    executed = []
    try:
        if args.skip_build:
            facts = {'skipped': 'true', 'exitCode': None}
            note('build', 'skipped', 'shared batch build; the actual CLI SHA is still reported')
        else:
            facts = build_cli(stamp)
            for key in ('IntDir', 'OutDir', 'VC_ExecutablePath_x64', 'Priority', 'SHA256'):
                note('build', key, facts.get(key, ''))
            check('build', 'the formal CLI build succeeded', facts.get('BUILD_RESULT') == 'SUCCESS',
                  f"BUILD_RESULT={facts.get('BUILD_RESULT')} EXIT_CODE={facts.get('EXIT_CODE')}")
            check('build', 'the CLI artifact exists', CLI.is_file(), str(CLI))
            artifact_sha = hashlib.sha256(CLI.read_bytes()).hexdigest() if CLI.is_file() else ''
            check('build', 'the CLI artifact hash is reported',
                  facts.get('SHA256', '').upper() == artifact_sha.upper(),
                  f"{facts.get('SHA256')} vs {artifact_sha}")

        target, seed = build_target()
        note('target', 'owned live range',
             f"pid={seed['pid']} base={hex(seed['base'])} pages={seed['pages']} gapPage={seed['gapPage']}")

        if args.suite == 'focused':
            project, project_id, sample, first_sha, first_data = case_snapshot_roundtrip(seed)
            executed.append('roundtrip')
            # 缩减批次保留一次错代次无读取检查与一次原 raw 不覆盖检查。
            case_rejections(seed, generation_only=True)
            executed.append('wrong-generation-no-read')
            case_api_raw_preserved(seed, project)
            executed.append('raw-not-overwritten')
            case_gap(seed)
            executed.append('gap')
            case_corruption(project, sample)
            executed.append('corruption')
        else:
            case_help_and_docs()
            project, project_id, sample, first_sha, first_data = case_snapshot_roundtrip(seed)
            case_rejections(seed)
            project, sample = case_append_segment(seed, project, sample, first_data)
            case_api_raw_preserved(seed, project)
            gap_project, gap_sample = case_gap(seed)
            case_corruption(project, sample)
            executed = ['help-and-docs', 'roundtrip', 'rejections', 'append-segment', 'api-raw',
                        'gap', 'corruption']
    finally:
        if target is not None:
            try:
                target.stdin.write('exit\n')
                target.stdin.flush()
                target.wait(timeout=10)
            except Exception:
                target.kill()
        release_mutex(handle)

    summary = {
        'started': started,
        'finished': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'suite': args.suite,
        'cases': executed,
        'cli': str(CLI),
        'cli_sha256': hashlib.sha256(CLI.read_bytes()).hexdigest() if CLI.is_file() else '',
        'build': facts,
        'work_dir': str(WORK),
        'checks': len(RESULTS),
        'failures': FAILURES,
        'results': RESULTS,
    }
    (LOG_DIR / f'action-analyze-memory-snapshot-cli-{stamp}.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'CHECKS={len(RESULTS)} FAILURES={len(FAILURES)}', flush=True)
    for failure in FAILURES:
        print(f'FAIL {failure}', flush=True)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    raise SystemExit(main())
