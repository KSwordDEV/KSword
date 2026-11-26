"""Serial transfer/rule validation batch.

Holds Local\\KSword.ActionAnalyze.CliValidation for the full build + run batch,
builds the formal CLI through the repository wrapper, builds the native graph
fixture, then runs the native transfer cases, the formal CLI cross-segment
readback and the rule identity integration fixture.  Every step is logged; a
failed step keeps the remaining independent steps running so the receipt can
record the real state instead of stopping at the first failure.
"""

import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r'E:\Projects\Ksword5.1')
RELEASE = ROOT / 'Ksword5.1/x64/Release'
LOG_DIR = ROOT / '.codex-build-logs'
MUTEX_NAME = r'Local\KSword.ActionAnalyze.CliValidation'
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
WAIT_OBJECT_0 = 0
WAIT_ABANDONED = 0x80
PROFILE = RELEASE / 'profiles/action_analyze_api_rules.json'
GRAPH_PROJECT = ROOT / 'KswordCLI/ActionAnalyze/Detection/tests/ActionAnalyzeCrossProcessEvidenceGraphValidation.vcxproj'
GRAPH_EXE = RELEASE / 'ActionAnalyzeCrossProcessEvidenceGraphValidation.exe'
GRAPH_FIXTURE = RELEASE / 'action-analyze-cross-process-graph-validation'
SCRATCH = RELEASE / 'action-analyze-cli-validation'


def run(label, args, timeout, log, env=None):
    """Run one step, echo bounded output to the batch log and return its result."""
    log.append(f'===== {label} ====')
    log.append('COMMAND=' + subprocess.list2cmdline([str(item) for item in args]))
    started = time.monotonic()
    try:
        result = subprocess.run([str(item) for item in args], capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=timeout,
                                env=env if env is not None else os.environ)
    except subprocess.TimeoutExpired as error:
        log.append(f'TIMEOUT={timeout}')
        log.append(f'STDOUT={(error.stdout or "")[-8000:]}')
        log.append(f'STDERR={(error.stderr or "")[-8000:]}')
        return None
    elapsed = round(time.monotonic() - started, 2)
    log.append(f'ELAPSED={elapsed}s EXIT={result.returncode}')
    if result.stdout:
        log.append('STDOUT=' + result.stdout[-20000:])
    if result.stderr:
        log.append('STDERR=' + result.stderr[-20000:])
    return result


def acquire():
    """Acquire the shared CLI validation mutex and report an abandoned owner."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.restype = ctypes.c_void_p
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.ReleaseMutex.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.CreateMutexW(None, False, MUTEX_NAME)
    if not handle:
        raise SystemExit(f'CreateMutexW failed: {ctypes.get_last_error()}')
    result = kernel.WaitForSingleObject(ctypes.c_void_p(handle), 300000)
    if result not in (WAIT_OBJECT_0, WAIT_ABANDONED):
        kernel.CloseHandle(ctypes.c_void_p(handle))
        raise SystemExit(f'{MUTEX_NAME} busy: {result}')
    return kernel, handle, result


def release(kernel, handle):
    kernel.ReleaseMutex(ctypes.c_void_p(handle))
    kernel.CloseHandle(ctypes.c_void_p(handle))


def artifact_sha(path):
    """Hash the exact CLI image used by every fixture in this batch."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).is_file() else None


def msbuild_path():
    candidates = [
        Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'),
        Path(r'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise SystemExit('64-bit HostX64 MSBuild was not found in the approved locations.')


def cleanup_scratch(log):
    """Remove only the fixed owned test root after a failed fixture run."""
    if not SCRATCH.exists():
        return
    resolved = SCRATCH.resolve()
    if resolved != (RELEASE / 'action-analyze-cli-validation').resolve():
        raise SystemExit(f'unexpected scratch path: {resolved}')
    shutil.rmtree(resolved)
    log.append(f'SCRATCH_REMOVED={not resolved.exists()}')


def main():
    LOG_DIR.mkdir(exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    log_path = LOG_DIR / f'action-analyze-transfer-rule-batch-{stamp}.log'
    summary_path = LOG_DIR / f'action-analyze-transfer-rule-batch-{stamp}.json'
    log = [f'START={stamp}', f'ROOT={ROOT}', f'MUTEX={MUTEX_NAME}']
    summary = {'log': str(log_path), 'steps': {}}
    profile_before = PROFILE.read_bytes() if PROFILE.is_file() else b''
    profile_hash = hashlib.sha256(profile_before).hexdigest()
    log.append(f'PROFILE_SHA256_BEFORE={profile_hash}')

    kernel, handle, mutex_result = acquire()
    log.append(f'MUTEX_RESULT={mutex_result}')  # 0x80 表示前一持有者异常退出。
    host = ctypes.WinDLL('kernel32', use_last_error=True)
    host.GetCurrentProcess.restype = ctypes.c_void_p
    host.GetPriorityClass.restype = ctypes.c_uint32
    host.GetPriorityClass.argtypes = [ctypes.c_void_p]
    host.SetPriorityClass.restype = ctypes.c_int
    host.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    process = ctypes.c_void_p(host.GetCurrentProcess())
    previous_priority = host.GetPriorityClass(process)
    try:
        if not host.SetPriorityClass(process, BELOW_NORMAL_PRIORITY_CLASS):
            raise SystemExit(f'SetPriorityClass failed: {ctypes.get_last_error()}')
        log.append(f'PRIORITY=BelowNormal previous={previous_priority}')

        # 1. Formal CLI increment through the repository wrapper.
        shell = Path(r'C:\Program Files\PowerShell\7\pwsh.exe')
        if not shell.is_file():
            shell = Path('powershell.exe')
        log.append(f'BUILD_SHELL={shell}')
        cli = run('cli-build', [shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                               '-File', ROOT / 'tools/Invoke-KSwordNativeBuildCheck.ps1', '-Product', 'CLI'],
                  900, log)
        cli_ok = bool(cli and cli.returncode == 0 and 'BUILD_RESULT=SUCCESS' in cli.stdout and
                      (RELEASE / 'KswordCLI.exe').is_file() and (RELEASE / 'KswordCLI.exe').stat().st_size)
        cli_hash = artifact_sha(RELEASE / 'KswordCLI.exe')
        log.append(f'CLI_SHA256_AT_BUILD={cli_hash}')
        summary['cliSha256'] = cli_hash
        summary['steps']['cli-build'] = {'ok': cli_ok, 'exit': None if cli is None else cli.returncode}
        log.append(f'CLI_BUILD_OK={cli_ok}')

        # 2. Native graph fixture increment and run with a fixed, cleanable fixture root.
        if GRAPH_FIXTURE.exists():
            raise SystemExit(f'graph fixture path already exists: {GRAPH_FIXTURE}')
        graph_build = run('graph-build', [msbuild_path(), GRAPH_PROJECT, '/t:Build', '/p:Configuration=Release',
                                         '/p:Platform=x64', '/p:PreferredToolArchitecture=x64',
                                         '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64',
                                         f'/p:SolutionDir={ROOT / "Ksword5.1"}\\', '/p:BuildProjectReferences=false',
                                         '/nologo', '/m:1', '/v:minimal'], 600, log)
        graph_build_ok = bool(graph_build and graph_build.returncode == 0 and GRAPH_EXE.is_file())
        summary['steps']['graph-build'] = {'ok': graph_build_ok, 'exit': None if graph_build is None else graph_build.returncode}
        log.append(f'GRAPH_BUILD_OK={graph_build_ok}')
        if graph_build_ok:
            graph_run = run('graph-run', [GRAPH_EXE, GRAPH_FIXTURE], 300, log)
            graph_ok = bool(graph_run and graph_run.returncode == 0 and 'passed' in graph_run.stdout)
            summary['steps']['graph-run'] = {'ok': graph_ok, 'exit': None if graph_run is None else graph_run.returncode}
            log.append(f'GRAPH_RUN_OK={graph_ok}')
        else:
            summary['steps']['graph-run'] = {'ok': False, 'exit': None}
        if GRAPH_FIXTURE.exists():
            shutil.rmtree(GRAPH_FIXTURE)
            log.append(f'GRAPH_FIXTURE_REMOVED={not GRAPH_FIXTURE.exists()}')

        # 3. Cross-segment transfer candidate readback through the formal CLI.
        before = artifact_sha(RELEASE / 'KswordCLI.exe')
        transfer = run('transfer-fixture', [sys.executable, '-B',
                       ROOT / 'tools/action_analyze_validation/cli/api_transfer_archive.py'], 180, log)
        after = artifact_sha(RELEASE / 'KswordCLI.exe')
        transfer_ok = bool(transfer and transfer.returncode == 0 and 'CLI_API_TRANSFER_ARCHIVE=PASS' in transfer.stdout
                           and before == after)
        log.append(f'TRANSFER_CLI_SHA256={before} AFTER={after}')
        summary['steps']['transfer-fixture'] = {'ok': transfer_ok, 'exit': None if transfer is None else transfer.returncode,
                                                 'cliSha256': before, 'artifactStable': before == after}
        log.append(f'TRANSFER_FIXTURE_OK={transfer_ok}')

        # 4. Rule identity integration fixture.
        before = artifact_sha(RELEASE / 'KswordCLI.exe')
        rule = run('rule-fixture', [sys.executable, '-B',
                   ROOT / 'tools/action_analyze_validation/cli/rule_profile_identity.py'], 300, log)
        after = artifact_sha(RELEASE / 'KswordCLI.exe')
        rule_ok = bool(rule and rule.returncode == 0 and 'CLI_RULE_PROFILE_IDENTITY=PASS' in rule.stdout
                       and before == after)
        log.append(f'RULE_CLI_SHA256={before} AFTER={after}')
        summary['steps']['rule-fixture'] = {'ok': rule_ok, 'exit': None if rule is None else rule.returncode,
                                             'cliSha256': before, 'artifactStable': before == after}
        log.append(f'RULE_FIXTURE_OK={rule_ok}')

        # 5. Static gates tied to the rule profile wiring.
        i18n = run('i18n-audit', [sys.executable, ROOT / 'tools/i18n_language_pack.py', 'audit',
                   '--source-root', ROOT / 'Ksword5.1/Ksword5.1',
                   '--zh-pack', ROOT / 'Ksword5.1/Ksword5.1/languages/zh-CN.json',
                   '--en-pack', ROOT / 'Ksword5.1/Ksword5.1/languages/en-US.json'], 180, log)
        i18n_ok = bool(i18n and i18n.returncode == 0)
        summary['steps']['i18n-audit'] = {'ok': i18n_ok, 'exit': None if i18n is None else i18n.returncode}
        diff = run('diff-check', ['git', '-C', ROOT, 'diff', '--check', '--',
                   'tools/action_analyze_validation/cli/rule_profile_identity.py',
                   'tools/action_analyze_validation/cli/api_transfer_archive.py',
                   'docs/CLI使用文档.md',
                   'docs/action-analyze-planning/rule-profile-integration-validation.md',
                   'docs/action-analyze-planning/api-transfer-consumer-validation.md'], 60, log)
        diff_ok = bool(diff and diff.returncode == 0)
        summary['steps']['diff-check'] = {'ok': diff_ok, 'exit': None if diff is None else diff.returncode}
    finally:
        try:
            # Restore the release profile if a probe left it modified.
            if profile_before:
                after = PROFILE.read_bytes() if PROFILE.is_file() else b''
                if hashlib.sha256(after).hexdigest() != profile_hash:
                    PROFILE.write_bytes(profile_before)
                    log.append('PROFILE_RESTORED_BY_BATCH=True')
            cleanup_scratch(log)
        except Exception as error:  # 清理失败仍必须写回执并释放互斥量。
            log.append(f'CLEANUP_ERROR={type(error).__name__}: {error}')
        finally:
            try:
                host.SetPriorityClass(process, previous_priority)
                release(kernel, handle)
            except Exception as error:
                log.append(f'RELEASE_ERROR={type(error).__name__}: {error}')
            log.append(f'PROFILE_SHA256_AFTER={hashlib.sha256(PROFILE.read_bytes()).hexdigest() if PROFILE.is_file() else "missing"}')
            summary['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            log_path.write_text('\n'.join(log) + '\n', encoding='utf-8')
            summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print('\n'.join(log[-50:]), flush=True)
            print('SUMMARY=' + json.dumps(summary, ensure_ascii=False), flush=True)
    failed = [name for name, value in summary['steps'].items() if not value['ok']]
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
