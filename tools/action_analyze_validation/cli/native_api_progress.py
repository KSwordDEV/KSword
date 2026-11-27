"""One focused execution-group API-capture progress validation."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = Path(__file__).with_name('native_api_progress')
EVIDENCE = EVIDENCE_ROOT / 'attempt-02'
RUN_LOG = EVIDENCE / 'run.log'
STDERR_LOG = EVIDENCE / 'stderr.jsonl'
RECEIPT = EVIDENCE / 'receipt.json'
APPEND_FIXTURE = Path(__file__).with_name('product_execution_group_append.py')
COOPERATIVE_FIXTURE = Path(__file__).with_name('cooperative_api_capture.py')
COOPERATIVE_ENV = 'KSWORD_APIMON_COOPERATIVE_SESSION_V1'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    os.environ['KSWORD_EXECUTION_GROUP_LOG_DIR'] = str(EVIDENCE)
    group = load_module('product_execution_group_append', APPEND_FIXTURE)
    group.LOG.close()
    log = RUN_LOG.open('w', encoding='utf-8', newline='\n')
    group.LOG = log
    api = load_module('cooperative_api_capture', COOPERATIVE_FIXTURE)
    group.LOG.write(f'CLI_SHA256={group.fingerprint(group.CLI)}\n')
    target_context = group.built_target(group.LOG) if not group.TARGET.exists() else None
    if target_context is None:
        raise group.Blocked(f'Owned target unexpectedly exists: {group.TARGET}')

    child = None
    source = controller = None
    source_identity = None
    controller_pid = None
    target_hash = None
    failure = None
    capture_issued = False
    stderr_log = None
        # The Agent validates this exact leaf name before accepting the private
        # cooperative directory; keep the attempt evidence as its parent.
        source_directory = EVIDENCE / 'KswordApiMonCooperative'
    project = EVIDENCE / 'project'
    sites = EVIDENCE / 'sites.json'
    outcome = 'FAIL'
    try:
        with target_context:
            child = group.Child()
            sites = group.write_sites(sites, [child.site()])
            environment = os.environ | {COOPERATIVE_ENV: str(source_directory)}
            api.create_session_directory(source_directory)
            source = subprocess.Popen([sys.executable, '-B', str(COOPERATIVE_FIXTURE), '--target'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=environment, cwd=REPO)
            identity_line = source.stdout.readline()
            if not identity_line:
                try:
                    _, source_error = source.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    source.kill()
                    _, source_error = source.communicate(timeout=5)
                (EVIDENCE / 'source-startup.stderr').write_bytes(source_error)
                raise RuntimeError('cooperative target stdout EOF before identity JSON; '
                                   f'exit={source.returncode}; stderr saved')
            identity = json.loads(identity_line.decode('utf-8'))
            source_identity = identity
            if identity['pid'] != source.pid or source.pid == child.pid:
                raise AssertionError(f'API source identity mismatch: {identity}, native PID={child.pid}')

            stderr_log = STDERR_LOG.open('w', encoding='utf-8', newline='\n')
            controller = group.Cli(sites, project, stderr=stderr_log)
            controller_pid = controller.process.pid
            hello = controller.hello
            collection = hello['control']['collectionId']
            if not collection or hello['sampleId'] is None:
                raise AssertionError(f'Incomplete execution-group setup: {hello}')
            group.ok(hello['executionArchive']['writerLeaseHeld'] is True,
                     'shared project/sample writer lease is held')
            child.fire()
            _, held_before = controller.wait_held(child.pid)
            if not held_before['held'] or held_before['control']['state'] != 'held':
                raise AssertionError(f'Native target did not reach real Held: {held_before}')
            token = held_before['sessionToken']
            owner_before = json.dumps(held_before['owner'], sort_keys=True)
            stop_before = json.dumps(held_before['stopToken'], sort_keys=True)
            group.ok(bool(token) and token.get('sessionId') == held_before['owner']['sessionId'],
                     'complete real Held member sessionToken captured')

            capture_issued = True
            response = controller.request('execution/1', 'control.api.capture', {
                'sourcePid': source.pid,
                'sourceCreationFileTime': str(identity['creation']),
                'durationMs': 2000,
                'confirm': True,
                'captureProgress': True,
            }, {'collectionId': collection, 'sessions': [token]})
            if controller.process.poll() is not None:
                raise AssertionError(f'Controller exited during API capture: {controller.process.returncode}')
            held_after = group.member_of(controller.status(), child.pid)
            group.ok(held_after['held'] is True and held_after['control']['state'] == 'held',
                     'API capture did not Continue or close the original Held owner')
            group.ok(json.dumps(held_after['owner'], sort_keys=True) == owner_before and
                     json.dumps(held_after['stopToken'], sort_keys=True) == stop_before,
                     'original owner and Held stop identity remain unchanged')

            group.LOG.flush()
            stderr_log.flush()
            progress_lines = [line for line in STDERR_LOG.read_text(encoding='utf-8').splitlines()
                              if line.strip()]
            frames = [json.loads(line) for line in progress_lines]
            if not frames or any(frame.get('type') != 'api-capture-progress' for frame in frames):
                raise AssertionError(f'Missing or unexpected stderr progress frames: {progress_lines}')
            sequences = [int(frame['progressSequence']) for frame in frames]
            if sequences != list(range(1, len(sequences) + 1)):
                raise AssertionError(f'Progress sequence is not contiguous: {sequences}')
            checkpoints = [frame for frame in frames if frame['kind'] == 'api-checkpoint']
            transfers = [frame for frame in frames if frame['kind'] in
                         ('api-transfer-candidates', 'transfer-handoff')]
            if not checkpoints:
                raise AssertionError(f'No api-checkpoint frame: {frames}')
            previous = (0, 0, 0)
            for frame in checkpoints:
                payload = frame['payload']
                watermarks = (int(payload['segmentOrdinal']), int(payload['rawSequence']),
                              int(payload['sourceSequence']))
                if watermarks < previous:
                    raise AssertionError(f'Checkpoint watermarks moved backwards: {previous} -> {watermarks}')
                previous = watermarks
            final = checkpoints[-1]['payload']
            if not final['finalSegment']:
                raise AssertionError(f'Last checkpoint is not final: {final}')
            if response['captureProgress']['enqueuedFrames'] != str(len(frames)) or \
                    response['captureProgress']['droppedFrames'] != '0' or \
                    response['captureProgress']['outputDrained'] is not True:
                raise AssertionError(f'Progress delivery does not reconcile: {response["captureProgress"]}')
            archive = response['executionArchive']
            rules = response['rules']
            if not rules or 'latest' not in rules:
                raise AssertionError(f'Missing rules.latest snapshot: {rules}')
            if int(final['ruleMatchedRows']) != int(rules['matchedRows']):
                raise AssertionError(f'Final checkpoint/rules.latest mismatch: {final}, {rules}')
            if final['latestRule'] != rules['latest']:
                raise AssertionError(f'Checkpoint latestRule differs from stdout rules.latest: {final}, {rules}')
            if transfers and transfers[-1]['payload']['candidates'] != response['transfers']:
                raise AssertionError('Final stderr transfer window differs from stdout transfers')
            if response['nativeContinueIssued'] or response['nativeCloseIssued']:
                raise AssertionError('API capture issued an automatic Continue or Close')
            if len(transfers) == 0:
                candidates = {'candidateCount': '0', 'recent': [], 'apcCandidateCount': '0',
                              'recentApc': [], 'contextCandidateCount': '0', 'recentContext': []}
            else:
                candidates = transfers[-1]['payload']['candidates']
            group.ok(bool(archive) and response['sampleId'] == hello['sampleId'],
                     'API result remains in the execution group sample')
            group.ok(response['captureProgress']['requested'] and response['captureProgress']['started'],
                     'stderr progress delivery reports requested and started')
            with RUN_LOG.open('a', encoding='utf-8', newline='\n') as summary_log:
                summary_log.write(f'PROGRESS_FRAMES={len(frames)} CHECKPOINTS={len(checkpoints)} '
                                  f'TRANSFER_FRAMES={len(transfers)} FINAL_WATERMARKS={previous}\n')
                summary_log.write('TRANSFER_CANDIDATES=' + json.dumps(candidates, separators=(',', ':')) + '\n')
                summary_log.write('API_RESPONSE=' + json.dumps(response, separators=(',', ':')) + '\n')

            source_tail, source_error = source.communicate(timeout=15)
            if source.returncode != 0:
                raise AssertionError(f'Cooperative source exited {source.returncode}: {source_tail!r} {source_error!r}')
            group.ok(True, 'separate cooperative API source exited normally')
            shutdown = controller.request('execution/2', 'controller.shutdown', {})
            group.ok(shutdown['clean'] is True and shutdown['state'] == 'closed',
                     'explicit unified shutdown closes original owner cleanly')
            summary = controller.receive('summary', None)
            if summary['reason'] != 'requested' or controller.finish() != 0:
                raise AssertionError(f'Unexpected CLI shutdown: {summary}')
            controller = None
            outcome = 'PASS'
    except BaseException as error:
        failure = {'type': type(error).__name__, 'message': str(error),
                   'captureIssued': capture_issued,
                   'controllerStarted': controller is not None}
        raise
    finally:
        if source is not None and source.poll() is None:
            source.kill()
            source.wait(timeout=5)
        if child is not None:
            child.close()
        if controller is not None and controller.process.poll() is None:
            controller.process.kill()
            controller.process.wait(timeout=5)
        group.LOG.flush()
        if not group.LOG.closed:
            group.LOG.close()
        if stderr_log is not None and not stderr_log.closed:
            stderr_log.flush()
            stderr_log.close()
        if not log.closed:
            log.close()
        if source_directory.exists() and source_identity is not None and source is not None:
            api.cleanup_session(source_directory, source.pid, source_identity['creation'],
                                controller_pid if controller_pid is not None else os.getpid())
        for path in (sites, project, source_directory):
            if path.exists():
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        if group.TARGET.exists():
            target_hash = group.fingerprint(group.TARGET)
            group.TARGET.unlink()
        if group.WORK.exists():
            shutil.rmtree(group.WORK)
        receipt = {'result': outcome, 'cliSha256': group.fingerprint(group.CLI),
                   'targetSha256': target_hash, 'evidenceDirectory': str(EVIDENCE),
                   'failure': failure}
        RECEIPT.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        with RUN_LOG.open('a', encoding='utf-8', newline='\n') as final_log:
            final_log.write('RESULT=' + outcome + '\n')
    print(f'RESULT={outcome} EVIDENCE={EVIDENCE}')


if __name__ == '__main__':
    main()
