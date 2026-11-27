"""验证显式附加 API 采集的行为历史、进度和归档坐标契约。

本夹具只启动已有的 ``cooperative_api_capture.py --attachment-target``，
再调用正式的 ``analyze api-evidence attach`` 命令。它不设置协作会话环境，
也不在目标进程中预加载 Agent；一次运行只发出一次正式采集请求。
"""

from contextlib import suppress
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


# 任务固定使用当前仓库的 Release CLI，避免把其它构建或临时副本当成产品。
REPO = Path(__file__).resolve().parents[3]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
CLI = RELEASE / 'KswordCLI.exe'
EXPECTED_CLI_SHA256 = '6543745263B80F44A94ED701DA23301FFFF43BF9716F8FDBFFB4C0DFFF5B2E44'.lower()
TARGET_SCRIPT = Path(__file__).with_name('cooperative_api_capture.py')
EVIDENCE = Path(__file__).with_name('behavior_history')
PROJECT = EVIDENCE / 'project'
STDOUT_LOG = EVIDENCE / 'capture.stdout.json'
STDERR_LOG = EVIDENCE / 'capture.stderr.jsonl'
RUN_LOG = EVIDENCE / 'run.log'
RECEIPT = EVIDENCE / 'receipt.json'

# 产品错误码和本采样中要求出现的规则 ID，均来自现有夹具与规则配置。
ERROR_ACCESS_DENIED = 5
BEHAVIOR_RULE_ID = 'ksword.behavior.memory-write-access-denied-return.v1'
BEHAVIOR_PRESET_SET = 'ksword.api.behavior-presets.v3'


def sha256(path):
    """计算文件 SHA256；传入产品文件路径，返回小写十六进制摘要。"""
    digest = hashlib.sha256()
    with path.open('rb') as binary:
        for block in iter(lambda: binary.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def load_cooperative_helpers():
    """加载已有夹具 helper，返回模块以复用项目、归档和规则回读 API。"""
    sys.path.insert(1, str(TARGET_SCRIPT.parent.parent))
    import cooperative_api_capture as helpers  # noqa: PLC0415
    return helpers


def product_receipt(return_code, stdout):
    """解析产品 JSON 回执；解析失败时保留原始文本而不覆盖产品错误。"""
    raw = stdout.decode('utf-8-sig', errors='replace')
    try:
        envelope = json.loads(raw)
        return envelope.get('data'), envelope
    except (TypeError, ValueError):
        return None, {'rawStdout': raw, 'returnCode': return_code}


def progress_frames(stderr):
    """拆分 stderr JSONL，返回启动帧、采集进度帧和全部帧。"""
    text = stderr.decode('utf-8-sig', errors='replace')
    frames = [json.loads(line) for line in text.splitlines() if line.strip()]
    startup = [frame for frame in frames
               if isinstance(frame, dict) and 'stage' in frame and 'progressSequence' not in frame]
    capture = [frame for frame in frames
               if isinstance(frame, dict) and frame.get('type') == 'api-capture-progress']
    assert frames and len(startup) + len(capture) == len(frames), frames
    assert capture, 'capture-progress did not emit any api-capture-progress frame'
    return startup, capture, frames


def check_progress(project, captured, stderr):
    """核对进度序列、最终检查点、交付计数和归档末端坐标。"""
    startup, capture, frames = progress_frames(stderr)
    sequences = [int(frame['progressSequence']) for frame in capture]
    assert sequences == list(range(1, len(sequences) + 1)), sequences

    # 所有采集帧必须绑定同一项目、样本和修订，不能把其它运行的帧混入窗口。
    project_id = json.loads((project / 'project.ksaproj').read_bytes())['projectId']
    assert all(frame['projectId'] == project_id and frame['sampleId'] == captured['sampleId'] and
               frame['revisionId'] == captured['revisionId'] for frame in capture), capture
    checkpoints = [frame for frame in capture if frame['kind'] == 'api-checkpoint']
    assert checkpoints, capture

    # 检查点使用原始段号、原包序号和来源序号，三者都不能倒退。
    previous = (0, 0, 0)
    for frame in checkpoints:
        payload = frame['payload']
        coordinate = (int(payload['segmentOrdinal']), int(payload['rawSequence']),
                      int(payload['sourceSequence']))
        assert coordinate >= previous, (previous, coordinate)
        previous = coordinate
    final = checkpoints[-1]['payload']
    archive = captured['archive']
    assert final['finalSegment'] is True
    assert int(final['segmentOrdinal']) == int(archive['committedSegments'])
    assert int(final['sourceSequence']) == int(archive['sourceRows'])

    # enqueuedFrames 同时包含 startup-progress 和 capture-progress，历史 bug 不得重现。
    delivery = captured['captureProgress']
    assert delivery['requested'] is True and delivery['started'] is True
    assert delivery['outputDrained'] is True and delivery['droppedFrames'] == '0'
    assert delivery['enqueuedFrames'] == str(len(startup) + len(capture)), delivery
    assert delivery['lastProgressSequence'] == str(sequences[-1]), delivery
    return startup, capture, final, previous


def check_behavior_window(captured, capture, replay_rows, expected_rule):
    """核对有界行为窗口、截断语义、原坐标及中英文释义。"""
    rules = captured['rules']
    assert rules['presetSet'] == BEHAVIOR_PRESET_SET, rules
    # The final receipt projects evaluation success as state=ready; only
    # api-capture-progress frames retain the internal failed boolean.
    assert rules['state'] == 'ready' and not rules.get('configError'), rules
    behavior_matches = int(rules['behaviorMatches'])
    recent = rules['recentBehaviors']
    assert behavior_matches > 0 and 0 < len(recent) <= 32, rules
    assert rules['behaviorWindowTruncated'] is (behavior_matches > len(recent)), rules

    # 从最终规则窗口和所有回放行建立原始坐标索引，拒绝用 UI 行号替代归档坐标。
    coordinates = {(int(row['rawSegment']), int(row['rawSequence'])): row for row in replay_rows}
    for entry in recent:
        coordinate = (int(entry['segmentOrdinal']), int(entry['rawSequence']))
        row = coordinates.get(coordinate)
        assert row is not None and row['sourceSequence'] == entry['sourceSequence'], entry
        assert entry['api'] == 'WriteProcessMemory' and entry['ruleId'] == BEHAVIOR_RULE_ID, entry
        behavior = entry['behavior']
        assert behavior == {
            'ruleId': BEHAVIOR_RULE_ID,
            'evidence': expected_rule['evidence'],
            'summary': expected_rule['summary'],
            'summaryZh': expected_rule['summaryZh'],
        }, entry

    # 每个最终检查点的行为窗口都必须遵守同一个 32 条上限和截断公式。
    for frame in capture:
        if frame['kind'] != 'api-checkpoint':
            continue
        snapshot = frame['payload']['rules']
        count = int(snapshot['behaviorMatches'])
        window = snapshot['recentBehaviors']
        assert snapshot['failed'] is False and not snapshot['configError'], snapshot
        assert len(window) <= 32 and snapshot['behaviorWindowTruncated'] is (count > len(window)), snapshot


def check_classification_preservation(project, captured, helpers, replay_rows):
    """确认拒绝调用有行为释义，而成功普通调用仍保持原分类且无行为字段。"""
    sample = captured['sampleId']
    denied = [row for row in replay_rows if row['reportedStatusCode'] == ERROR_ACCESS_DENIED]
    successful = [row for row in replay_rows
                  if row['api'] == 'WriteProcessMemory' and row['reportedStatusCode'] == 0]
    assert denied and successful, (denied, successful)

    # 复用已有行为回放 helper，核对拒绝返回、成功返回和最终最新命中坐标。
    helpers.verify_behavior(project, captured,
                            (int(denied[0]['rawSegment']), int(denied[0]['rawSequence']),
                             {'sourceSequence': denied[0]['sourceSequence']}, bytes.fromhex(denied[0]['packet'])),
                            (int(successful[0]['rawSegment']), int(successful[0]['rawSequence']),
                             {'sourceSequence': successful[0]['sourceSequence']}, bytes.fromhex(successful[0]['packet'])))

    # 所有成功写入的规则回放都不得凭邻近拒绝调用附加行为解释。
    offset = 0
    seen_success = 0
    while True:
        report = helpers.invoke('analyze', 'replay-api-rules', '--project', project, '--sample', sample,
                                '--profile', 'by-category', '--offset', str(offset), '--limit', '100')
        for match in report['matches']:
            if match['raw']['sequence'] in {row['rawSequence'] for row in successful}:
                assert match['api'] == 'WriteProcessMemory' and 'behavior' not in match, match
                seen_success += 1
        if report.get('nextOffset') is None:
            break
        offset = int(report['nextOffset'])
    assert seen_success == len(successful), (seen_success, len(successful))


def main():
    """执行一次正式显式附加采集，保留证据并在结束时删除项目和目标状态。"""
    helpers = load_cooperative_helpers()
    EVIDENCE.mkdir(exist_ok=True)
    if PROJECT.exists():
        raise RuntimeError(f'task evidence project already exists; refusing reuse: {PROJECT}')

    result = 'FAIL'
    failure = None
    target = controller = None
    captured = None
    target_hash = None
    try:
        # 采集前立即冻结并核验授权 CLI，哈希不匹配时不启动目标、不发采集请求。
        actual_hash = sha256(CLI)
        assert actual_hash == EXPECTED_CLI_SHA256, (actual_hash, EXPECTED_CLI_SHA256)
        helpers.create_project(PROJECT, 'Explicit attachment behavior history')

        environment = os.environ.copy()
        environment.pop(helpers.COOPERATIVE_ENV, None)
        target = subprocess.Popen([sys.executable, '-B', str(TARGET_SCRIPT), '--attachment-target'],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=environment, cwd=REPO)
        identity_line = target.stdout.readline()
        assert identity_line, 'attachment target did not publish identity'
        identity = json.loads(identity_line.decode('utf-8'))
        assert identity['pid'] == target.pid and identity['agentLoaded'] is False, identity

        # 这是本任务唯一一次产品采集请求；只使用正式 attach 和 capture-progress 选项。
        command = [str(CLI), 'analyze', 'api-evidence', 'attach', '--project', str(PROJECT),
                   '--title', 'Explicit attachment behavior history', '--pid', str(target.pid),
                   '--creation-filetime', str(identity['creation']), '--confirm', '--duration-ms', '2000',
                   '--startup-progress', '1', '--capture-progress', '1', '--json']
        controller = subprocess.Popen(command, cwd=RELEASE, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=environment)
        stdout, stderr = controller.communicate(timeout=60)
        STDOUT_LOG.write_bytes(stdout)
        STDERR_LOG.write_bytes(stderr)
        captured, envelope = product_receipt(controller.returncode, stdout)
        assert captured is not None, envelope
        assert controller.returncode in (0, 6), envelope
        assert captured['captureMode'] == 'explicit-r3-attachment'
        assert captured['attachmentIdentityVerified'] is True and captured['agentReady'] is True
        assert captured['cleanupComplete'] is True and captured['targetExited'] is False
        assert captured['pid'] == target.pid and int(captured['creationFileTime']) == int(identity['creation'])

        # 产品先完成归档，再由既有 helper 验证所有原包、回放坐标和规则输入。
        startup, capture, final, watermarks = check_progress(PROJECT, captured, stderr)
        emitted = None
        target.stdin.close()
        tail, target_error = target.communicate(timeout=15)
        assert target.returncode == 0, (target.returncode, tail, target_error)
        emitted = json.loads(tail.decode('utf-8'))
        assert emitted['agentLoaded'] is True and emitted['calls'] >= 2, emitted
        replay = helpers.invoke('analyze', 'api-evidence', 'replay', '--project', PROJECT,
                                '--sample', captured['sampleId'], '--packet', '1', '--limit', '100')
        replay_rows = replay['rows']
        expected_rule = helpers.behavior_rule(BEHAVIOR_RULE_ID)
        check_behavior_window(captured, capture, replay_rows, expected_rule)
        helpers.verify_archive(PROJECT, identity, captured, emitted['calls'], require_multiple=True)
        check_classification_preservation(PROJECT, captured, helpers, replay_rows)
        result = 'PASS'
    except BaseException as error:
        failure = {'type': type(error).__name__, 'message': str(error),
                   'captureIssued': controller is not None, 'controllerExitCode':
                   controller.returncode if controller is not None else None,
                   'productResponse': captured}
        raise
    finally:
        # 目标和控制器只允许由本任务创建；失败时也要先正常收尾，再清理项目目录。
        if controller is not None and controller.poll() is None:
            controller.kill()
            with suppress(subprocess.TimeoutExpired):
                controller.wait(timeout=5)
        if target is not None and target.poll() is None:
            with suppress(Exception):
                target.stdin.close()
            with suppress(subprocess.TimeoutExpired):
                target.wait(timeout=10)
        if target is not None and target_hash is None:
            target_hash = None
        if PROJECT.exists():
            shutil.rmtree(PROJECT)
        RECEIPT.write_text(json.dumps({
            'result': result,
            'cliSha256': sha256(CLI),
            'targetSha256': target_hash,
            'evidenceDirectory': str(EVIDENCE),
            'failure': failure,
        }, indent=2), encoding='utf-8')
        RUN_LOG.write_text(f'RESULT={result}\n', encoding='utf-8')
    print(f'RESULT={result} EVIDENCE={EVIDENCE}')


if __name__ == '__main__':
    main()
