"""用冻结的正式CLI对本次GUI保留项目只读回放一次；不启动目标或采集。"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api_rule_profile import behavior_rule


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', choices=('light', 'qt'), required=True)
    parser.add_argument('--cli-sha256', required=True)
    parser.add_argument('--offline-captured', action='store_true')
    parser.add_argument('--sample')
    parser.add_argument('--after', type=int, default=0)
    parser.add_argument('--output-name')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    directory = Path(__file__).resolve().parents[1] / 'desktop_behavior_history' / args.endpoint
    output_name = args.output_name or ('cli-replay-offline-correction' if args.offline_captured else 'cli-replay')
    if args.output_name:
        assert args.offline_captured and output_name.startswith('cli-replay-offline-')
        assert Path(output_name).name == output_name
    output = directory / output_name
    receipt = json.loads((directory / 'receipt.json').read_text(encoding='utf-8'))
    project = directory / 'archived-project'
    binary = root / 'Ksword5.1/x64/Release/KswordCLI.exe'
    assert receipt['binaries']['KswordCLI.exe'] == args.cli_sha256.lower()
    # 离线校正使用首次CLI进程退出时保存的stdout；此后Release可能已被整合者替换。
    if not args.offline_captured:
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.cli_sha256.lower()
    frozen = None if args.offline_captured else {
        path.relative_to(project).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in project.rglob('*') if path.is_file()}
    # 离线更正只读取已完成的真实回放输出；不再启动 CLI，也不触碰项目。
    source_run = directory / 'cli-replay-setup-fail-02' if args.offline_captured else output
    prior_receipt = json.loads((source_run / 'receipt.json').read_text(encoding='utf-8')) if args.offline_captured else None
    sample = receipt.get('sample') or args.sample
    assert sample and (project / 'samples' / sample).is_dir(), ('样本不存在', sample)
    if args.offline_captured:
        assert prior_receipt['status'] == 'FAIL' and prior_receipt['exitCode'] == 0
        assert prior_receipt['projectUnchanged'] is True and (source_run / 'stdout.json').is_file()
    output.mkdir(exist_ok=False)  # 本轮一次原生回放或一次离线更正各自使用唯一固定目录。
    result = {'status': 'FAIL', 'sample': sample, 'cliSha256': args.cli_sha256.lower(), 'after': args.after}
    try:
        if args.offline_captured:
            stdout = (source_run / 'stdout.json').read_bytes()
            result.update(exitCode=prior_receipt['exitCode'], originalSetupFailurePreserved=True,
                          capturedOutputSha256=hashlib.sha256(stdout).hexdigest())
        else:
            command = [str(binary), 'analyze', 'api-evidence', 'replay', '--project', str(project),
                       '--sample', sample, '--packet', '1', '--after', str(args.after), '--limit', '100', '--json']
            process = subprocess.run(command, cwd=binary.parent, capture_output=True, timeout=45,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            (output / 'stdout.json').write_bytes(process.stdout)
            (output / 'stderr.txt').write_bytes(process.stderr)
            result['exitCode'] = process.returncode
            assert process.returncode == 0, process.stderr.decode('utf-8', errors='replace')
            stdout = process.stdout
        response = json.loads(stdout)['data']
        assert response['status'] == 'readback-verified' and response['sampleId'] == sample, response
        assert response['finalSegment'], response
        profile = response['ruleProfile']
        profile_path = binary.parent / 'profiles/action_analyze_api_rules.json'
        deployed_profile = profile_path.read_bytes()
        profile_digest = hashlib.sha256(deployed_profile).hexdigest()
        assert profile['configError'] is None and len(profile['sourceSha256']) == 64, profile
        assert profile['presetSet'] == 'ksword.api.behavior-presets.v3', profile
        expected = behavior_rule('ksword.behavior.memory-write-access-denied-return.v1')
        behaviors = [row for row in response['rows'] if row['rule']['behavior'] is not None]
        assert behaviors
        for row in behaviors:
            behavior = row['rule']['behavior']
            assert row['rule']['status'] == 'evaluated'
            assert (behavior['ruleId'], behavior['evidence'], behavior['summary'], behavior['summaryZh']) == (
                expected['ruleId'], 'reported-api-return', expected['summary'], expected['summaryZh']), row
            assert row['api'] == 'WriteProcessMemory' and row['reportedStatusCode'] == 5, row
        if args.endpoint == 'light':
            stopped = json.loads((directory / 'stopped.json').read_text(encoding='utf-8'))['history']
            entries = stopped['entries']
            assert len(behaviors) == stopped['total']
        else:
            entries = [{'coordinate': [int(row['rawSegment']), int(row['rawSequence']),
                                        int(row['sourceSequence'])]} for row in behaviors]
        by_coordinate = {(int(row['rawSegment']), int(row['rawSequence']), int(row['sourceSequence'])): row
                         for row in behaviors}
        for entry in entries:
            assert tuple(entry['coordinate']) in by_coordinate, entry
        result.update(status='PASS', rows=len(response['rows']), behaviors=len(behaviors),
                      guiHistoryCoordinates=len(entries), ruleProfile=profile,
                      currentReleaseProfileSha256=profile_digest,
                      currentReleaseProfileMatchesReplay=(profile['sourceSha256'] == profile_digest),
                      recordedProfileComparison='not exposed by frozen CLI/checkpoint')
        if args.offline_captured:
            result['projectUnchanged'] = prior_receipt['projectUnchanged']
    finally:
        if args.offline_captured:
            result['projectUnchanged'] = bool(prior_receipt and prior_receipt.get('projectUnchanged'))
        else:
            after = {path.relative_to(project).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in project.rglob('*') if path.is_file()}
            result['projectUnchanged'] = after == frozen
            if after != frozen:
                result['status'] = 'FAIL'
        (output / 'receipt.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
