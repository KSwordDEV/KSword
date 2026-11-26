"""第 11 项规则内容身份：正式 CLI 三端链路的固定夹具验收。

只使用固定目录与既有 API／JSONL 夹具；不编译产品、不复制运行时。
- 目录摘要核对 `Ksword5.1/x64/Release/profiles/action_analyze_api_rules.json` 原始字节。
- 既有被动 JSONL 跟随夹具完成一次新采样，回放当前摘要必须等于采集摘要。
- 只改 summary 保持 presetSet 不变后目录／回放摘要变化、recorded 保持原值、matches=false，还原后 true。
- 关闭 JSONL 导入样（旧 API 档）没有记录摘要，recorded／matches 均为 null。
- 固定旧 callback 档不是 API 规则档，不得当作规则身份证据使用。
- 坏规则文件让目录与回放失败关闭，原包仍可读；发布配置在 finally 恢复并核对原始摘要。
"""

import hashlib
import json
from contextlib import contextmanager
import subprocess
import sys

from api_evidence import archive_line, cli as api_cli, packet, read_graph
from live_etw import decode_raw
from passive_api_session import CREATION, run as run_passive_fixture
from project_v1 import owned_project_path
from smoke import EXE, ROOT, TIMEOUT, require

PROFILE = EXE.parent / 'profiles/action_analyze_api_rules.json'
CALLBACK_FIXTURE = ROOT / 'tools/action_analyze_validation/project/x64/Release/callback-project-fixture'
IMPORT_SOURCE = 'rule-identity-import-events.jsonl'  # 固定测试根内的自有输入文件名。
PRESET_SET = 'ksword.api.behavior-presets.v1'


def digest(payload):
    """摘要只取文件原始字节，不做任何 JSON 重序列化。"""
    return hashlib.sha256(payload).hexdigest()


def run_cli(args):
    """执行正式 CLI 并返回（退出码，data）；失败用例也解析 JSON 回执。"""
    result = subprocess.run([EXE, *args, '--json'], capture_output=True, timeout=TIMEOUT)
    return result.returncode, json.loads(result.stdout)['data']


@contextmanager
def profile_bytes(payload, label):
    """临时替换发布规则文件字节；恢复后核对原始字节与摘要。"""
    PROFILE.write_bytes(payload)
    try:
        yield
    finally:
        PROFILE.write_bytes(ORIGINAL)
        require(digest(PROFILE.read_bytes()), ORIGINAL_HASH, f'{label}: release profile finally restored')


def catalog_identity(expected_hash, expected_preset, label):
    """目录摘要必须等于 Release/profiles 实际字节的 SHA-256。"""
    code, data = run_cli(('analyze', 'api-rule-catalog'))
    require(code, 0, f'{label}: catalog native exit')
    require(data['sourceSha256'], expected_hash, f'{label}: catalog digest equals profile bytes')
    require(data['presetSet'], expected_preset, f'{label}: catalog preset set')
    return data


def plan_identity(segments):
    """从存储段首条冻结计划独立读回采集时的规则摘要。"""
    hashes = set()
    sequence = 1  # 后续段的 Stored 序号接续前段，不能按每段重新从 1 解码。
    for path in segments:
        records, _ = decode_raw(path, sequence)
        sequence += len(records)
        plan = records[0][0]
        require(plan['rulePresetSet'], PRESET_SET, 'capture plan preset set')
        hashes.add(plan['ruleSourceSha256'])
    require(len(hashes), 1, 'every segment reuses the same frozen plan digest')
    return hashes.pop()


def replay_identity(project, sample, label):
    """回放当前摘要、归档记录摘要及匹配值的三元组。"""
    code, data = run_cli(('analyze', 'replay-api-rules', '--project', str(project), '--sample', sample))
    require(code, 0, f'{label}: replay-api-rules native exit')
    return data


def import_fixture(project):
    """用既有 API 归档行夹具创建无检查点的关闭 JSONL 导入样。"""
    source = project.parent / IMPORT_SOURCE
    require(source.exists(), False, 'import source path is free')
    wire = packet('KernelBase', 'WriteProcessMemory', 8, 0x52545631, status=299)
    with source.open('xb') as stream:
        stream.write(archive_line(1, wire, processCreation100ns=CREATION))
    try:
        receipt = api_cli('import', '--archive', source, '--project', project, '--title', 'Rule identity legacy import')
        require(receipt['status'], 'readback-verified', 'import status')
        return receipt['sampleId']
    finally:
        source.unlink()


def summary_probe_bytes(profile_text):
    """只替换一条 ASCII summary；presetSet 与其余字节保持不变。"""
    raw = PROFILE.read_bytes()
    for definition in profile_text['behaviorRules']:
        text = definition['summary']
        needle = text.encode('ascii')
        if text.isascii() and raw.count(needle) == 1:
            break
    else:
        raise AssertionError('no uniquely replaceable ASCII summary in the release profile')
    modified = raw.replace(needle, (text + ' identity-probe').encode('ascii'))
    require(json.loads(modified)['presetSet'], profile_text['presetSet'], 'probe keeps presetSet unchanged')
    require(digest(modified) != ORIGINAL_HASH, True, 'probe changes the raw byte digest')
    return modified


def callback_negative():
    """固定旧 callback 档不适用：回放必须拒绝，且不得产生任何规则身份结论。"""
    if not CALLBACK_FIXTURE.is_dir():
        print('RULE_IDENTITY_CALLBACK_OUT_OF_SCOPE=SKIP fixture absent; scope recorded as not applicable', flush=True)
        return
    manifest = json.loads((CALLBACK_FIXTURE / 'project.ksaproj').read_bytes())
    sample = next(json.loads(path.read_bytes())['sampleId'] for path in (CALLBACK_FIXTURE / 'samples').glob('*/sample.json'))
    code, data = run_cli(('analyze', 'replay-api-rules', '--project', str(CALLBACK_FIXTURE), '--sample', sample))
    require(code != 0, True, 'callback archive is not an API rule archive')
    require(data['status'] in ('archive-unsupported', 'archive-unavailable', 'archive-invalid'),
            True, 'callback archive rejected without rule identity claims')
    require(data.get('matchesRecordedRules'), None, 'callback archive makes no match claim')
    require('matches' not in data, True, 'callback archive yields no rule matches')
    print(f'RULE_IDENTITY_CALLBACK_OUT_OF_SCOPE=PASS SAMPLE={sample}', flush=True)


def main():
    require(sys.platform, 'win32', 'Windows-only CLI fixture')
    require(EXE.is_file() and PROFILE.is_file(), True, 'Release CLI and deployed rules profile exist')

    profile_text = json.loads(ORIGINAL)  # 只读解析，不重写发布文件。
    preset = profile_text['presetSet']
    require(preset, PRESET_SET, 'release profile preset set')

    with owned_project_path() as project:
        # 1. 目录摘要等于 Release/profiles 实际字节 hash。
        catalog_identity(ORIGINAL_HASH, preset, 'baseline')

        # 2. 既有被动 JSONL 夹具完成新采样；每段冻结计划携带采集摘要。
        sample, segments, _markers, _packets = run_passive_fixture(project, behavior=True)
        captured = plan_identity(segments)
        require(captured, ORIGINAL_HASH, 'capture plan digest equals the parsed release bytes')

        # 3. 回放当前：sourceSha256 == 采集摘要且 matches=true。
        current = replay_identity(project, sample, 'fresh capture')
        require(current['sourceSha256'], ORIGINAL_HASH, 'replay digest equals capture digest')
        require(current['recordedSourceSha256'], ORIGINAL_HASH, 'recorded digest equals capture digest')
        require(current['matchesRecordedRules'], True, 'fresh capture matches the current rules')
        require(current['archiveSource'], 'jsonl-follow', 'passive fixture archive source')
        require(current['presetSet'], preset, 'replay preset set')
        print(f'RULE_FRESH source={current["sourceSha256"]} recorded={current["recordedSourceSha256"]} '
              f'matches={current["matchesRecordedRules"]}', flush=True)

        # 4. 旧 API 档（关闭 JSONL 导入）无摘要：recorded／matches 均为 null。
        legacy_sample = import_fixture(project)
        legacy = replay_identity(project, legacy_sample, 'legacy import')
        require(legacy['archiveKind'], 'closed-api-import', 'legacy archive kind')
        require(legacy['sourceSha256'], ORIGINAL_HASH, 'legacy replay still shows current digest')
        require(legacy['recordedSourceSha256'], None, 'legacy archive records no digest')
        require(legacy['matchesRecordedRules'], None, 'legacy archive makes no match claim')
        print(f'RULE_LEGACY source={legacy["sourceSha256"]} recorded={legacy["recordedSourceSha256"]} '
              f'matches={legacy["matchesRecordedRules"]}', flush=True)

        # 5. 固定旧 callback 档不适用，不得误用为规则身份证据。
        callback_negative()

        # 6. 只改 summary：目录／回放摘要变化，recorded 仍原值，matches=false；还原后 true。
        modified = summary_probe_bytes(profile_text)
        with profile_bytes(modified, 'summary probe'):
            changed = catalog_identity(digest(modified), preset, 'probe')
            mismatched = replay_identity(project, sample, 'summary probe')
            require(mismatched['sourceSha256'], changed['sourceSha256'], 'replay follows the changed bytes')
            require(mismatched['recordedSourceSha256'], ORIGINAL_HASH, 'recorded digest stays frozen')
            require(mismatched['matchesRecordedRules'], False, 'changed content breaks the recorded match')
            print(f'RULE_PROBE source={mismatched["sourceSha256"]} recorded={mismatched["recordedSourceSha256"]} '
                  f'matches={mismatched["matchesRecordedRules"]}', flush=True)
        restored = replay_identity(project, sample, 'restored')
        require(restored['sourceSha256'], ORIGINAL_HASH, 'restore returns the baseline digest')
        require(restored['matchesRecordedRules'], True, 'restore returns a matching archive')
        print(f'RULE_RESTORED source={restored["sourceSha256"]} recorded={restored["recordedSourceSha256"]} '
              f'matches={restored["matchesRecordedRules"]}', flush=True)

        # 7. 坏规则失败关闭；原包仍可读；配置在 finally 恢复。
        with profile_bytes(b'{"presetSet": "ksword.api.behavior-presets.v1",', 'broken rules'):
            code, failed = run_cli(('analyze', 'api-rule-catalog'))
            require(code, 4, 'broken rules fail the catalog')
            require(failed['status'], 'rule-profile-unavailable', 'catalog reports the failure')
            require(bool(failed['configError']), True, 'catalog carries a config diagnostic')
            code, blocked = run_cli(('analyze', 'replay-api-rules', '--project', str(project), '--sample', sample))
            require(code, 4, 'broken rules block rule replay')
            require(blocked['status'], 'rule-profile-unavailable', 'replay reports the failure')
            print(f'RULE_BROKEN catalog={code} status={failed["status"]} replay={blocked["status"]}', flush=True)
            # 分段跟随档没有单段结束尾记，api-evidence replay 只适用于已关闭导入；
            # 用同一项目图入口证明跟随档原包仍可逐段核验，另用关闭导入证明单段回读。
            project_id = json.loads((project / 'project.ksaproj').read_bytes())['projectId']
            graph = read_graph(project, project_id, sample, {'limit': 1})
            require(graph[0]['error'], None, 'follow raw graph stays readable while rules are unavailable')
            require(len(graph[0]['result']['observations']) > 0, True, 'follow raw observations still publish')
            raw = run_cli(('analyze', 'api-evidence', 'replay', '--project', str(project), '--sample', legacy_sample))
            print(f'BROKEN_RULES_LEGACY_RAW={raw[1]["status"]}', flush=True)
            require(raw[0], 0, 'closed import packets stay readable while rules are unavailable')
            require(raw[1]['status'], 'readback-verified', 'closed import readback stays verified')
        after = catalog_identity(ORIGINAL_HASH, preset, 'restored after failure')

        print(f'CLI_RULE_PROFILE_IDENTITY=PASS CLI_SHA256={hashlib.sha256(EXE.read_bytes()).hexdigest()} '
              f'PROFILE_SHA256={ORIGINAL_HASH} SAMPLE={sample} LEGACY={legacy_sample}', flush=True)


if not PROFILE.is_file():
    raise SystemExit(f'missing release rules profile: {PROFILE}')
ORIGINAL = PROFILE.read_bytes()  # 发布配置的原始字节；全部探针结束后必须逐字节恢复。
ORIGINAL_HASH = digest(ORIGINAL)

if __name__ == '__main__':
    main()
