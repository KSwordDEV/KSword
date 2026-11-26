"""用固定的内存合成夹具验收正式 CLI 的 KSword 回调档回读。"""

import hashlib
import json
import struct
import subprocess
import sys

from referencing import Registry, Resource
from jsonschema import Draft202012Validator

from live_etw import decode_raw
from smoke import EXE, ROOT, SESSION, invoke, line, read, request


FIXTURE = ROOT / 'tools/action_analyze_validation/project/x64/Release/callback-project-fixture'
SEGMENT = 'raw/00000000000000000001.ksaseg'
BATCH_PLAN_FIELDS = ('sourceEpoch', 'afterSequence', 'maxRecords')
BATCH_END_FIELDS = ('state', 'nextSequence', 'latestSequence', 'returnedCount', 'lostBeforeFirst', 'droppedCount')


def create_fixture():
    """只在预定空目录生成合成档，保留给正式桌面端核对同一项目。"""
    assert not FIXTURE.exists() and not FIXTURE.is_symlink(), FIXTURE
    native = EXE.with_name('ActionAnalyzeProjectValidation.exe')
    outcome = subprocess.run([native, '--callback', FIXTURE], cwd=ROOT, capture_output=True, timeout=30)
    print(f'NATIVE_CALLBACK_EXIT={outcome.returncode}', flush=True)
    print(outcome.stdout.decode('utf-8', errors='replace'), end='', flush=True)
    assert outcome.returncode == 0 and b'PROJECT_CALLBACK_VALIDATION=PASS' in outcome.stdout, outcome.stderr


def verify():
    """只读取已知标题的三个合成采样，并用实际文件校验 CLI 回执。"""
    manifest = FIXTURE / 'project.ksaproj'
    project = json.loads(manifest.read_bytes())
    assert project['title'] == 'Synthetic callback archive', project
    samples = {doc['title']: doc for path in (FIXTURE / 'samples').glob('*/sample.json')
               if (doc := json.loads(path.read_bytes()))['projectId'] == project['projectId']}
    assert set(samples) == {'Synthetic thread creation', 'Complete empty callback batch', 'Conflicting callback counts'}

    # 同一离线进程验证成功、完整空、坏计数、错误续页和不存在的段。
    commands = [request('open', 'project.open', {'path': str(manifest), 'access': 'read-only'})]

    def inspect(name, sample, **extra):
        coordinates = {'projectId': project['projectId'], 'sampleId': samples[sample]['sampleId'],
                       'stream': 'raw', 'ordinal': '1', 'view': 'graph'}
        commands.append(request(name, 'archive.inspect', coordinates | extra))

    positive = 'Synthetic thread creation'
    empty = 'Complete empty callback batch'
    paths = {title: FIXTURE / 'samples' / sample['sampleId'] / SEGMENT for title, sample in samples.items()}
    data = {title: path.read_bytes() for title, path in paths.items()}
    sha = hashlib.sha256(data[positive]).hexdigest()
    batches = {}
    for title in (positive, empty):
        records, digest = decode_raw(paths[title])
        (plan, plan_bytes), *rows, (end, end_bytes) = records
        assert digest == hashlib.sha256(data[title]).hexdigest() and not plan_bytes and not end_bytes, records
        assert end['observationCount'] == str(len(rows)), end
        batch = {key: plan[key] for key in BATCH_PLAN_FIELDS} | {key: end[key] for key in BATCH_END_FIELDS}
        batches[title] = batch
        if title == positive:
            (_, stored_event), = rows
            assert (batch['returnedCount'], batch['lostBeforeFirst'], batch['droppedCount']) == ('3', '4', '17'), batch
        else:
            assert not rows and batch['nextSequence'] == batch['latestSequence'] == batch['afterSequence'], batch
            assert (batch['returnedCount'], batch['lostBeforeFirst'], batch['droppedCount']) == ('0', '0', None), batch
    inspect('positive', positive, limit=1)
    inspect('end-of-page', positive, afterSequence='2', expectedSha256=sha)
    inspect('empty', empty)
    inspect('conflict', 'Conflicting callback counts')
    inspect('wrong-digest', positive, expectedSha256='0' * 64)
    inspect('missing-ordinal', positive, ordinal='2')
    commands.append(request('shutdown', 'controller.shutdown'))

    stdout, _ = invoke(SESSION, b''.join(map(line, commands)))
    frames = [json.loads(raw) for raw in stdout.splitlines()]
    assert frames[0]['capabilities']['backend'] == 'offline', frames[0]
    responses = {frame['requestId']: frame for frame in frames if frame['type'] == 'response'}
    assert list(responses) == [cmd['requestId'] for cmd in commands], responses
    assert responses['open']['result']['access'] == 'read-only', responses['open']

    # 固定 JSON Schema 与真实输出一起检查，避免 CLI 与文档协议分叉。
    names = ('value.schema.json', 'request.schema.json', 'request-message.schema.json',
             'archive-inspect-method.schema.json')
    schemas = [read(name) for name in names]
    registry = Registry().with_resources((doc['$id'], Resource.from_contents(doc)) for doc in schemas)
    validator = Draft202012Validator({'$ref': schemas[-1]['$id'] + '#/$defs/graphResult'}, registry=registry)
    for key, title, observations in (('positive', positive, '1'), ('end-of-page', positive, '1'), ('empty', empty, '0')):
        reply = responses[key]
        assert reply['error'] is None, reply
        graph = reply['result']
        validator.validate(graph)
        assert graph['sampleId'] == samples[title]['sampleId'], graph
        assert graph['archiveSource'] == 'ksword-callback-batch' and graph['sourceCoverage'] == 'unknown', graph
        assert graph['finalSegment'] is None and graph['nextAfterSequence'] is None, graph
        assert graph['nodes'] == graph['relations'] == [], graph
        assert graph['observationCount'] == observations, graph
        assert graph['callbackBatch'] == batches[title], graph
        assert graph['prefix']['sha256'] == hashlib.sha256(data[title]).hexdigest(), graph
        assert graph['prefix']['endOffset'] == str(len(data[title])), graph
        if key != 'positive':
            assert graph['observations'] == [], graph

    graph = responses['positive']['result']
    row, = graph['observations']
    assert row['sourceSequence'] == '107' and row['raw']['recordSequence'] == '2', row
    assert graph['tree'] == {'contextObservations': ['2'], 'unresolvedCandidates': []}, graph
    assert all(row[field] is None for field in ('actorInstance', 'targetInstance', 'threadInstance', 'execution', 'finding')), row
    offset = int(row['raw']['recordOffset'])
    packet = int(row['raw']['inlineOffset'])
    size = int(row['raw']['inlineBytes'])
    assert struct.unpack_from('<Q', data[positive], offset + 16)[0] == 2, row
    assert data[positive][packet:packet + size] == stored_event and len(stored_event) == size and 0 < offset < packet, row
    # Callback Monitor ABI: the signed 64-bit notification time follows version, size and sequence.
    timestamp = row['callbackHints']['notificationUtc100ns']
    assert row['callbackHints'] == {'originPid': 4101, 'originTid': 4102, 'targetPid': 4201, 'targetTid': 4202,
                                    'notificationUtc100ns': '133000000000000123'}, row
    assert struct.pack('<q', int(timestamp)) == stored_event[16:24], row

    for key, expected in (('conflict', 'project-corrupt'), ('wrong-digest', 'stale-revision'),
                          ('missing-ordinal', 'project-data-not-found')):
        reply = responses[key]
        assert reply['result'] is None and reply['error']['errorId'] == expected, reply
    assert all(path.read_bytes() == data[title] for title, path in paths.items()), paths
    print(f'CLI_CALLBACK_ARCHIVE_GRAPH=PASS SAMPLE={graph["sampleId"]} EMPTY={samples[empty]["sampleId"]} '
          f'RAW=1#2 SOURCE=107 RECORD_OFFSET={offset} INLINE_OFFSET={packet} '
          f'INLINE_BYTES={size} NOTIFICATION_UTC100NS={timestamp} BATCH_PAGES=positive,continuation,empty '
          'ARCHIVE_UNCHANGED=True')


if __name__ == '__main__':
    assert sys.argv[1:] in ([], ['--create-fixture']), sys.argv[1:]
    if sys.argv[1:]:
        create_fixture()
    verify()
