"""用合成 API Monitor 归档验证正式 ActionAnalyze 导入和回放。"""

import base64
import hashlib
import json
import struct
import subprocess
import time

from project_v1 import owned_project_path
from smoke import EXE, SESSION, TIMEOUT, contract, line, request


def packet(module, api, category, marker=0, result_kind=0, status=0, returned=0):
    """构造现行 1000 字节包的数据夹具。该函数不执行包内描述的操作。"""
    wire = bytearray(1000)  # 从双位数共用 Windows 包布局写入字段。
    struct.pack_into('<IIIIQIi', wire, 0, 1000, 0x20261003, 42, 43, 134400565183024188, category, status)
    for offset, text in ((32, module), (96, api)):
        encoded = text.encode('utf-16-le')
        wire[offset:offset + len(encoded)] = encoded
    struct.pack_into('<I', wire, 864, result_kind)
    struct.pack_into('<I', wire, 884, marker)
    struct.pack_into('<Q', wire, 896, 1234)
    struct.pack_into('<Q', wire, 920, returned)
    return bytes(wire)


def archive_line(index, wire, **overrides):
    """生成既有 events.jsonl 布局。故意保留错误的文本提示以校验原包才是分类入口。"""
    row = {'sequence': str(index), 'readerPid': 42, 'api': 'ignored',
           'packetBase64': base64.b64encode(wire).decode('ascii')}
    return (json.dumps(row | overrides) + '\n').encode('utf-8')


def cli(*args, code=0):
    """执行正式工具并读取 JSON 回执。"""
    result = subprocess.run([EXE, 'analyze', 'api-evidence', *args, '--json'], capture_output=True, timeout=TIMEOUT)
    assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
    return json.loads(result.stdout)['data']


def import_fixture(project, title):
    """为 CLI 和桌面工具创建同一份五类线索采样，返回清单、段路径和正式回放结果。"""
    creation = subprocess.run([EXE, 'analyze', 'session'], input=f'project create "{project}" Fixture\nquit\n'.encode(),
                              capture_output=True, timeout=TIMEOUT, check=True)
    manifest = project / 'project.ksaproj'  # 用户实际打开的项目入口。
    assert manifest.is_file(), creation.stdout

    # 原始包仅为合成记录。非匹配模块和不一致分类用于核对原包判定。
    cases = (
        ('', 'CreateRemoteThreadEx', packet('Other', 'CreateRemoteThreadEx', 9), {}),
        ('memory-write', 'WriteProcessMemory', packet('KernelBase', 'WriteProcessMemory', 8, 0x52545631, status=299),
         {'processCreation100ns': '134400565183024180'}),
        ('apc-queue', 'NtQueueApcThread', packet('NTDLL.DLL', 'NtQueueApcThread', 9, result_kind=1), {}),
        ('', 'NtWriteVirtualMemory', packet('ntdll', 'NtWriteVirtualMemory', 9), {}),
        ('thread-create', 'CreateRemoteThreadEx', packet('Kernel32.dll', 'CreateRemoteThreadEx', 9, 0x52545631, returned=20), {}),
        ('thread-context', 'SetThreadContext', packet('KernelBase', 'SetThreadContext', 9), {}),
        ('section-map', 'NtMapViewOfSection', packet('ntdll', 'NtMapViewOfSection', 8), {}),
    )
    source = project.parent / 'events.jsonl'  # 自有测试目录中的原始输入。
    original = b''.join(archive_line(i, wire, **extra) for i, (_, _, wire, extra) in enumerate(cases, 1))
    with source.open('xb') as output:
        output.write(original)
    receipt = cli('import', '--archive', source, '--project', project, '--title', title)
    assert (receipt['status'], receipt['sourceRows'], receipt['clueRows'], receipt['coverage']) == (
        'readback-verified', '7', '5', 'unknown')
    assert source.read_bytes() == original

    # 桌面校验按同一个采样 UUID 和实际 CLI 回读行逐条比对。
    sample = receipt['sampleId']
    rows = cli('replay', '--project', project, '--sample', sample, '--packet', '1')['rows']
    expected = [(str(i), family, name, wire.hex()) for i, (family, name, wire, _) in enumerate(cases, 1) if family]
    assert [(row['sourceSequence'], row['family'], row['api'], row['packet']) for row in rows] == expected, rows
    assert all(row[key] is None for row in rows for key in ('targetIdentity', 'completedWriteBytes', 'executed', 'attribution'))
    segment = project / 'samples' / sample / 'raw/00000000000000000001.ksaseg'
    with EXE.open('rb') as image:
        print(f"CLI_SHA256={hashlib.file_digest(image, 'sha256').hexdigest()}", flush=True)
    print(f"CLI_SOURCE_ROWS={receipt['sourceRows']} CLI_CLUES={len(rows)} SAMPLE={sample}", flush=True)
    return manifest, segment, rows


def read_graph(project, project_id, sample, *pages):
    """通过正式 JSONL 会话读图，按同一方法契约验证成功回执。"""
    envelope, methods = contract()
    method = 'archive.inspect'
    schema_base = 'https://ksword.invalid/schemas/action_analyze/'
    result_validator = envelope.evolve(schema={'$ref': schema_base + methods[method]['resultSchema']})
    params = {'projectId': project_id, 'sampleId': sample, 'stream': 'raw', 'ordinal': '1', 'view': 'graph'}
    commands = [request('open', 'project.open', {'path': str(project)})]
    commands.extend(request(f'graph-{index}', method, params | page) for index, page in enumerate(pages))
    commands.append(request('shutdown', 'controller.shutdown'))
    session = subprocess.run([EXE, *SESSION], input=b''.join(map(line, commands)), capture_output=True, timeout=TIMEOUT)
    assert session.returncode == 0 and not session.stderr, (session.returncode, session.stdout, session.stderr)
    replies = {record['requestId']: record for raw in session.stdout.splitlines()
               if (record := json.loads(raw))['type'] == 'response'}
    assert replies['open']['error'] is None, replies['open']
    assert replies['shutdown']['error'] is None, replies['shutdown']
    graph_replies = [replies[f'graph-{index}'] for index in range(len(pages))]
    for reply in graph_replies:
        if reply['error'] is None:
            result_validator.validate(reply['result'])
    return graph_replies


def check_graph(project, project_id, sample, segment, packets):
    """核对分类、分页和原包坐标，保留身份与执行证据的缺口。"""
    contents = segment.read_bytes()
    digest = hashlib.sha256(contents).hexdigest()
    first, following, stale = read_graph(project, project_id, sample, {'limit': 1},
                                       {'afterSequence': '1', 'expectedSha256': digest},
                                       {'afterSequence': '1', 'expectedSha256': '0' * 64})
    assert first['error'] is None and following['error'] is None, (first, following)
    assert stale['result'] is None and stale['error']['errorId'] == 'stale-revision', stale
    head, tail = first['result'], following['result']
    assert (head['nextAfterSequence'], tail['nextAfterSequence']) == ('1', None)
    for page in (head, tail):
        assert (page['archiveSource'], page['observationCount'], page['sourceCoverage']) == ('api-import', '5', 'unknown')
        assert page['apiInputKind'] == 'closed-jsonl'
        assert page['prefix']['sha256'] == digest and page['nodes'] == [] and page['relations'] == []
    rows = head['observations'] + tail['observations']
    assert [(row['sourceSequence'], row['apiFamily'], row['apiCategory'], row['operation']) for row in rows] == [
        ('2', 'memory-write', 'memory', 'WriteProcessMemory'), ('3', 'apc-queue', 'thread', 'NtQueueApcThread'),
        ('5', 'thread-create', 'thread', 'CreateRemoteThreadEx'), ('6', 'thread-context', 'thread', 'SetThreadContext'),
        ('7', 'section-map', 'memory', 'NtMapViewOfSection'),
    ], rows
    for row, wire in zip(rows, packets, strict=True):
        assert (row['headerPid'], row['headerTid']) == (42, 43)
        assert all(row[key] is None for key in ('actorInstance', 'targetInstance', 'threadInstance', 'execution', 'finding'))
        assert 'source-unverified' in row['gaps']
        offset, size = int(row['raw']['inlineOffset']), int(row['raw']['inlineBytes'])
        assert contents[offset:offset + size] == wire


def main():
    """从同一项目验证原包、分页、负例、容量与耗时。"""
    write = packet('KernelBase', 'WriteProcessMemory', 8, 0x52545631, status=299)
    apc = packet('NTDLL.DLL', 'NtQueueApcThread', 9, result_kind=1)
    create = packet('Kernel32.dll', 'CreateRemoteThreadEx', 9, 0x52545631, returned=20)
    context = packet('KernelBase', 'SetThreadContext', 9)
    mapping = packet('ntdll', 'NtMapViewOfSection', 8)
    unrelated = packet('Other', 'CreateRemoteThreadEx', 9)
    wrong_category = packet('ntdll', 'NtWriteVirtualMemory', 9)
    with owned_project_path() as project:
        result = subprocess.run([EXE, 'analyze', 'session'], input=f'project create "{project}" Fixture\nquit\n'.encode(),
                                capture_output=True, timeout=TIMEOUT, check=True)
        assert project.joinpath('project.ksaproj').is_file(), result.stdout
        project_id = next(json.loads(row)['projectId'] for row in result.stdout.splitlines() if row.startswith(b'{'))
        source = project.parent / 'events.jsonl'  # 固定测试根中独占创建的合成事件文件。
        source.write_bytes(b''.join(archive_line(index, wire, **extra) for index, (wire, extra) in enumerate(
            [(unrelated, {}), (write, {'processCreation100ns': '134400565183024180'}), (apc, {}),
             (wrong_category, {}), (create, {'api': 'ignored', 'clueFamily': 'wrong'}), (context, {}), (mapping, {})], 1)))
        known_input = source.read_bytes()  # 完成导入后原证据仍必须字节一致。
        ingest = ('import', '--archive', source, '--project', project, '--title', 'API evidence')
        imported = cli(*ingest)
        assert (imported['status'], imported['sourceRows'], imported['clueRows'], imported['coverage']) == (
            'readback-verified', '7', '5', 'unknown'), imported
        assert source.read_bytes() == known_input
        sample = imported['sampleId']
        replay = ('replay', '--project', project, '--sample', sample)
        first = cli(*replay, '--limit', '1', '--packet', '1')
        row = first['rows'][0]
        assert row['packet'] == write.hex() and first['nextAfter'] == '1'
        assert (row['sourceSequence'], row['reportedStatusCode'], row['phase'], row['archivedCallerCreation100ns']) == (
            '2', 299, 'return', '134400565183024180')
        assert all(row[key] is None for key in ('targetIdentity', 'completedWriteBytes', 'executed', 'attribution'))
        rest = cli(*replay, '--after', first['nextAfter'])
        assert [row['family'] for row in rest['rows']] == ['apc-queue', 'thread-create', 'thread-context', 'section-map']
        assert rest['nextAfter'] is None and rest['rows'][0]['phase'] == 'entry'

        # 尾部损坏时页不交付任何线索。输入损坏应在写项目之前被拒绝。
        segment = project / 'samples' / sample / 'raw' / '00000000000000000001.ksaseg'
        check_graph(project, project_id, sample, segment, (write, apc, create, context, mapping))
        clean = segment.read_bytes()
        segment.write_bytes(clean[:-1])
        assert cli(*replay, code=4)['status'] == 'archive-invalid-or-incomplete'
        broken, = read_graph(project, project_id, sample, {'limit': 1})
        assert broken['result'] is None and broken['error']['errorId'] == 'project-corrupt', broken
        segment.write_bytes(clean)
        assert cli(*replay)['clueRows'] == '5'
        source.write_bytes(known_input[:-3])
        assert cli(*ingest, code=4)['sourceSequence'] == '7'
        source.write_bytes(archive_line(1, write, readerPid=44))
        assert cli(*ingest, code=4)['sourceSequence'] == '1'
        source.write_bytes(archive_line(1, unrelated))
        assert cli(*ingest)['status'] == 'no-clues'

        # 固定的混合负载测量解析、Stored 持久化及完整回读的端到端耗时。
        source.write_bytes(b''.join(archive_line(index, write if index % 10 == 0 else unrelated)
                                    for index in range(1, 15001)))
        started = time.perf_counter()
        perf = cli(*ingest)
        elapsed = time.perf_counter() - started
        assert (perf['sourceRows'], perf['clueRows']) == ('15000', '1500')
        print(f'PASS mixed import: 15000 rows, {source.stat().st_size} bytes, 1500 clues, {elapsed:.3f}s')
        print('PASS source/Stored corruption, raw packet equality, pagination, identity gaps, all five clue families')
        print('PASS archive graph classification, raw anchors, continuation and unverified-tail rejection')


if __name__ == '__main__':
    main()
