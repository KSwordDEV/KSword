"""AA-04 consumer fixture: formal CLI cross-segment transfer candidate readback.

The fixture writes two self-owned API-follow segments through the formal CLI:
the first segment carries a successful WriteProcessMemory packet with explicit
AAIP1 fields, the second carries a later CreateRemoteThread request whose entry
falls inside the actual half-open write range.  The graph view for the second
segment must project one candidate that keeps both raw coordinates, while the
separate observation keeps execution unknown.  Candidate presence never proves
that the requested thread executed.

Negative cases remove the first checkpoint and corrupt the first segment; both
must fail closed without publishing a candidate.  All bytes are restored and
the fixed test root is removed by ``owned_project_path``.
"""

import json
import struct
import sys
from contextlib import ExitStack

from api_evidence import archive_line
from continuous_etw import cleanup_child, shutdown
from live_etw import call, controller
from passive_api_session import CREATION, SESSION_ID, wait_for_segment
from project_v1 import owned_project_path
from smoke import EXE, require

AAIP1_MARKER = 0x49505631
RETURN_MARKER = 0x52545631
DETAIL_OFFSET = 224  # ApiMonitorEventPacket::detailText。
WRITE_ADDRESS = 0x400000
WRITE_BYTES = 8
ENTRY_INSIDE = WRITE_ADDRESS + 4
ACTOR_PID = 42
TARGET_PID = 20
ACTOR_CREATION = 1000
TARGET_CREATION = 2000


def injection_packet(module, api, category, values):
    """构造带固定 AAIP1 字段的 1000 字节包；不执行包内描述。"""
    wire = bytearray(1000)
    struct.pack_into('<IIIIQIi', wire, 0, 1000, 0x20261003, ACTOR_PID, 43,
                     134400565183024188, category, 0)
    for offset, text in ((32, module), (96, api)):
        encoded = text.encode('utf-16-le')
        wire[offset:offset + len(encoded)] = encoded
    struct.pack_into('<I', wire, 864, 0)              # resultKind = StatusCode
    struct.pack_into('<I', wire, 876, AAIP1_MARKER)   # coverageState
    struct.pack_into('<I', wire, 880, 0)              # hookKind = Strong
    struct.pack_into('<I', wire, 884, RETURN_MARKER)  # snapshotIndex 返回槽位
    struct.pack_into('<Q', wire, 896, SESSION_ID)     # sessionIdentity
    struct.pack_into('<Q', wire, 920, 8)              # 非零成功返回位
    detail = 'AAIP1|' + '|'.join(f'{value:016x}' for value in values)
    encoded = detail.encode('utf-16-le')
    require(len(encoded) <= 640, True, 'AAIP1 detail fits the fixed packet slot')
    wire[DETAIL_OFFSET:DETAIL_OFFSET + len(encoded)] = encoded
    return bytes(wire)


def write_fields(address, requested=WRITE_BYTES, completed=WRITE_BYTES):
    """写入包的有效位与实际完成范围，返回字段顺序与 ApiInjectionFieldsV1 一致。"""
    flags = (1 << 0) | (1 << 1) | (1 << 6) | (1 << 4) | (1 << 3)  # 身份、稳定、地址、实际长度
    return [1, flags, ACTOR_CREATION, TARGET_PID, TARGET_CREATION, 0, 0,
            address, requested, completed, 0, 100, 110, 0]


def thread_fields(start_address):
    """创建请求的有效位；返回线程身份与请求入口分开保存。"""
    flags = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 6) | (1 << 5)  # 身份、稳定、请求入口
    return [2, flags, ACTOR_CREATION, TARGET_PID, TARGET_CREATION, 30, 3000,
            0, 0, 0, start_address, 200, 210, 0]


def packets():
    """返回写入包与创建请求包；两者来自不同归档段。"""
    write = injection_packet('KernelBase', 'WriteProcessMemory', 8, write_fields(WRITE_ADDRESS))
    create = injection_packet('Kernel32.dll', 'CreateRemoteThread', 9, thread_fields(ENTRY_INSIDE))
    return write, create


def graph_page(reader, identity, sample, ordinal, **options):
    """按同一已登记采样读取显式图页。"""
    params = dict(identity, sampleId=sample, stream='raw', ordinal=str(ordinal), view='graph') | options
    return call(reader, f'graph-{ordinal}', 'archive.inspect', params)


def graph_error(reader, identity, sample, ordinal):
    """读取失败回执并返回错误 ID；失败页不得发布候选。"""
    params = dict(identity, sampleId=sample, stream='raw', ordinal=str(ordinal), view='graph')
    reader.send(json.dumps(dict(schemaVersion=1, requestId='graph-failure',
                                method='archive.inspect', params=params)))
    message = reader.next()
    require((message['type'], message['requestId']), ('response', 'graph-failure'), 'graph error response')
    require(message['result'], None, 'failed graph read publishes no page')
    return message['error']['errorId']


def expected_page(reader, identity, sample):
    """核对第 2 段的候选、真实坐标和未知执行状态。"""
    page = graph_page(reader, identity, sample, 2)
    require(page['archiveSource'], 'api-follow-checkpoint', 'cross-segment graph source')
    candidates = page['apiTransferCandidates']
    require(candidates['count'], '1', 'one cross-segment candidate')
    require(candidates['evictedWrites'], '0', 'no write eviction in the short fixture')
    require(candidates['truncated'], False, 'candidate window retains the only link')
    link, = candidates['links']
    require((link['kind'], link['execution']), ('write-to-requested-thread-entry', None),
            'candidate is a source declaration, not an execution claim')
    require((link['write']['segmentOrdinal'], link['write']['recordSequence']), ('1', '2'),
            'write keeps its first-segment raw coordinate')
    require((link['threadCreate']['segmentOrdinal'], link['threadCreate']['recordSequence']), ('2', '4'),
            'creation keeps its second-segment raw coordinate')
    require((link['actorPid'], link['targetPid']), (ACTOR_PID, TARGET_PID), 'candidate pid identity')
    require((link['actorCreationFileTime'], link['targetCreationFileTime']),
            (str(ACTOR_CREATION), str(TARGET_CREATION)), 'candidate generation identity')
    require((link['writtenAddress'], link['writtenBytes'], link['requestedStartAddress']),
            (str(WRITE_ADDRESS), str(WRITE_BYTES), str(ENTRY_INSIDE)),
            'candidate keeps the actual half-open range')
    rows = page['observations']
    require(len(rows), 1, 'second segment holds the creation observation')
    row = rows[0]
    require((row['execution'], row['finding']), (None, None), 'observation execution remains unknown')
    require('execution-unknown' in row['gaps'], True, 'creation explicitly reports unknown execution')
    require('thread-instance-unknown' in row['gaps'], True, 'creation has no native thread instance')
    require(page['nodes'] == [] and page['relations'] == [], True, 'no native roles from source context')
    require(page['tree']['unresolvedCandidates'], ['4'], 'creation stays an unresolved candidate')
    first = graph_page(reader, identity, sample, 1)
    require(first['apiTransferCandidates']['count'], '0', 'write-only segment makes no candidate')
    require(first['observations'][0]['apiFamily'], 'memory-write', 'first segment keeps the write observation')
    require('actual-write-range-unknown' in first['observations'][0]['gaps'], True,
            'observation still reports unknown actual range')
    return page, first


def verify_raw_bytes(project, sample, row, expected):
    """按图页给出的绝对内联偏移回读原包字节；不依赖单段结束尾记。"""
    segment = project / 'samples' / sample / 'raw' / f'{int(row["raw"]["segmentOrdinal"]):020d}.ksaseg'
    data = segment.read_bytes()
    offset, size = int(row['raw']['inlineOffset']), int(row['raw']['inlineBytes'])
    require(data[offset:offset + size].hex(), expected.hex(), 'observation points at the exact raw packet')


def run(project):
    """创建两段跟随采样、核对候选与坏段边界。"""
    write, create = packets()
    source = project.parent / 'transfer-events.jsonl'  # 固定测试根内的自有输入。
    with source.open('xb') as stream:
        stream.write(archive_line(1, write, pid=ACTOR_PID, processCreation100ns=CREATION))
    with ExitStack() as children:
        cli = controller('r3')  # 正式 CLI 仅跟随文件，不打开目标进程。
        children.callback(cleanup_child, cli)
        created = call(cli, 'create', 'project.create', {'path': str(project),
                       'settings': {'title': 'AA-04 cross-segment transfer', 'notes': ''}})
        identity = {'projectId': created['projectId']}
        settings = created['settings'] | {'breakpointDefinitions': []}
        saved = call(cli, 'save', 'project.save', identity | {'expectedRevisionId': created['revisionId'],
                     'settings': settings})
        revision = {'expected': {'revisionId': saved['revisionId']}}
        api = {'path': str(source), 'sessionIdentity': str(SESSION_ID), 'authorized': True}
        options = dict(identity, title='Cross-segment transfer', pid=ACTOR_PID,
                       creationFileTime=CREATION, apiArchive=api)
        opened = call(cli, 'open', 'session.open', options, **revision)
        owner = {'session': opened['session']}
        sample = project / 'samples' / opened['sampleId']
        checkpoints = sample / 'checkpoints'

        wait_for_segment(checkpoints, 1)  # 写入必须先在首段完整发布。
        with source.open('ab') as stream:
            stream.write(archive_line(2, create, pid=ACTOR_PID, processCreation100ns=CREATION))
        wait_for_segment(checkpoints, 2)  # 创建请求进入下一段后才允许停止。
        active = call(cli, 'status', 'session.query', {}, **owner)
        stopped = call(cli, 'stop', 'session.stop', {}, expected={'stateRevision': active['stateRevision']}, **owner)
        require((stopped['capture'], stopped['stopReason']), ('stopped', 'requested'), 'fixture stop receipt')
        require(stopped['archive']['recordedRows'], '2', 'two source packets committed')
        require(call(cli, 'close', 'session.close', {}, expected={'stateRevision': stopped['stateRevision']},
                     **owner)['closed'], True, 'fixture session closed')
        require(shutdown(cli), 0, 'fixture controller shutdown')
        source.unlink()  # 项目已持有原包，不需要再次访问输入。

    segments = sorted((sample / 'raw').glob('*.ksaseg'))
    require(len(segments), 3, 'two data segments plus the terminal segment')
    markers = sorted(checkpoints.glob('*.json'))
    require(len(markers), 3, 'one published checkpoint per segment')

    with ExitStack() as children:
        reader = controller('offline')
        children.callback(cleanup_child, reader)
        call(reader, 'reopen', 'project.open', {'path': str(project)})
        page, first = expected_page(reader, identity, opened['sampleId'])
        verify_raw_bytes(project, opened['sampleId'], first['observations'][0], write)
        verify_raw_bytes(project, opened['sampleId'], page['observations'][0], create)

        # 缺首段检查点时不得越过缺口发布第 2 段候选。
        first_marker = markers[0].read_bytes()
        raw_first = segments[0].read_bytes()
        markers[0].unlink()
        try:
            require(graph_error(reader, identity, opened['sampleId'], 2), 'project-data-not-found',
                    'missing checkpoint blocks cross-segment candidate')
        finally:
            markers[0].write_bytes(first_marker)

        # 首段字节损坏时整条链失败关闭；恢复后候选重新完整发布。
        corrupted = bytearray(raw_first)
        corrupted[len(corrupted) // 2] ^= 0xff
        segments[0].write_bytes(corrupted)
        try:
            require(graph_error(reader, identity, opened['sampleId'], 2) in
                    ('project-corrupt', 'project-data-invalid', 'project-data-not-found'), True,
                    'corrupt segment blocks cross-segment candidate')
        finally:
            segments[0].write_bytes(raw_first)
        expected_page(reader, identity, opened['sampleId'])
        require(shutdown(reader), 0, 'offline reader shutdown')

    print(f'CLI_API_TRANSFER_ARCHIVE=PASS SAMPLE={opened["sampleId"]} WRITE=1#2 CREATE=2#4', flush=True)


def main():
    require(sys.platform, 'win32', 'Windows-only CLI fixture')
    require(EXE.is_file(), True, 'formal Release CLI exists')
    with owned_project_path() as project:
        run(project)


if __name__ == '__main__':
    main()
