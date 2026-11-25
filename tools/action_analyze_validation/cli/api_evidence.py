"""用合成 API Monitor 归档验证正式 ActionAnalyze 导入和回放。"""

import base64
import hashlib
import json
import struct
import subprocess
import time

from project_v1 import owned_project_path
from smoke import EXE, TIMEOUT


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
        clean = segment.read_bytes()
        segment.write_bytes(clean[:-1])
        assert cli(*replay, code=4)['status'] == 'archive-invalid-or-incomplete'
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


if __name__ == '__main__':
    main()
