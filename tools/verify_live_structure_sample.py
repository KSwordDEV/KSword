"""Independently audit a live-sampler CLI receipt against its exact TSV profile.

This validates evidence consistency, not how the evidence was acquired. Synthetic
fixtures must never be described as guest live-sampling acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


class EvidenceError(ValueError):
    """表示回执、分片或严格覆盖率不符合现场验收约束。"""


def require(condition: bool, message: str) -> None:
    """输入可核对条件和错误原因；失败立即终止，不生成通过结果。"""
    if not condition:
        raise EvidenceError(message)


def scalar_width(type_name: str) -> int:
    """从精确 CodeView 简单类型独立取得存储宽度；不猜数组或未知类型。"""
    if type_name.endswith('*'):
        return 8
    if '[' in type_name:
        return 0
    match = re.match(r'^(?:bitfield\()?0x([0-9a-fA-F]+) ', type_name)
    if not match:
        return 0
    code = int(match[1], 16)
    if code >= 0x1000:
        return 0
    mode = (code >> 8) & 15
    if mode:
        return 8 if mode == 6 else 0
    groups = (
        (1, {0x10, 0x68, 0x70, 0x20, 0x69, 0x7c, 0x30}),
        (2, {0x11, 0x72, 0x21, 0x71, 0x73, 0x7a, 0x31}),
        (4, {0x08, 0x12, 0x74, 0x22, 0x75, 0x7b, 0x32}),
        (8, {0x13, 0x76, 0x23, 0x77, 0x33}),
    )
    return next((width for width, codes in groups if code in codes), 0)


def read_profile(path: Path) -> tuple[dict, list[dict]]:
    """输入精确 TSV；输出头身份和全量成员，拒绝父索引环或格式漂移。"""
    lines = path.read_text(encoding='utf-8-sig').splitlines()
    require(bool(lines), 'empty profile')
    header = lines[0].split('\t')
    require(len(header) == 6 and header[0] in {'KSWTHREAD1', 'KSWPROCESS1'}, 'invalid profile header')
    identity = dict(zip(('machine', 'timestamp', 'imageSize'), map(int, header[1:4])))
    identity['pdbKey'] = header[4]
    identity['rootSize'] = int(header[5])
    identity['rootType'] = '_ETHREAD' if header[0] == 'KSWTHREAD1' else '_EPROCESS'
    fields: list[dict] = []
    for index, line in enumerate(lines[1:], 1):
        values = line.split('\t')
        require(len(values) == 7, f'profile row {index}: invalid column count')
        parent, relative = map(int, values[:2])
        require(0 <= parent < index and relative >= 0, f'profile row {index}: invalid parent/offset')
        require(values[6] in {'member', 'union'}, f'profile row {index}: invalid member kind')
        ancestor = fields[parent - 1] if parent else None
        fields.append({
            'id': index, 'parent': parent, 'name': values[2], 'type': values[3],
            'parentRelativeOffset': relative,
            'offset': relative + (ancestor['offset'] if ancestor else 0),
            'path': (ancestor['path'] + '.' if ancestor else '') + values[2],
            'bitOffset': int(values[4]) if values[4] else None,
            'bitWidth': int(values[5]) if values[5] else None,
            'unionInterpretation': values[6] == 'union' or bool(ancestor and ancestor['unionInterpretation']),
            'width': scalar_width(values[3]),
        })
    require(0 < len(fields) <= 4096 and 0 < identity['rootSize'] <= 8192, 'unbounded profile')
    return identity, fields


def verify(packet: dict, profile_path: Path, *, pid: int, process_creation: int,
           tid: int | None = None, thread_creation: int | None = None) -> dict:
    """输入原始 CLI 封套、精确分片和独立夹具身份；输出重算计数或抛出拒绝。"""
    identity, expected = read_profile(profile_path)
    require(packet.get('schemaVersion') == 1, 'incompatible CLI envelope')
    data = packet.get('data')
    require(isinstance(data, dict), 'missing sample data')
    for name, value in {'source': 'live_object_body', 'live': True, 'atomic': False,
                        'metadataOnly': False, 'identityVerified': True,
                        'driverIdentityVerified': True, 'deviceAccessAttempted': True,
                        'requestAttempted': True, 'deviceOpenFailed': False}.items():
        require(type(data.get(name)) is type(value) and data[name] == value, f'invalid {name}')
    require(data.get('sampleStatus') in {'ok', 'partial'}, 'sample is unavailable')
    require(data.get('rootType') == identity['rootType'], 'root type does not match the TSV')
    require(data.get('pid') == pid and pid > 0, 'wrong fixture PID')
    require(str(process_creation) == data.get('processCreationTime100ns') ==
            data.get('expectedProcessCreationTime100ns') and process_creation > 0, 'wrong process incarnation')
    require((tid is not None) == (identity['rootType'] == '_ETHREAD'), 'thread identity required only for ETHREAD')
    require(data.get('tid') == tid, 'wrong fixture TID')
    if tid is not None:
        require(tid > 0 and thread_creation is not None and thread_creation > 0, 'invalid fixture thread identity')
        require(str(thread_creation) == data.get('threadCreationTime100ns') ==
                data.get('expectedThreadCreationTime100ns'), 'wrong thread incarnation')
    require(isinstance(data.get('target'), dict) and data['target'].get('aliveAtReadback') is True,
            'target did not remain alive at readback')
    for source in ('diskKernelIdentity', 'loadedKernelIdentity'):
        actual = data.get(source)
        require(isinstance(actual, dict), f'missing {source}')
        for key in ('machine', 'timestamp', 'imageSize', 'pdbKey'):
            require(actual.get(key) == identity[key], f'{source}: mismatched {key}')
    root_size = identity['rootSize']
    require(data.get('rootSize') == data.get('profileRootSize') == root_size, 'mismatched root size')
    start, end = (int(data.get(key) or 0) for key in ('sampleStartTime100ns', 'sampleEndTime100ns'))
    require(0 < start <= end, 'invalid sampling interval')
    bitmap_text = data.get('validByteBitmap')
    require(isinstance(bitmap_text, str) and re.fullmatch(r'[0-9a-fA-F]+', bitmap_text) is not None,
            'invalid validity bitmap')
    require(len(bitmap_text) == ((root_size + 7) // 8) * 2, 'truncated/oversized validity bitmap')
    bitmap = bytes.fromhex(bitmap_text)
    valid = {offset for offset in range(len(bitmap) * 8) if bitmap[offset // 8] & (1 << (offset % 8))}
    require(not valid or max(valid) < root_size, 'out-of-root validity bits')
    require(data.get('bytesCopied') == len(valid) > 0, 'copied count does not match validity population')
    require((data['sampleStatus'] == 'ok') == (len(valid) == root_size), 'sample status disagrees with bitmap')
    fields = data.get('fields')
    require(isinstance(fields, list) and len(fields) == len(expected) == data.get('totalRows'), 'dropped profile rows')
    parents = {row['parent'] for row in expected if row['parent']}
    storage: set[tuple] = set()
    observed_bytes: dict[int, int] = {}
    sampled_values: dict[str, int] = {}
    zero_values = 0  # 只有完整有效字节且已成功独立解码的行才计入零值。
    zero_storage = 0  # 区分整段存储为零与非零标志字中的零位域。
    zero_bitfields_in_nonzero_storage = 0  # 证明大量零位域不等于内存读取全部失败。
    counts = dict(sampledRows=0, unionRows=0, aggregateRows=0, unsupportedRows=0, unreadRows=0)
    base = int(data.get('objectAddress') or '0', 16)
    require(0xffff800000000000 <= base <= (1 << 64) - root_size, 'invalid object base')
    for actual, source in zip(fields, expected):
        label = f"row {source['id']} ({source['path']})"
        require(isinstance(actual, dict), f'{label}: invalid row')
        for key, value in source.items():
            require(type(actual.get(key)) is type(value) and actual[key] == value, f'{label}: mismatched {key}')
        offset, width = source['offset'], source['width']
        bit, bits = source['bitOffset'], source['bitWidth']
        require(0 <= offset < root_size, f'{label}: invalid root-relative offset')
        require(actual.get('storageAddress') == hex(base + offset), f'{label}: invalid storage address')
        if source['id'] in parents:
            status, counter = 'aggregate', 'aggregateRows'
        elif not width:
            status, counter = 'unsupported_type', 'unsupportedRows'
        elif offset + width > root_size or not all(at in valid for at in range(offset, offset + width)):
            status, counter = 'not_copied', 'unreadRows'
        else:
            require((bit is None) == (bits is None), f'{label}: incomplete bitfield')
            require(bit is None or (0 <= bit < width * 8 and 0 < bits <= width * 8 - bit), f'{label}: bad bitfield')
            status, counter = 'sampled', 'sampledRows'
        require(actual.get('status') == status and actual.get('sampled') is (status == 'sampled'), f'{label}: false field status')
        require(actual.get('activeUnionBranchKnown') is False, f'{label}: invented active union branch')
        counts[counter] += 1
        if status != 'sampled':
            require(all(actual.get(key) is None for key in ('raw', 'value', 'valueBits', 'text')), f'{label}: fabricated missing value')
            continue
        raw = int(actual.get('raw') or '-1', 16)
        effective_bits = bits if bits is not None else width * 8
        require(0 <= raw < (1 << (width * 8)), f'{label}: oversized raw storage')
        require(actual.get('valueBits') == effective_bits, f'{label}: wrong value width')
        require(int(actual.get('value') or '-1', 16) == ((raw >> (bit or 0)) & ((1 << effective_bits) - 1)),
                f'{label}: wrong bitfield/scalar decode')
        sampled_values[source['path']] = int(actual['value'], 16)
        if sampled_values[source['path']] == 0:
            zero_values += 1
            zero_storage += raw == 0
            zero_bitfields_in_nonzero_storage += bit is not None and raw != 0
        for at, byte in enumerate(raw.to_bytes(width, 'little'), offset):
            require(at not in observed_bytes or observed_bytes[at] == byte, f'{label}: contradictory overlapping storage')
            observed_bytes[at] = byte
        if source['unionInterpretation']:
            counts['unionRows'] += 1
        else:
            storage.add((offset, width, bit, bits))
    counts['coverageRows'] = len(storage)
    for key, value in counts.items():
        require(data.get(key) == value, f'incorrect {key}: reported={data.get(key)}, recalculated={value}')
    require(len(storage) * 2 > len(expected) and data.get('coverageExceedsHalf') is True,
            'strict deduplicated non-union coverage does not exceed half')
    public_values = ({'UniqueProcessId': pid, 'CreateTime.QuadPart': process_creation} if tid is None else
                     {'Cid.UniqueProcess': pid, 'Cid.UniqueThread': tid, 'CreateTime.QuadPart': thread_creation})
    for path, value in public_values.items():
        require(sampled_values.get(path) == value, f'public-API cross-check failed: {path}')
    return {**counts, 'totalRows': len(expected), 'pid': pid, 'tid': tid, 'rootType': identity['rootType'],
            'pdbKey': identity['pdbKey'], 'bytesCopied': len(valid), 'interval100ns': str(end - start),
             'publicIdentityFieldCrossChecks': public_values,
             'zeroValueRows': zero_values, 'zeroStorageRows': zero_storage,
             'zeroBitfieldsInNonzeroStorage': zero_bitfields_in_nonzero_storage,
            'profileSha256': hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            'evidenceConsistencyVerified': True, 'acquisitionIndependentlyProven': False}


def main() -> int:
    """命令行只读校验保存的 JSON；不连接驱动、不部署、不改变任何虚拟机状态。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--process-creation', required=True, type=int)
    parser.add_argument('--tid', type=int)
    parser.add_argument('--thread-creation', type=int)
    args = parser.parse_args()
    try:
        report = verify(json.loads(args.receipt.read_text(encoding='utf-8-sig')), args.profile,
                        pid=args.pid, process_creation=args.process_creation,
                        tid=args.tid, thread_creation=args.thread_creation)
        report['receiptSha256'] = hashlib.sha256(args.receipt.read_bytes()).hexdigest()
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except (EvidenceError, OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({'evidenceConsistencyVerified': False, 'error': str(error)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
