#!/usr/bin/env python3
"""将单个已验证的内核和匹配 PDB 转成只读线程布局分片。"""

import argparse
import re
from pathlib import Path

from ksword_ntos_pdb_deep_offsets import (
    DEFAULT_LLVM_PDBUTIL, build_type_info, normalize_type_id, parse_member_line,
    resolve_type_display, split_type_records,
)
from ksword_thread_symbol_corpus import dump_types, read_pdb_identity, read_pe, symbol_key


# 只遍历内嵌的类型；指针字段保留类型名，不沿指针展开。
AGGREGATES = {'LF_STRUCTURE', 'LF_UNION', 'LF_CLASS'}


def extract(text, root_name='_ETHREAD'):
    """输入 TPI 文本，返回以父行编号和局部偏移表达的有限字段树。"""
    records = split_type_records(text)  # 按 CodeView 记录 ID 取原始记录。
    infos = build_type_info(records)  # 类型名、大小和位域位置的索引。
    rows = []  # 根行索引为 0；实际字段行的索引从 1 开始。

    def concrete(info):
        """按 CodeView 的精确转发目标跟踪，不用结构名找同名匿名类型。"""
        if not info or not info.forward_ref:
            return info
        match = re.search(r'forward ref \(-> (0x[0-9a-fA-F]+)\)',
                          '\n'.join([records[info.record_id].header, *records[info.record_id].body]))
        target = infos.get(normalize_type_id(match[1])) if match else None  # 转发目标可能没有公开。
        return target if target and not target.forward_ref and target.name == info.name else None

    def members(info, parent, ancestors):
        """返回无结果；追加当前内嵌类型的直接字段，并递归追加可展开子项。"""
        record = records.get(info.field_list_id)  # 这里不处理任何运行时地址。
        if record is None or info.record_id in ancestors:
            return
        ancestors = ancestors | {info.record_id}  # 避免异常的内嵌递归。
        visited = set()  # 折返的 LF_INDEX 不能造成无限遍历。
        while record and record.record_id not in visited:
            visited.add(record.record_id)
            continuation = None  # 同一类型的后续字段列表（如有）。
            for line in record.body:
                member = parse_member_line(line)  # 保留重叠位置和符号中的独立成员名。
                if not member:
                    match = re.search(r'\bLF_INDEX\b.*?(0x[0-9A-Fa-f]+)', line)
                    if match:
                        continuation = records.get(normalize_type_id(match[1]))
                    continue
                offset = member['offset']  # 严格使用相对于当前父类型的偏移。
                if not 0 <= offset < info.size:
                    raise ValueError(f'Out-of-bounds field: {info.name}.{member["name"]}')
                field_info = concrete(infos.get(member['typeId']))  # 精确解析内嵌的匿名 union。
                bits = field_info if field_info and field_info.kind == 'LF_BITFIELD' else None
                name = member['name']  # 原始字段名，不当作翻译键。
                type_text = resolve_type_display(member['typeToken'], infos)  # 结构化位域列另存。
                rows.append((parent, offset, name, type_text, bits.bit_offset if bits else '',
                             bits.bit_size if bits else '', 'union' if info.kind == 'LF_UNION' else 'member'))
                if len(rows) > 4096:
                    raise ValueError('Thread field catalog exceeds 4096 rows')
                if (field_info and field_info.kind in AGGREGATES and field_info.size
                        and offset + field_info.size <= info.size):
                    members(field_info, len(rows), ancestors)
            record = continuation

    # 根类型须唯一；_KTHREAD 通过 Tcb 展开，不重复生成一份根表。
    roots = [i for i in infos.values() if i.name == root_name and not i.forward_ref and i.size and i.field_list_id]
    if len({(i.size, i.field_list_id) for i in roots}) != 1:
        raise ValueError(f'Missing or ambiguous {root_name} definition')
    members(roots[0], 0, set())
    embedded = 'Tcb' if root_name == '_ETHREAD' else 'Pcb'  # 内嵌的调度对象必须存在。
    tcb = [index for index, row in enumerate(rows, 1) if row[:3] == (0, 0, embedded)]
    if len(tcb) != 1 or not any(row[0] == tcb[0] for row in rows):
        raise ValueError(f'Missing embedded {embedded} layout')
    return roots[0].size, rows


def export(pe_path, pdb_path, out_dir, tool, root_name='_ETHREAD'):
    """核对磁盘 PE / DBI 身份后写单个分片，返回路径和各层字段数。"""
    pe = read_pe(pe_path, None)  # amd64 PE 的 RSDS GUID/Age 与映像元数据。
    source_stamp, pdb = read_pdb_identity(pdb_path)  # PDB DBI Age，不是 Info Age。
    if pe['status'] != 'indexed' or symbol_key(pdb) != pe['key']:
        raise ValueError('PE RSDS does not match PDB GUID and DBI Age')
    dump = dump_types(tool, 90, pdb_path, source_stamp)  # 单次提取并校验源文件未变化。
    dump.check_returncode()
    size, rows = extract(dump.stdout, root_name)  # 第一列为父行号，第二列为相对偏移。
    marker = 'KSWTHREAD1' if root_name == '_ETHREAD' else 'KSWPROCESS1'  # 防止分片串用。
    header = (marker, pe['machine'], pe['timestamp'], pe['sizeOfImage'], pe['key'], size)
    lines = [header, *rows]  # UTF-8 TSV，仅供用户态显示，不是驱动协议。
    if any(any(ord(ch) < 32 for ch in str(cell)) for row in lines for cell in row):
        raise ValueError('Unexpected control character in field metadata')
    payload = '\n'.join('\t'.join(map(str, row)) for row in lines) + '\n'
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{pe['machine']}-{pe['timestamp']}-{pe['sizeOfImage']}.tsv"  # 以运行中内核可比较的 PE 三元组定位。
    if path.exists() and path.read_text(encoding='utf-8').splitlines()[0] != payload.splitlines()[0]:
        raise ValueError(f'Ambiguous image identity, refusing to overwrite {path.name}')
    path.write_text(payload, encoding='utf-8', newline='\n')
    return path, len(rows)


def main():
    """接收一对 PE/PDB 与分片目录，打印生成路径和记录数。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pe', type=Path, required=True)
    parser.add_argument('--pdb', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--llvm-pdbutil', default=DEFAULT_LLVM_PDBUTIL)
    parser.add_argument('--type', choices=('_ETHREAD', '_EPROCESS'), default='_ETHREAD')
    args = parser.parse_args()  # 未匹配的输入不生成分片。
    path, count = export(args.pe, args.pdb, args.out_dir, args.llvm_pdbutil, args.type)
    print(f'{path}: {count} fields')


if __name__ == '__main__':
    main()
