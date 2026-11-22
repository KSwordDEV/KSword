#!/usr/bin/env python3
"""为已发布的精确结构分片生成仅用于红黄风险提示的数字版本目录。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re

from ksword_thread_layout_neighbors import parse_version, read_image


MARKER = 'KSWLAYOUTVERSIONS1'  # 运行时版本元数据的独立格式，不改变精确布局格式。
DIRECTORIES = {'thread_layouts': 'KSWTHREAD1', 'process_layouts': 'KSWPROCESS1'}
PROFILE = re.compile(r'^ntoskrnl_amd64_(\d+\.\d+\.\d+\.\d+)_([0-9a-fA-F]{33,40})$')


def identities_from_pack(pack: dict) -> dict[tuple, tuple]:
    """输入正式 v4 包；按完整 PE/RSDS 身份提取已有发布元数据中的四段版本。"""
    versions = {}  # 身份只能对应一个数字版本；不按时间戳大小或文件名排序猜测。
    if pack.get('packVersion') != 4:
        raise ValueError('Expected the existing v4 release pack')
    for profile in pack['profiles']:
        if profile['moduleClassId'] != 0 or profile['machine'] != 0x8664:
            continue
        match = PROFILE.fullmatch(profile['profileName'])  # profileName 由原发布器保存文件版本与符号键。
        if not match:
            raise ValueError('Missing explicit NTOS four-part release version')
        key = profile['pdbGuid'].replace('-', '').upper() + format(profile['pdbAge'], 'X')
        if match[2].upper() != key:
            raise ValueError('Profile name and explicit RSDS identity disagree')
        identity = (profile['machine'], profile['timeDateStamp'], profile['sizeOfImage'], key)
        version = parse_version(match[1])  # 数字比较，避免 9/10 或修订号的字符串排序错误。
        if identity in versions and versions[identity] != version:
            raise ValueError('One exact identity has conflicting release versions')
        versions[identity] = version
    return versions


def build_catalog(directory: Path, marker: str, versions: dict) -> bytes:
    """只纳入指定目录内真实分片；缺少身份对应的版本时拒绝发布，不伪造边界。"""
    rows = []  # 每个精确分片只追加一条版本记录，原有 TSV 完全不修改。
    for path in sorted(directory.glob('*.tsv')):
        with path.open('rb') as source:
            header = source.readline(512).decode('ascii').rstrip('\n').split('\t')
        if len(header) != 6 or header[0] != marker:
            raise ValueError(f'Invalid exact-layout header: {path}')
        identity = (*map(int, header[1:4]), header[4])  # 同时绑定 Machine/时间戳/大小与 RSDS。
        expected = '-'.join(map(str, identity[:3])) + '.tsv'
        if path.name != expected or identity not in versions:
            raise ValueError(f'No unambiguous explicit version for published shard: {path}')
        version = '.'.join(map(str, versions[identity]))  # 写回规范四段数字文本。
        rows.append('\t'.join(map(str, (*identity, version))) + '\n')
    if not rows:
        raise ValueError(f'No published layouts: {directory}')
    return (MARKER + '\n' + ''.join(rows)).encode('ascii')


def main() -> int:
    """读取现有正式包与可选真实 PE；只写小版本索引，不重新生成布局或后端偏移。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profiles', type=Path, required=True)
    parser.add_argument('--pack', type=Path, required=True)
    parser.add_argument('--extra-image', type=Path, action='append', default=[])
    args = parser.parse_args()
    versions = identities_from_pack(json.loads(args.pack.read_text(encoding='utf-8')))
    for path in args.extra_image:
        image, _ = read_image(path)  # 增量布局不在原包时，必须从实际 PE 的 RSDS 和固定版本资源取值。
        if image.identity in versions and versions[image.identity] != image.version:
            raise ValueError('Extra PE version contradicts existing exact release identity')
        versions[image.identity] = image.version
    pending = {}  # 两个目录都成功后再写入，避免只生成一类结构的边界元数据。
    for directory, marker in DIRECTORIES.items():
        target = args.profiles / directory / '_versions.index'
        pending[target] = build_catalog(target.parent, marker, versions)
    for target, data in pending.items():
        if target.exists() and target.read_bytes() == data:
            continue
        temporary = target.with_suffix('.index.pending')  # 固定、同目录且可清理的元数据临时文件。
        if temporary.exists():
            raise ValueError(f'Existing pending catalog must be inspected first: {temporary}')
        try:
            with temporary.open('xb') as destination:
                destination.write(data)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    print(json.dumps({str(path): len(data.splitlines()) - 1 for path, data in pending.items()}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
