#!/usr/bin/env python3
"""从已完成的本地语料库索引发布只读 ETHREAD/EPROCESS TSV，不生成驱动偏移。"""

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
import errno
from functools import partial
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from pefile import PEFormatError

from ksword_thread_layout import extract
from ksword_thread_symbol_corpus import (
    DEFAULT_LLVM_PDBUTIL, KEY_RE, MAX_WORKERS, PDB_NAME, PDB_TREE, REPORT_TREE,
    bounded, dump_types, read_pdb_identity, read_pe, retry_io, symbol_key,
)


# 两个运行时目录分别保存自己的格式；文件名不包含 RSDS，因此不能覆盖碰撞。
FORMATS = {
    '_ETHREAD': ('thread_layouts', 'KSWTHREAD1'),
    '_EPROCESS': ('process_layouts', 'KSWPROCESS1'),
}
DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / 'Ksword5.1/Ksword5.1/profiles'
IMAGE_FIELDS = ('machine', 'timestamp', 'sizeOfImage')  # 运行时分片文件名的 PE 三元组。


def read_release_pe(path):
    """回读单个 PE；短时掉盘的 EINVAL/WinError 433 等待挂载后有限重试。"""
    delays = (0, 1, 2, 4, 8, 16)  # 实测语料盘偶发短时不可用，永久失败仍阻止发布。
    for delay in delays:
        if delay:
            time.sleep(delay)
        try:
            return retry_io(read_pe, path, None)
        except OSError as exc:
            transient = exc.errno == errno.EINVAL or getattr(exc, 'winerror', None) == 433
            if not transient or delay == delays[-1]:
                raise


def index_images(root, images):
    """回读索引中的 PE；返回按 RSDS/三元组分组的映像，以及读取失败或索引漂移。"""
    aliases = defaultdict(Counter)  # RSDS → 三元组 → 具有该身份的 PE 文件数。
    owners = defaultdict(set)  # 三元组 → 所有 PE 的 RSDS（包括没有 PDB 的 PE）。
    failures = []  # 保留失败来源，不将无法读取当成未知版本继续发布。
    for entry in sorted(images, key=lambda item: item['path']):
        path = root / entry['path']
        try:
            image = read_release_pe(path)  # 不信任索引的缓存状态或文件戳。
        except (PEFormatError, OSError, ValueError, IndexError, OverflowError) as exc:
            failures.append({'path': entry['path'], 'error': str(exc)})
            continue
        expected = tuple(entry.get(field) for field in (*IMAGE_FIELDS, 'key', 'status'))
        actual = tuple(image.get(field) for field in (*IMAGE_FIELDS, 'key', 'status'))
        if actual != expected or image['status'] != 'indexed' or not KEY_RE.fullmatch(image['key']):
            failures.append({'path': entry['path'], 'error': image.get('error', 'unindexed or changed PE identity')})
            continue
        identity = actual[:3]  # 三元组归属必须在尝试提取前确定。
        key = image['key']
        aliases[key][identity] += 1
        owners[identity].add(key)
    return aliases, owners, failures


def shard_name(identity):
    """将已核验的 PE 三元组转成运行时查询的文件名。"""
    return '-'.join(map(str, identity)) + '.tsv'


def field_body(rows):
    """校验提取器结果符合 R3 分片消费者的文本/位域约束；返回编码后字段行。"""
    lines = []  # 两种根布局分别生成；同一 PDB 的多个三元组只重用正文。
    for parent, offset, name, kind, bit, width, branch in rows:
        for label in (name, kind):
            if (not label or len(label.encode('utf-8')) > 1024
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in label)):
                raise ValueError('Invalid field name or type text')
        if (bit, width) != ('', ''):
            if not isinstance(bit, int) or not isinstance(width, int) or not (0 <= bit < bit + width <= 64):
                raise ValueError('Invalid field bit range')
        lines.append('\t'.join(map(str, (parent, offset, name, kind, bit, width, branch))) + '\n')
    return ''.join(lines).encode('utf-8')


def stage_key(root, tool, timeout, stage, key, tuples):
    """处理同一 RSDS 键的全部 PE 别名，返回配对状态、布局字段数和逐项失败。"""
    path = root / PDB_TREE / key / PDB_NAME  # 不信任历史 exactPair 标志；读取当前文件。
    result = {'key': key, 'exactPair': False, 'status': 'pdb_error', 'layouts': {}, 'errors': {}}
    try:
        started, pdb = retry_io(read_pdb_identity, path)
    except (OSError, ValueError) as exc:
        if isinstance(exc, FileNotFoundError):
            result['status'] = 'pdb_missing'
        result['errors']['pdb'] = str(exc)
        return result
    if symbol_key(pdb) != key:
        result['status'] = 'pdb_identity_mismatch'
        result['errors']['pdb'] = f'Found {symbol_key(pdb)} using DBI Age'
        return result

    # 只调用一次 llvm-pdbutil；各根布局独立提取，另一根成功时仍保留。
    result['exactPair'] = True
    try:
        dump = retry_io(dump_types, tool, timeout, path, started)
        if dump.returncode:
            raise ValueError((dump.stderr or dump.stdout).strip()[-500:] or f'exit {dump.returncode}')
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result['status'] = 'type_dump_error'
        result['errors']['dump'] = str(exc)
        return result

    result['status'] = 'extracted'
    for name, (directory, marker) in FORMATS.items():
        try:
            size, rows = extract(dump.stdout, name)
            body = field_body(rows)
            if not 0 < size <= 65536 or not body:
                raise ValueError('Invalid root size or empty layout')
            # 每个无歧义三元组使用自己的头；不同符号键不会写到同一个路径。
            for identity in tuples:
                header = ('\t'.join(map(str, (marker, *identity, key, size))) + '\n').encode('ascii')
                if len(header) + len(body) > 512 * 1024:
                    raise ValueError('Layout exceeds runtime shard size limit')
                (stage / directory / shard_name(identity)).write_bytes(header + body)
            result['layouts'][directory] = len(rows)
        except (ValueError, RecursionError) as exc:
            result['errors'][name] = str(exc)
    return result


def publish(stage, output, collisions):
    """先检查两个目录，无冲突后逐文件发布；现有分片不覆盖、不删除。"""
    pending = []  # 发布前已生成完整文件，读者不会看到半个 TSV。
    stats = {}  # 分别统计新发布、已有一致、仅保留的文件和最终文件数。
    for directory, _ in FORMATS.values():
        destination = output / directory
        destination.mkdir(exist_ok=True)
        stats[directory] = {'added': 0, 'unchanged': 0, 'retained': 0, 'total': 0}
        staged = {path.name: path for path in (stage / directory).glob('*.tsv')}
        for path in sorted(destination.glob('*.tsv')):
            if path.name in collisions:
                raise ValueError(f'Ambiguous PE tuple already published: {path}')
            source = staged.pop(path.name, None)
            if source is None:
                stats[directory]['retained'] += 1
            elif source.read_bytes() != path.read_bytes():
                raise ValueError(f'Existing shard differs from exact layout: {path}')
            else:
                stats[directory]['unchanged'] += 1
        pending.extend((directory, source, destination / name) for name, source in sorted(staged.items()))

    # 同卷硬链接原子插入且不会替换现有文件；即使另一进程刚写入也不覆盖。
    for directory, source, target in pending:
        os.link(source, target)
        stats[directory]['added'] += 1
    for directory, counts in stats.items():
        counts['total'] = len(list((output / directory).glob('*.tsv')))
    return stats


def run(root, corpus, tool, output, workers, timeout):
    """读入完整索引，分批暂存并发布；返回可审计的实际计数与失败。"""
    images = corpus['images']  # 历史索引只给出需要逐条核验的路径和 PE 身份。
    aliases, owners, pe_errors = index_images(root, images)
    collisions = {shard_name(identity): sorted(keys) for identity, keys in owners.items() if len(keys) > 1}
    summary = {
        'indexedPeFiles': len(images), 'verifiedPeFiles': sum(sum(group.values()) for group in aliases.values()),
        'verifiedPdbKeys': len(aliases), 'verifiedPeTuples': len(owners), 'exactPdbKeys': 0, 'exactPeFiles': 0,
        'collisions': dict(sorted(collisions.items())), 'peErrors': pe_errors, 'failures': [],
    }
    if pe_errors:
        # 未知 PE 身份不能排除其他分片的文件名碰撞；无需再消耗整轮符号提取时间。
        summary['publicationError'] = 'PE index is not fully verified'
        return summary
    status_counts = Counter()  # PDB 身份核验和 TPI 状态与各根布局结果分开记录。
    layout_counts = Counter()
    output.mkdir(parents=True, exist_ok=True)
    # 暂存目录与最终发布目录同卷；只清理本次创建的暂存目录。
    with TemporaryDirectory(prefix='.layout-release-', dir=output) as tmp:
        stage = Path(tmp)
        for directory, _ in FORMATS.values():
            (stage / directory).mkdir()
        arguments = ((key, sorted(t for t in group if len(owners[t]) == 1))
                     for key, group in sorted(aliases.items()))
        task = partial(stage_key, root, tool, timeout, stage)
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for done, result in enumerate(bounded(pool, task, arguments, workers), 1):
                key = result['key']
                status_counts[result['status']] += 1
                if result['exactPair']:
                    summary['exactPdbKeys'] += 1
                    summary['exactPeFiles'] += sum(aliases[key].values())
                layout_counts.update(result['layouts'].keys())
                if result['errors']:
                    summary['failures'].append(result)
                if done % 128 == 0:
                    print(f'Processed {done}/{len(aliases)} RSDS keys', file=sys.stderr, flush=True)

        summary['pdbStatusCounts'] = dict(sorted(status_counts.items()))
        summary['extractedKeysByDirectory'] = {directory: layout_counts[directory] for directory, _ in FORMATS.values()}
        summary['stagedShards'] = {directory: len(list((stage / directory).glob('*.tsv')))
                                   for directory, _ in FORMATS.values()}
        summary['failures'].sort(key=lambda result: result['key'])  # 与 worker 完成顺序无关。
        if not any(summary['stagedShards'].values()):
            summary['publicationError'] = 'No publishable layouts were produced'
        else:
            try:
                summary['published'] = publish(stage, output, collisions)
            except (OSError, ValueError) as exc:
                summary['publicationError'] = str(exc)
    return summary


def main(argv=None):
    """解析路径和并发限制，输出 JSON 汇总；非零退出表示批次不能发布。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-root', type=Path, default=Path(r'F:\KswordPDB\PDB'))
    parser.add_argument('--corpus-json', type=Path, help='Default: <corpus-root>/profiles/ksword_thread_symbol_metadata/corpus.json')
    parser.add_argument('--llvm-pdbutil')
    parser.add_argument('--out-dir', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--workers', type=int, choices=range(1, MAX_WORKERS + 1), default=2)
    parser.add_argument('--pdb-timeout', type=int, default=90)
    args = parser.parse_args(argv)
    root = args.corpus_root.resolve()
    index = args.corpus_json or root / REPORT_TREE / 'corpus.json'
    try:
        corpus = json.loads(retry_io(index.read_text, 'utf-8'))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not (corpus.get('fullCorpusScope') and corpus.get('scanFinished') and corpus.get('images')):
        parser.error('Expected a finished full-corpus symbol index')
    tool = shutil.which(args.llvm_pdbutil) if args.llvm_pdbutil else (
        shutil.which('llvm-pdbutil') or shutil.which(corpus['source']['pdbutil']) or shutil.which(DEFAULT_LLVM_PDBUTIL))
    if not tool or not 1 <= args.pdb_timeout <= 600:
        parser.error('llvm-pdbutil must exist and --pdb-timeout must be between 1 and 600 seconds')
    report = run(root, corpus, str(Path(tool).resolve()), args.out_dir.resolve(), args.workers, args.pdb_timeout)
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    return int('published' not in report)


if __name__ == '__main__':
    raise SystemExit(main())
