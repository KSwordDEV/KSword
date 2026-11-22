#!/usr/bin/env python3
"""Compare two bracketing amd64 NTOS layouts for offline display only.

Agreement means both sources present identical local metadata, not that the
target has this field or layout. No target PDB is needed; this tool never
reads or writes live kernel storage or produces an exact layout profile.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import NamedTemporaryFile

import pefile

from ksword_thread_layout import extract
from ksword_thread_symbol_corpus import (
    AMD64, DEFAULT_LLVM_PDBUTIL, KEY_RE, PDB_NAME, PDB_TREE, REPORT_TREE,
    dump_types, read_pdb_identity, read_pe, stamp, symbol_key,
)


ROOT = '_ETHREAD'
MARKER = 'KSWNEIGHBORS1'
MAX_BYTES = 512 * 1024
MAX_FIELDS = 4096
MAX_DISPLAY_ROWS = 2 * MAX_FIELDS
Version = tuple[int, int, int, int]
Identity = tuple[int, int, int, str]  # Machine, time stamp, SizeOfImage, RSDS GUID+Age.
ExactRow = tuple[int, int, str, str, int | str, int | str, str]
ExactLayout = tuple[int, Iterable[ExactRow]]
DisplayRow = tuple[str, str, int | str, str, int | str, int | str]


@dataclass(frozen=True)
class Image:
    path: Path
    version: Version
    identity: Identity


@dataclass(frozen=True)
class CorpusEntry:
    image: Image
    pdb: Path | None


def parse_version(text: str) -> Version:
    if not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}', text):
        raise ValueError(f'Expected a four-part PE file version, got {text!r}')
    major, minor, build, revision = map(int, text.split('.'))
    if not major or not build or max(major, minor, build, revision) > 0xFFFF:
        raise ValueError(f'Invalid PE file version: {text}')
    return major, minor, build, revision


def version_text(version: Version) -> str:
    return '.'.join(map(str, version))


def pe_identity(record: dict) -> Identity:
    machine, timestamp, size, key = (record[k] for k in ('machine', 'timestamp', 'sizeOfImage', 'key'))
    if (type(machine) is not int or machine != AMD64 or type(timestamp) is not int
            or not 0 <= timestamp <= 0xFFFFFFFF or type(size) is not int or not 0 < size <= 0xFFFFFFFF
            or not isinstance(key, str) or not KEY_RE.fullmatch(key) or key[32] == '0'):
        raise ValueError('Invalid amd64 PE/RSDS identity')
    return machine, timestamp, size, key


def read_image(path: Path) -> tuple[Image, list[int]]:
    """Read exact identity and numeric file version from disk, not the OS or folder name."""
    record = read_pe(path, None)
    if record['status'] != 'indexed':
        raise ValueError(f'No supported NTOS RSDS identity in {path}')
    # Buffer the PE when reading resources: mapping a removable corpus volume is unsafe.
    with pefile.PE(data=path.read_bytes(), fast_load=True) as pe:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        versions = {(v.FileVersionMS >> 16, v.FileVersionMS & 0xFFFF, v.FileVersionLS >> 16,
                     v.FileVersionLS & 0xFFFF) for v in getattr(pe, 'VS_FIXEDFILEINFO', [])}
    if len(versions) != 1:
        raise ValueError(f'Missing or ambiguous fixed PE file version in {path}')
    if stamp(path) != record['sourceStamp']:
        raise ValueError(f'PE changed while reading version: {path}')
    version = parse_version(version_text(versions.pop()))
    return Image(path, version, pe_identity(record)), record['sourceStamp']


def corpus_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if not path.parts or path.anchor or '..' in path.parts:
        raise ValueError(f'Expected a relative corpus path, got {relative!r}')
    return root / path


def read_index(root: Path, report: Path) -> list[CorpusEntry]:
    """Use report entries to find candidates; check the chosen disk files again."""
    data = json.loads(report.read_text(encoding='utf-8'))
    if data.get('scanFinished') is not True:
        raise ValueError('Corpus scan not finished')
    result = []
    for record in data['images']:
        if record.get('status') != 'indexed' or record.get('machine') != AMD64:
            continue
        identity = pe_identity(record)
        key = identity[3]
        path = corpus_path(root, record['path'])
        version = parse_version(record['corpusVersion'])
        match = data['byPdbKey'].get(key, {})
        pdb = None
        sizes = match.get('typeSizes', {})
        if (match.get('exactPair') is True and match.get('status') in {'complete', 'partial'}
                and all(sizes.get(name, 0) > 0 for name in (ROOT, '_KTHREAD'))):
            indexed = match['identity']
            if indexed['machine'] != identity[0] or symbol_key(indexed) != key:
                raise ValueError(f'Corpus PE/PDB identity mismatch for {key}')
            pdb = corpus_path(root, match['path'])
            if pdb != root / PDB_TREE / key / PDB_NAME:
                raise ValueError(f'Unexpected symbol cache location for {key}')
        result.append(CorpusEntry(Image(path, version, identity), pdb))
    return result


def unique_entry(entries: list[CorpusEntry], version: Version) -> CorpusEntry:
    if not entries:
        raise ValueError(f'No indexed target with PE file version {version_text(version)}')
    if len({entry.image.identity for entry in entries}) != 1:
        raise ValueError(f'Ambiguous PE identities for revision {version_text(version)}; refusing to guess')
    return min(entries, key=lambda entry: entry.image.path.as_posix())


def select_neighbors(target: Image, entries: list[CorpusEntry]) -> tuple[CorpusEntry, CorpusEntry]:
    """Select nearest eligible revisions numerically, with a strict branch/arch boundary."""
    revisions: dict[Version, list[CorpusEntry]] = {}
    for entry in entries:
        image = entry.image
        if (entry.pdb is not None and image.identity[0] == target.identity[0]
                and image.identity[3] != target.identity[3] and image.version[:3] == target.version[:3]):
            revisions.setdefault(image.version, []).append(entry)
    earlier = max((v for v in revisions if v < target.version), default=None)
    later = min((v for v in revisions if v > target.version), default=None)
    if earlier is None or later is None:
        raise ValueError('Target lacks two bracketing exact PE/PDB candidates in the same architecture and branch')
    previous, next_entry = unique_entry(revisions[earlier], earlier), unique_entry(revisions[later], later)
    if previous.image.identity[3] == next_entry.image.identity[3]:
        raise ValueError('Both neighbors use the same PDB identity; not two distinct sources')
    return previous, next_entry


def verified_pdb(image: Image, path: Path) -> list[int]:
    started, pdb = read_pdb_identity(path)
    if pdb['machine'] != image.identity[0] or symbol_key(pdb) != image.identity[3]:
        raise ValueError(f'PE RSDS does not match PDB GUID and DBI Age: {path}')
    return started


def read_exact_neighbor(entry: CorpusEntry, tool: str) -> ExactLayout:
    image, started = read_image(entry.image.path)
    if image != entry.image:
        raise ValueError(f'Disk PE identity/version differs from corpus index: {image.path}')
    if entry.pdb is None:
        raise ValueError('No exact PDB recorded for neighbor')
    source_stamp = verified_pdb(image, entry.pdb)
    dump = dump_types(tool, 90, entry.pdb, source_stamp)
    dump.check_returncode()
    if stamp(image.path) != started:
        raise ValueError(f'Neighbor PE changed during extraction: {image.path}')
    return extract(dump.stdout)


def check_text(value: str) -> None:
    if (not value or len(value.encode('utf-8')) > 1024
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise ValueError('Invalid field name, path, or display type')


def index_fields(size: int, rows: Iterable[ExactRow]):
    """Resolve prior parent row IDs into unique paths; preserve overlapping aliases."""
    if type(size) is not int or not 0 < size <= 65536:
        raise ValueError('Invalid thread root size')
    parents = [(ROOT, 0)]
    fields = {}
    for i, (parent, offset, name, display, bit, width, kind) in enumerate(rows, 1):
        if (i > MAX_FIELDS or type(parent) is not int or not 0 <= parent < i
                or type(offset) is not int or offset < 0 or kind not in ('member', 'union')):
            raise ValueError(f'Invalid exact layout row {i}')
        check_text(name)
        check_text(display)
        if '.' in name:
            raise ValueError(f'Unrepresentable dot in field name: {name}')
        prefix, absolute = parents[parent]
        path = f'{prefix}.{name}'
        check_text(path)
        if path in fields or absolute + offset >= size:
            raise ValueError(f'Duplicate or out-of-bounds qualified field: {path}')
        if (bit, width) != ('', '') and (type(bit) is not int or type(width) is not int
                                       or not 0 <= bit < bit + width <= 64):
            raise ValueError(f'Invalid bit range for {path}')
        fields[path] = (offset, display, bit, width, kind)
        parents.append((path, absolute + offset))
    if not fields:
        raise ValueError('Empty exact layout')
    return fields


def compare(previous: ExactLayout, following: ExactLayout) -> list[DisplayRow]:
    """Compare two (root size, exact rows) tuples; return display TSV row tuples.

    This compares local offsets, display type, bit range, and member/union kind.
    Parent metadata is compared on its own row, not used to infer child addresses.
    A missing path gets its own before/after row with four empty metadata cells.
    """
    before, after = index_fields(*previous), index_fields(*following)
    result = []
    for path in sorted(before.keys() | after.keys()):
        old, new = before.get(path), after.get(path)
        if old is not None and old == new:
            result.append(('agree', path, *old[:4]))
        else:
            absent = ('', '', '', '')
            result.append(('before', path, *(old[:4] if old is not None else absent)))
            result.append(('after', path, *(new[:4] if new is not None else absent)))
    return result


def build_sidecar(target: Image, entries: list[CorpusEntry], tool: str) -> tuple[bytes, list[DisplayRow]]:
    previous, following = select_neighbors(target, entries)
    rows = compare(read_exact_neighbor(previous, tool), read_exact_neighbor(following, tool))
    if len(rows) > MAX_DISPLAY_ROWS:
        raise ValueError('Neighbor sidecar exceeds display row budget')
    header = (MARKER, *target.identity, version_text(previous.image.version), version_text(following.image.version))
    payload = ''.join('\t'.join(map(str, row)) + '\n' for row in (header, *rows)).encode('utf-8')
    if len(payload) > MAX_BYTES:
        raise ValueError('Neighbor sidecar exceeds display budget')
    return payload, rows


def write_sidecar(out_dir: Path, identity: Identity, payload: bytes) -> Path:
    machine, timestamp, size, _ = identity
    path = out_dir / f'{machine}-{timestamp}-{size}.tsv.neighbors'
    if path.exists():
        with path.open('rb') as existing:
            expected = '\t'.join(map(str, (MARKER, *identity))).encode('ascii').split(b'\t')
            if existing.readline(256).split(b'\t')[:5] != expected:
                raise ValueError(f'Conflicting neighbor sidecar identity; refusing to overwrite {path}')
    out_dir.mkdir(parents=True, exist_ok=True)
    pending_path = None
    try:
        with NamedTemporaryFile(dir=out_dir, prefix='.neighbors-', delete=False) as pending:
            pending_path = Path(pending.name)
            pending.write(payload)
        pending_path.replace(path)
    finally:
        if pending_path is not None:
            pending_path.unlink(missing_ok=True)
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-root', type=Path, default=Path(r'F:\KswordPDB\PDB'))
    parser.add_argument('--report', type=Path, help='Corpus index (default: corpus.json under the corpus root)')
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--target-pe', type=Path, help='Explicit offline NTOS PE, even if absent from the corpus')
    selection.add_argument('--target-version', help='Select an unambiguous four-part PE file version from the report')
    parser.add_argument('--target-pdb', type=Path, help='Optional target PDB; verify identity without extracting it')
    parser.add_argument('--out-dir', type=Path, required=True, help='Destination for the display-only .tsv.neighbors file')
    parser.add_argument('--llvm-pdbutil', default=shutil.which('llvm-pdbutil') or DEFAULT_LLVM_PDBUTIL)
    args = parser.parse_args(argv)
    try:
        entries = read_index(args.corpus_root, args.report or args.corpus_root / REPORT_TREE / 'corpus.json')
        if args.target_pe is None:
            version = parse_version(args.target_version)
            indexed = unique_entry([e for e in entries if e.image.version == version], version).image
            target, started = read_image(indexed.path)
            if target != indexed:
                raise ValueError('Target disk PE identity/version differs from corpus index')
        else:
            target, started = read_image(args.target_pe)
        if args.target_pdb is not None:
            verified_pdb(target, args.target_pdb)
        payload, rows = build_sidecar(target, entries, args.llvm_pdbutil)
        if stamp(target.path) != started:
            raise ValueError('Target disk PE changed while generating the sidecar')
        path = write_sidecar(args.out_dir, target.identity, payload)
    except (OSError, ValueError, KeyError, TypeError, IndexError, pefile.PEFormatError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'{parser.prog}: {exc}\n')
    agreements = sum(row[0] == 'agree' for row in rows)
    print(f'{path}: {agreements} agree, {(len(rows) - agreements) // 2} conflicts (display metadata only)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
