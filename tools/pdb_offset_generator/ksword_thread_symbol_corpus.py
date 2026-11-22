#!/usr/bin/env python3
"""Export selected Windows amd64 thread type metadata from a local PE/PDB corpus.

Reads only disk files; JSON is research evidence, not a runtime driver profile.
Requires pefile and llvm-pdbutil. Rerun to resume: completed PDB extractions are
checkpointed in the report and reused while their source stamps are unchanged.
No launch, symbol download, kernel memory access, or driver configuration.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import errno
from functools import partial
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import struct
import subprocess
import sys
import time
from typing import BinaryIO
from uuid import UUID

import pefile

from ksword_ntos_pdb_deep_offsets import DEFAULT_LLVM_PDBUTIL, build_type_info, normalize_type_id, parse_member_line, split_type_records
from ksword_pdb_profile_generator import CODEVIEW_PRIMITIVE_TYPE_SIZES, PdbIdentity, normalize_record_id


PE_TREE = Path('pe-store/amd64/ntoskrnl.exe')
PDB_TREE = Path('pdb-cache/amd64/ntkrnlmp.pdb')
REPORT_TREE = Path('profiles/ksword_thread_symbol_metadata')
PDB_NAME = 'ntkrnlmp.pdb'
MAX_WORKERS = 4
AMD64 = 0x8664
KEY_RE = re.compile(r'[0-9A-F]{33,40}\Z')
STRUCTS = {
    '_ETHREAD': 'Tcb Cid CreateTime ExitStatus'.split(),
    '_KTHREAD': ('ApcQueueable ApcState ApcStateIndex CombinedApcDisable ContextSwitches InitialStack '
                 'KernelApcDisable KernelStack KernelStackResident Process SavedApcState SpecialApcDisable '
                 'StackBase StackLimit State WaitMode WaitReason').split(),
    '_KAPC_STATE': 'KernelApcInProgress KernelApcPending UserApcPending'.split(),
}
AGGREGATES = {'LF_STRUCTURE', 'LF_STRUCTURE2', 'LF_CLASS', 'LF_CLASS2', 'LF_UNION', 'LF_UNION2'}
SIGNED = {'0011', '0012', '0013', '0068', '0072', '0074', '0076'}
CHAR_TYPES = {'0010', '0070'}  # CodeView char spellings; sign not encoded.
MEMBER_NAMES = tuple(f'{name}.{field}' for name, fields in STRUCTS.items() for field in fields)
MSF_SIGNATURE = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'
REUSABLE = {'complete', 'partial', 'no_thread_types'}
TRANSIENT_VOLUME_ERRORS = {3, 21, 53, 55, 64, 1006, 1117, 1167}


def retry_io(operation, *arguments, pending_output=False):
    """Retry a briefly detached corpus volume; permanent failures still surface."""
    delays = (0.0, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0) if pending_output else (0.0, 0.5, 1.0, 2.0, 4.0)
    for delay in delays:
        if delay:
            time.sleep(delay)
        try:
            return operation(*arguments)
        except OSError as exc:
            # Windows Python open() can surface an unavailable output volume
            # as errno 22 without a WinError. The fixed JSON path was valid
            # before detachment, so allow a bounded remount window there.
            if (getattr(exc, 'winerror', None) not in TRANSIENT_VOLUME_ERRORS
                    and not (pending_output and exc.errno == errno.EINVAL)) or delay == delays[-1]:
                raise


def pdb_identity(stream: BinaryIO) -> dict:
    """Read the MSF 7 Info GUID and DBI header age (not the Info stream age)."""
    def read_at(offset: int, size: int) -> bytes:
        stream.seek(offset)
        data = stream.read(size)
        if len(data) != size:
            raise ValueError('Truncated MSF data')
        return data

    file_size = stream.seek(0, 2)
    header = read_at(0, 56)
    if header[:32] != MSF_SIGNATURE:
        raise ValueError('Not an MSF 7 PDB')
    page_size, _, page_count, dir_size, _, map_page = struct.unpack_from('<6I', header, 32)
    if page_size not in (512, 1024, 2048, 4096) or page_count * page_size != file_size:
        raise ValueError('Invalid MSF page geometry')
    dir_count = (dir_size + page_size - 1) // page_size
    if dir_size < 4 or not 0 < map_page < page_count or dir_count * 4 > page_size:
        raise ValueError('Invalid MSF directory geometry')
    dir_pages = struct.unpack(f'<{dir_count}I', read_at(map_page * page_size, dir_count * 4))
    if any(not 0 < page < page_count for page in dir_pages):
        raise ValueError('Invalid MSF directory page')
    directory = b''.join(read_at(page * page_size, page_size) for page in dir_pages)[:dir_size]
    count, = struct.unpack_from('<I', directory)
    cursor = 4 + count * 4
    if count < 4 or cursor > dir_size:
        raise ValueError('Missing PDB Info or DBI stream')
    for i in range(4):
        size, = struct.unpack_from('<I', directory, 4 + i * 4)
        pages = 0 if size == 0xffffffff else (size + page_size - 1) // page_size
        if cursor + pages * 4 > dir_size:
            raise ValueError('Invalid MSF stream directory')
        if i in (1, 3):
            need = 28 if i == 1 else 64
            if not pages or size < need:
                raise ValueError('Short PDB Info or DBI header')
            page, = struct.unpack_from('<I', directory, cursor)
            if not 0 < page < page_count:
                raise ValueError('Invalid MSF stream page')
            data = read_at(page * page_size, need)
            if i == 1:
                guid = str(UUID(bytes_le=data[12:28])).upper()
                info_age, = struct.unpack_from('<I', data, 8)
            else:
                signature, _, dbi_age = struct.unpack_from('<iII', data)
                machine, = struct.unpack_from('<H', data, 58)
                if signature != -1 or machine != AMD64 or not dbi_age:
                    raise ValueError('Invalid amd64 DBI header')
        cursor += pages * 4
    return {'guid': guid, 'dbiAge': dbi_age, 'infoAge': info_age, 'machine': machine}


def symbol_key(identity: dict) -> str:
    return identity['guid'].replace('-', '') + f"{identity['dbiAge']:X}"


def extract_layouts(text: str) -> dict:
    """Extract the whitelist from a single indexed TPI dump, without guessing widths."""
    records = split_type_records(text)
    sizes, members, missing = {}, {}, {}
    heads = defaultdict(list)
    for type_id, record in records.items():
        if record.kind in AGGREGATES:
            name = record.header.partition('`')[2].partition('`')[0]
            if name in STRUCTS:
                heads[name].append(type_id)

    infos = {}

    def info(type_id):
        if type_id not in infos:
            infos[type_id] = build_type_info({type_id: records[type_id]})[type_id]
        return infos[type_id]

    def describe(type_id, visited=frozenset()):
        if type_id in visited:
            return None
        visited = visited | {type_id}
        short_id = normalize_record_id(type_id)
        if short_id in CHAR_TYPES:
            return {'sizeBytes': 1, 'kind': 'integer', 'signed': None}
        width = CODEVIEW_PRIMITIVE_TYPE_SIZES.get(short_id)
        if width:
            return {'sizeBytes': width, 'kind': 'integer', 'signed': short_id in SIGNED}
        if type_id not in records:
            if re.fullmatch(r'06[0-9a-f]{2}', short_id):  # CV SimpleTypeMode::NearPointer64
                return {'sizeBytes': 8, 'kind': 'pointer'}
            return None
        record = info(type_id)
        if record.kind == 'LF_MODIFIER':
            referent = re.search(r'\breferent\s*=\s*(0x[0-9A-Fa-f]+)', ' '.join(records[type_id].body))
            return describe(normalize_type_id(referent[1]), visited) if referent else None
        if record.kind in AGGREGATES:
            if record.forward_ref:
                target = re.search(r'forward ref \(-> (0x[0-9A-Fa-f]+)\)', ' '.join(records[type_id].body))
                if target:
                    target_id = normalize_type_id(target[1])
                    if target_id in records and info(target_id).name == record.name:
                        return describe(target_id, visited)
                return None
            if record.size:
                return {'sizeBytes': record.size, 'kind': 'aggregate', 'typeName': record.name}
        if record.kind == 'LF_POINTER' and record.pointer_kind == 'ptr64':
            return {'sizeBytes': 8, 'kind': 'pointer'}
        if record.kind == 'LF_BITFIELD' and record.bit_base_type:
            storage_id = normalize_type_id(record.bit_base_type)
            storage = describe(storage_id, visited)
            if (storage and storage['kind'] == 'integer' and record.bit_offset is not None and record.bit_size
                    and 0 <= record.bit_offset < record.bit_offset + record.bit_size <= 8 * storage['sizeBytes']):
                return {**storage, 'kind': 'bitfield', 'bitOffset': record.bit_offset, 'bitWidth': record.bit_size}
        return None

    for name, wanted in STRUCTS.items():
        definitions = [info(i) for i in heads[name] if not info(i).forward_ref and info(i).size]
        struct_sizes = {item.size for item in definitions}
        if len(struct_sizes) != 1:
            reason = 'ambiguous_type_size' if struct_sizes else 'type_not_found'
            missing[name] = reason
            missing.update((f'{name}.{member}', reason) for member in wanted)
            continue
        sizes[name] = struct_sizes.pop()
        fields = defaultdict(list)
        for field_list_id in dict.fromkeys(defn.field_list_id for defn in definitions):
            if field_list_id in records and records[field_list_id].kind == 'LF_FIELDLIST':
                for line in records[field_list_id].body:
                    parsed = parse_member_line(line)
                    if parsed and parsed['name'] in wanted:
                        fields[parsed['name']].append(parsed)
        for member in wanted:
            key = f'{name}.{member}'
            candidates = fields[member]
            layouts = []
            for entry in candidates:
                typed = describe(entry['typeId'])
                offset = entry['offset']
                if not typed or not 0 <= offset < offset + typed['sizeBytes'] <= sizes[name]:
                    break
                layouts.append({'offsetBytes': offset, **typed})
            if not candidates:
                missing[key] = 'member_not_found'
            elif len(layouts) != len(candidates):
                missing[key] = 'unsupported_or_out_of_bounds_layout'
            elif any(layout != layouts[0] for layout in layouts[1:]):
                missing[key] = 'ambiguous_member_layout'
            else:
                members[key] = layouts[0]
    return {'typeSizes': sizes, 'members': members, 'missingEntries': missing}


def stamp(path: Path) -> list[int]:
    st = path.stat()
    return [st.st_size, st.st_mtime_ns, st.st_ino]


def buffered_pe_identity(path: Path, size: int) -> tuple[dict, PdbIdentity]:
    """Use pefile on buffered headers and read RSDS without mapping the volume.

    The shared path-based parse_rsds_identity opens a Windows memory mapping;
    removal can terminate the worker with an in-page error before Python can
    catch it. Retain its PdbIdentity/key format and read only referenced ranges.
    """
    with path.open('rb') as source:
        def read_at(offset: int, count: int) -> bytes:
            if offset < 0 or count < 0 or offset + count > size:
                raise ValueError('PE read out of bounds')
            source.seek(offset)
            data = source.read(count)
            if len(data) != count:
                raise ValueError('Truncated PE data')
            return data

        with pefile.PE(data=read_at(0, min(size, 64 * 1024)), fast_load=True) as pe:
            item = dict(machine=int(pe.FILE_HEADER.Machine), timestamp=int(pe.FILE_HEADER.TimeDateStamp),
                        sizeOfImage=int(pe.OPTIONAL_HEADER.SizeOfImage))
            if item['machine'] != AMD64:
                raise ValueError('Not an amd64 PE')
            debug = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']]
            if not debug.VirtualAddress or not 0 < debug.Size <= 64 * 1024 or debug.Size % 28:
                raise ValueError('Missing or invalid PE debug directory')
            sections = [s for s in pe.sections if s.VirtualAddress <= debug.VirtualAddress
                        and debug.VirtualAddress - s.VirtualAddress + debug.Size <= s.SizeOfRawData]
            if len(sections) != 1:
                raise ValueError('PE debug directory lacks a unique file-backed section')
            raw = read_at(sections[0].get_offset_from_rva(debug.VirtualAddress), debug.Size)
        records = set()
        for _, _, _, _, kind, length, _, pointer in struct.iter_unpack('<IIHHIIII', raw):
            if kind != 2 or length < 25 or length > 64 * 1024 or not pointer:
                continue
            data = read_at(pointer, length)
            if not data.startswith(b'RSDS'):
                continue
            guid = str(UUID(bytes_le=data[4:20])).upper()
            age, = struct.unpack_from('<I', data, 20)
            name, terminator, _ = data[24:].partition(b'\0')
            if not terminator or not name:
                continue
            name = PureWindowsPath(name.decode('utf-8', errors='replace')).name
            records.add((name, guid, age))
        if len(records) != 1:
            raise ValueError('Expected one distinct PE RSDS record')
        name, guid, age = records.pop()
        return item, PdbIdentity(name, guid, age, guid.replace('-', '') + f'{age:X}')


def read_pe(path: Path, previous: dict | None) -> dict:
    started = stamp(path)
    if previous and previous.get('status') in {'indexed', 'unsupported_rsds'} and previous.get('sourceStamp') == started:
        return previous
    item, rsds = buffered_pe_identity(path, started[0])
    if stamp(path) != started:
        raise ValueError('PE changed during scan')
    return {**item, 'pdbName': rsds.pdb_name, 'guid': rsds.pdb_guid, 'rsdsAge': rsds.pdb_age,
            'key': rsds.symbol_key, 'sourceStamp': started,
            'status': 'indexed' if rsds.pdb_name.casefold() == PDB_NAME and rsds.pdb_age else 'unsupported_rsds'}


def scan_pe(root: Path, path: Path, previous: dict | None) -> dict:
    item = {'path': path.relative_to(root).as_posix(), 'corpusVersion': path.parent.parent.name.removeprefix('ntoskrnl.exe.')}
    try:
        item.update(retry_io(read_pe, path, previous))
    except (pefile.PEFormatError, OSError, ValueError, IndexError, OverflowError) as exc:
        item.update(status='pe_error', error=str(exc))
    return item


def read_pdb_identity(path: Path):
    started = stamp(path)
    with path.open('rb') as source:
        identity = pdb_identity(source)
    if stamp(path) != started:
        raise OSError('PDB changed during identity check')
    return started, identity


def dump_types(tool: str, timeout: int, path: Path, started: list[int]):
    dump = subprocess.run([tool, 'dump', '-types', str(path)], capture_output=True,
                          encoding='utf-8', errors='replace', timeout=timeout)
    if stamp(path) != started:
        raise OSError('PDB changed during extraction')
    return dump


def inspect_pdb(root: Path, tool: str, timeout: int, key: str, previous: dict | None) -> dict:
    rel = PDB_TREE / key / PDB_NAME
    path = root / rel
    result = {'path': rel.as_posix()}
    try:
        started, result['identity'] = retry_io(read_pdb_identity, path)
    except FileNotFoundError:
        return {**result, 'status': 'pdb_missing'}
    except (OSError, ValueError) as exc:
        return {**result, 'status': 'pdb_identity_error', 'error': str(exc)}
    if symbol_key(result['identity']) != key:
        return {**result, 'status': 'pdb_identity_mismatch'}
    result['sourceStamp'] = started
    result['exactPair'] = True
    try:
        if (previous and previous.get('status') in REUSABLE and previous.get('sourceStamp') == started
                and previous.get('identity') == result['identity']):
            return previous
        dump = retry_io(dump_types, tool, timeout, path, started)
    except subprocess.TimeoutExpired:
        return {**result, 'status': 'type_timeout'}
    except OSError as exc:
        return {**result, 'exactPair': False, 'status': 'pdb_io_error', 'error': str(exc)}
    if dump.returncode:
        return {**result, 'status': 'type_dump_error', 'error': (dump.stderr or dump.stdout)[-500:].strip()}
    layout = extract_layouts(dump.stdout)
    status = 'no_thread_types' if not layout['typeSizes'] else 'partial' if layout['missingEntries'] else 'complete'
    return {**result, **layout, 'status': status}


def bounded(pool, task, arguments, workers):
    """Keep at most workers jobs in flight rather than queueing the entire corpus."""
    pending = set()
    args = iter(arguments)
    while True:
        while len(pending) < workers:
            next_args = next(args, None)
            if next_args is None:
                break
            pending.add(pool.submit(task, *next_args))
        if not pending:
            break
        done, pending = wait(pending, return_when=FIRST_COMPLETED)
        for future in done:
            yield future.result()


def inspect_key(root, tool, timeout, key, previous):
    return key, inspect_pdb(root, tool, timeout, key, previous)


def make_report(ident, images, groups, cache_keys, completed, all_scope, done, discovered=None):
    discovered = len(images) if discovered is None else discovered
    pdb_statuses = Counter(item['status'] for item in completed.values())
    pe_statuses = Counter(item['status'] for item in images)
    per_field = Counter(key for result in completed.values() for key in result.get('members', {}))
    exact = {key for key, result in completed.items() if result.get('exactPair')}
    return {
        'scope': 'offline amd64 NTOS thread symbol metadata; not a runtime profile', 'source': ident,
        'fullCorpusScope': all_scope, 'scanFinished': done,
        'coverage': {
            'peFiles': discovered,
            'examinedPeFiles': len(images), 'peStatusCounts': dict(pe_statuses),
            'indexedPeKeys': len(groups), 'indexedPeAliases': pe_statuses['indexed'] - len(groups),
            'cacheKeyDirectories': len(cache_keys) if all_scope else None,
            'examinedPairedKeys': len(completed), 'unprocessedKeys': sorted(groups.keys() - completed.keys()),
            'exactPairs': len(exact), 'peFilesWithExactPair': sum(len(groups[key]) for key in exact),
            'pdbStatusCounts': dict(sorted(pdb_statuses.items())),
            'memberCoverage': {key: {'present': per_field[key], 'missingAmongExactPairs': len(exact) - per_field[key]}
                               for key in MEMBER_NAMES},
        },
        'cacheKeysWithoutIndexedPe': sorted(cache_keys - groups.keys()) if all_scope and len(images) == discovered else None,
        'images': images,
        'byPdbKey': {key: completed[key] for key in sorted(completed)},
    }


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix('.pending.json')
    with pending.open('w', encoding='utf-8', newline='\n') as handle:
        # Compact, deterministic research data. No generated binary/driver file.
        json.dump(report, handle, ensure_ascii=False, separators=(',', ':'))
        handle.write('\n')
    pending.replace(path)


def pe_paths(search_roots):
    # pathlib.glob can suppress intermittent filesystem errors while walking.
    def on_error(error):
        raise error

    return sorted({Path(base) / name for root in search_roots for base, _, files in os.walk(root, onerror=on_error)
                   for name in files if name.casefold() == 'ntoskrnl.exe'})


def find_cache_keys(root):
    return {path.name.upper() for path in (root / PDB_TREE).iterdir()
            if KEY_RE.fullmatch(path.name.upper()) and path.is_dir()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-root', type=Path, default=Path(r'F:\KswordPDB\PDB'))
    parser.add_argument('--llvm-pdbutil', default=shutil.which('llvm-pdbutil') or DEFAULT_LLVM_PDBUTIL)
    parser.add_argument('--workers', type=int, choices=range(1, MAX_WORKERS + 1), default=MAX_WORKERS)
    parser.add_argument('--pdb-timeout', type=int, default=90, help='Seconds per llvm-pdbutil invocation')
    parser.add_argument('--pe-version', action='append', default=[], help='Select a corpus directory version, e.g. 10.0.19041.631; repeatable')
    parser.add_argument('--require-key', type=str.upper, action='append', default=[], help='Fail if a required exact key lacks complete metadata; repeatable')
    args = parser.parse_args(argv)
    if not 1 <= args.pdb_timeout <= 600 or any(not KEY_RE.fullmatch(key) for key in args.require_key):
        parser.error('Invalid --pdb-timeout or --require-key')
    if any(not re.fullmatch(r'\d+(?:\.\d+){3}', version) for version in args.pe_version):
        parser.error('--pe-version expects a four-part numeric version')
    root = args.corpus_root.resolve()
    tool = shutil.which(args.llvm_pdbutil)
    if not tool or not (root / PE_TREE).is_dir() or not (root / PDB_TREE).is_dir():
        parser.error('llvm-pdbutil and both corpus trees must exist')
    tool = str(Path(tool).resolve())
    search_roots = [root / PE_TREE / f'ntoskrnl.exe.{version}' for version in sorted(set(args.pe_version))]
    if not search_roots:
        search_roots = [root / PE_TREE]
    if any(not directory.is_dir() for directory in search_roots):
        parser.error('A selected PE version directory does not exist')
    paths = retry_io(pe_paths, search_roots)
    if not paths:
        parser.error('No ntoskrnl.exe images found')
    all_scope = not args.pe_version
    cache_keys = retry_io(find_cache_keys, root) if all_scope else set()
    report_path = root / REPORT_TREE / ('corpus.json' if all_scope else 'selected.json')
    # Fingerprint the parser and the selected binary's file stamp so a changed
    # interpretation or tool does not silently reuse stale typed metadata.
    parser_sources = ('ksword_thread_symbol_corpus.py', 'ksword_ntos_pdb_deep_offsets.py', 'ksword_pdb_profile_generator.py')
    ident = {'root': str(root), 'pdbutil': tool, 'pdbutilStamp': stamp(Path(tool)),
             'parserSha256': [hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in parser_sources]}
    previous = {}
    previous_images = {}
    if report_path.is_file():
        saved = json.loads(retry_io(report_path.read_text, 'utf-8'))
        if saved.get('source') == ident:
            previous = saved.get('resumeEntries', {}) | saved.get('byPdbKey', {})
            previous_images = {item['path']: item for item in saved.get('resumeImages', []) + saved.get('images', [])}
    print(f'Indexing {len(paths)} offline PE files with {args.workers} workers.', flush=True)
    groups = defaultdict(list)
    images = []
    completed = {}

    def checkpoint():
        report = make_report(ident, sorted(images, key=lambda item: item['path']), groups, cache_keys,
                             completed, all_scope, False, len(paths))
        report['resumeEntries'] = {k: v for k, v in previous.items()
                                   if k not in completed and v['status'] in REUSABLE}
        seen_paths = {item['path'] for item in images}
        report['resumeImages'] = [v for k, v in previous_images.items() if k not in seen_paths]
        retry_io(write_report, report_path, report, pending_output=True)

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        pe_inputs = ((path, previous_images.get(path.relative_to(root).as_posix())) for path in paths)
        for image in bounded(pool, partial(scan_pe, root), pe_inputs, args.workers):
            images.append(image)
            if image['status'] == 'indexed':
                groups[image['key']].append(image['path'])
            if len(images) % 128 == 0:
                checkpoint()
                print(f'Checkpoint: {len(images)}/{len(paths)} PE files', flush=True)
        images.sort(key=lambda item: item['path'])
        print(f'Indexed {len(groups)} distinct RSDS keys; {len(previous)} prior results available.', flush=True)
        required = set(args.require_key)
        inputs = ((key, previous.get(key)) for key in sorted(groups, key=lambda key: (key not in required, key)))
        for key, result in bounded(pool, partial(inspect_key, root, tool, args.pdb_timeout), inputs, args.workers):
            completed[key] = result
            if len(completed) % 64 == 0:
                checkpoint()
                print(f'Checkpoint: {len(completed)}/{len(groups)} keys', flush=True)
    report = make_report(ident, images, groups, cache_keys, completed, all_scope, True)
    retry_io(write_report, report_path, report, pending_output=True)
    print(json.dumps(report['coverage'] | {'memberCoverage': 'see report'}), flush=True)
    print(report_path, flush=True)
    failed = [key for key in args.require_key if completed.get(key, {}).get('status') != 'complete']
    if failed:
        print(f'Required complete exact keys missing: {", ".join(failed)}', file=sys.stderr)
    return int(not groups or bool(failed))


if __name__ == '__main__':
    raise SystemExit(main())
