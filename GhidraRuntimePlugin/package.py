"""Assemble a private/offline plugin tree from the exact official archives.

No runtime or sample is executed. No existing output is replaced or removed.
This tool does not publish/mirror binaries; downstream redistribution has its
own corresponding-source obligations described in NOTICE.md.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile

SOURCE = Path(__file__).resolve().parent
METADATA = ('plugin.json', 'runtime-assets.json', 'LICENSE.txt', 'NOTICE.md',
            'KSword-LICENSE.txt', 'UPSTREAM-GHIDRA-NOTICE.txt')
MAX_EXPANDED_BYTES = 4 * 1024 ** 3
MAX_ENTRIES = 100000
DEVICES = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(10)), *(f'lpt{i}' for i in range(10))}


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def safe_member(name: str, expected_root: str) -> PurePosixPath:
    if '\\' in name or '\x00' in name:
        raise ValueError('unsafe ZIP separator or NUL')
    parts = name.rstrip('/').split('/')
    if not parts or parts[0] != expected_root:
        raise ValueError('ZIP root does not match pinned upstream root')
    for part in parts:
        if not part or part in ('.', '..') or part.endswith((' ', '.')):
            raise ValueError('unsafe ZIP path component')
        if any(character in part for character in ':<>"|?*'):
            raise ValueError('invalid Windows ZIP path')
        if part.split('.')[0].casefold() in DEVICES:
            raise ValueError('reserved Windows device in ZIP')
    return PurePosixPath(*parts)


def inspect_archive(path: Path, profile: dict) -> dict:
    if not path.is_file() or path.stat().st_size > profile['max_archive_bytes']:
        raise ValueError('archive missing or exceeds pinned size bound')
    digest = file_hash(path)
    if digest != profile['sha256']:
        raise ValueError('archive SHA256 differs from pinned upstream release')
    files = {}
    folded = set()
    total = 0
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) > MAX_ENTRIES:
            raise ValueError('too many ZIP entries')
        for entry in archive.infolist():
            relative = safe_member(entry.filename, profile['root_directory'])
            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode) or entry.flag_bits & 1:
                raise ValueError('symlink or encrypted ZIP entry')
            if entry.is_dir():
                continue
            key = str(relative).casefold()
            if key in folded:
                raise ValueError('duplicate or case-colliding ZIP file')
            folded.add(key)
            total += entry.file_size
            if total > MAX_EXPANDED_BYTES:
                raise ValueError('expanded runtime exceeds size budget')
            files[str(relative)] = {'bytes': entry.file_size, 'crc32': f'{entry.CRC:08x}'}
    return {'asset': profile['name'], 'archive_sha256': digest, 'file_count': len(files),
            'expanded_bytes': total, 'files': files}


def extract_verified(path: Path, profile: dict, output: Path) -> list[dict]:
    destination = output / profile['destination_directory']
    inventory = []
    with zipfile.ZipFile(path) as archive:
        for entry in sorted(archive.infolist(), key=lambda item: item.filename):
            relative = safe_member(entry.filename, profile['root_directory'])
            target = destination.joinpath(*relative.parts)
            # Output is exclusively newly created. No rename/delete/overwrite,
            # no links; the relative path was checked before this extraction.
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            count = 0
            with archive.open(entry) as source, target.open('xb') as sink:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(block)
                    count += len(block)
                    sink.write(block)
            if count != entry.file_size:
                raise ValueError('extracted size mismatch')
            os.utime(target, (315532800, 315532800))
            inventory.append({'path': target.relative_to(output).as_posix(), 'bytes': count,
                              'sha256': digest.hexdigest()})
    return inventory


def make_zip(tree: Path, output: Path):
    if output.exists():
        raise ValueError('output ZIP already exists; refusing replacement')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6,
                         allowZip64=True) as archive:
        for file in sorted(path for path in tree.rglob('*') if path.is_file()):
            info = zipfile.ZipInfo('ghidra/' + file.relative_to(tree).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            with file.open('rb') as source, archive.open(info, 'w', force_zip64=True) as sink:
                shutil.copyfileobj(source, sink, 1024 * 1024)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra-archive', type=Path, required=True)
    parser.add_argument('--jdk-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--zip', type=Path, help='Optional deterministic private/offline plugin ZIP')
    parser.add_argument('--inventory-only', action='store_true')
    args = parser.parse_args()
    description = json.loads((SOURCE / 'runtime-assets.json').read_text(encoding='utf-8'))
    archives = (args.ghidra_archive.resolve(), args.jdk_archive.resolve())
    profiles = description['assets']
    inspections = [inspect_archive(path, profile) for path, profile in zip(archives, profiles)]
    if args.inventory_only:
        for item in inspections:
            print(json.dumps({key: value for key, value in item.items() if key != 'files'}))
        print('GHIDRA_PLUGIN_ARCHIVES=PASS')
        return
    if args.output is None:
        parser.error('--output is required unless --inventory-only is specified')
    output = args.output.resolve()
    if output.exists():
        raise ValueError('output directory already exists; refusing replacement')
    if args.zip and args.zip.resolve().is_relative_to(output):
        raise ValueError('output ZIP must be outside the plugin tree')
    output.mkdir(parents=True, exist_ok=False)
    inventory = []
    for path, profile in zip(archives, profiles):
        inventory.extend(extract_verified(path, profile, output))
    for name in METADATA:
        shutil.copyfile(SOURCE / name, output / name)
    legal = [item for item in inventory if ('/legal/' in item['path'].lower() or '/licenses/' in item['path'].lower()
             or Path(item['path']).name.lower() in {'license', 'license.txt', 'notice', 'module.manifest'})]
    report = {'schema_version': 1, 'id': 'ghidra', 'assets': [
        {key: value for key, value in item.items() if key != 'files'} for item in inspections],
        'preserved_payload_files': len(inventory), 'preserved_legal_files': len(legal),
        'legal_inventory': legal, 'payload_inventory': inventory}
    (output / 'payload-inventory.json').write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    if args.zip:
        make_zip(output, args.zip.resolve())
    print(f'GHIDRA_PLUGIN_PACKAGE=PASS files={len(inventory)} legal_files={len(legal)} output={output}')


if __name__ == '__main__':
    main()
