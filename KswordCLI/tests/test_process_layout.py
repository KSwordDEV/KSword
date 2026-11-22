"""Exercise the production CLI against an exact disk PE and source layout shards."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


REPO = Path(__file__).resolve().parents[2]
RELEASE = REPO / 'Ksword5.1' / 'x64' / 'Release'
SOURCE = REPO / 'Ksword5.1' / 'Ksword5.1' / 'profiles'
KINDS = (
    (('process', 'thread', 'layout', 'query'), 'thread_layouts', '_ETHREAD', 'KSWTHREAD1', 'Tcb', '_KTHREAD'),
    (('process', 'layout', 'query'), 'process_layouts', '_EPROCESS', 'KSWPROCESS1', 'Pcb', '_KPROCESS'),
)


def invoke(exe, args, code=0, *, json_output=True):
    cmd = [str(exe), *map(str, args), *(['--json'] if json_output else [])]
    run = subprocess.run(cmd, cwd=REPO, capture_output=True, encoding='utf-8', timeout=30)
    assert run.returncode == code, (cmd, run.returncode, run.stdout[:1000], run.stderr)
    if not json_output:
        return run.stdout
    output = json.loads(run.stdout)
    assert output['schemaVersion'] == 1 and output['command'] == ' '.join(args[:args.index('query') + 1])
    assert output['status'] == {0: 'success', 1: 'failed', 5: 'unsupported'}[code], output
    assert bool(output['diagnostics']) == (code != 0)
    return output['data']


def unavailable(data, reason):
    assert data['availability'] == reason, data
    assert data['metadataOnly'] is True and data['rootSize'] is None and data['fields'] == [], data


def test_image(exe, root, image, scratch, *, default_image):
    for command, directory, root_type, marker, embedded_name, embedded_type in KINDS:
        options = ('--image', image, '--profiles', root)
        data = invoke(exe, (*command, *options))
        assert data['metadataOnly'] is True and data['source'] == 'pdb_layout_profile', data
        assert data['rootType'] == root_type and data['availability'] == 'available'
        assert Path(data['imagePath']) == image
        identity = data['imageIdentity']
        filename = '{machine}-{timestamp}-{imageSize}.tsv'.format(**identity)
        path = root / directory / filename
        assert Path(data['profilePath']) == path
        text = path.read_text(encoding='utf-8').splitlines()
        assert text[0].split('\t') == [marker, '34404', str(identity['timestamp']),
                                       str(identity['imageSize']), identity['pdbKey'], str(data['rootSize'])]
        assert identity['machine'] == 0x8664 and type(data['rootSize']) is int
        rows = []
        for index, line in enumerate(text[1:], 1):
            parent, offset, name, type_name, bit_offset, bit_width, union = line.split('\t')
            rows.append(dict(id=index, parent=int(parent), offset=int(offset), name=name, type=type_name,
                             bitOffset=int(bit_offset) if bit_offset else None,
                             bitWidth=int(bit_width) if bit_width else None, unionAlias=union == 'union'))
        # Compare every source row (including types), and forbid invented fields in the row schema.
        assert json.dumps(data['fields'], sort_keys=True) == json.dumps(rows, sort_keys=True)
        assert any(row['parent'] == 0 and row['name'] == embedded_name and row['type'] == embedded_type for row in rows)
        assert any(row['parent'] != 0 for row in rows) and any(row['unionAlias'] for row in rows)
        assert any(row['bitOffset'] == 0 and row['bitWidth'] for row in rows)
        defaults = invoke(exe, command if default_image else (*command, '--image', image))
        assert Path(defaults['profilePath']) == exe.parent / 'profiles' / directory / filename
        assert defaults['imageIdentity'] == identity and defaults['fields'] == data['fields']

        missing_options = (*command, '--image', image, '--profiles', scratch)
        unavailable(invoke(exe, missing_options, 5), 'profile_unavailable')
        candidate = scratch / directory / filename
        candidate.parent.mkdir(exist_ok=True)
        source = path.read_bytes()
        key = identity['pdbKey'].encode('ascii')
        altered_age = key[:-1] + (b'2' if key[-1:] == b'1' else b'1')
        altered_guid = (b'1' if key[:1] == b'0' else b'0') + key[1:]
        other_marker = b'KSWPROCESS1' if marker == 'KSWTHREAD1' else b'KSWTHREAD1'
        for rejected in (source.replace(key, altered_age, 1), source.replace(key, altered_guid, 1),
                         source.replace(marker.encode('ascii'), other_marker, 1),
                         source + b'malformed\n', source + b'0\t0\t\xff\tint\t\t\tmember\n'):
            candidate.write_bytes(rejected)
            unavailable(invoke(exe, missing_options, 5), 'profile_unavailable')
        candidate.unlink()

        missing_image = invoke(exe, (*command, '--image', scratch / 'ntoskrnl.exe'), 5)
        unavailable(missing_image, 'image_identity_unavailable')
        assert missing_image['imageIdentity'] is None and missing_image['profilePath'] is None
        invoke(exe, (*command, '--image'), 1)
        invoke(exe, (*command, '--pid', '4'), 1)
        invoke(exe, (*command, '--backend', 'r0'), 1)
        print(f'{root_type}: {len(rows)} exact rows, root {data["rootSize"]} bytes, '
              f'profile SHA-256 {hashlib.sha256(source).hexdigest()}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', action='append', type=Path, help='Disk PE(s) matching source shards; default: host ntoskrnl.exe')
    parser.add_argument('--profiles', type=Path, default=SOURCE, help='Source profiles root')
    opts = parser.parse_args()
    exe = RELEASE / 'KswordCLI.exe'
    root = opts.profiles.resolve(strict=True)
    # Keep any malformed fixtures in the fixed Release directory, never overwrite an existing test directory.
    scratch = RELEASE / 'cli-layout-test'
    scratch.mkdir()
    try:
        for command, *_ in KINDS:
            assert '--profiles' in invoke(exe, ('help', *command), json_output=False)
            assert 'query' in invoke(exe, ('help', *command[:-1]), json_output=False)
        for image in opts.image or [Path(os.environ['SystemRoot']) / 'System32' / 'ntoskrnl.exe']:
            test_image(exe, root, image.resolve(strict=True), scratch, default_image=not opts.image)
    finally:
        shutil.rmtree(scratch)
    print('Layout CLI checks passed.')


if __name__ == '__main__':
    main()
