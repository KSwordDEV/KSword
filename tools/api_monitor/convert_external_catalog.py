"""Create a reviewable, single-file native catalog from an XML definition tree.

This is an offline conversion, not an import of executable hook definitions.
Unverified source declarations must not be used to choose an ABI at runtime.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from audit_external_definitions import MAX_XML_BYTES, normalize_charset, parse_xml


def convert(source: Path, project: Path):
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError('source must be a directory')
    document = json.loads(project.read_text(encoding='utf-8-sig'))
    if document.get('schema_version') != 1 or not isinstance(document.get('apis'), list):
        raise ValueError('unsupported project catalog')
    local = {}
    for entry in document['apis']:
        key = (entry['module'].casefold(), entry['export'])
        if key in local:
            raise ValueError('duplicate project definition')
        local[key] = entry

    candidates, files, skipped = {}, [], Counter()
    for path in sorted(source.rglob('*.xml')):
        if path.is_symlink() or not path.is_file():
            continue
        if not path.resolve().is_relative_to(source):
            raise ValueError('input escapes source directory')
        if path.stat().st_size > MAX_XML_BYTES:
            raise ValueError('file exceeds size limit: ' + str(path))
        content = path.read_bytes()
        root = parse_xml(content)  # fail closed rather than silently losing files
        relative = path.relative_to(source).as_posix()
        source_hash = hashlib.sha256(content).hexdigest()
        files.append({'path': relative, 'sha256': source_hash})
        for module in root.iter('Module'):
            module_name = module.get('Name', '')
            if not re.fullmatch(r'[A-Za-z0-9_]+\.dll', module_name, re.I):
                skipped['unsupported_module'] += 1
                continue
            for api in module.findall('Api'):
                name = api.get('Name', '')
                ret = api.find('Return')
                if not name or ret is None:
                    skipped['reference_or_missing_return'] += 1
                    continue
                if api.get('BothCharset', '').casefold() == 'true':
                    if api.get('SuffixA') is not None or api.get('SuffixW') is not None:
                        skipped['custom_charset_suffix'] += 1
                        continue
                    names = [(name + 'A', 'A'), (name + 'W', 'W')]
                else:
                    names = [(name, '')]
                for exported, suffix in names:
                    if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', exported):
                        skipped['unsupported_export'] += 1
                        continue
                    params = [{'name': p.get('Name', ''),
                               'type': normalize_charset(p.get('Type', ''), suffix),
                               'attributes': dict(sorted(p.attrib.items()))}
                              for p in api.findall('Param')]
                    candidate = {'module': module_name, 'export': exported,
                                 'calling_convention': api.get('CallingConvention', module.get('CallingConvention', '')),
                                 'return_type': normalize_charset(ret.get('Type', ''), suffix),
                                 'parameters': params, 'source': relative, 'source_sha256': source_hash,
                                 'review_status': 'unverified'}
                    key = (module_name.casefold(), exported)
                    candidates.setdefault(key, []).append(candidate)

    additions, conflicts, matches = [], [], 0
    for key, variants in sorted(candidates.items()):
        own = local.get(key)
        if own is not None:
            for variant in variants:
                types = [p['type'] for p in variant['parameters']]
                own_types = [p['type'] for p in own.get('parameters', [])]
                if types == own_types and variant['return_type'] == own.get('return_type'):
                    matches += 1
                else:
                    conflicts.append({'project_id': own.get('id'), 'candidate': variant})
        else:
            # Keep duplicate declarations together; no implicit conflict resolution.
            additions.append({'module': variants[0]['module'], 'export': key[1], 'variants': variants})
    document['external_review'] = {
        'schema_version': 1, 'status': 'unverified_not_runtime',
        'source_files': files, 'additions': additions, 'conflicts': conflicts,
        'matching_declarations': matches, 'skipped': dict(sorted(skipped.items())),
        'limitations': ['COM methods, aliases, includes and type definitions are not resolved',
                        'parameter direction, ABI and return semantics are not verified',
                        'not a complete conversion of the XML data model'],
    }
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xml-root', required=True, type=Path)
    parser.add_argument('--project-definitions', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.resolve() == args.project_definitions.resolve():
        raise ValueError('output must be a new file')
    document = convert(args.xml_root, args.project_definitions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8', newline='\n') as out:
        json.dump(document, out, ensure_ascii=False, indent=2)
        out.write('\n')
    result = document['external_review']
    print(json.dumps({'files': len(result['source_files']), 'additions': len(result['additions']),
                      'conflicts': len(result['conflicts']), 'matches': result['matching_declarations'],
                      'skipped': result['skipped']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
