"""Merge unverified API Monitor declarations as metadata, never Hook definitions.

The input review file comes from convert_external_catalog.py. Existing Hook
definitions must match the review input exactly; conflicts remain quarantined.
"""
import argparse
import json
from pathlib import Path
import re


def merge(project, review):
    if project.get('schema_version') != 1 or project.get('apis') != review.get('apis'):
        raise ValueError('review does not match current Hook definitions')
    external = review['external_review']
    if external.get('status') != 'unverified_not_runtime':
        raise ValueError('invalid review status')
    source = {item['path']: item['sha256'] for item in external['source_files']}
    entries = []
    quarantined = []
    used = set()
    identities = {(x['module'].casefold(), x['export']) for x in project['apis']}
    for item in external['additions']:
        variants = item['variants']
        # Distinct alternatives are not silently promoted to a declaration.
        if len(variants) != 1:
            quarantined.append([item['module'], item['export'], 'multiple_variants'])
            continue
        variant = variants[0]
        key = (variant['module'].casefold(), variant['export'])
        if key in identities or key != (item['module'].casefold(), item['export']):
            raise ValueError('duplicate or inconsistent identity')
        identities.add(key)
        if variant['source'] not in source or source[variant['source']] != variant['source_sha256']:
            raise ValueError('invalid source identity')
        params = variant['parameters']
        fields = [variant['module'], variant['export'], variant['calling_convention'], variant['return_type']]
        if (not all(isinstance(x, str) and x and len(x) <= 512 and '\x1f' not in x for x in fields)
                or len(params) > 64 or any(not p.get('name') or not p.get('type') for p in params)):
            quarantined.append([item['module'], item['export'], 'invalid_signature'])
            continue
        used.add(variant['source'])
        entries.append(fields + [[[p['name'], p['type']] for p in params], variant['source']])
    # References contain only declarations. Source attributes such as complex
    # buffer counts/conditions are intentionally not interpreted as fact.
    result = dict(project)
    result['reference_signatures'] = {
        'schema_version': 1,
        'source': 'API Monitor v2 Alpha r13 XML; copyright 2010-2011 Rohitab Batra',
        'status': 'unverified',
        'limitations': 'Reference declarations only. No source direction, buffer semantics, COM, alias or include resolution.',
        'files': [[name, source[name]] for name in sorted(used)],
        'entries': entries,
        'conflicts': [[x['project_id'], x['candidate']['module'], x['candidate']['export'], x['candidate']['source']]
                      for x in external['conflicts']],
        'quarantined': quarantined,
        'skipped': external['skipped'],
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--review', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('output must be a new file')
    project = json.loads(args.project.read_text(encoding='utf-8-sig'))
    review = json.loads(args.review.read_text(encoding='utf-8-sig'))
    merged = merge(project, review)
    # Keep the existing formatted definitions readable; compact the reference
    # rows to reduce disk size and avoid exceeding the runtime JSON bound.
    refs = merged.pop('reference_signatures')
    base = json.dumps(merged, ensure_ascii=False, indent=2)
    data = base[:-2] + ',\n  "reference_signatures": ' + json.dumps(refs, ensure_ascii=False, separators=(',', ':')) + '\n}\n'
    if json.loads(data)['apis'] != project['apis']:
        raise ValueError('Hook definitions changed')
    with args.output.open('x', encoding='utf-8', newline='\n') as out:
        out.write(data)
    print(json.dumps({'references': len(refs['entries']), 'conflicts': len(refs['conflicts']),
                      'quarantined': len(refs['quarantined']), 'bytes': len(data.encode('utf-8'))}))


if __name__ == '__main__':
    main()
