"""Preserve unresolved XML reference relationships in the project catalog.

No XML is executed. These are unverified source records, not DLL exports,
vtable indices, executable hooks or authoritative API signatures. A source
node is encoded as [tag, attributes, text, children]; all nonempty text and
all element attributes/children are preserved in declaration order.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

from audit_external_definitions import MAX_XML_BYTES, parse_xml, normalize_charset


def node_data(node):
    if any(child.tail and child.tail.strip() for child in node):
        raise ValueError('mixed XML content cannot be preserved safely')
    text = node.text if node.text and node.text.strip() else ''
    return [node.tag, dict(sorted(node.attrib.items())), text, [node_data(c) for c in node]]


def build_metadata(root: Path):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('source must be a directory')
    documents = []
    for path in sorted(root.rglob('*.xml')):
        if path.is_symlink() or not path.is_file():
            continue
        if not path.resolve().is_relative_to(root) or path.stat().st_size > MAX_XML_BYTES:
            raise ValueError('unsafe input: ' + str(path))
        data = path.read_bytes()
        tree = parse_xml(data)
        includes = [node_data(n) for n in tree.iter('Include')]
        interfaces = [node_data(n) for n in tree.iter('Interface')]
        modules = []
        for mod in tree.iter('Module'):
            aliases = [node_data(n) for n in mod.findall('ModuleAlias')]
            sources = [node_data(n) for n in mod.findall('SourceModule')]
            charset = [node_data(n) for n in mod.findall('Api')
                       if n.get('BothCharset', '').casefold() == 'true'
                       and ('SuffixA' in n.attrib or 'SuffixW' in n.attrib)]
            if aliases or sources or charset:
                modules.append({'name': mod.get('Name', ''), 'attributes': dict(sorted(mod.attrib.items())),
                                'aliases': aliases, 'source_modules': sources, 'custom_charset': charset})
        if includes or interfaces or modules:
            documents.append({'path': path.relative_to(root).as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
                              'includes': includes, 'interfaces': interfaces, 'modules': modules})
    return {'schema_version': 1, 'status': 'unverified_reference_only',
            'source': 'API Monitor v2 Alpha r13 XML; copyright 2010-2011 Rohitab Batra',
            'encoding': '[tag, attributes, text, children]', 'documents': documents}


def merge(catalog, metadata):
    if catalog.get('schema_version') != 1 or not isinstance(catalog.get('apis'), list):
        raise ValueError('invalid project catalog')
    # Copy only the mutable reference section; preserve Hook definitions and
    # already SDK-verified ABI entries unchanged on every incremental pass.
    output = dict(catalog)
    refs = json.loads(json.dumps(catalog['reference_signatures']))
    existing = {(x['module'].casefold(), x['export']): None for x in catalog['apis']}
    existing.update({(r[0].casefold(), r[1]): r for r in refs['entries']})
    files = {p: sha for p, sha in refs['files']}
    conflicts = []
    added = []
    for doc in metadata['documents']:
        for mod in doc['modules']:
            for node in mod['custom_charset']:
                attrs, children = node[1], node[3]
                ret = [n for n in children if n[0] == 'Return']
                params = [n for n in children if n[0] == 'Param']
                if len(ret) != 1 or len(params) > 64:
                    conflicts.append([mod['name'], attrs.get('Name', ''), doc['path'], 'invalid_signature'])
                    continue
                for encoding in ('A', 'W'):
                    suffix = attrs.get('Suffix' + encoding, encoding)
                    name = attrs.get('Name', '') + suffix
                    convention = attrs.get('CallingConvention', mod['attributes'].get('CallingConvention', ''))
                    return_type = normalize_charset(ret[0][1].get('Type', ''), encoding)
                    arguments = [[p[1].get('Name', ''), normalize_charset(p[1].get('Type', ''), encoding)] for p in params]
                    if (not re.fullmatch(r'[A-Za-z0-9_]+\.dll', mod['name'], re.I)
                            or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name)
                            or not convention or not return_type or any(not x[0] or not x[1] for x in arguments)):
                        conflicts.append([mod['name'], name, doc['path'], 'invalid_signature'])
                        continue
                    key = (mod['name'].casefold(), name)
                    row = [mod['name'], name, convention, return_type, arguments, doc['path']]
                    if key in existing:
                        if existing[key] != row:
                            conflicts.append([mod['name'], name, doc['path'], 'existing_identity'])
                        continue
                    existing[key] = row
                    added.append(row)
                    files[doc['path']] = doc['sha256']
    refs['entries'].extend(added)
    refs['files'] = [[p, files[p]] for p in sorted(files)]
    refs['charset_conflicts'] = conflicts
    output['reference_signatures'] = refs
    output['reference_metadata'] = metadata
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xml-root', required=True, type=Path)
    parser.add_argument('--catalog', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('output must be a new file')
    source = json.loads(args.catalog.read_text(encoding='utf-8-sig'))
    merged = merge(source, build_metadata(args.xml_root))
    metadata = merged.pop('reference_metadata')
    refs = merged.pop('reference_signatures', None)
    base = json.dumps(merged, ensure_ascii=False, indent=2)[:-2]
    if refs is not None:
        base += ',\n  "reference_signatures": ' + json.dumps(refs, ensure_ascii=False, separators=(',', ':'))
    data = base + ',\n  "reference_metadata": ' + json.dumps(metadata, ensure_ascii=False, separators=(',', ':')) + '\n}\n'
    if len(data.encode('utf-8')) > 16 * 1024 * 1024:
        raise ValueError('merged catalog would exceed current runtime limit')
    check = json.loads(data)
    oldrefs = source['reference_signatures']
    newrefs = check['reference_signatures']
    if (check['apis'] != source['apis']
            or newrefs['entries'][:len(oldrefs['entries'])] != oldrefs['entries']
            or newrefs.get('verified_abis') != oldrefs.get('verified_abis')):
        raise ValueError('existing catalog data changed')
    with args.output.open('x', encoding='utf-8', newline='\n') as out:
        out.write(data)
    print(json.dumps({'bytes': len(data.encode('utf-8')), 'documents': len(metadata['documents']),
                      'interfaces': sum(len(d['interfaces']) for d in metadata['documents']),
                      'includes': sum(len(d['includes']) for d in metadata['documents']),
                      'charset_references_added': len(newrefs['entries']) - len(oldrefs['entries']),
                      'charset_conflicts': len(newrefs['charset_conflicts'])}))


if __name__ == '__main__':
    main()
