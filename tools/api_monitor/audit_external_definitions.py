"""Read-only API Monitor XML audit with a hash-pinned, out-of-tree repair.

The tool never edits input or infers a correction from the project catalog.
It records type differences as review candidates, not verified mistakes. It can
copy input XML to a new output directory, or write only the approved corrected
XML. Outputs may contain third-party material and should not be committed.

Example:
  python tools/api_monitor/audit_external_definitions.py --api-root PATH \
    --project-definitions APIMonitor_x64/api_monitor_definitions.json \
    --sdk-root SDK_INCLUDE_VERSION --output-dir .codex-build-logs/xml-audit \
    --copy-unchanged
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

MAX_XML_BYTES = 32 * 1024 * 1024
# Approved only for the exact downloaded file hash. The stray byte is outside
# XML and removal is accepted only if the remainder parses as ApiMonitor.
PREFIX_REPAIRS = {
    'e080692d609b5dcee324d30450719465d1b8cbecba59cf64cb308a4f31700c5b': b'c',
}
# Only this exact upstream source is authorised for the single return-type
# edit. This does not assert that its success or ErrorFunc semantics are correct.
RETURN_TYPE_REPAIRS = {
    'e4bdd39463baaa9ede0ee560faccbe586132d377052c0ba0302efdd23b1750f4': True,
}
WINVERIFYTRUST_OLD = b'<Return Type="HRESULT" Display="LONG" />'
WINVERIFYTRUST_NEW = b'<Return Type="LONG" Display="LONG" />'
WINVERIFYTRUST_DOCUMENTATION = 'https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_xml(data: bytes) -> ET.Element:
    if len(data) > MAX_XML_BYTES:
        raise ValueError('file exceeds bounded XML size')
    if re.search(br'<!\s*(?:DOCTYPE|ENTITY)\b', data, re.I):
        raise ValueError('DOCTYPE/ENTITY is not accepted')
    root = ET.fromstring(data)
    if root.tag != 'ApiMonitor':
        raise ValueError('unexpected root element')
    return root


def repair_for(original: bytes) -> bytes | None:
    prefix = PREFIX_REPAIRS.get(digest(original))
    if prefix is None or not original.startswith(prefix + b'<!--'):
        return None
    candidate = original[len(prefix):]
    try:
        parse_xml(candidate)
    except (ET.ParseError, ValueError):
        return None
    return candidate


def repair_winverifytrust_return(original: bytes) -> bytes | None:
    if not RETURN_TYPE_REPAIRS.get(digest(original)):
        return None
    try:
        root = parse_xml(original)
    except (ET.ParseError, ValueError):
        return None
    matches = [api for module in root.iter('Module')
               if module.get('Name', '').casefold() == 'wintrust.dll'
               for api in module.findall('Api') if api.get('Name') == 'WinVerifyTrust']
    if len(matches) != 1:
        return None
    returns = matches[0].findall('Return')
    if len(returns) != 1 or returns[0].get('Type') != 'HRESULT' or returns[0].get('Display') != 'LONG':
        return None
    # Constrain byte replacement to the one verified API block and the exact
    # original element; retain all other bytes including line endings.
    blocks = list(re.finditer(br'<Api Name="WinVerifyTrust">[\s\S]*?</Api>', original))
    if len(blocks) != 1 or blocks[0].group().count(WINVERIFYTRUST_OLD) != 1:
        return None
    block = blocks[0]
    replaced = block.group().replace(WINVERIFYTRUST_OLD, WINVERIFYTRUST_NEW, 1)
    candidate = original[:block.start()] + replaced + original[block.end():]
    try:
        revised = parse_xml(candidate)
    except (ET.ParseError, ValueError):
        return None
    corrected = [api for module in revised.iter('Module')
                 if module.get('Name', '').casefold() == 'wintrust.dll'
                 for api in module.findall('Api') if api.get('Name') == 'WinVerifyTrust']
    if len(corrected) != 1 or len(corrected[0].findall('Return')) != 1 \
            or corrected[0].find('Return').get('Type') != 'LONG':
        return None
    return candidate


def project_index(path: Path):
    document = json.loads(path.read_text(encoding='utf-8-sig'))
    if document.get('schema_version') != 1 or not isinstance(document.get('apis'), list):
        raise ValueError('unsupported project definition catalog')
    index = {}
    for entry in document['apis']:
        key = (entry['module'].casefold(), entry['export'])
        if key in index:
            raise ValueError('duplicate project definition identity')
        index[key] = entry
    return index


def sdk_locations(sdk_root: Path | None, names: set[str]):
    if sdk_root is None or not names:
        return {}, 0
    pattern = re.compile(r'\b(' + '|'.join(re.escape(x) for x in sorted(names, key=lambda x: (-len(x), x))) + r')\s*\(')
    found = {}
    examined = 0
    for path in sorted(sdk_root.rglob('*.h')):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_XML_BYTES:
            continue
        examined += 1
        try:
            text = path.read_text(encoding='utf-8-sig', errors='replace')
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            match = pattern.search(line)
            if match and len(found.setdefault(match.group(1), [])) < 8:
                found[match.group(1)].append({'path': path.relative_to(sdk_root).as_posix(), 'line': number})
    return found, examined


def normalize_charset(value: str, suffix: str) -> str:
    # The third-party format uses generic TCHAR names with BothCharset.
    # Treat these as aliases only when suffix is known; other aliases remain
    # unresolved rather than being inferred from spelling.
    aliases = {'LPCTSTR': ('LPCSTR', 'LPCWSTR'), 'LPTSTR': ('LPSTR', 'LPWSTR'),
               'PCTSTR': ('PCSTR', 'PCWSTR'), 'PTSTR': ('PSTR', 'PWSTR'),
               'TCHAR': ('CHAR', 'WCHAR')}
    pair = aliases.get(value)
    return pair[0 if suffix == 'A' else 1] if pair and suffix in ('A', 'W') else value


def audit(api_root: Path, project_file: Path, sdk_root: Path | None, output_dir: Path,
          copy_unchanged: bool = False):
    source = api_root.resolve(strict=True)
    project = project_file.resolve(strict=True)
    output = output_dir.resolve()
    if not source.is_dir():
        raise ValueError('api-root must be a directory')
    # No output under the source; no overlap that could accidentally include
    # the scan's own output. Existing output is never overwritten.
    if output == source or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('output and input must not overlap')
    if output.exists():
        raise ValueError('output already exists')
    if sdk_root is not None:
        sdk_root = sdk_root.resolve(strict=True)
        if not sdk_root.is_dir():
            raise ValueError('sdk-root must be a directory')
    own = project_index(project)
    files = sorted(p for p in source.rglob('*.xml') if p.is_file() and not p.is_symlink())
    stats = Counter(xml_files=len(files), project_definitions=len(own))
    tags, parameters = Counter(), Counter()
    diagnostics, repairs, payloads, manifest = [], [], [], []
    for path in files:
        relative = path.relative_to(source).as_posix()
        # Defensive even on platforms where rglob can encounter links/junctions.
        if not path.resolve().is_relative_to(source):
            diagnostics.append({'kind': 'unsafe_input_path', 'path': relative})
            stats['unresolved_files'] += 1
            continue
        try:
            if path.stat().st_size > MAX_XML_BYTES:
                raise ValueError('file exceeds bounded XML size')
            original = path.read_bytes()
        except (OSError, ValueError) as error:
            diagnostics.append({'kind': 'read_error', 'path': relative, 'message': str(error)})
            stats['unresolved_files'] += 1
            continue
        before = digest(original)
        content = original
        try:
            tree = parse_xml(original)
            stats['parse_ok_original'] += 1
            candidate = repair_winverifytrust_return(original)
            if candidate is not None:
                content = candidate
                tree = parse_xml(content)
                repairs.append({'kind': 'winverifytrust_return_type', 'path': relative,
                                'before_sha256': before, 'after_sha256': digest(content),
                                'module': 'Wintrust.dll', 'api': 'WinVerifyTrust',
                                'field': 'Return.Type', 'before': 'HRESULT', 'after': 'LONG',
                                'status': 'partial_review_required',
                                'remaining_review': 'GetLastError and success semantics are not verified',
                                'sdk_declaration': 'um/wintrust.h: WinVerifyTrust returns LONG',
                                'documentation': WINVERIFYTRUST_DOCUMENTATION})
                diagnostics.append({'kind': 'return_semantics_pending', 'status': 'review',
                                    'path': relative, 'module': 'Wintrust.dll', 'api': 'WinVerifyTrust',
                                    'message': 'Type corrected only; GetLastError and success semantics remain unverified'})
                stats['mechanically_repaired_files'] += 1
                stats['partially_corrected_files'] += 1
        except (ET.ParseError, ValueError) as error:
            stats['parse_error_original'] += 1
            candidate = repair_for(original)
            if candidate is None:
                diagnostics.append({'kind': 'parse_error', 'path': relative, 'sha256': before,
                                    'message': str(error), 'status': 'review'})
                stats['unresolved_files'] += 1
                payloads.append((relative, original, False))
                manifest.append({'path': relative, 'before_sha256': before, 'after_sha256': before,
                                 'status': 'unresolved_parse_error'})
                continue
            content = candidate
            tree = parse_xml(content)
            repairs.append({'kind': 'known_prefix_repair', 'path': relative,
                            'before_sha256': before, 'after_sha256': digest(content),
                            'remove_prefix_hex': original[:len(original)-len(content)].hex(),
                            'evidence': 'hash-pinned prefix; resulting ApiMonitor XML parses'})
            stats['mechanically_repaired_files'] += 1
        changed = content is not original
        payloads.append((relative, content, changed))
        manifest.append({'path': relative, 'before_sha256': before, 'after_sha256': digest(content),
                         'status': ('partially_corrected' if changed and before in RETURN_TYPE_REPAIRS
                                    else 'repaired' if changed else 'unchanged')})
        for node in tree.iter():
            tags[node.tag] += 1
            if node.tag == 'Param':
                parameters.update(node.attrib.keys())
            if node.tag == 'Api':
                stats['api_elements'] += 1
                if node.get('BothCharset', '').casefold() == 'true':
                    stats['api_both_charset'] += 1
                if len(node) == 0:
                    stats['api_empty_reference'] += 1
        # Compare only explicit Module/Api definitions with an exact module
        # identity; aliases/empty references and COM methods are not resolved.
        for module in tree.iter('Module'):
            module_name = module.get('Name', '')
            for api in module.findall('Api'):
                function = api.get('Name', '')
                if not function:
                    continue
                params = api.findall('Param')
                ret = api.find('Return')
                if not params and ret is None:
                    continue
                if api.get('BothCharset', '').casefold() == 'true':
                    if api.get('SuffixA') is not None or api.get('SuffixW') is not None:
                        stats['charset_custom_suffix_skipped'] += 1
                        continue
                    names = [(function + 'A', 'A'), (function + 'W', 'W')]
                else:
                    names = [(function, '')]
                for exported, suffix in names:
                    entry = own.get((module_name.casefold(), exported))
                    if entry is None:
                        continue
                    stats['project_matched_declarations'] += 1
                    own_params = entry.get('parameters', [])
                    if len(params) != len(own_params):
                        diagnostics.append({'kind': 'parameter_count_difference', 'status': 'review',
                            'path': relative, 'module': module_name, 'api': exported,
                            'external_count': len(params), 'project_count': len(own_params),
                            'project_id': entry.get('id')})
                        continue
                    for position, (external, local) in enumerate(zip(params, own_params), 1):
                        raw_type = external.get('Type', '')
                        external_type = normalize_charset(raw_type, suffix)
                        local_type = local.get('type', '')
                        if external_type != local_type:
                            diagnostics.append({'kind': 'parameter_type_difference', 'status': 'review',
                                'path': relative, 'module': module_name, 'api': exported, 'position': position,
                                'external_type': raw_type, 'charset_resolved_type': external_type,
                                'project_type': local_type, 'project_id': entry.get('id'),
                                'decorated_type': raw_type.startswith('[') and raw_type.endswith(']')})
                    if ret is not None and ret.get('Type', '') != entry.get('return_type', ''):
                        diagnostics.append({'kind': 'return_type_difference', 'status': 'review',
                            'path': relative, 'module': module_name, 'api': exported,
                            'external_type': ret.get('Type', ''), 'project_type': entry.get('return_type', ''),
                            'project_id': entry.get('id'), 'decorated_type': ret.get('Type', '').startswith('[')})
    # SDK hits are source locations for human review, not an assertion that a
    # textual hit is a declaration or semantically equivalent across SDKs.
    names = {d['api'] for d in diagnostics if 'api' in d}
    sdk, sdk_count = sdk_locations(sdk_root, names)
    for d in diagnostics:
        if 'api' in d:
            d['sdk_candidates'] = sdk.get(d['api'], [])
    stats['sdk_headers_scanned'] = sdk_count
    stats['unresolved_differences'] = sum(d.get('status') == 'review' for d in diagnostics)
    # Create only after all source reading and validation are complete.
    output.mkdir(parents=True, exist_ok=False)
    copied = 0
    for relative, data, changed in payloads:
        if not (copy_unchanged or changed):
            continue
        dest = output / 'xml' / Path(relative)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        copied += 1
    stats['output_xml_files'] = copied
    report = {'schema_version': 1, 'input_root': str(source), 'project_definitions': str(project),
              'project_sha256': digest(project.read_bytes()), 'sdk_root': str(sdk_root) if sdk_root else None,
              'copy_unchanged': copy_unchanged, 'stats': dict(stats),
              'tag_counts': dict(tags.most_common()), 'parameter_attributes': dict(parameters.most_common()),
              'files': manifest, 'repairs': repairs, 'diagnostics': diagnostics,
              'limitations': ['type differences are candidates, not confirmed errors',
                  'ModuleAlias, includes, decorated types and COM method signatures are not resolved',
                  'SDK text matches are navigation candidates, not semantic verification',
                  'source files are never changed; unresolved XML is copied byte-for-byte if requested']}
    (output / 'audit.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-root', type=Path, required=True)
    parser.add_argument('--project-definitions', type=Path, required=True)
    parser.add_argument('--sdk-root', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--copy-unchanged', action='store_true')
    args = parser.parse_args()
    report = audit(args.api_root, args.project_definitions, args.sdk_root, args.output_dir, args.copy_unchanged)
    print(json.dumps(report['stats'], ensure_ascii=False, sort_keys=True))
    print('REPORT=' + str(args.output_dir / 'audit.json'))


if __name__ == '__main__':
    main()
