"""Match real caller observations to Agent events; report unavailable hooks separately."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATEGORIES = {'File': 1, 'Registry': 2, 'Network': 3, 'Process': 4, 'Loader': 5,
              'Clipboard': 7, 'Memory': 8, 'Thread': 9, 'Service': 10, 'Security': 11,
              'Crypto': 12, 'Com': 13, 'Window': 14, 'Gui': 15}


def group_for(api_id):
    if 642 <= api_id <= 699 or 801 <= api_id <= 829:
        return 'window'
    if 700 <= api_id <= 759 or 830 <= api_id <= 859:
        return 'memory-thread'
    if 760 <= api_id <= 800 or 860 <= api_id <= 889:
        return 'service-security'
    if 900 <= api_id <= 949:
        return 'gui-objects'
    if 950 <= api_id <= 999:
        return 'gui-drawing'
    raise ValueError(f'No probe group for API {api_id}')


def signed32(value):
    value &= 0xffffffff
    return value - 0x100000000 if value & 0x80000000 else value


def expected_result(api, bits, error):
    if api['id'] == 831:
        return 0, 0 if bits in (0, 170) else signed32(bits)
    policy = api['wrapper']['policy']
    success = None
    if policy == 'bool':
        success = bits != 0
    elif policy == 'handle':
        success = bits != 0
        if api['return']['success'] == 'not_invalid_handle':
            success = success and bits not in (0xffffffff, 0xffffffffffffffff)
    elif policy in ('dword_nonzero', 'uint_nonzero'):
        success = bits != 0
    elif policy == 'int_positive':
        success = signed32(bits) > 0
    if api['return']['error_source'] == 'none' and success is False:
        return 2, None
    if success is not None:
        return 0, 0 if success else signed32(error)
    return 0, signed32(bits)


def call_succeeded(api, bits):
    if api['id'] == 831:
        return bits in (0, 170)
    policy = api['wrapper']['policy']
    if policy in ('bool', 'dword_nonzero', 'uint_nonzero'):
        return bits != 0
    if policy == 'handle':
        return bits != 0 and (api['return']['success'] != 'not_invalid_handle'
                              or bits not in (0xffffffff, 0xffffffffffffffff))
    if policy == 'int_positive':
        return signed32(bits) > 0
    if policy in ('hresult', 'ntstatus', 'security_status'):
        return signed32(bits) >= 0
    return bits == 0


def read_trace(path):
    calls, skips = defaultdict(list), defaultdict(list)
    for number, line in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
        parts = line.split('\t')
        if parts[0] == 'CALL' and len(parts) == 9:
            round_no, api_id, begin, end, tid, has_return = map(int, parts[1:7])
            calls[api_id].append({'round': round_no, 'begin': begin, 'end': end,
                                  'tid': tid, 'hasReturn': bool(has_return), 'bits': int(parts[7], 16),
                                  'error': int(parts[8])})
        elif parts[0] == 'SKIP' and len(parts) >= 4:
            skips[int(parts[2])].append({'round': int(parts[1]), 'reason': '\t'.join(parts[3:])})
        elif parts[0] != 'BEGIN':
            raise ValueError(f'Invalid trace at {path}:{number}')
    return calls, skips


def analyze(report_root, definitions):
    catalog_bytes = definitions.read_bytes()
    catalog = json.loads(catalog_bytes)['apis']
    focus = {api['id']: api for api in catalog if api['id'] > 641}
    sha = hashlib.sha256(catalog_bytes).hexdigest()
    report = {'definitionSha256': sha, 'catalogTotal': len(catalog), 'focusDefinitions': len(focus),
              'architectures': {}, 'criticalFailures': []}
    for arch in ('x64', 'x86'):
        api_results = []
        for group in sorted({group_for(api_id) for api_id in focus}):
            directory = report_root / 'results' / f'{arch}-{group}'
            data = json.loads((directory / 'capture.json').read_text(encoding='utf-8-sig'))['data']
            if not (data['completedRequestedInterval'] and data['cleanupComplete'] and data['stopWritten']):
                raise ValueError(f'Incomplete capture: {directory}')
            if int(data['invalidPacketCount']) or int(data['bufferDroppedCount']):
                raise ValueError(f'Capture loss: {directory}')
            processes = data['processes']
            if len(processes) != 1 or any(not p['coverageComplete'] or p['coverageStale'] or not p['hooksInstalled'] or not p['hooksRemoved']
                                          or int(p['agentDroppedCount']) for p in processes):
                raise ValueError(f'Invalid process coverage: {directory}')
            pid = processes[0]['pid']
            installed_times = [int(e['timestampFileTime']) for e in data['events'] if e['api'] == 'HooksInstalled']
            removed_times = [int(e['timestampFileTime']) for e in data['events'] if e['api'] == 'HooksRemoved']
            if not installed_times or not removed_times:
                raise ValueError(f'Missing capture boundaries: {directory}')
            # FILETIME observations are coarse. Avoid the install/remove clock
            # buckets, and pair each caller invocation with at most one event.
            active_begin = min(installed_times) + 200000
            # Hook removal confirmation follows restoration/coverage publishing;
            # caller activity after the requested interval must not be treated
            # as a missing event from an installed hook.
            active_end = min(max(removed_times), min(installed_times) + int(data['requestedDurationMs']) * 10000) - 200000
            calls, skips = read_trace(directory / 'trace.tsv')
            events, coverage = defaultdict(list), defaultdict(list)
            for event in data['events']:
                if event['eventKind'] == 0 and event['pid'] == pid:
                    events[event['apiId']].append(event)
            for row in processes[0]['coverage']:
                if row['hookKind'] == 0:
                    coverage[row['apiId']].append(row)
            for api_id, api in sorted(focus.items()):
                if group_for(api_id) != group:
                    continue
                baseline = [c for c in calls[api_id] if c['round'] == 0]
                monitored = [c for c in calls[api_id] if c['round'] > 0]
                active_calls = [c for c in monitored if c['begin'] >= active_begin and c['end'] <= active_end]
                observed, matched, mismatches = events[api_id], 0, []
                success_calls = failure_calls = 0
                valid_events = []
                for event in observed:
                    bad_identity = event['category'] != CATEGORIES[api['category']] or event['api'] != api['export']
                    bad_identity |= event['module'].lower() != api['module'][:-4].lower()
                    bad_identity |= event['definitionSha256'] != sha or not event['declarationCatalogMatchesAgent']
                    if bad_identity:
                        mismatches.append('identity/category/catalog mismatch')
                        continue
                    valid_events.append(event)
                used, unmatched_calls = set(), 0
                for call in active_calls:
                    candidates = [(i, e) for i, e in enumerate(valid_events) if i not in used
                                  and call['tid'] == e['tid']
                                  and call['begin'] <= int(e['timestampFileTime']) <= call['end']]
                    compatible = [(i, e) for i, e in candidates if e['returnValueAvailable'] and e['durationAvailable']
                                  and call['hasReturn'] and int(e['returnValue'], 16) == call['bits']
                                  and (e['resultKind'], e['resultCode']) == expected_result(api, call['bits'], call['error'])
                                  and (api_id != 831 or call['bits'] != 170 or 'reclaimed_discarded=1' in e['detail'])]
                    if not compatible:
                        unmatched_calls += 1
                        if candidates:
                            mismatches.append('caller return/status has no matching event')
                        continue
                    used.add(compatible[0][0])
                    matched += 1
                    if call_succeeded(api, call['bits']):
                        success_calls += 1
                    else:
                        failure_calls += 1
                states = sorted({row['state'] for row in coverage[api_id]})
                details = sorted({row['detail'] for row in coverage[api_id] if row['detail']})
                if mismatches:
                    status = 'contract_mismatch'
                elif not monitored:
                    status = 'not_called'
                elif not active_calls:
                    status = 'not_exercised_while_active'
                elif matched and not unmatched_calls:
                    status = 'verified'
                elif any(s in (0, 1, 8) for s in states):
                    status = 'installed_without_matched_event'
                elif states and all(s in (3, 4, 5, 6, 7) for s in states):
                    status = 'hook_unavailable'
                else:
                    status = 'unexplained_missing_event'
                item = {'id': api_id, 'module': api['module'], 'api': api['export'], 'category': api['category'],
                        'baselineCalls': len(baseline), 'monitoredCalls': len(monitored), 'events': len(observed),
                        'activeCalls': len(active_calls), 'unmatchedCalls': unmatched_calls,
                        'unattributedEvents': len(valid_events) - len(used),
                        'matchedEvents': matched, 'status': status, 'coverageStates': states,
                        'verifiedSuccessCalls': success_calls, 'verifiedFailureCalls': failure_calls,
                        'coverageDetails': details, 'skipReasons': sorted({s['reason'] for s in skips[api_id]}),
                        'mismatches': sorted(set(mismatches))}
                api_results.append(item)
                if status in ('contract_mismatch', 'installed_without_matched_event', 'unexplained_missing_event'):
                    report['criticalFailures'].append({'architecture': arch, **item})
        counts = Counter(item['status'] for item in api_results)
        report['architectures'][arch] = {'counts': dict(counts), 'attempted': sum(bool(i['monitoredCalls']) for i in api_results),
                                          'verifiedPrevious115': sum(i['status'] == 'verified' and i['id'] <= 800 for i in api_results),
                                          'verifiedNewBatch': sum(i['status'] == 'verified' and 801 <= i['id'] < 900 for i in api_results),
                                          'verifiedGuiBatch': sum(i['status'] == 'verified' and i['id'] >= 900 for i in api_results),
                                          'apis': api_results}
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report_root', type=Path)
    parser.add_argument('--definitions', type=Path, default=ROOT / 'APIMonitor_x64/api_monitor_definitions.json')
    args = parser.parse_args()
    result = analyze(args.report_root, args.definitions)
    (args.report_root / 'per-api-summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for arch, data in result['architectures'].items():
        print(arch, 'attempted=' + str(data['attempted']), data['counts'],
              'previous115=' + str(data['verifiedPrevious115']), 'previous65=' + str(data['verifiedNewBatch']),
              'gui77=' + str(data['verifiedGuiBatch']))
    print('CONTRACT_FAILURES=' + str(len(result['criticalFailures'])))
    raise SystemExit(bool(result['criticalFailures']))
