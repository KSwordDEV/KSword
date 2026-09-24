"""Compare two metrics-v8 snapshots; invalid rows never become zero activity."""
import argparse
import json
import pathlib

COUNTERS = ('lookups', 'hits', 'resets', 'resetFailures', 'tlbRequests', 'invlpgaCount', 'poolRecycles')


def read(path):
    raw = pathlib.Path(path).read_bytes()
    return json.loads(raw.decode('utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8-sig'))


def compare(first, second):
    for snapshot in (first, second):
        if snapshot.get('version') != 9 or snapshot.get('backend') != 2:
            raise ValueError('Matching AMD metrics v9 snapshots required')
    frequency = int(first['qpcFrequency'])
    ticks = int(second['snapshotBeginQpc']) - int(first['snapshotBeginQpc'])
    if frequency <= 0 or frequency != int(second['qpcFrequency']) or ticks <= 0:
        raise ValueError('Incomparable clock intervals')

    def indexed(snapshot):
        rows = snapshot['svmProcessors']
        result = {(r['group'], r['number']): r for r in rows}
        if len(result) != len(rows) or not rows:
            raise ValueError('Empty or duplicate CPU set')
        return result

    a, b = indexed(first), indexed(second)
    if a.keys() != b.keys():
        raise ValueError('CPU topology changed')
    totals = dict.fromkeys(COUNTERS, 0)
    causes, included, excluded = {}, [], []
    for cpu in sorted(a):
        x, y = a[cpu].get('nptCache', {}), b[cpu].get('nptCache', {})
        reason = None
        if a[cpu]['generation'] != b[cpu]['generation']:
            reason = 'generation changed'
        elif any(r.get('valid') != 1 or not int(r.get('sequence', 0)) or
                 int(r.get('sequence', 0)) & 1 for r in (x, y)):
            reason = 'incoherent snapshot'
        elif x.get('saturated') != 0 or y.get('saturated') != 0:
            reason = 'saturated counters'
        elif x['reasons'].keys() != y['reasons'].keys() or len(x['reasons']) != 18:
            reason = 'incomplete reasons'
        else:
            delta = {k: int(y[k]) - int(x[k]) for k in COUNTERS}
            changes = {k: int(y['reasons'][k]) - int(x['reasons'][k]) for k in x['reasons']}
            if any(v < 0 for v in (*delta.values(), *changes.values())):
                reason = 'counter reset'
            elif delta['lookups'] != delta['hits'] + delta['resets'] + delta['resetFailures']:
                reason = 'counter accounting mismatch'
        if reason:
            excluded.append({'cpu': cpu, 'reason': reason})
            continue
        included.append(cpu)
        for key, value in delta.items():
            totals[key] += value
        for key, value in changes.items():
            causes[key] = causes.get(key, 0) + value
    seconds = ticks / frequency
    return {'seconds': seconds, 'includedCpus': included, 'excludedCpus': excluded,
            'completeCpuCoverage': len(included) == len(a), 'deltas': totals,
            'hitFraction': totals['hits'] / totals['lookups'] if totals['lookups'] else None,
            'entryResetsPerSecond': totals['resets'] / seconds if included else None,
            'reasons': causes, 'reasonsOverlap': True,
            'note': 'Entry reasons can overlap. Epoch changes may follow INVLPGA/pool recycling; do not sum causes as independent resets. This is not a boot/performance pass.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('first')
    parser.add_argument('second')
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    output = json.dumps(compare(read(args.first), read(args.second)), indent=2) + '\n'
    if args.output:
        args.output.write_text(output, encoding='utf-8')
    print(output, end='')
