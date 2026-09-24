import copy
import json
import pathlib
import subprocess
from analyze_npt_cache import compare

root = pathlib.Path(__file__).resolve().parents[2]
first = json.loads(subprocess.check_output([str(root / 'tools/hvm_ctl/test_query_json.exe'), 'metrics']))
first['snapshotBeginQpc'] = '10000000'
second = copy.deepcopy(first)
second['snapshotBeginQpc'] = '20000000'
cache = second['svmProcessors'][0]['nptCache']
for key, value in [('lookups', 10), ('hits', 7), ('resets', 3)]:
    cache[key] = str(int(cache[key]) + value)
cache['reasons']['ownerChanged'] = str(int(cache['reasons']['ownerChanged']) + 3)
result = compare(first, second)
assert result['completeCpuCoverage'] and result['hitFraction'] == 0.7
assert result['entryResetsPerSecond'] == 3 and result['reasons']['ownerChanged'] == 3
for key, value in [('valid', 0), ('sequence', '3'), ('saturated', 1), ('hits', '0')]:
    bad = copy.deepcopy(second)
    bad['svmProcessors'][0]['nptCache'][key] = value
    result = compare(first, bad)
    assert not result['completeCpuCoverage'] and result['entryResetsPerSecond'] is None
for kind in ('generation', 'accounting'):
    bad = copy.deepcopy(second)
    if kind == 'generation':
        bad['svmProcessors'][0]['generation'] += 1
    else:
        bad['svmProcessors'][0]['nptCache']['lookups'] = '9999999999'
    assert compare(first, bad)['excludedCpus']
for kind in ('version', 'duplicate', 'clock'):
    bad = copy.deepcopy(second)
    if kind == 'version': bad['version'] = 7
    if kind == 'duplicate': bad['svmProcessors'] *= 2
    if kind == 'clock': bad['snapshotBeginQpc'] = first['snapshotBeginQpc']
    try:
        compare(first, bad)
    except ValueError:
        continue
    raise AssertionError(kind)
print('NPT_CACHE_ANALYSIS=PASS (synthetic snapshots)')
