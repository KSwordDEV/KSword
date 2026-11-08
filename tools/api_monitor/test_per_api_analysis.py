"""Coverage counts require a matching caller, return, status and time window."""
import copy
import json
from pathlib import Path
import tempfile
from analyze_per_api_capture import analyze
import hashlib

api={'id':801,'module':'User32.dll','export':'DestroyMenu','category':'Window',
     'wrapper':{'kind':'generated','policy':'bool'},'return':{'success':'bool','error_source':'none'}}
with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary); catalog=root/'definitions.json'
    catalog.write_text(json.dumps({'apis':[api]}),encoding='utf-8')
    sha=hashlib.sha256(catalog.read_bytes()).hexdigest()
    packet={'eventKind':0,'pid':42,'tid':7,'apiId':801,'timestampFileTime':'15','category':14,
            'api':'DestroyMenu','module':'User32','definitionSha256':sha,
            'declarationCatalogMatchesAgent':True,'returnValueAvailable':True,'returnValue':'0x0',
            'durationAvailable':True,'resultKind':2,'resultCode':None,'detail':'call_failed=1 error=unavailable'}
    base={'completedRequestedInterval':True,'cleanupComplete':True,'stopWritten':True,'requestedDurationMs':1000,
          'invalidPacketCount':'0','bufferDroppedCount':'0','events':[packet],
            'processes':[{'pid':42,'coverageComplete':True,'coverageStale':False,'hooksInstalled':True,
                        'hooksRemoved':True,'agentDroppedCount':'0',
                        'coverage':[{'apiId':801,'hookKind':0,'state':8,'detail':''}]}]}
    for arch in ('x64','x86'):
        for group in ('window','memory-thread','service-security'):
            folder=root/'results'/f'{arch}-{group}';folder.mkdir(parents=True)
            (folder/'trace.tsv').write_text('CALL\t1\t801\t300010\t300020\t7\t1\t0\t23130\n')
            (folder/'capture.json').write_text(json.dumps({'data':base}))
    packet['timestampFileTime']='300015'
    base['events'] += [{'api':'HooksInstalled','timestampFileTime':'1','eventKind':0,'pid':42,'apiId':0},
                       {'api':'HooksRemoved','timestampFileTime':'900000','eventKind':0,'pid':42,'apiId':0}]
    for path in (root/'results').glob('*/capture.json'):
        path.write_text(json.dumps({'data':base}))
    def result(data):
        (root/'results/x64-window/capture.json').write_text(json.dumps({'data':data}))
        return analyze(root,catalog)['architectures']['x64']['apis'][0]
    assert result(base)['status']=='verified'
    changed=copy.deepcopy(base);extra=copy.deepcopy(packet)
    extra.update(returnValue='0x1',resultKind=0,resultCode=0)
    changed['events'].append(extra)
    assert result(changed)['status']=='verified'  # A separate cleanup call is not an oracle failure.
    trace=root/'results/x64-window/trace.tsv'
    trace.write_text('CALL\t1\t801\t300010\t300020\t7\t1\t0\t23130\n'*2)
    assert result(base)['status']=='installed_without_matched_event'  # One event cannot verify two calls.
    trace.write_text('CALL\t1\t801\t300010\t300020\t7\t1\t0\t23130\n')
    for field,value in [('tid',8),('timestampFileTime','30')]:
        changed=copy.deepcopy(base);changed['events'][0][field]=value
        assert result(changed)['status']=='installed_without_matched_event'
    for field,value in [('returnValue','0x1'),('resultKind',0),('category',4),('definitionSha256','wrong')]:
        changed=copy.deepcopy(base);changed['events'][0][field]=value
        assert result(changed)['status']=='contract_mismatch',field
    changed=copy.deepcopy(base);changed['events']=[e for e in changed['events'] if e['api']!='DestroyMenu'];changed['processes'][0]['coverage'][0].update(state=7,detail='unsupported entry')
    assert result(changed)['status']=='hook_unavailable'
    print('PASS: caller/thread/time/return/status/category/catalog mismatch detection; unavailable is not verified')
