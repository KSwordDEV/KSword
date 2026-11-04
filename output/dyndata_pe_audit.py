import collections
import ctypes
import hashlib
import gc
import json
import pathlib
import struct
import sys
import time
import uuid

import pefile

ROOT = pathlib.Path(r'F:\KswordPDB\PDB')
OUT = pathlib.Path('output/dyndata-pe-audit')
OUT.mkdir(exist_ok=True)
DIRECT = {
    'EpUniqueProcessId':'PsGetProcessId', 'EpImageFileName':'PsGetProcessImageFileName',
    'EpCreateTime':'PsGetProcessCreateTimeQuadPart', 'EpExitStatus':'PsGetProcessExitStatus',
    'EpPeb':'PsGetProcessPeb', 'EpWin32Process':'PsGetProcessWin32Process',
    'EpWow64Process':'PsGetProcessWow64Process',
    'EpInheritedFromUniqueProcessId':'PsGetProcessInheritedFromUniqueProcessId',
    'EpSectionBaseAddress':'PsGetProcessSectionBaseAddress', 'EpJob':'PsGetProcessJob',
    'EpDebugPort':'PsGetProcessDebugPort', 'EpPriorityClass':'PsGetProcessPriorityClass',
    'EpActiveThreads':'PsGetProcessActiveThreadCount',
    'EpWin32WindowStation':'PsGetProcessWin32WindowStation',
    'EpSecurityPort':'PsGetProcessSecurityPort', 'KtProcess':'PsGetThreadProcess',
    'EtStartAddress':'PsGetThreadStartAddress', 'EtWin32StartAddress':'PsGetThreadWin32StartAddress',
    '_ThreadProcessId':'PsGetThreadProcessId', '_ThreadId':'PsGetThreadId',
}
STACK = {'KtInitialStack':'IoGetInitialStack', 'KtStackLimit':'PsGetCurrentThreadStackLimit',
         'KtStackBase':'PsGetCurrentThreadStackBase'}
class Result(ctypes.Structure):
    _fields_ = [('offset', ctypes.c_int32), ('kind', ctypes.c_int)]
READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte))
decoder = ctypes.CDLL(str((OUT/'accessor.dll').resolve()))
decoder.KswordARKResolveAccessorDisplacement.argtypes = [READ, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Result)]
decoder.KswordARKResolveAccessorDisplacement.restype = ctypes.c_int

profiles = collections.defaultdict(list)
for path in (ROOT/'profiles/ark_dyndata').glob('ntos*.json'):
    try:
        p=json.loads(path.read_bytes()); m=p['module']
        profiles[(m['machine'], m['timeDateStamp'], m['sizeOfImage'], m['pdbGuid'].replace('-','').upper(), m['pdbAge'])].append((p,path.name))
    except Exception as ex:
        print('PROFILE_ERROR',path,repr(ex),flush=True)

# The current published pack can include identities newer than the corpus's
# scattered exports. Prefer it where exact PE and PDB identities and SHA match.
published=json.loads(pathlib.Path('Ksword5.1/Ksword5.1/profiles/ark_dyndata_pack_v4.json').read_bytes())
for item in published['profiles']:
    if item['moduleClassId'] != 0: continue
    key=(item['machine'],item['timeDateStamp'],item['sizeOfImage'],item['pdbGuid'].replace('-','').upper(),item['pdbAge'])
    p={'module':{'sha256':item.get('sha256','')},'v4Items':[{'name':v['name'],'value':v['valueLow']+(v['valueHigh']<<32)} for v in item['items']]}
    profiles[key].insert(0,(p,'published:'+item['profileName']))

def candidate_protection(b):
    found=set()
    for i in range(len(b)-6):
        if b[i:i+2]==b'\x8a\x81': pos=i+2; end=i+6
        elif b[i:i+3]==b'\x0f\xb6\x81' and i+8<=len(b): pos=i+3; end=i+7
        else: continue
        v=struct.unpack_from('<i',b,pos)[0]
        if 0<v<=0xfff and end<len(b) and b[end]==0xc3: found.add(v)
    return next(iter(found)) if len(found)==1 else None

def signature(b,protect):
    sig=set(); sec=set()
    for i in range(len(b)-7):
        if b[i:i+2]!=b'\x8a\x81': continue
        v=struct.unpack_from('<i',b,i+2)[0]
        if not 0<v<=0xfff: continue
        if b[i+6:i+8]==b'\x88\x02': sec.add(v)
        if b[i+6]==0xc3: sig.add(v)
    if len(sig)==len(sec)==1:
        a=next(iter(sig)); s=next(iter(sec))
        if a+1==s and s+1==protect: return a,s
    return None,None

def stack(b):
    if len(b)<32 or b[:9]!=bytes.fromhex('65 48 8b 04 25 88 01 00 00'): return None
    if b[9:12]==bytes.fromhex('48 8b 40'): v=b[12]; end=13
    elif b[9:12]==bytes.fromhex('48 8b 80'): v=struct.unpack_from('<i',b,12)[0]; end=16
    else: return None
    # KSW_RUNTIME_THREAD_SCAN_BYTES in process_resolver.c
    return v if 0<v<=0x1000 and b[end]==0xc3 else None

counts=collections.Counter(); fieldcounts=collections.defaultdict(collections.Counter); examples=collections.defaultdict(list)
if len(sys.argv)>1 and sys.argv[1]=='--retry-unmatched':
    previous=[json.loads(line) for line in (OUT/'results.jsonl').read_text(encoding='utf8').splitlines()]
    paths=[pathlib.Path(row['path']) for row in previous if row['status'] in ('no_unique_profile','error')]
    result_name='retry-results.jsonl'; summary_name='retry-summary.json'
else:
    paths=sorted((ROOT/'pe-store/amd64/ntoskrnl.exe').rglob('ntoskrnl.exe'))
    if len(sys.argv)>1: paths=paths[:int(sys.argv[1])]
    result_name='results.jsonl'; summary_name='summary.json'
start=time.monotonic()
with (OUT/result_name).open('w',encoding='utf-8') as out:
  for n,path in enumerate(paths,1):
    row={'path':str(path),'results':{}}
    try:
      for attempt in range(6):
        try:
          raw=path.read_bytes(); break
        except OSError:
          if attempt==5: raise
          time.sleep(1.0)
      sha=hashlib.sha256(raw).hexdigest(); pe=pefile.PE(data=raw,fast_load=True)
      pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
      rsds=[]
      for d in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
        s=d.struct; b=raw[s.PointerToRawData:s.PointerToRawData+s.SizeOfData]
        if b[:4]==b'RSDS' and len(b)>=24: rsds.append((uuid.UUID(bytes_le=b[4:20]).hex.upper(),struct.unpack_from('<I',b,20)[0]))
      key=(pe.FILE_HEADER.Machine,pe.FILE_HEADER.TimeDateStamp,pe.OPTIONAL_HEADER.SizeOfImage,*rsds[0]) if len(rsds)==1 else None
      matched=profiles.get(key,[]); exact=[p for p in matched if p[0]['module'].get('sha256','').lower()==sha]
      row.update(sha256=sha,identity=key,identity_profiles=len(matched),sha_profiles=len(exact))
      counts['pe_read']+=1
      if not exact:
        counts['no_unique_profile']+=1; row['status']='no_unique_profile'
        out.write(json.dumps(row,ensure_ascii=False)+'\n'); continue
      profile=exact[0][0]; row['profile']=exact[0][1]; values={i['name']:i['value'] for i in profile['v4Items']}; counts['matched']+=1
      exports={e.name.decode('ascii'):e.address for e in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[]) if e.name and not e.forwarder}
      sections=[(s.VirtualAddress,s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData),s) for s in pe.sections if s.Characteristics & 0x20000000]
      def read_rva(rva,size):
        try:
          sec=next(s for lo,hi,s in sections if lo<=rva and rva+size<=hi)
          delta=rva-sec.VirtualAddress
          if delta+size>sec.SizeOfRawData: return b''
          off=sec.PointerToRawData+delta
          return raw[off:off+size]
        except StopIteration: return b''
      @READ
      def readcode(_ctx,addr,dest):
        b=read_rva(addr,1)
        if len(b)!=1: return 0
        dest[0]=b[0]; return 1
      candidates={}
      for field,export in DIRECT.items():
        rva=exports.get(export); result=Result()
        candidates[field]=(result.offset if rva and decoder.KswordARKResolveAccessorDisplacement(readcode,None,rva,ctypes.byref(result)) else None)
      tp=candidates.pop('_ThreadProcessId'); ti=candidates.pop('_ThreadId')
      candidates['EtCid']=tp if tp and ti==tp+8 else None
      for field,export in STACK.items(): candidates[field]=stack(read_rva(exports.get(export,0),32))
      p=candidate_protection(read_rva(exports.get('PsGetProcessProtection',0),32))
      candidates['EpProtection']=p
      a,b=signature(read_rva(exports.get('PsGetProcessSignatureLevel',0),32),p)
      candidates['EpSignatureLevel']=a; candidates['EpSectionSignatureLevel']=b
      # Exported global: runtime also validates the live list; static RVA is a candidate.
      candidates['PsLoadedModuleList']=exports.get('PsLoadedModuleList')
      for field,v in candidates.items():
        expected=values.get(field)
        status=('both_missing' if v is None else 'reference_missing') if expected is None else 'candidate_unavailable' if v is None else 'match' if v==expected else 'mismatch'
        row['results'][field]={'candidate':v,'reference':expected,'status':status}
        fieldcounts[field][status]+=1; counts[status]+=1
        if status=='mismatch' and len(examples[field])<8: examples[field].append({'path':str(path),'candidate':v,'reference':expected})
      row['status']='compared'
    except Exception as ex:
      import traceback
      counts['error']+=1; row['status']='error'; row['error']=repr(ex); row['traceback']=traceback.format_exc()
    out.write(json.dumps(row,ensure_ascii=False)+'\n')
    gc.collect()
    if n%100==0: print('progress',n,'/',len(paths),'matched',counts['matched'],'errors',counts['error'],'seconds',int(time.monotonic()-start),flush=True)
summary={'total_files':len(paths),'counts':dict(counts),'fields':{k:dict(v) for k,v in fieldcounts.items()},'mismatch_examples':dict(examples),'seconds':time.monotonic()-start}
(OUT/summary_name).write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8')
print(json.dumps(summary,ensure_ascii=False),flush=True)
