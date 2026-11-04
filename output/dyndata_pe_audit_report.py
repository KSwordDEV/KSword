import collections
import json
import pathlib

out=pathlib.Path('output/dyndata-pe-audit')
pack=json.loads(pathlib.Path('Ksword5.1/Ksword5.1/profiles/ark_dyndata_pack_v4.json').read_bytes())
index=collections.defaultdict(list)
for p in pack['profiles']:
    if p['moduleClassId']!=0: continue
    key=(p['machine'],p['timeDateStamp'],p['sizeOfImage'],p['pdbGuid'].replace('-','').upper(),p['pdbAge'])
    index[key].append(p)
original=[json.loads(x) for x in (out/'results.jsonl').read_text(encoding='utf8').splitlines()]
retry={x['path']:x for x in (json.loads(y) for y in (out/'retry-results.jsonl').read_text(encoding='utf8').splitlines())}
rows=[retry.get(r['path'],r) for r in original]
totals=collections.Counter(); fields=collections.defaultdict(collections.Counter); mismatch=[]; changed=[]
for r in rows:
    totals[r['status']]+=1
    if r['status']!='compared': continue
    same=[p for p in index.get(tuple(r['identity']),[]) if p.get('sha256','').lower()==r['sha256']]
    if len(same)>1: totals['duplicate_pack_identity']+=1; continue
    if same:
        totals['published_reference']+=1
        values={v['name']:v['valueLow']+(v['valueHigh']<<32) for v in same[0]['items']}
        r['reference_source']='published:'+same[0]['profileName']
        for name,x in r['results'].items():
            v=values.get(name)
            if x['reference']!=v: changed.append({'path':r['path'],'field':name,'corpus':x['reference'],'published':v})
            x['reference']=v
            x['status']=('both_missing' if x['candidate'] is None else 'reference_missing') if v is None else 'candidate_unavailable' if x['candidate'] is None else 'match' if x['candidate']==v else 'mismatch'
    else:
        totals['corpus_reference']+=1; r['reference_source']='corpus:'+r['profile']
    for name,x in r['results'].items():
        fields[name][x['status']]+=1; totals[x['status']]+=1
        if x['status']=='mismatch': mismatch.append({'path':r['path'],'field':name,**x})
summary={'pe_files':len(rows),'totals':dict(totals),'fields':{k:dict(v) for k,v in fields.items()},'mismatches':mismatch,'published_vs_corpus_changes':changed,'uncompared':[r for r in rows if r['status']!='compared']}
(out/'final-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
with (out/'final-results.jsonl').open('w',encoding='utf8') as f:
    for r in rows:f.write(json.dumps(r,ensure_ascii=False)+'\n')
lines=['# NTOS 离线动态偏移核对','',f"映像文件：{len(rows)}；可比较：{totals['compared']}；无法匹配参考或读取失败：{len(rows)-totals['compared']}。",f"参考来源：新版发布包 {totals['published_reference']} 个，F 盘散装导出 {totals['corpus_reference']} 个。",f"字段候选与参考一致：{totals['match']}；不一致：{totals['mismatch']}；候选不可用：{totals['candidate_unavailable']}；参考缺失：{totals['reference_missing']}；两者均不可用：{totals['both_missing']}。",'', '同一 PE 的 machine、时间戳、映像大小、RSDS GUID/Age 和 SHA256 必须对应参考。生产访问器解码器原样编译；栈、保护和签名代码形态按驱动对应实现离线提取。结果为静态候选，不含驱动现场对象、容器和生命周期校验。新版包优先；未被新版包覆盖时使用身份及哈希一致的 F 盘导出。发布包 JSON SHA256：15b6510660ea0f211dff46318672d9bb7e0cd8bcd833b989de49016f31a560cf。', '', '| 字段 | 一致 | 不一致 | 候选不可用 | 参考缺失 | 两者均无 |', '|---|---:|---:|---:|---:|---:|']
for name,c in sorted(fields.items()): lines.append(f"| {name} | {c['match']} | {c['mismatch']} | {c['candidate_unavailable']} | {c['reference_missing']} | {c['both_missing']} |")
lines += ['',f"上述受检字段在发布包与对应旧导出中的参考值差异：{len(changed)} 条；逐映像逐字段明细见 final-results.jsonl。",'', '以下映像未找到精确对应的发布包或 F 盘散装导出，未进行字段比较：']
for r in rows:
    if r['status']!='compared': lines.append(f"- {pathlib.Path(r['path']).parts[-3]}，SHA256 `{r.get('sha256','不可用')}`")
lines += ['', '目录下另有 6 个版本目录没有任何 PE 文件：10.0.19041.1200、10.0.20348.2652、10.0.22621.4036、10.0.22621.4111、10.0.22621.4387、10.0.26100.3025。', '', '注：无法从静态 PE 验证的动态链表、令牌、进程、线程、回调容器等现场解析不在上述字段覆盖范围。']
(out/'report.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
print(json.dumps({'totals':dict(totals),'changes':len(changed),'mismatch':len(mismatch)},ensure_ascii=False))
