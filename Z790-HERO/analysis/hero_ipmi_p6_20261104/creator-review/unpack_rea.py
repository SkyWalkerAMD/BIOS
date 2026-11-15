from pathlib import Path
import json
P=Path(__file__).resolve().parent
out=P/'decompiled';out.mkdir(exist_ok=True)
index=[]
for path in sorted(P.glob('rea-*/responses/*.json')):
 response=json.loads(path.read_text(encoding='utf-8')).get('result',{})
 evidence=response.get('structuredContent')
 if evidence is None:
  for content in response.get('content',[]):
   if content.get('type')=='text':
    try:evidence=json.loads(content['text']);break
    except ValueError:pass
 if not isinstance(evidence,dict) or not evidence.get('evidence_id'):continue
 subject=evidence.get('subject',{})
 normalized=evidence.get('normalized_result',{})
 row={'response':str(path.relative_to(P)),'evidence_id':evidence['evidence_id'],
      'operation':evidence.get('operation'),'subject':subject,'functions':[]}
 items=normalized.get('items',[]) if isinstance(normalized,dict) else []
 for item in items:
  if item.get('pseudocode'):
   dest=out/f"{Path(subject.get('name','unknown')).stem}-{item['address']}.c"
   dest.write_text(item['pseudocode'].replace('\r\n','\n'),encoding='utf-8')
   row['functions'].append({'address':item['address'],'file':str(dest.relative_to(P))})
  elif item.get('status')=='error':row.setdefault('failed_functions',[]).append(item.get('address'))
 if evidence.get('operation')=='list_procedures':row['procedures']=[x['address'] for x in normalized]
 index.append(row)
(P/'rea-evidence-index.json').write_text(json.dumps(index,indent=2)+'\n',encoding='utf-8')
for row in index:print(row['response'],row['operation'],len(row.get('functions',[])),row.get('procedures',''))
