from pathlib import Path
import json
HERE=Path(__file__).resolve().parent
summary=[]
for p in sorted(HERE.glob('rea*/response-*.json')):
 r=json.loads(p.read_text())
 if r.get('isError'):
  summary.append(dict(file=str(p.relative_to(HERE)),failed=True));continue
 s=r['structuredContent'];n=s.get('normalized_result')
 if s.get('operation')=='analyze_function':
  label=s['parameters']['procedure'].replace('0x','fn_')
  (HERE/'rea_text'/f'{label}.c').write_text(n['pseudocode'].replace('\r',''),encoding='utf-8',newline='\n')
  (HERE/'rea_text'/f'{label}.asm.json').write_text(json.dumps(n['assembly'],indent=2)+'\n')
  summary.append(dict(file=p.name,evidence=s['evidence_id'],procedure=n['procedure'],callers=n['callers'],callees=n['callees']))
 elif s.get('operation')=='xrefs':summary.append(dict(file=p.name,evidence=s['evidence_id'],address=s['parameters']['address'],references=n))
(HERE/'rea_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(dict(records=len(summary))))
