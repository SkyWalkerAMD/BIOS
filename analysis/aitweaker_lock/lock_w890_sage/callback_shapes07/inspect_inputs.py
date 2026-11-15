from pathlib import Path
import json,zipfile,collections
H=Path(__file__).resolve().parent;B=H.parent
j=json.loads((B/'foreign_hii05/decoded/Setup_0.json').read_text())
q=[r for r in j['records']if 'question_id'in r]
print('first_question',json.dumps(q[0]))
print('question_count',len(q),'opcode_counts',dict(collections.Counter(r['op']for r in q)))
with zipfile.ZipFile(B/'integration05/parser-snapshot.zip')as z:
 s=json.loads(z.read('state.json'));print('snapshot_keys',list(s));print('snapshot_first_pages',json.dumps(s['pages'][:2]))
