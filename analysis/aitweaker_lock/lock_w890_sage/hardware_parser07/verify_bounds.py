"""Compare both loop comparisons with the earlier unmodified and tail-only tests."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parent
p=B/'parser_review06/boundary_contract.py'
t=p.read_text();assert t.count('\nresults=')==1
prefix=t.split('\nresults=')[0]
ns={'__file__':str(p),'__name__':'boundary_model_definitions_only'}
exec(compile(prefix,str(p),'exec'),ns)
original_run=ns['run']
needle='    if strict_end:\n'
assert prefix.count(needle)==1
replacement=needle+"        assert bytes(u.mem_read(TSE+0x41010,6))==bytes.fromhex('0f8223010000')\n        u.mem_write(TSE+0x41010,bytes.fromhex('0f8623010000'))\n"
exec(compile(prefix.replace(needle,replacement),'both_bounds_explicit_model','exec'),ns)
both_run=ns['run']
results=[]
for count in (0,1,2,379):
 for mode in ('original','tail_only','both_comparisons'):
  r=(both_run if mode=='both_comparisons' else original_run)(count,mode!='original')
  r['mode']=mode
  safe=(mode=='both_comparisons') or count==0 or (mode=='tail_only' and count>=2)
  if safe:
   assert r['stopped']['kind']=='LOOP_EXIT' and r['indices']==list(range(1,count))
  else:
   assert r['stopped']['kind']=='DECLARED_ARRAY_BOUND' and r['indices'][-1]==count
  results.append(r)
out={'status':'PASS_TWELVE_ACTUAL_LOOP_CONTRACTS','results':results,
 'original_boundary_model_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
 'original_model_source':str(p),
 'patches_emulator_only':[{'rva':'0x41010','before':'0f8223010000','after':'0f8623010000'},
                        {'rva':'0x4112c','before':'0f86eefeffff','after':'0f82eefeffff'}],
 'limits':['The isolated41DCC lookup deliberately returns a synthetic-last-package index, suppressing output mutation.',
           'Count0/1/2 are semantic boundary probes; the shipped layout count remains379.',
           'This verifies loop comparisons, not arbitrary corrupt count/offset safety or allocator ownership.',
           'No original file, deployment PE, capsule or hardware was changed.']}
(H/'bounds_tests.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'status':out['status'],'cases':len(results)}))
