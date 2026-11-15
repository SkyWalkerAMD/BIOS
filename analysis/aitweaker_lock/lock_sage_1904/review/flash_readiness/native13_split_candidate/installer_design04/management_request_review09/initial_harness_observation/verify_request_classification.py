"""Actual frozen07 predicates and polling with explicit service/provider models."""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;C07=D04/'static_chrome_candidate07'
source=(C07/'verify_chrome.py').read_text(encoding='utf8').split('\nchecks=[];observations=[]',1)[0]
ns={'__file__':str(C07/'verify_chrome.py')};exec(compile(source,str(C07/'verify_chrome.py')+' [prefix only]','exec'),ns)
V,S,q,d,w,TSE,HEAP=[ns[x]for x in ['ChromeVM','S','q','d','w','TSE','HEAP']]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(C07/'build/guard_template.bin')=='2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa'
rows=[]
def run(name,kind=1,change=None,expected=0,polls=1):
 v=V(kind);v.provider_present=True;v.provider_bits=3;v.request_accept=False
 v.u.mem_write(TSE+0x83468,q(5))
 if change:change(v)
 frame_result=v.call(S['AMITSE']['frame_protected'],v.frame)
 page_result=v.call(S['AMITSE']['page_protected'],v.page)
 def signed(x):return -1 if x in [0xffffffff,0xffffffffffffffff] else x
 assert signed(page_result)==expected,(name,hex(page_result))
 for _ in range(polls):v.call(S['AMITSE']['gate_poll'])
 assert v.provider_calls['request']==(polls if expected else 0),name
 assert v.provider_calls['manage']==0,name
 assert v.calls['poll']==(0 if expected else polls),name
 assert bytes(v.u.mem_read(v.app+0x5a,1))==b'\0',name
 rows.append({'name':name,'frame_kind':kind,'frame_class':signed(frame_result),'page_class':signed(page_result),
  'poll_invocations':polls,'request_calls':v.provider_calls['request'],'manage_calls':0,
  'original_poll_calls':v.calls['poll'],'exit_flag':0,
  'control_vtable_rva':hex(v.getq(v.control)-TSE),'control_source_hii':hex(v.getq(v.control+0x20)),
  'control_callback_fields':[hex(v.getq(v.control+x))for x in [8,16,24]],
  'control_kind_field':v.getd(v.control+0x6c),'control_type':int.from_bytes(v.u.mem_read(v.control+0x34,2),'little')})
 print('PASS '+name,flush=True)

for kind in [1,2,3,5]:run(f'known foreign Form1 with exact native subtitle kind{kind}',kind)
run('foreign owner does not turn a protected numeric FormId into Setup ownership',change=lambda v:v.u.mem_write(v.records+10,w(0x2714)))
def setup_page(v):
 v.u.mem_write(v.page+0x20,q(v.handle));v.u.mem_write(v.records+10,w(0x2714))
run('actual protected Setup page also requests',change=setup_page,expected=1)
run('missing page-form table produces unknown and requests',change=lambda v:v.u.mem_write(TSE+0x930b0,q(0)),expected=-1)
run('out-of-range page-record index produces unknown and requests',change=lambda v:v.u.mem_write(v.page+0x30,w(1)),expected=-1)
run('unknown page HII owner requests',change=lambda v:v.u.mem_write(v.page+0x20,q(0x98886644)),expected=-1)
run('known subtitle with null source stays unknown and requests',change=lambda v:v.u.mem_write(v.control+0x20,q(0)),expected=-1)
run('native kind4 own AMITSE string HII cannot resolve ConfigAccess; repeats request',kind=4,expected=-1,polls=2)
run('kind4 with modeled foreign ConfigAccess source passes generic classification',kind=4,change=lambda v:v.u.mem_write(v.control+0x20,q(0x99998888)))
run('known subtitle write-protection refusal remains unknown',change=lambda v:v.memory_deny.append((v.control,v.control+0x88,1)),expected=-1)

report={'status':'PASS_BOUNDED_ACTUAL_GUARD_REQUEST_CLASSIFICATION_NOT_PHYSICAL_CAUSE',
 'cases':len(rows),'rows':rows,'guard_template_sha256':sha(C07/'build/guard_template.bin'),
 'source_sha256':sha(Path(__file__)),
 'finding':'The same Request endpoint is reached by true protected pages and several distinct unknown classifications. Original kind4 creation supplies AMITSE string HII without ConfigAccess, which the frozen generic path cannot classify. A read-only actual-state trace is necessary before physical attribution.',
 'models':['HII database, ConfigAccess and provider Query/Request denial endpoints; gate_memory ranges; allocator/CopyMem/color helpers; original poll endpoint counter.',
 'Only kind1/2/3/4/5 original frame construction executes, with a synthetic single-page container and synthetic global table. Actual P14 provider implementation and original ASUS full browser body do not execute here.'],
 'not_a_fix':'No allow rule, provider, guard, installer or firmware image is changed. The modeled foreign source substitution is a control experiment only, not proposed for production.'}
(HERE/'request_classification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'cases':len(rows)}))
