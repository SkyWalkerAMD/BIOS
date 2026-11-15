"""Independent regression of concrete review findings on final local bytes."""
from pathlib import Path
import hashlib,json,re,sys,zlib
HERE=Path(__file__).resolve().parent;D04=HERE.parent;CANDIDATE=D04/'static_chrome_candidate07'
FINAL=HERE/'input_2aef4bfc';HASH='2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
if not(FINAL/'snapshot.json').exists():
 meta=json.loads((CANDIDATE/'build/split_build.json').read_text());assert meta['template_sha256']==HASH
 rows=[]
 selected=list((CANDIDATE/'source').glob('*'))+[CANDIDATE/x for x in ['verify_split.py','verify_chrome.py','build_split.py','generate_chrome_identity.py','native_chrome_identity.json']]
 selected += [p for p in (CANDIDATE/'build').iterdir()if p.is_file()and (p.suffix in ['.bin','.pe','.obj','.map']or p.name in ['split_build.json','chrome_verification.json'])]
 for p in selected:
  rel=p.relative_to(CANDIDATE);out=FINAL/rel;out.parent.mkdir(parents=True,exist_ok=True);raw=p.read_bytes();out.write_bytes(raw)
  rows.append({'path':rel.as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
 (FINAL/'snapshot.json').write_text(json.dumps({'scope':'Final local classifier bytes only; no provider/app','files':rows},indent=2)+'\n')
source=(HERE/'independent_cases.py').read_text().split('\nv=ChromeVM();assert',1)[0]
source=source.replace("SNAP=HERE/'input_candidate'","SNAP=HERE/'input_2aef4bfc'")
scope={'__file__':str(HERE/'independent_cases.py')}
exec(compile(source,str(HERE/'independent_cases.py')+' [final input path]','exec'),scope)
V,U,R,TSE,HEAP,S,q,d,w,ns=[scope[x]for x in ['ChromeVM','U','R','TSE','HEAP','S','q','d','w','ns']]
assert ns['SPLIT_META']['template_sha256']==HASH
rows=[]
def check(name,condition):
 assert condition,name
 rows.append({'case':name,'status':'PASS'})
 print(name,flush=True)
def denied(value):return value in [0xffffffff,0xffffffffffffffff]
for kind in [1,2,3,5]:
 v=V(kind);check(f'original_constructor_kind{kind}_sentinel_allowed',v.classified()==0)
 for origin,hii in [('setup',v.handle),('foreign',0x99998888),('amitse',v.amih)]:
  v.u.mem_write(v.control+0x20,q(hii));check(f'kind{kind}_valid_source_{origin}',v.classified()==0)

for slot in range(10):
 v=V();v.u.mem_write(TSE+0x6b8b8+8*slot,q(TSE+0x11164))
 check(f'frame_method_slot{slot}_mutation_now_denied',denied(v.classified()))

for name,mutate in [
 ('object_callback',lambda v:v.u.mem_write(v.control+8,q(TSE+0x11164))),
 ('expression',lambda v:v.u.mem_write(v.control+0x50,q(v.ifr))),
 ('control_vtable',lambda v:v.u.mem_write(v.control,q(TSE+0x6bbe0))),
 ('question_opcode',lambda v:v.u.mem_write(v.ifr,b'\x05')),
]:
 for source in ['sentinel','setup','foreign','amitse']:
  v=V();hii={'sentinel':0xffffffffffffffff,'setup':v.handle,'foreign':0x99998888,'amitse':v.amih}[source]
  v.u.mem_write(v.control+0x20,q(hii));mutate(v)
  check(f'{name}_{source}_does_not_fall_back_to_generic',denied(v.classified()))

for name,field in [('frame','frame'),('control','control'),('ifr','ifr')]:
 v=V(5);p=getattr(v,field);n={'frame':0x78,'control':0x88,'ifr':7}[name]
 v.memory_deny.append((p,p+n,1));check(f'read_only_kind5_{name}_denied',denied(v.classified()))
for where,label in [(0x14a80,'frame_render_body'),(0x1532f,'frame_input_body'),(0x15320,'frame_input_detour_opcode'),(0x1532e,'frame_input_detour_padding')]:
 v=V();v.u.mem_write(TSE+where,b'\xcc');check(label+'_mutation_denied',denied(v.classified()))

# Valid parent Ai form protection must dominate any verified chrome exemption.
v=V();v.u.mem_write(v.page+0x20,q(v.handle));v.u.mem_write(v.records+10,w(0x2714))
check('protected_parent_Ai_form_stays_protected',v.call(S['AMITSE']['page_protected'],v.page)==1)
# An invalid claimed-static frame remains denied even with no safe destination;
# preserving this state is evidence of the remaining unwind gap, not success.
v=V();v.u.mem_write(v.control+8,q(TSE+0x11164));key=HEAP+0x26c000
v.u.mem_write(key+8,w(1));v.u.mem_write(key+12,w(0x17))
before=bytes(v.u.mem_read(v.app,0x60))
for name,args in [('gate_render',[v.page]),('gate_page_input',[v.page,key]),('gate_app_input',[v.app,key]),('gate_poll',[])]:
 v.call(S['AMITSE'][name],*args)
check('no_safe_page_still_suppresses_original_render_input_poll',all(v.calls[x]==0 for x in ['render','page_input','app_input','poll'])and not v.provider_calls['request'])
check('no_safe_page_does_not_claim_native_exit',v.u.mem_read(v.app+0x5a,1)==before[0x5a:0x5b])

# Recompute identity table entries and all declared CRC spans from pinned PE.
import pefile
pe=pefile.PE(str(D04.parent/'boot_context/AMITSE.original.efi'));native=pe.get_memory_mapped_image()
identity=json.loads((FINAL/'native_chrome_identity.json').read_text())
for row in identity['unchanged_native_ranges']:
 a=int(row['rva'],16);raw=native[a:a+row['bytes']]
 assert hashlib.sha256(raw).hexdigest()==row['sha256'] and f'{zlib.crc32(raw):08x}'==row['crc32']
for field,at in [('frame_method_rvas',0x6b8b8),('control_method_rvas',0x6bb20)]:
 assert [int.from_bytes(native[at+i*8:at+i*8+8],'little')for i in range(len(identity[field]))]==[int(x,16)for x in identity[field]]
check('all_declared_native_ranges_and_both_method_tables_match_original_bytes',True)
report={'status':'PASS_INDEPENDENT_REVIEW_FINDING_REGRESSION_LOCAL_CLASSIFIER_ONLY',
 'template_sha256':HASH,'template_bytes':16932,'checks':len(rows),'cases':rows,
 'source_sha256':sha(FINAL/'source/gate.c'),'snapshot_sha256':sha(FINAL/'snapshot.json'),
 'remaining':['No-safe-page native unwind is still unimplemented; the suppression case is explicitly retained as an unresolved gap.',
 'Provider13 still binds the old guard; no full application/ISO or target run is validated here.',
 'Page accessibility, HII ownership/services and original renderer/input endpoints are models; actual selected native constructors and final classifier bytes execute.',
 'Identity CRCs cover declared spans, not every transitive callee. A future provider must still enforce complete original .text and the exact twelve patch sites.',
 'Kind5 exact seven-byte heap IFR shape is constructor-backed; these checks do not prove allocation ownership against arbitrary hostile RAM corruption.']}
(HERE/'independent_final_cases.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'checks':len(rows)}))
