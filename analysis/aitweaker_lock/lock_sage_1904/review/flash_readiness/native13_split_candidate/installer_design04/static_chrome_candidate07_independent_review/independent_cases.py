"""Actual snapshotted classifier with bounded original constructors.

Only fixture path bindings are adapted. HII, page accessibility and firmware
endpoints remain explicit models from the frozen parent harness. No rebuild.
"""
from pathlib import Path
import hashlib,json,sys,types,uuid
HERE=Path(__file__).resolve().parent;D04=HERE.parent;SNAP=HERE/'input_candidate'
sys.dont_write_bytecode=True
N13=D04.parent
snapshot=json.loads((SNAP/'snapshot.json').read_text())
for row in snapshot['files']:
 p=SNAP/row['path'];assert len(p.read_bytes())==row['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256']
split_source=(SNAP/'verify_split.py').read_text()
split_source=split_source.replace('N13=HERE.parents[1]',f'N13=Path({str(N13)!r})')
module=types.ModuleType('verify_split');module.__file__=str(SNAP/'verify_split.py')
sys.modules['verify_split']=module
exec(compile(split_source,str(SNAP/'verify_split.py')+' [path-only adapter]','exec'),module.__dict__)
chrome=(SNAP/'verify_chrome.py').read_text().split('\nchecks=[];observations=[]',1)[0]
chrome=chrome.replace("PROOF=HERE.parent/'guard_blackout_review01'",f'PROOF=Path({str(D04/"guard_blackout_review01")!r})')
scope={'__file__':str(SNAP/'verify_chrome.py')}
exec(compile(chrome,str(SNAP/'verify_chrome.py')+' [prefix/path-only adapter]','exec'),scope)
ChromeVM,U,R,TSE,HEAP,S,q,d,w=[scope[x]for x in ['ChromeVM','U','R','TSE','HEAP','S','q','d','w']]
ns=scope['ns'];rows=[]

def record(name,v):
 result=v.classified();row={'case':name,'classification':hex(result),'accepted':result==0}
 rows.append(row);print(json.dumps(row),flush=True);return result

v=ChromeVM();assert record('positive_real_kind1_sentinel',v)==0
for slot in [0,3,4,6,9]:
 v=ChromeVM();v.u.mem_write(TSE+0x6b8b8+8*slot,q(TSE+0x11164))
 assert record(f'frame_method_slot_{slot}_changed_before_hii_initialization',v)==0

for name,mutate in [
 ('nonzero_object_callback',lambda v:v.u.mem_write(v.control+8,q(TSE+0x11164))),
 ('nonzero_expression',lambda v:v.u.mem_write(v.control+0x50,q(v.ifr))),
 ('wrong_control_vtable',lambda v:v.u.mem_write(v.control,q(TSE+0x6bbe0))),
]:
 for hii in ['sentinel','setup','foreign','amitse']:
  v=ChromeVM()
  source={'sentinel':0xffffffffffffffff,'setup':v.handle,'foreign':0x99998888,'amitse':v.amih}[hii]
  v.u.mem_write(v.control+0x20,q(source));mutate(v)
  result=record(name+'_source_'+hii,v)
  if hii=='sentinel':assert result in [0xffffffff,0xffffffffffffffff]

# Run the actual PE entry's argument-preserving prefix and HII creation site.
# Stub early library init5F8, predicate618C and standard service endpoints;
# stop at1136 before all subsequent native initialization/display work.
v=ChromeVM();ST=HEAP+0x270000;DB=ST+0x200;PKG=ST+0x400
IMAGE=0xa1904000;HII=0xa1904001;OPEN=ns['STOP']+0x4700;LOCATE=OPEN+0x10;NEW=OPEN+0x20
v.u.mem_write(ST+0x58,q(ST+0x600));v.u.mem_write(ST+0x60,q(v.bs))
v.u.mem_write(v.bs+0x118,q(OPEN));v.u.mem_write(v.bs+0x140,q(LOCATE));v.u.mem_write(DB,q(NEW))
captured=[]
def creation_hook(u,a,size,unused):
 if a in [TSE+0x5f8,TSE+0x618c]:v.ret(0);return
 if a==OPEN:
  guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(v.arg(1),16))))
  sp=u.reg_read(R.UC_X86_REG_RSP)
  assert v.arg(0)==IMAGE and v.arg(3)==IMAGE and v.getq(sp+40)==0 and v.getq(sp+48)==2
  captured.append({'operation':'OpenProtocol','handle':hex(v.arg(0)),'guid':guid})
  u.mem_write(v.arg(2),q(PKG));v.ret(0);return
 if a==LOCATE:
  guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(v.arg(0),16))))
  assert guid=='ef9fc172-a1b2-4693-b327-6d32fc416042'
  captured.append({'operation':'LocateProtocol','guid':guid})
  u.mem_write(v.arg(2),q(DB));v.ret(0);return
 if a==NEW:
  assert [v.arg(i)for i in range(4)]==[DB,PKG,IMAGE,TSE+0x93970]
  captured.append({'operation':'NewPackageList','driver_handle':hex(v.arg(2)),'output_rva':'0x93970'})
  u.mem_write(v.arg(3),q(HII));v.ret(0);return
 if a==TSE+0x1136:
  u.reg_write(R.UC_X86_REG_RIP,ns['STOP']);u.emu_stop()
for at in [TSE+0x5f8,TSE+0x618c,OPEN,LOCATE,NEW,TSE+0x1136]:v.u.hook_add(U.UC_HOOK_CODE,creation_hook,begin=at,end=at)
v.call(TSE+0x5a0,IMAGE,ST)
assert v.getq(TSE+0x93970)==HII and len(captured)==3
rows.append({'case':'original5A0_to1034_HII_creation_prefix','events':captured,'scope':'Actual original prefix; early helper and UEFI services modeled; no physical HII association observation.'})
result={'status':'REPRODUCED_UNFROZEN_CLASSIFIER_IDENTITY_GAP_AND_SOURCE_HII_CREATION',
 'template_sha256':module.meta['template_sha256'],'cases':rows,
 'scope':['Exact snapshotted actual classifier/constructors; no recompilation or native GUI claim.',
 'Frame method table gap is a concrete mutation accepted by new static exception; no exploit or physical cause claimed.',
 'Known valid owner fallback results are reported separately from the new sentinel exception and require policy interpretation.',
 'HII source creation passes the original entry ImageHandle to NewPackageList in actual native instructions. Standard service effects and GetHiiDriverHandle topology remain modeled.']}
(HERE/'independent_initial_cases.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'output':'independent_initial_cases.json','rows':len(rows)}))
