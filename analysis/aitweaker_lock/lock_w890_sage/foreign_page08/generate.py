"""Derive UI scope descriptions from frozen policy and exact physical forms.
No callback or producer execution permission is produced.
"""
from pathlib import Path
import json,hashlib,uuid,difflib,copy
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sha=lambda b:hashlib.sha256(b).hexdigest()
p=json.loads((B/'policy05/storage_policy.json').read_text());rows=[];bindings=[]
def read(path):
 raw=path.read_bytes();bindings.append({'path':path.relative_to(R).as_posix(),'bytes':len(raw),'sha256':sha(raw)});return raw
for src in p['packages']:
 blob=read(R/src['blob_path']);assert sha(blob)==src['sha256']
 rows.append({'name':src['module'],'bytes':len(blob),'sha256':sha(blob),'blob_path':src['blob_path'],
 'forms':copy.deepcopy(src['forms']),'controls':copy.deepcopy(src['controls']),'provenance':'FROZEN_POLICY05_UI_SCOPE_ONLY'})
baseline={r['name']:r for r in rows};dh=B/'hardware_delta07/capture_6e7a57f9729b082c'
rec=json.loads(read(dh/'reconciled.json'))
for obj in rec['objects']:
 ident=obj['artifact_id'];path=R/obj['blob']['path'];blob=read(path);assert sha(blob)==obj['sha256']
 decoded=json.loads(read(dh/f'object_{ident:02d}.ifr.json'));records=decoded['records']
 name={1:'GetCpuInfo',2:'NvmeDynamicSetup',3:'NIC_D7_A',4:'NIC_D7_B',5:'SocketSetup'}[ident]
 if ident in(1,2,5):
  old=baseline[name];oldblob=(R/old['blob_path']).read_bytes()
  # Byte-exact opcode equality yields a monotone offset map; only independently
  # observed inert TEXT/SUBTITLE insertions are accepted, never guessed bytes.
  def ops(b):
   x=[];at=4
   while at<len(b):n=b[at+1]&127;assert n>=2 and at+n<=len(b);x.append((at,b[at:at+n]));at+=n
   assert at==len(b);return x
  a=ops(oldblob);z=ops(blob);sm=difflib.SequenceMatcher(a=[b for _,b in a],b=[b for _,b in z],autojunk=False);mapping={};inserted=[]
  for tag,ai,aj,bi,bj in sm.get_opcodes():
   if tag=='equal':
    for i,j in zip(range(ai,aj),range(bi,bj)):mapping[a[i][0]]=z[j][0]
   else:
    assert tag=='insert' and ai==aj
    for off,b in z[bi:bj]:assert b[0]in(2,3)and not b[1]&128;inserted.append({'offset':off,'hex':b.hex()})
  r=copy.deepcopy(old);r.update(name=name+'_PHYSICAL_D7',bytes=len(blob),sha256=sha(blob),blob_path=path.relative_to(R).as_posix(),provenance='ACTUAL_D7_INERT_INSERTION_MAPPING',inserted=inserted)
  for key in('forms','controls'):
   for x in r[key]:x['offset']=mapping[x['offset']]
  rows.append(r)
 else:
  # Both physical NIC objects have a single declared BUFFER store and no
  # expression-side variable access. This describes only their UI storage.
  assert len(decoded['formsets'])==1
  fs=decoded['formsets'][0];assert fs['guid']=='25fd9f0b-a3ef-4788-a40c-81849d178a6c'
  assert len(fs['varstores'])==1 and not fs['variable_accesses']
  store=fs['varstores'][0]
  assert (store['guid'],store['name'],store['varstore_size'])==('e2c85968-6906-4b27-9d09-3343af064676','NicCfgData',134)
  knownforms={f['form_id']for f in fs['forms']};forms=[];controls=[]
  for f in fs['forms']:forms.append({'formset':fs['guid'],'form':f['form_id'],'offset':f['package_offset'],'storage_risk':0,'review_flags':16})
  for q in fs['questions']:
   assert q['varstore_resolution']in('UNIQUE','NO_STORAGE') and not q['ancestor_guid_extensions']
   if q['varstore']:assert q['varstore']['guid']==store['guid'] and q['varstore']['name']==store['name']
   if q['op']==15:assert not q['dynamic'] and not q['device_path_string_id'] and q['target_formset_effective']==fs['guid'] and q['target_form']in knownforms
   controls.append({'formset':fs['guid'],'form':q['form_id'],'offset':q['package_offset'],'length':q['size'],'opcode':q['op'],'question':q['question_id'],'hex':q['hex'],'storage_risk':0,'review_flags':16|(1 if q['callback'] else 0),'reason':'EXACT_D7_NIC_STORAGE_UI_SCOPE_NOT_CODE_AUTHORIZATION'})
  rows.append({'name':name,'bytes':len(blob),'sha256':sha(blob),'blob_path':path.relative_to(R).as_posix(),'forms':forms,'controls':controls,'provenance':'NON_FV_PHYSICAL_DATA_ONLY_NO_EXECUTION_AUTHORITY'})
# Identical physical instances remain separate evidence, but one data signature.
unique={}
for r in rows:
 if r['sha256']in unique:
  old=unique[r['sha256']];assert old['forms']==r['forms']and old['controls']==r['controls'];old.setdefault('equivalent_instances',[]).append(r['name'])
 else:unique[r['sha256']]=r
rows=list(unique.values());lines=['/* Generated exact data descriptions. Never a code/callback permission table. */']
for i,r in enumerate(rows):
 guids=sorted({x['formset']for k in('forms','controls')for x in r[k]});r['formsets']=guids
 lines.append('static const uint8_t fs_%d[][16]={%s};'%(i,','.join('{'+','.join('0x%02x'%v for v in uuid.UUID(g).bytes_le)+'}'for g in guids)))
 records=[(x['offset'],x['form'],guids.index(x['formset']),0,x['storage_risk'],x['review_flags'])for x in r['forms']]
 records +=[(x['offset'],x['form'],guids.index(x['formset']),1,x['storage_risk'],x['review_flags'])for x in r['controls']]
 records.sort();assert len({x[0]for x in records})==len(records)
 lines.append('static const FP08_RECORD records_%d[]={%s};'%(i,','.join('{%d,%d,%d,%d,%d,%d}'%x for x in records)))
lines.append('static const FP08_PACKAGE packages[]={')
for i,r in enumerate(rows):lines.append(' {{%s},%d,fs_%d,%d,records_%d,%d},'%(','.join('0x'+r['sha256'][j:j+2]for j in range(0,64,2)),r['bytes'],i,len(r['formsets']),i,len(r['forms'])+len(r['controls'])))
lines.append('};')
(H/'scope_data.h').write_text('\n'.join(lines)+'\n')
(H/'scope_catalog.json').write_text(json.dumps({'packages':rows,'bindings':bindings,'runtime_authorized':False,'scope':'Exact forms data UI classification only; callbacks retain original lifecycle and no source is granted new execution.'},indent=2)+'\n')
print(json.dumps({'packages':len(rows),'forms':sum(len(r['forms'])for r in rows),'controls':sum(len(r['controls'])for r in rows),'hardware_actions':0}))
