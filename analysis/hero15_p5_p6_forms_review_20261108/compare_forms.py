"""Read frozen P5/P6 resources and execute S22 exact-form rejection offline."""
from pathlib import Path
import hashlib,json,struct,uuid
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
P5=ROOT/'analysis/hero_ipmi_p5';P6=ROOT/'analysis/hero_p6_s22_20261108'
sha=lambda b:hashlib.sha256(b).hexdigest()
def scan(data):
 assert len(data)==int.from_bytes(data[:3],'little') and data[3]==2
 pos=4;stack=[];current=None;forms={};stores=[]
 while pos<len(data):
  op,size=data[pos],data[pos+1]&127;scoped=data[pos+1]&128;assert size>=2 and pos+size<=len(data)
  b=data[pos:pos+size]
  if op==0x01:
   assert size==6;current=int.from_bytes(b[2:4],'little');forms[current]=[]
  if current in range(0x3100,0x3105):
   row={'offset':pos,'opcode':op,'bytes':size}
   if op in (5,6,7,8,0x0c,0x1c,0x23):row.update(question=int.from_bytes(b[6:8],'little'),store=int.from_bytes(b[8:10],'little'),var_offset=int.from_bytes(b[10:12],'little'))
   forms[current].append(row)
  if op==0x26:stores.append({'id':int.from_bytes(b[2:4],'little'),'guid':str(uuid.UUID(bytes_le=b[4:20])),'attributes':int.from_bytes(b[20:24],'little'),'size':int.from_bytes(b[24:26],'little'),'name':b[26:].rstrip(b'\0').decode()})
  if op==0x29:
   assert stack;old=stack.pop()
   if old==0x01:current=None
  elif scoped:stack.append(op)
  pos+=size
 assert not stack and pos==len(data)
 return {'bytes':len(data),'sha256':sha(data),'stores':stores,'ipmi_forms':{f'{key:04X}':{'text_count':sum(r['opcode']==3 for r in value),'editable_questions':[r for r in value if r['opcode'] in (5,6,7,8,0x0c,0x1c,0x23)],'raw_op_count':len(value)} for key,value in forms.items() if key in range(0x3100,0x3105)}}
old=(P5/'Setup-forms-P5.bin').read_bytes();new=(P6/'native/Setup-forms-P6.bin').read_bytes()
result={'P5':scan(old),'P6_S22':scan(new),'on_host_inference':'The visible five read-only WDT values are consistent with P5. Actual .15 complete HII bytes have not been captured here, so appearance alone is not a version proof.'}
ns={'__file__':str(P6/'tests/test_refresh_lifecycle.py'),'__name__':'forms_only_fixture'}
prior=ROOT/'analysis/hero_p6_settings21r_20261108/tests/test_refresh_lifecycle.py'
exec(compile(prior.read_text().split('\nrows=[]')[0],str(prior),'exec'),ns)
checks=[]
for label,forms,accept in [('P5',old,False),('P6',new,True)]:
 package=uuid.UUID('a85810b5-ad33-4350-b7f5-37905d0dbdb9').bytes_le+struct.pack('<I',24+len(forms))+forms+b'\x04\0\0\xdf'
 ns['package']=package;m=ns['Machine']().start();m.dispatch(ns['AFTER'])
 assert (m.boundary['p1_collect']==1)==accept
 assert (m.boundary['p5_publish']==1)==accept
 if not accept:
  assert 'P6_AFTER_SYNC_BIND_STATUS=800000000000000E' in m.audit()
  assert not m.dev.packets and not m.hii_sets and not m.nv_writes and not m.pci_writes
 checks.append({'resource':label,'actual_S22_PE_sha256':sha((P6/'HeroIpmiP6.efi').read_bytes()),'bind_accepts':accept,'read_calls':m.boundary['p1_collect'],'publish_calls':m.boundary['p5_publish'],'standard_BMC_requests':len(m.dev.packets),'HII_SetString_calls':len(m.hii_sets)})
result['actual_PE_callback_checks']=checks
schema=json.loads((ROOT/'analysis/hero_ipmi_p6_20261104/native/settings-schema.json').read_text())
result['settings_fields']=[{'name':f['name'],'form':f'{f["form_id"]:04X}','question':f'{f["question_id"]:04X}','offset':f['offset']} for f in schema['fields']]
result['limits']=['No actual target was contacted.','Resource layout comparison uses frozen local P5/P6 inputs; .15 visible UI only supports a hypothesis until exact HII binding/export evidence.','The compiled S22 code refuses P5 before p1_collect and SetString. This is expected resource version protection, not a PCI-discovery failure.','No dynamic HII injection or production guard changes.','F10 editing and applied BMC readback are separate acceptance steps.']
(BASE/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
