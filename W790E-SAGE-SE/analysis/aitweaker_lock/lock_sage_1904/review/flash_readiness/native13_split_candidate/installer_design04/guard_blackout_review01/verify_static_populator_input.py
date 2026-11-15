"""Original 33634 population and static subtitle input write audit.

No authorization rule is changed. Full native page rendering remains untested.
"""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_native_static_controls.py').read_text().split('\nchecks=[];rows=[]',1)[0]
scope={'__file__':str(HERE/'verify_native_static_controls.py')};exec(compile(prefix,str(HERE/'verify_native_static_controls.py'),'exec'),scope)
StaticVM,U,R,TSE,HEAP,S,q,d,w=[scope[x]for x in ['StaticVM','U','R','TSE','HEAP','S','q','d','w']]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
class InputVM(StaticVM):
 def __init__(self,kind):
  super().__init__(kind);self.action=0;self.key=HEAP+0x250000;self.input_writes=[];self.audit_input=False;self.decoded_calls=0
  self.presentation=[];self.conditions=[]
  self.u.mem_write(self.bs+0x168,q(scope['STOP']+0x4510))
  self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=TSE+0x5c60,end=TSE+0x5c60)
  for at in [scope['STOP']+0x4510,TSE+0x33da4,TSE+0x4b30,TSE+0x4d40,TSE+0x4e6c,TSE+0x6ffc,TSE+0x31da4,TSE+0x31e06,TSE+0x31e36]:
   self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=at,end=at)
  self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.write)
 def hook(self,u,a,n,data):
  if a==TSE+0x5c60:self.decoded_calls+=1;self.ret(self.action);return
  if a==scope['STOP']+0x4510:
   self.presentation.append('SetMem');u.mem_write(self.arg(0),bytes([self.arg(2)&255])*self.arg(1));self.ret(0);return
  if a==TSE+0x33da4:
   self.presentation.append('HII_string_lookup33DA4_model');self.ret(HEAP+0x270000);return
  if a==TSE+0x4e6c:
   self.presentation.append('string_wrap4E6C_model');u.mem_write(self.arg(2),w(1));self.ret(self.arg(0));return
  if a in [TSE+x for x in [0x4b30,0x4d40,0x6ffc]]:
   self.presentation.append(hex(a-TSE)+'_presentation_model');self.ret(0);return
  if a==TSE+0x31da4:self.conditions.append('real_condition_entry');return
  if a==TSE+0x31e06:
   assert self.u.reg_read(R.UC_X86_REG_R14)==0;self.conditions.append('real_null_expression_fast_path');return
  if a==TSE+0x31e36:raise AssertionError('unexpected expression interpreter')
  super().hook(u,a,n,data)
 def write(self,u,access,address,size,value,data):
  if self.audit_input and not scope['ns']['STACK']<=address<scope['ns']['STACK']+0x400000:
   self.input_writes.append({'address':address,'size':size,'value':value})
checks=[];rows=[]
def check(s,ok):assert ok,s;checks.append(s)
for kind in [1,2,3,5]:
 v=InputVM(kind);source=HEAP+0x260000;layout=v.getq(TSE+0x6c1a0)+v.layout_index*24
 v.u.mem_write(HEAP+0x270000,'Native static subtitle\0'.encode('utf-16le'))
 result=v.call(TSE+0x33634,v.frame,layout,source)
 control=v.getq(v.getq(v.frame+0x48));ifr=v.getq(control+0x48)
 data=bytes(v.u.mem_read(control,0x88));descriptor=data[0x20:0x60]
 check(f'kind{kind} actual33634 population succeeds',result==0 and v.getd(v.frame+0x3c)==1)
 check(f'kind{kind} actual33634 leaves static HII sentinel',v.getq(control+0x20)==0xffffffffffffffff and v.getq(control)==TSE+0x6bb20)
 check(f'kind{kind} final IFR is exact subtitle7',bytes(v.u.mem_read(ifr,7))== (b'\x02\x07\x03\0\0\0\0' if kind==5 else b'\x02\x07\0\0\0\0\0'))
 check(f'kind{kind} constructed frame rejected by frozen classifier',v.call(S['AMITSE']['frame_protected'],v.frame) in [0xffffffff,0xffffffffffffffff])
 input_rows=[]
 for event_type,actions in [(1,range(32)),(2,[0]),(0,[0]),(3,[0])]:
  for action in actions:
   v.u.mem_write(control,data);v.u.mem_write(v.key,bytes(32));v.u.mem_write(v.key+8,w(event_type));v.action=action
   v.input_writes=[];before_models=len(v.models);before_decodes=v.decoded_calls;v.audit_input=True
   r=v.call(TSE+0x1c2cc,control,v.key);v.audit_input=False
   # Native input changes only local scroll position/timer. It has no generic
   # callback pointer, variable service call or original ConfigAccess edge.
   allowed=all((x['address'] in [control+0x72,control+0x80,control+0x82] and x['size'] in [1,2]) or x['address'] in [TSE+0x6b600,TSE+0x6b5f8] or HEAP+0x270000<=x['address']<HEAP+0x270100 for x in v.input_writes)
   assert allowed and len(v.models)==before_models,(kind,event_type,action,v.input_writes)
   assert v.decoded_calls-before_decodes==(1 if event_type==1 else 0)
   input_rows.append({'event_type':event_type,'decoded_action':action,'status':hex(r),'local_writes':[{'offset':hex(x['address']-control),'size':x['size'],'value':x['value']}for x in v.input_writes]})
 check(f'kind{kind} 35 input cases only local/presentation writes',len(input_rows)==35 and not v.callback_calls and not v.getvar_calls)
 check(f'kind{kind} ESC action13 refused without edit or callback',next(x for x in input_rows if x['event_type']==1 and x['decoded_action']==13)['status']=='0x8000000000000003')
 rows.append({'frame_kind':kind,'descriptor_hex':descriptor.hex(),'ifr_hex':bytes(v.u.mem_read(ifr,7)).hex(),'ifr_source':'newly_allocated_native7B' if kind==5 else 'original_module_static_data','native_input_cases':input_rows,'presentation_helper_models':sorted(set(v.presentation)),'original_condition_paths':v.conditions,'full_native_render_tested':False})
report={'status':'PASS_ORIGINAL_STATIC_FRAME_POPULATION_AND_BOUNDED_INPUT_WRITE_AUDIT','checks':len(checks),'input_cases':sum(len(x['native_input_cases'])for x in rows),'check_names':checks,'cases':rows,'test_source_sha256':sha(Path(__file__)),'fixture_source_sha256':sha(HERE/'verify_native_static_controls.py'),'original_sha256':sha(HERE.parent.parent/'boot_context/AMITSE.original.efi'),'findings':['The full native33634 populator preserves HII=-1 for standard frame kinds1/2/3/5. Kind5 allocates a new7-byte subtitle descriptor and sets its string token3, so a blanket original-IFR-address-only exception would miss a legitimate static footer.','Actual1C2CC input reaches the original1BE5C redraw on scrolling. The original31DA4 condition interpreter takes its null-expression fast path. Local control and screen-bounds/string writes are audited; HII-string/wrapping/painting helpers are explicit models. No ConfigAccess or OC variable endpoint is reached in these140 modeled event/action cases.','This supports a narrow known-native-chrome classifier, not allowing arbitrary null/sentinel HII or all foreign pages. A final allow rule needs exact class/type/frame/descriptor/condition/callback provenance and negative tests.'],'limits':['Color, allocation, CopyMem, HII ownership, keyboard-to-action and presentation/string helpers are explicit service models. Physical page construction, input hardware and rendering remain untested.','The function-level write audit does not claim arbitrary surrounding OEM callbacks or UI navigation are side-effect free. No new classifier or installer was produced.','The initial incomplete test lacked BS.SetMem at the real condition entry, stopped at RIP0, and emitted no PASS report. This was a fixture omission, preserved in initial_input_fixture_failure.json.']}
(HERE/'static_populator_input_review.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'checks':len(checks),'input_cases':report['input_cases'],'sha256':sha(HERE/'static_populator_input_review.json')}))
