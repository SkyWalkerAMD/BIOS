"""Execute native AppInput/hotkey/F5 dispatcher up to explicit defaults hook."""
from pathlib import Path
import json
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_guard.py').read_text().split('\nv=GateVM();check(',1)[0]
exec(compile(prefix,str(HERE/'verify_guard.py'),'exec'),globals())
class HotkeyVM(GateVM):
 def __init__(self,baseline=False):
  super().__init__();self.defaults_calls=0;self.key_clears=0
  self.key=HEAP+0x1d0000;self.hotkey=HEAP+0x1d0100;array=HEAP+0x1d0200
  self.u.mem_write(self.key+8,w(1));self.u.mem_write(self.key+12,w(15)+w(0)+d(0))
  self.u.mem_write(self.hotkey+8,q(TSE+0x330e0)+q(self.app)+q(0)+w(15)+w(0)+d(0))
  self.u.mem_write(array,q(self.hotkey));self.u.mem_write(self.app+0x38,q(1)+q(array))
  self.clear_target=self.getq(TSE+0x6b908)
  for a in [TSE+0x5abc,self.clear_target]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
  if baseline:self.u.mem_write(TSE+0x6b840,q(TSE+0x12168))
 def hook(self,u,a,n,data):
  if a==TSE+0x12168:return # execute real original AppInput
  if a==self.clear_target:self.key_clears+=1;self.ret(0);return
  if a==TSE+0x5abc:
   assert self.arg(0)==0xffff001d;self.defaults_calls+=1;self.ret(0);return # OEM defaults side effects boundary
  super().hook(u,a,n,data)
 def press(self,index):self.current(index);return self.native_site(0xe8ec,0xe8f2,self.app,self.key)
checks=[]
v=HotkeyVM(True);v.press(5);check('original F5 from unrelated visible page reaches global defaults hook',v.defaults_calls==1)
v=HotkeyVM();v.press(5);check('missing provider F5 blocked before native defaults dispatch',v.defaults_calls==0 and v.provider_calls['request']==0)
v.press(0);check('native index0 inert F5 preserved without password prompt',v.defaults_calls==0 and v.key_clears==1 and v.provider_calls['request']==0)
v=HotkeyVM();v.provider_present=True;v.start();v.press(5)
check('owned locked F5 requests authentication then cancel denies',v.provider_calls['request']==1 and v.defaults_calls==0)
v.request_accept=True;v.press(5);check('correct owned F5 grant reaches original dispatcher',v.provider_calls['request']==2 and v.defaults_calls==1)
v.press(5);check('same session F5 reuses grant',v.provider_calls['request']==2 and v.defaults_calls==2)
v.end();v.request_accept=False;v.start();v.press(5);check('new BIOS session F5 relocks',v.provider_calls['request']==3 and v.defaults_calls==2);v.end()
v=HotkeyVM();v.provider_present=True;v.provider_bits=7|16;v.press(5);check('stale busy grant cannot trigger defaults',v.defaults_calls==0)
r={'status':'PASS_NATIVE_F5_ENTRY_GATE_WITH_EXPLICIT_OEM_HOOK_BOUNDARY','checks':len(checks),'check_names':checks,'modules_sha256':{n:r['sha256']for n,r in manifest['modules'].items()},'native_chain':['E8EC indirect AppInput call','6B840 -> static gate_app_input','12168 -> hotkey method6B9F0=18C2C','18C9F callback=330E0','33104 ->5ABC eventFFFF001D'],'original_hotkey_record':{'scan_word_rva':'0x6cce8','scan':'0x000f','callback_slot':'0x6ccf0','callback':'0x330e0'},'test_source_sha256':sha(Path(__file__)),'limits':['Original AppInput, hotkey key/modifier comparison and F5 callback execute; final OEM defaults hook is an explicit effect counter.','Correct password result/provider methods are modeled here; actual provider/core has separate candidate tests.','Other Load Optimized Defaults invocation routes and direct profile storage/hardware side effects remain separately unaccepted; no claim every defaults route traverses AppInput.']}
(HERE/'build/hotkey_verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'checks':len(checks)}))
