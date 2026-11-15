"""Actual F5 and native shortcut dispatch through the new common gate."""
from pathlib import Path
import json
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_hotkeys.py').read_text().split('\nchecks=[]',1)[0]
exec(compile(prefix,str(HERE/'verify_hotkeys.py'),'exec'),globals())
class EntryVM(HotkeyVM):
 def __init__(self):
  super().__init__();self.effects=[];self.discards=0;self.saves=0
  for r in [0x36c34,0x5d44c,0x3ce14,0x609c,0x13a1c,0x1422c]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=TSE+r,end=TSE+r)
 def hook(self,u,a,n,data):
  if a==TSE+0x5abc:return # execute patched dispatcher, not the old hook fixture
  if a in [TSE+0x36c34,TSE+0x5d44c,TSE+0x3ce14]:self.effects.append(hex(a-TSE));self.ret(0);return
  if a==TSE+0x609c:self.ret(0x14);return # decoded native shortcut event class fixture
  if a==TSE+0x13a1c:self.discards+=1;self.ret(0);return
  if a==TSE+0x1422c:self.saves+=1;self.ret(0);return
  super().hook(u,a,n,data)
 def menu(self,action=6,index=5):
  key=HEAP+0x1d4000;control=HEAP+0x1d4100
  self.u.mem_write(self.app+0x20,q(key));self.u.mem_write(key+0xc,d(0x100+action));self.u.mem_write(control+0x24,d(0x100));self.current(index)
  return self.call(TSE+0x33188,self.app,control)

checks=[];v=EntryVM();v.start();v.press(5)
check('real F5 full chain denies absent provider before every defaults callback',not v.effects and not v.provider_calls['request'])
v.menu();check('real shortcut full chain denies absent provider',not v.effects and not v.provider_calls['request'])
v.menu(5);v.menu(7)
check('native shortcut Discard remains reachable without password',v.discards==1 and not v.effects)
check('native shortcut Save remains reachable without password',v.saves==1 and not v.effects)
v.end()
v=EntryVM();v.provider_present=True;v.start();v.menu()
check('locked native shortcut prompts and canceled result denies',v.provider_calls['request']==1 and not v.effects)
v.request_accept=True;v.menu()
check('accepted native shortcut executes all three original registered callbacks',v.provider_calls['request']==2 and v.effects==['0x36c34','0x5d44c','0x3ce14'])
v.press(5)
check('F5 same native invocation reuses menu grant through both guards',v.provider_calls['request']==2 and len(v.effects)==6)
v.end();v.start();v.press(5)
check('new native F5 invocation prompts only once across both guards',v.provider_calls['request']==3 and len(v.effects)==9)
v.end()
v=EntryVM();v.menu();check('native shortcut with missing outer frame cannot use vendor initialization exception',not v.effects)
v=EntryVM();v.provider_present=True;v.start();v.press(0);v.menu(index=0)
check('original index0 inert F5 and shortcut behavior preserved',not v.effects and not v.provider_calls['request']);v.end()
r={'status':'PASS_NATIVE_F5_AND_SHORTCUT_THROUGH_COMMON_DEFAULTS_GATE','checks':len(checks),'check_names':checks,'module_sha256':{n:r['sha256']for n,r in manifest['modules'].items()},'test_source_sha256':sha(Path(__file__)),'shared_source_sha256':{'verify_guard.py':sha(HERE/'verify_guard.py'),'verify_hotkeys.py':sha(HERE/'verify_hotkeys.py')},
 'native_chains':['E8EC ->gate_app_input ->12168 ->18C2C ->330E0 ->5ABC ->gate_defaults ->original5ABC/5A04 ->all three registered callbacks','33188: event class20, selector base+6 ->3321D ->5ABC ->gate_defaults ->original5ABC/5A04'],
 'limits':['Native shortcut event decoding609C returns an explicit fixture class20; complete mouse input/graphics are not executed.','Three defaults callback bodies, Save/Discard side effects, firmware protocols and password result are explicit fixtures.','The static gate and original hotkey, shortcut branch, event lookup and callback iteration execute actual bytes.','No additional native module patch or hardware access; frozen11-point SHA remains unchanged.']}
(HERE/'build/defaults_entries_verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'checks':len(checks)}))
