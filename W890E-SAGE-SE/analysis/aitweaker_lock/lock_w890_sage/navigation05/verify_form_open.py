"""Actual parser descriptors + native FormOpen batch + compiled guards.

Raw pages/control descriptors/IFR and three management controls are immutable
outputs of the real AMITSE parser. Outer APP/PAGE containers and UEFI services
remain explicit models. Original 3F414 executes its real loop; 3E700 is the
documented callback boundary, not a claim that Setup side effects ran here.
"""
from pathlib import Path
import ast,json,hashlib,struct,time,sys
import verify_bridges as b
from verify_bridges import H,B,m,ns,TSE,DATA,Q,I,OS,SY,SHA,O

# Import only declarations from the earlier executable test; never rerun it
# or let it overwrite its frozen report while constructing this composition.
src=H/'verify_parser_navigation.py';tree=ast.parse(src.read_text());nodes=[]
for node in tree.body:
 if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='started'for t in node.targets):break
 nodes.append(node)
p={'__file__':str(src),'__name__':'parser_fixture_readonly'}
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(src),'exec'),p)
S=p['S'];ZS=p['ZS']
SOURCES={str(f.relative_to(H)):hashlib.sha256(f.read_bytes()).hexdigest()for f in [Path(__file__),src,H/'verify_bridges.py',H/'verify_navigation.py',H/'bridges.c',H/'visit/form_descriptor.inc',H/'visit/observer_visit05.c']}

class VM(b.VM,p['ParserVM']):
 def __init__(self):
  super().__init__();self.form_callbacks=[];self.bad_callback=None
 def hook(self,u,address,size,opaque):
  if address==TSE+0x3e700:
   self.form_callbacks.append({'descriptor':self.arg(0),'question':self.arg(1),'value':self.arg(2),'action':self.arg(3)})
   self.ret(0);return
  return super().hook(u,address,size,opaque)
 def ready_full(self):
  self.ready_parser();assert self.run('n05_bridges_bind')==0
 def raw(self,index):
  pt=self.q(TSE+0xbaaf0);return self.q(TSE+0xbabc0)+int.from_bytes(self.r(pt+4+4*index,4),'little')
 def callbacks(self,index):
  raw=self.raw(index);cb=self.q(TSE+0xbab08);count=int.from_bytes(self.r(raw+0x1c,4),'little');result=[]
  for i in range(count):
   c=cb+int.from_bytes(self.r(raw+0x20+4*i,4),'little')
   if int.from_bytes(self.r(c+0x1c,4),'little')&32:result.append(c)
  return result
 def open_step(self,index):
  self.w(self.app+0x28,I(index));return ('n05_native_form_open',[self.raw(index),3,DATA+0x2a000])

def main():
 cases=[]
 def case(name,fn):
  if len(sys.argv)>1 and not any(x.lower()in name.lower()for x in sys.argv[1:]):return
  start=time.time();v=VM();fn(v);cases.append({'name':name,'status':'PASS','seconds':round(time.time()-start,3)});print(name,flush=True)
  (O/'form_open_progress.json').write_text(json.dumps({'component_sha256':SHA,'cases':cases},indent=2)+'\n')
 def ordinary(v,which,phase=None,action=3):
  v.ready_full();index=getattr(v,which);flagged=v.callbacks(index)
  if phase is not None:v.w(TSE+0x93aa0,struct.pack('<H',phase))
  step=v.open_step(index);step[1][1]=action;expected=[]
  def capture(w):expected.extend(w.form_callbacks);w.form_callbacks.clear();w.w(DATA+0x2a000,I(0))
  v.loop([(v.q(OS['n05_form_open_trampoline']),step[1]),capture,step])
  assert v.sequence_values==[0,0],(v.sequence_values,len(flagged),v.observe_native[-12:])
  assert v.observe_native.count(0x3f423)==2 and v.form_callbacks==expected,{'observed':v.form_callbacks,'expected':expected,'native':v.observe_native}
  if phase==0:assert [x['descriptor']for x in expected]==flagged
  assert all(x['action']==action for x in v.form_callbacks)and not v.set_count
 case('Main actual parser page executes original zero-callback FormOpen',lambda v:ordinary(v,'main'))
 case('Security original phase2 filtering exactly matches the unguarded native batch',lambda v:ordinary(v,'security'))
 case('Security phase0 preserves all five original flagged callbacks',lambda v:ordinary(v,'security',0))
 case('Security FormClose2 phase0 exactly preserves the original callback batch',lambda v:ordinary(v,'security',0,2))
 def locked(v):
  v.ready_full();v.queue('\x1b');v.loop([v.open_step(v.ai)])
  assert v.sequence_values==[ns['ERR'](15)]and not v.form_callbacks and 0x3f423 not in v.observe_native and not v.set_count
 case('locked Ai Tweaker Escape refuses before original FormOpen callbacks',locked)
 def granted(v):
  password=b'NavTest5';v.record=ns['core'].signed_record(password=password)
  v.ready_full();v.w(TSE+0x93aa0,struct.pack('<H',0));v.queue(password.decode()+'\r');expected=v.callbacks(v.ai);assert len(expected)==56
  v.loop([v.open_step(v.ai)]);assert v.sequence_values==[0],(v.sequence_values,v.observe_native[-8:],v.transcript[-300:])
  assert [x['descriptor']for x in v.form_callbacks]==expected and not v.set_count
 case('correct password allows all 56 original Ai Tweaker FormOpen callbacks',granted)
 def bad_ifr(v):
  v.ready_full();c=v.callbacks(v.security)[0];v.w(c+0x28,Q(DATA+0x2b000));v.w(DATA+0x2b000,b'\x01\x06\xff\xff\x00\x00')
  v.loop([v.open_step(v.security)]);assert v.sequence_values==[ns['ERR'](15)]and not v.form_callbacks and 0x3f423 not in v.observe_native
 case('unknown flagged descriptor rejects full batch before any callback',bad_ifr)
 def bad_jump(v):
  v.ready_full();tr=v.q(OS['n05_form_open_trampoline']);v.w(tr+16,struct.pack('<i',TSE+0x3f424-(tr+20)))
  v.loop([v.open_step(v.main)]);assert v.sequence_values==[ns['ERR'](15)]and not v.form_callbacks and 0x3f423 not in v.observe_native
 case('wrong exact FormOpen trampoline destination is refused',bad_jump)
 def bad_action(v):
  v.ready_full();step=v.open_step(v.main);step[1][1]=5;v.loop([step]);assert v.sequence_values==[ns['ERR'](15)]and not v.form_callbacks and 0x3f423 not in v.observe_native
 case('unproved batch action is denied before original callbacks',bad_action)
 report={'component_sha256':SHA,'parser_zip_sha256':ZS,'sources':SOURCES,'checks':len(cases),'cases':cases,'parser_raw_pages':len(S['pages']),'limitations':['UEFI and outer App/Page containers modeled','actual original 3F414 loop executed; 3E700 is an explicit callback destination model returning success','does not establish ConfigAccess or native variable write effects','SHA/PBKDF/RDSEED are explicit frozen oracles','no hardware or firmware update testing']}
 target='form_open_tests.json'if len(sys.argv)==1 else'form_open_selected_tests.json'
 (O/target).write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases))

if __name__=='__main__':main()
