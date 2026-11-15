"""Reproduce a specific fail-closed/no-exit path with frozen N13 guard bytes.
The page/control state is a synthetic, precisely declared counterexample, NOT a
dump of the black-screen hardware. No frozen artifact or hardware is changed.
"""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;CORE=D04/'split_core';ROOT=D04.parents[6]
sys.path.insert(0,str(CORE));from verify_split import make_namespace
ns=make_namespace();V=ns['GateVM'];S=ns['S'];TSE=ns['TSE'];HEAP=ns['HEAP'];q,d,w=ns['q'],ns['d'],ns['w'];U,R=ns['U'],ns['R']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
class OneForeignPage(V):
 def __init__(self,null_control=False,bad_form=False,bits=1):
  super().__init__();self.provider_present=True;self.provider_bits=bits
  # Existing explicit HII service fixture recognizes 99998888 as a foreign
  # ConfigAccess package and preserves one genuine original Setup elsewhere.
  self.page=self.pages[5];self.frame=self.page+0x100;self.control=self.page+0x300;self.ifr=self.page+0x400
  self.u.mem_write(self.app+0x28,d(0)+d(1));self.u.mem_write(self.array,q(self.page))
  self.u.mem_write(self.page+0x30,w(0xffff if bad_form else 0));self.u.mem_write(self.page+0x2a,w(1))
  self.u.mem_write(self.table,d(1)+d(0));self.u.mem_write(self.records+10,w(1))
  self.u.mem_write(self.control+0x20,q(0 if null_control else 0x99998888))
  # EFI_IFR_TEXT (opcode03), not a Question and not an OC varstore control.
  self.u.mem_write(self.ifr,bytes([3,8,1,0,2,0,3,0]));self.u.mem_write(self.app+0x5a,b'\0')
  self.key=HEAP+0x9000;self.u.mem_write(self.key,bytes(32));self.u.mem_write(self.key+8,w(1));self.u.mem_write(self.key+12,w(0x17))
  self.u.mem_write(TSE+0x83594,d(0));self.u.mem_write(TSE+0x835b8,d(1))
  self.u.mem_write(self.getq(TSE+0x835a0),q(0x99998888)+d(1));self.stores=[]
  self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.store,begin=self.app,end=self.app+0x60-1)
 def store(self,u,access,a,n,v,data):self.stores.append((a,n,v))
 def native_still_loops(self):
  # Execute exact original E91E test, stop on E6BD (poll) or E92F (cleanup).
  sp=ns['STACK']+0x3ffe08;self.u.mem_write(sp,q(ns['STOP'])+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp);self.u.reg_write(R.UC_X86_REG_R14,0)
  stops=[]
  def stop(u,a,n,d):stops.append(a-TSE);u.emu_stop()
  hooks=[self.u.hook_add(U.UC_HOOK_CODE,stop,begin=TSE+a,end=TSE+a)for a in [0xe6bd,0xe92f]]
  self.u.emu_start(TSE+0xe91e,0,count=1000)
  for hook in hooks:self.u.hook_del(hook)
  return stops
checks=[];observations=[]
def check(label,ok):assert ok,label;checks.append(label)
normal=OneForeignPage();check('known foreign page TEXT control is unprotected',normal.call(S['AMITSE']['page_protected'],normal.page)==0)
normal.call(S['AMITSE']['gate_render'],normal.page);normal.call(S['AMITSE']['gate_page_input'],normal.page,normal.key);normal.call(S['AMITSE']['gate_app_input'],normal.app,normal.key)
check('known foreign text page reaches original render and ESC input',all(normal.calls[n]==1 for n in ['render','page_input','app_input']))
for label,args in [('TEXT control with NULL source HII',{'null_control':True}),('page-form index outside table',{'bad_form':True})]:
 for bits in [1,3]:
  v=OneForeignPage(bits=bits,**args);unknown=v.call(S['AMITSE']['page_protected'],v.page)
  check(label+' is unknown with provider bits '+str(bits),unknown in [0xffffffff,0xffffffffffffffff])
  check(label+' has no verified redirect destination',v.call(S['AMITSE']['gate_redirect'])==0)
  before=bytes(v.u.mem_read(v.app,0x60))
  for _ in range(4):
   v.call(S['AMITSE']['gate_render'],v.page);v.call(S['AMITSE']['gate_page_input'],v.page,v.key);v.call(S['AMITSE']['gate_app_input'],v.app,v.key);v.call(S['AMITSE']['gate_poll'])
  check(label+' suppresses original renderer and ESC paths bits '+str(bits),all(v.calls[n]==0 for n in ['render','page_input','app_input','poll']))
  check(label+' does not set native exit flag or mutate app state',bytes(v.u.mem_read(v.app,0x60))==before and not v.stores)
  check(label+' original E91E returns to poll instead of cleanup',v.native_still_loops()==[0xe6bd])
  check(label+' only owned provider can be asked for password',(v.provider_calls['request']==0 if bits==1 else v.provider_calls['request']==4))
  observations.append({'synthetic_case':label,'provider_bits':bits,'classification':'UNKNOWN_MINUS_ONE','original_calls':dict(v.calls),'provider_calls':dict(v.provider_calls),'native_next_rva':'0xe6bd','physical_root_cause_proven':False})
 # Isolate the ordering defect: a non-question TEXT reaches HII validation
 # before question_op; it is not a case of a malformed protected Question.
 if args.get('null_control'):
  v=OneForeignPage(null_control=True);check('null-HII TEXT frame returns unknown before inspecting question opcode',v.call(S['AMITSE']['frame_protected'],v.frame)in [0xffffffff,0xffffffffffffffff])
  v.u.mem_write(v.control+0x20,q(0x99998888));check('same exact TEXT/array becomes unprotected with validated foreign HII',v.call(S['AMITSE']['frame_protected'],v.frame)==0)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,capstone
p=pefile.PE(str(D04.parent/'boot_context/AMITSE.original.efi'));code=p.get_memory_mapped_image();cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for name,start,end in [('native_exit_test',0xe91e,0xe942),('native_cleanup',0xe52d,0xe632),('native_sendform',0x20ee4,0x21360)]:
 (HERE/(name+'.asm.txt')).write_text('\n'.join(f'{i.address:08X} {i.bytes.hex():32} {i.mnemonic} {i.op_str}'for i in cs.disasm(code[start:end],start))+'\n')
report={'status':'REPRODUCED_POSSIBLE_UNKNOWN_PAGE_NO_SAFE_EXIT_COUNTEREXAMPLE_NOT_HARDWARE_DIAGNOSIS','checks':len(checks),'check_names':checks,'observations':observations,'frozen_guard_build_sha256':sha(CORE/'build/split_build.json'),'guard_sha256':{name:sha(CORE/'build'/(name+'.split-guard.bin'))for name in ['AMITSE','Setup']},'source_sha256':sha(CORE/'source/gate.c'),'fixture_sha256':sha(CORE/'verify_split.py'),'test_sha256':sha(Path(__file__)),'original_amitse_sha256':sha(D04.parent/'boot_context/AMITSE.original.efi'),'limits':['Exact frozen guard instructions and exact original native E91E branch execute. HII, provider, page-memory and original renderer/input bodies are explicit models.','This intentionally constructs a sole foreign form with a NULL-HII TEXT or out-of-range form index. No hardware page/control structures were captured; these states are not claimed to occur in physical screenshot310/311/312.','Provider bits1 models no ownership; bits3 models owned locked. An owned provider would be asked to display a password message, so the same all-black symptom is not established for every ownership state.','No screenshot/actual ASUS graphics/UI execution here. No NVRAM writes, new installer, physical actions, or changes to frozen artifacts.']}
(HERE/'counterexample.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'checks':len(checks),'report_sha256':sha(HERE/'counterexample.json')}))
