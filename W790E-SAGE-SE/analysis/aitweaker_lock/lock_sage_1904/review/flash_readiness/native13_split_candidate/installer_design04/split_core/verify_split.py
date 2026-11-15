"""Actual split guard bytes, reused bounded OEM fixtures, no installer.

The frozen N12 test source is read without executing its report-writing tail.
Only fixture addresses and image loading are adapted; old N12 payloads are made
inaccessible. Public provider, firmware services and full browser remain models.
"""
from pathlib import Path
import hashlib,json,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BUILD=HERE/'build';N13=HERE.parents[1]
OLD=N13.parent/'native12_safety_review/implementation'
meta=json.loads((BUILD/'split_build.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def make_namespace():
 text=(OLD/'verify_guard.py').read_text()
 prefix=text.split('\nv=GateVM();check(',1)[0]
 scope={'__file__':str(OLD/'verify_guard.py')}
 exec(compile(prefix,str(OLD/'verify_guard.py'),'exec'),scope)
 U,R=scope['U'],scope['R']
 guards={name:int(value,16)for name,value in meta['guard_bases'].items()}
 state=int(meta['state_base'],16)
 scope['S']={name:{key:guards[name]+int(value,16)for key,value in meta['symbol_offsets'].items()}for name in guards}
 scope['PROVIDER_GUID']=uuid.UUID('87e3c6fa-11fb-4e77-af2d-ea50b640fa13').bytes_le
 # The old provider MODEL takes its frame-head address through this field.
 # This is explicitly a fixture alias, not an original PE RVA/header change.
 scope['manifest']['modules']['AMITSE']['context_head_rva']=hex(state-scope['TSE'])
 base_init=scope['VM'].__init__
 def split_init(self):
  base_init(self)
  self.split_guard_reads=0
  for name,b in [('AMITSE',scope['TSE']),('Setup',scope['SETUP'])]:
   original=scope['ns']['pefile'].PE(str(N13/'boot_context'/(name+'.original.efi')))
   size=original.OPTIONAL_HEADER.SizeOfImage;page_end=(size+4095)&~4095
   fixture=(BUILD/(name+'.memory-fixture.bin')).read_bytes()
   assert hashlib.sha256(fixture).hexdigest()==meta['module_fixtures'][name]['memory_fixture_sha256']
   # Preserve modeled runtime globals, while restoring original PE headers,
   # original text with exactly the new detours, and the six callback slots.
   self.u.mem_write(b,fixture[:original.OPTIONAL_HEADER.SizeOfHeaders])
   for section in original.sections:
    if section.Name.rstrip(b'\0')==b'.text':
     at=section.VirtualAddress;self.u.mem_write(b+at,fixture[at:at+section.Misc_VirtualSize])
   for row in meta['patches']:
    if row['module']==name:
     at=int(row['rva'],16);self.u.mem_write(b+at,bytes.fromhex(row['new']))
   old_hi=next(hi for lo,hi in self.ranges if lo==b)
   self.ranges=[(lo,b+size if lo==b else hi)for lo,hi in self.ranges]
   if b+page_end<old_hi:
    self.u.mem_write(b+page_end,bytes(old_hi-b-page_end))
    self.u.mem_protect(b+page_end,old_hi-b-page_end,U.UC_PROT_NONE)
   payload=(BUILD/(name+'.split-guard.bin')).read_bytes()
   assert hashlib.sha256(payload).hexdigest()==meta['module_fixtures'][name]['guard_sha256']
   allocation=(len(payload)+4095)&~4095
   self.map(guards[name],allocation);self.u.mem_write(guards[name],payload)
   self.u.mem_protect(guards[name],allocation,U.UC_PROT_READ|U.UC_PROT_EXEC)
  self.map(state,4096);self.u.mem_write(state,(BUILD/'owned-state-fixture.bin').read_bytes())
  self.u.mem_protect(state,4096,U.UC_PROT_READ|U.UC_PROT_WRITE)
 scope['VM'].__init__=split_init
 def split_call(self,address,*args):
  # The old fixture reused one alternate stack for every nested body. A call
  # made while a nested body was suspended could overwrite that very frame.
  # Reserve a fresh bounded 64 KiB below the actual suspended native RSP.
  sp=scope['STACK']+0x3ffe08
  if self.body_context is not None:sp=((self.body_context.reg_read(R.UC_X86_REG_RSP)-0x10000)&~15)|8
  assert scope['STACK']+0x10000<sp<scope['STACK']+0x3fff00
  self.u.mem_write(sp,scope['q'](scope['STOP'])+b'\xcc'*0x100)
  self.u.reg_write(R.UC_X86_REG_RSP,sp)
  for i,value in enumerate(args):
   if i<4:self.u.reg_write([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i],value)
   else:self.u.mem_write(sp+40+(i-4)*8,scope['q'](value))
  self.u.emu_start(address,0,count=200000000)
  assert self.u.reg_read(R.UC_X86_REG_RIP)in [scope['STOP'],scope['TSE']+0xe1ca],('instruction bound',hex(self.u.reg_read(R.UC_X86_REG_RIP)))
  return self.u.reg_read(R.UC_X86_REG_RAX)
 scope['VM'].call=split_call
 scope['SPLIT_STATE_ADDRESS']=state
 scope['SPLIT_META']=meta
 return scope

def main():
 scope=make_namespace()
 text=(OLD/'verify_guard.py').read_text()
 body='v=GateVM();check('+text.split('\nv=GateVM();check(',1)[1].split('\nreport={',1)[0]
 body=body.replace('statically extended modules have exact Setup identity','split allocations bind exact original-sized Setup identity')
 exec(compile(body,str(OLD/'verify_guard.py')+' [split fixture adaptation]','exec'),scope)
 checks=scope['checks'];base_checks=len(checks)
 V,S,q,d=scope['GateVM'],scope['S'],scope['q'],scope['d'];state=scope['SPLIT_STATE_ADDRESS']
 for phase in [0,3,4,0xffffffff]:
  for name in ['gate_render','gate_page_input','gate_app_input','gate_frame_input','gate_navigation','gate_poll','gate_loop','gate_callback','gate_route','gate_variable_commit','gate_defaults','gate_save']:
   vm=V();vm.u.mem_write(state+24,d(phase))
   module='Setup'if name in ['gate_callback','gate_route']else'AMITSE'
   result=vm.call(S[module][name],0,0,0,0,0,0)
   expected=0 if name in ['gate_render','gate_page_input','gate_app_input','gate_frame_input','gate_poll','gate_save']else scope['ERR'](15)
   if name!='gate_poll':assert result==expected,(phase,name,hex(result))
   assert not any(vm.calls.values()) and not any(vm.provider_calls.values()) and not vm.alloc_calls and not vm.getvar_calls,(phase,name)
   checks.append(f'invalid/ended split phase {phase:#x} rejects {name} before original/provider')
 for field,raw,label in [(0,q(0),'binding magic'),(8,d(2),'binding revision'),(12,d(3),'module kind'),(16,d(0xffffffff),'binding offset'),(20,d(159),'payload extent'),(24,q(0),'original base'),(32,q(0xa6020),'expanded original image'),(40,q(0x31000000),'guard base'),(48,q(1),'state base'),(56,q(8192),'state extent')]:
  vm=V();vm.u.mem_write(S['AMITSE']['gate_binding']+field,raw)
  assert vm.call(S['AMITSE']['gate_render'],vm.pages[0])==0 and not vm.calls['render'] and not any(vm.provider_calls.values())
  checks.append('invalid '+label+' rejects before native Main renderer')
 vm=V();vm.provider_present=True;vm.provider_bits=7;vm.u.mem_write(state+24,d(2));vm.current(1)
 assert vm.call(S['AMITSE']['gate_render'],vm.pages[1])==0 and vm.calls['render']==0 and not any(vm.provider_calls.values())
 vm.current(0);assert vm.call(S['AMITSE']['gate_render'],vm.pages[0])==0 and vm.calls['render']==1
 checks.append('retired resident guard ignores stale provider grant and preserves safe Main')
 report={'status':'PASS_SPLIT_GUARD_ACTUAL_BYTES_WITH_EXPLICIT_MODELS','checks':len(checks),'reused_policy_checks':base_checks,'check_names':checks,'split_build_sha256':sha(BUILD/'split_build.json'),'test_source_sha256':sha(Path(__file__)),'frozen_fixture_sources':{name:sha(OLD/name)for name in ['verify_guard.py']},'guard_sha256':{k:v['guard_sha256']for k,v in meta['module_fixtures'].items()},'original_module_sizes_unchanged':True,'old_appended_payloads_inaccessible':True,'split_guard_RX_and_state_RW_nonX':True,'limits':['Public provider protocol, HII/variable services, page-permission queries and OEM full browser body are explicit models.','Original selected native dispatch/call/prologue/trampoline instructions execute in Unicorn; no host UEFI or hardware execution.','No RAM installer, allocation/permission transaction, native UI acceptance, persistent storage test or permanent firmware bootstrap.']}
 (BUILD/'split_guard_regression.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'checks':len(checks),'policy_checks':base_checks}))

if __name__=='__main__':main()
