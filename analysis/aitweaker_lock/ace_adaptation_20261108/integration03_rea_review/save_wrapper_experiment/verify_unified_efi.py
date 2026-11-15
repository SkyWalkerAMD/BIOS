"""Read-only replay of the root-built integrated04 EFI and original ACE.

No production rebuild. Original save functions call the actual EFI guarded_set,
protected_change, password-core access predicate, feedback wrappers and notices.
Only hardware page-table checking and UEFI services use local doubles.
"""
import importlib.util
import json
import re
import struct
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ace_retry_state_unified',HERE/'verify_retry_state.py')
state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
b=state.base
DRIVER=b.ROOT/'analysis/aitweaker_lock/ace_adaptation_20261108/lock_1904_integrated04/driver'
EFI=DRIVER/'build/AiTweakerLock1904.efi';MAP=DRIVER/'build/driver.map'
PIN='463b94139cb64207e1b756965ebb9ca3513250c8712bbbcd20798fd317dec904'
DBASE=0x70000000


def symbols():
 result={}
 for line in MAP.read_text().splitlines():
  match=re.match(r'\s+[0-9a-fA-F]{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})\s+.*?(\w+\.obj)\s*$',line)
  if match:result[(match[1],match[3])]=DBASE+int(match[2],16)-0x140000000
 return result


class UnifiedFixture(state.StateFixture):
 def __init__(self,reconnect=False,install=True):
  self.actual_ready=False;self.stack_args=None;self.syms=symbols();self.guard_inputs=[]
  assert b.sha(EFI.read_bytes())==PIN
  super().__init__(False,False,reconnect)
  pe=b.pefile.PE(str(EFI));pe.relocate_image(DBASE);mapped=pe.get_memory_mapped_image()
  self.uc.mem_map(DBASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.uc.mem_write(DBASE,mapped)
  self.uc.mem_write(b.TSE+0x142ac,self.original_prologue)
  self.uc.mem_write(b.TRAMP,b'\xa5'*128);self.uc.mem_write(b.TRAMP+256,b'\xb5'*128)
  self.patch_array=b.ARENA+0x7000
  self.st=b.ARENA+0x6800
  self.q(self.sym('system_table','services.obj'),self.st)
  self.q(self.st+88,b.ARENA+0x4000);self.q(self.st+96,self.bs)
  self.q(self.sym('original_set_variable','services.obj'),b.STOP+0x1b0)
  self.q(b.ARENA+0x4058,self.sym('guarded_set','services.obj'))
  self.service_map[0x1b0]='SetVariableBackend'
  # The actual guarded policy recognizes this real protected memory store.
  self.target_guid=uuid.UUID('98cf19ed-4109-4681-b79d-9196757c7824').bytes_le
  self.uc.mem_write(b.ARENA+0x2100,self.target_guid)
  self.uc.mem_write(self.target_name,'SocketMemoryConfig\0'.encode('utf-16-le'))
  self.key=self.key_at(self.target_name,b.ARENA+0x2100)
  self.value_size=1392
  self.q(b.ARENA+0x3008,self.value_size)
  self.initial_persisted=bytes(self.value_size)
  edited=bytearray(self.initial_persisted);edited[0x10]=0x2a
  self.edited=bytes(edited);self.uc.mem_write(b.ARENA+0x3200,self.edited)
  self.persisted={self.key:(7,self.initial_persisted)}
  self.actual_ready=True
  self.set_owner(1,True,False)
  result=self.call(self.sym('save_feedback_prepare'),[b.TSE,0x94000,b.TRAMP+128,128,self.patch_array])
  assert result==1
  assert bytes(self.uc.mem_read(b.TRAMP,128))==b'\xa5'*128
  assert bytes(self.uc.mem_read(b.TRAMP+256,128))==b'\xb5'*128
  self.patches=[]
  for index in range(2):
   target,length,original,replacement=struct.unpack('<QQ18s18s4x',self.uc.mem_read(self.patch_array+index*56,56))
   self.patches.append({'target':target,'length':length,'original':original[:length],'replacement':replacement[:length]})
  assert [(p['target']-b.TSE,p['length']) for p in self.patches]==[(0x142ac,18),(0x440fc,16)]
  if install:
   for patch in self.patches:self.uc.mem_write(patch['target'],patch['replacement'])
   assert self.call(self.sym('save_feedback_commit'),[0,0,0,0])==1

 def sym(self,name,obj='save_feedback.obj'):return self.syms[(name,obj)]
 def d(self,address,value):self.uc.mem_write(address,struct.pack('<I',value))
 def get_actual(self,name,size=8,obj='save_feedback.obj'):return int.from_bytes(self.uc.mem_read(self.sym(name,obj),size),'little')
 def set_owner(self,token,owned,unlocked,busy=False):
  core=self.sym('password_core','services.obj')
  self.q(core+168,token);self.d(core+196,1)
  self.uc.mem_write(core+200,bytes([1,int(unlocked),int(busy),0]))
  self.d(self.sym('loop_depth','platform.obj'),1 if owned else 0)
  self.d(self.sym('platform_ready','services.obj'),1)

 def call(self,address,args,check_canaries=True):
  self.stack_args=(address,args[4:]) if len(args)>4 else None
  return super().call(address,args[:4],check_canaries)

 def hook(self,uc,address,size,data):
  if self.stack_args and address==self.stack_args[0]:
   rsp=uc.reg_read(b.x86.UC_X86_REG_RSP)
   for index,value in enumerate(self.stack_args[1]):self.q(rsp+0x28+index*8,value)
   self.stack_args=None
  if self.actual_ready and address==self.sym('memory_present','services.obj'):
   pointer=uc.reg_read(b.x86.UC_X86_REG_RCX);length=uc.reg_read(b.x86.UC_X86_REG_RDX)
   valid=length>0 and any(start<=pointer and pointer+length-1<=end for start,end,_ in uc.mem_regions())
   self.return_service(int(valid));return
  if self.actual_ready and address==self.sym('guarded_set','services.obj'):
   args=[uc.reg_read(r) for r in (b.x86.UC_X86_REG_RCX,b.x86.UC_X86_REG_RDX,b.x86.UC_X86_REG_R8,b.x86.UC_X86_REG_R9)]
   args.append(self.readq(uc.reg_read(b.x86.UC_X86_REG_RSP)+0x28))
   key=self.key_at(args[0],args[1]);payload=bytes(uc.mem_read(args[4],args[3]))
   self.guard_inputs.append({'name':key[1],'size':args[3],'sha256':b.sha(payload),'protected':key==self.key})
  if self.actual_ready and address==b.STOP+0x1b0:
   rcx,rdx,r8,r9=[uc.reg_read(r) for r in (b.x86.UC_X86_REG_RCX,b.x86.UC_X86_REG_RDX,b.x86.UC_X86_REG_R8,b.x86.UC_X86_REG_R9)]
   key=self.key_at(rcx,rdx);value=self.readq(uc.reg_read(b.x86.UC_X86_REG_RSP)+0x28)
   assert r9<=4096
   payload=bytes(uc.mem_read(value,r9));self.persisted[key]=(r8,payload)
   self.writes.append({'name':key[1],'status':'0x0','size':r9,'sha256':b.sha(payload),'protected_fixture':key==self.key})
   self.service_calls.append('ActualGuardChainedSetVariable')
   self.return_service(0);return
  super().hook(uc,address,size,data)

 def take_notice(self):return self.call(self.sym('save_feedback_take_notice'),[0,0,0,0])
 def attempt(self,caller,locked):
  # The fixture status fields in the superclass are unused: RT now points to
  # the actual unified EFI guard and its original_set_variable points to UEFI I/O.
  core=self.sym('password_core','services.obj');self.uc.mem_write(core+201,bytes([int(not locked)]))
  before_guard=len(self.guard_inputs);before_status=len(self.native_commit_statuses)
  row=super().attempt(caller,locked)
  assert self.get_actual('save_head')==self.get_actual('action_head')==0
  assert self.get_actual('save_depth',4)==self.get_actual('action_depth',4)==0
  row.update({'unified_efi_sha256':PIN,'actual_guard_inputs':self.guard_inputs[before_guard:],
   'actual_native_commit_statuses':[hex(x) for x in self.native_commit_statuses[before_status:]],
   'actual_private_heads_and_depths_empty':True,'repair_flags':True,'save_stay_wrapper':True})
  # Keep artifacts compact: exact edited/persisted bytes have independent hashes.
  for key in ('cache_bytes','persisted_protected'):
   row[key+'_sha256']=b.sha(bytes.fromhex(row.pop(key)))
  return row


def main():
 rows=[]
 for caller in ('F10','CommonSave','SaveStay','SaveStayCachedBefore','SaveStayCachedAfter'):
  for reconnect in (False,True):
   f=UnifiedFixture(reconnect)
   failed=f.attempt(caller,True)
   assert failed['cache_bytes_sha256']==b.sha(f.edited)
   assert failed['persisted_protected_sha256']==b.sha(f.initial_persisted)
   assert failed['actual_native_commit_statuses']==[hex(b.DENIED)]
   assert not any(w['protected_fixture'] for w in failed['writes'])
   assert failed['changed_82789']==failed['unsaved_82738']==1
   assert f.take_notice()==b.DENIED and f.take_notice()==0
   retry=f.attempt(caller,False)
   assert retry['cache_bytes_sha256']==retry['persisted_protected_sha256']==b.sha(f.edited)
   assert retry['actual_native_commit_statuses']==['0x0']
   assert retry['cache_pointer']!=failed['cache_pointer'] and retry['changed_82789']==0
   assert f.take_notice()==0
   if caller.startswith('SaveStay'):assert retry['unsaved_82738']==0
   rows.append({'case':'actual_guard_denial_then_unlocked_retry','caller':caller,'reconnect':reconnect,'first':failed,'retry':retry})
 for mode in ('unchanged','unprotected_memory_offset'):
  f=UnifiedFixture();data=bytearray(f.initial_persisted)
  if mode=='unprotected_memory_offset':data[0x11]=0x5a
  f.edited=bytes(data);f.uc.mem_write(b.ARENA+0x3200,f.edited)
  row=f.attempt('CommonSave',True)
  assert row['actual_native_commit_statuses']==['0x0'] and row['persisted_protected_sha256']==b.sha(f.edited)
  assert f.take_notice()==0
  rows.append({'case':'actual_locked_guard_'+mode,'result':row})
 f=UnifiedFixture();f.set_owner(1,False,False);row=f.attempt('CommonSave',True)
 assert row['changed_82789']==1 and f.take_notice()==0
 rows.append({'case':'unowned_denial_no_notice','result':row})
 f=UnifiedFixture();f.attempt('CommonSave',True);f.set_owner(2,True,False);assert f.take_notice()==0
 rows.append({'case':'stale_session_notice_dropped'})
 f=UnifiedFixture();f.attempt('CommonSave',True);f.set_owner(1,True,False,True);assert f.take_notice()==0
 f.set_owner(1,True,False,False);assert f.take_notice()==b.DENIED and f.take_notice()==0
 rows.append({'case':'busy_notice_deferred_then_consumed_once'})
 f=UnifiedFixture();f.set_owner(1,False,False);f.uc.mem_write(b.ARENA+0x3200,f.initial_persisted)
 result=f.call(b.TSE+0x5ef44,[0,0,0,0]);assert result==0 and f.native_body_entries==1 and f.take_notice()==0
 rows.append({'case':'vendor_initializer_unowned_unchanged_protected_value','return':hex(result),'native_save_calls':1})
 f=UnifiedFixture(install=False);p=f.patches[0];f.uc.mem_write(p['target'],p['replacement'])
 assert f.call(f.sym('save_feedback_commit'),[0,0,0,0])==0
 assert f.call(f.sym('save_feedback_cancel_unpublished'),[0,0,0,0])==0
 f.uc.mem_write(p['target'],p['original']);assert f.call(f.sym('save_feedback_cancel_unpublished'),[0,0,0,0])==1
 rows.append({'case':'partial_publish_commit_rejected_rollback_cancel'})
 f=UnifiedFixture()
 for p in reversed(f.patches):f.uc.mem_write(p['target'],p['original'])
 assert f.call(f.sym('save_feedback_cancel_unpublished'),[0,0,0,0])==0
 f.call(f.sym('end_platform','platform.obj'),[0,0,0,0]);assert f.get_actual('retired',4)==1 and f.get_actual('armed',4)==0
 rows.append({'case':'late_install_failure_restored_then_actual_end_platform_retires'})
 f=UnifiedFixture();f.attempt('CommonSave',True);f.call(f.sym('end_platform','platform.obj'),[0,0,0,0])
 assert f.take_notice()==0 and f.get_actual('loop_depth',4,'platform.obj')==0
 before=f.native_body_entries;assert f.call(b.TSE+0x142ac,[0,0,0,0])==0 and f.native_body_entries==before
 rows.append({'case':'actual_end_platform_clears_owner_notice_and_retires_saved_entries'})
 f=UnifiedFixture();f.uc.mem_write(b.TSE+0x440fc,b'\x90');row=f.attempt('CommonSave',True)
 assert row['changed_82789']==0 and f.get_actual('password_core',4,'services.obj')==0  # environment opaque remains zero
 core=f.sym('password_core','services.obj');assert int.from_bytes(f.uc.mem_read(core+196,4),'little')==3
 rows.append({'case':'foreign_entry_owner_loss_faults_without_dirty_rewrite','result':row})
 report={'status':'PASS_UNIFIED_EFI_WITH_ACTUAL_GUARD_AND_ORIGINAL_ACE_SAVE','case_groups':len(rows),'rows':rows,
  'unified_efi':{'path':str(EFI),'sha256':PIN,'map_sha256':b.sha(MAP.read_bytes())},
  'script_sha256':b.sha(Path(__file__).read_bytes()),'fixture_source_sha256':b.sha((HERE/'verify_retry_state.py').read_bytes()),
  'original_amitse_sha256':b.PIN,'production_rebuild':False,'device_access':False,
  'actual_unified_functions':['save_feedback_prepare','save_feedback_commit','save_wrapper','stay_wrapper','save_feedback_note_denial',
   'save_feedback_take_notice','save_feedback_retire','save_feedback_cancel_unpublished','guarded_set','protected_change',
   'platform_can_enter','platform_session_owned','ap_can_enter','ap_fault','end_platform','audit'],
  'scope':'Real SocketMemoryConfig GUID/name/1392-byte payload with changed protected byte or unrelated byte; original native cache/OEM calls execute.',
  'limits':['UEFI services, page-table permission result and authenticated/locked state are controlled fixtures; actual password KDF/UI not exercised.',
   'Optional OEM protocol and arbitrary notification registrants are absent; full HII dynamic rebuilding and physical UI remain separate.',
   'The safe visible error message is not rendered in this test; exact notice status/token/owner/once semantics are verified.',
   'Unrelated OEM save count is still written on a denied save; this is not transactional rollback.']}
 out=HERE/'unified_efi_verification.json';out.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'groups':len(rows),'output':str(out),'sha256':b.sha(out.read_bytes()),'efi_sha256':PIN},indent=2))


if __name__=='__main__':main()
