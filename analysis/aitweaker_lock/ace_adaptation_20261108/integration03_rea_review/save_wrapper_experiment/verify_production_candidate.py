"""Compile and replay the actual integrated04 save_feedback source.

The shared production sources are read only by this script. All binaries,
fixtures and reports are confined to this independent experiment directory.
"""
import importlib.util
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ace_retry_fixture',HERE/'verify_retry_state.py')
state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
b=state.base
DRIVER=b.ROOT/'analysis/aitweaker_lock/ace_adaptation_20261108/lock_1904_integrated04/driver'
OUT=HERE/'production_build';OUT.mkdir(exist_ok=True)
DLL=OUT/'save_feedback_test.dll'


def build():
 env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(HERE/'.zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'.zig-local')
 commands=[];objects=[]
 for source in (DRIVER/'save_feedback.c',HERE/'production_fixture_support.c'):
  obj=OUT/(source.stem+'.obj');objects.append(str(obj))
  commands.append([str(b.ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(b.ZIG.parent/'lib/include'),
   '-I',str(DRIVER),'-std=c11','-O2','-DAITWK_SAVE_FEEDBACK_TEST_EXPORT','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone',
   '-fshort-wchar','-Wall','-Wextra','-Werror','-Wno-dll-attribute-on-redeclaration','-c',str(source),'-o',str(obj)])
 commands.append([str(b.ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0',
  '/map:'+str(OUT/'save_feedback.map'),'/out:'+str(DLL),*objects])
 logs=[]
 for command in commands:
  r=subprocess.run(command,capture_output=True,text=True,env=env,cwd=HERE,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  logs.append({'command':command,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if r.returncode:
   (OUT/'build.json').write_text(json.dumps(logs,indent=2)+'\n');raise RuntimeError('actual production source build failed')
 pe=b.pefile.PE(str(DLL));assert not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
 report={'status':'PASS_ACTUAL_SOURCE_COMPILED','commands_and_logs':logs,'dll_sha256':b.sha(DLL.read_bytes()),
  'inputs':{str(p):b.sha(p.read_bytes()) for p in (DRIVER/'save_feedback.c',DRIVER/'save_feedback.h',HERE/'production_fixture_support.c')},
  'test_export_only':'AITWK_SAVE_FEEDBACK_TEST_EXPORT adds query/exports; normal logic is unchanged'}
 (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');return report


class ProductionFixture(state.StateFixture):
 def __init__(self,reconnect=False,install=True):
  self.stack_args=None
  b.DLL=DLL
  super().__init__(False,False,reconnect)
  self.uc.mem_write(b.TSE+0x142ac,self.original_prologue)
  self.uc.mem_write(b.TRAMP,b'\xa5'*128)
  self.uc.mem_write(b.TRAMP+256,b'\xb5'*128)
  self.patch_array=b.ARENA+0x7000
  self.call(self.exports['fixture_owner'],[1,1,0,0])
  result=self.call(self.exports['save_feedback_prepare'],[b.TSE,0x94000,b.TRAMP+128,128,self.patch_array])
  assert result==1
  assert bytes(self.uc.mem_read(b.TRAMP,128))==b'\xa5'*128
  assert bytes(self.uc.mem_read(b.TRAMP+256,128))==b'\xb5'*128
  self.patches=[]
  for index in range(2):
   target,length,original,replacement=struct.unpack('<QQ18s18s4x',self.uc.mem_read(self.patch_array+index*56,56))
   self.patches.append({'target':target,'length':length,'original':original[:length],'replacement':replacement[:length]})
  assert [(p['target']-b.TSE,p['length']) for p in self.patches]==[(0x142ac,18),(0x440fc,16)]
  assert self.readq(b.TSE+0x6bb18)==b.TSE+0x440fc
  if install:
   for patch in self.patches:self.uc.mem_write(patch['target'],patch['replacement'])
   assert self.call(self.exports['save_feedback_commit'],[0,0,0,0])==1

 def call(self,address,args,check_canaries=True):
  self.stack_args=(address,args[4:]) if len(args)>4 else None
  return super().call(address,args[:4],check_canaries)

 def hook(self,uc,address,size,data):
  if self.stack_args and address==self.stack_args[0]:
   rsp=uc.reg_read(b.x86.UC_X86_REG_RSP)
   for index,value in enumerate(self.stack_args[1]):self.q(rsp+0x28+index*8,value)
   self.stack_args=None
  if hasattr(self,'exports') and address in [self.exports.get('save_wrapper'),self.exports.get('save_stay_wrapper')]:
   raise AssertionError('constructor compatibility wrapper must never execute')
  super().hook(uc,address,size,data)

 def query(self,field):return self.call(self.exports['save_feedback_test_query'],[field,0,0,0])
 def take_notice(self):return self.call(self.exports['save_feedback_take_notice'],[0,0,0,0])

 def attempt(self,caller,denied):
  row=super().attempt(caller,denied)
  assert [self.query(n) for n in range(4)]==[0,0,0,0]
  row.update({'implementation':'actual integrated04 save_feedback.c','actual_private_scope_state_empty':True,
   'repair_flags':True,'save_stay_wrapper':True,'shared_page_gateway_offset':128,'gateway_capacity':128})
  return row


def main():
 build_report=build();rows=[]
 for caller in ('F10','CommonSave','SaveStay','SaveStayCachedBefore','SaveStayCachedAfter'):
  for reconnect in (False,True):
   f=ProductionFixture(reconnect)
   first=f.attempt(caller,True)
   assert first['cache_bytes']==f.edited.hex() and first['persisted_protected']==f.initial_persisted.hex()
   assert first['changed_82789']==first['unsaved_82738']==1 and not first['freed']
   assert f.take_notice()==b.DENIED and f.take_notice()==0
   retry=f.attempt(caller,False)
   assert retry['persisted_protected']==retry['cache_bytes']==f.edited.hex()
   assert retry['changed_82789']==0 and retry['cache_pointer']!=first['cache_pointer']
   assert f.take_notice()==0
   if caller.startswith('SaveStay'):assert retry['unsaved_82738']==0
   rows.append({'case':'failed_then_success','caller':caller,'reconnect':reconnect,'first':first,'retry':retry,'notice_once':True})
 # Ownership gates messages only; they never silently bypass a save or clear edits.
 f=ProductionFixture();f.call(f.exports['fixture_owner'],[1,0,0,0]);row=f.attempt('CommonSave',True)
 assert row['changed_82789']==row['unsaved_82738']==1 and f.take_notice()==0
 rows.append({'case':'unowned_denial_no_popup','result':row})
 f=ProductionFixture();f.attempt('CommonSave',True);f.call(f.exports['fixture_owner'],[2,1,0,0]);assert f.take_notice()==0
 rows.append({'case':'stale_token_notice_dropped'})
 f=ProductionFixture();f.attempt('CommonSave',True);f.call(f.exports['fixture_owner'],[1,1,1,0]);assert f.take_notice()==0
 f.call(f.exports['fixture_owner'],[1,1,0,0]);assert f.take_notice()==b.DENIED and f.take_notice()==0
 rows.append({'case':'busy_defers_notice'})
 f=ProductionFixture();f.call(f.exports['fixture_owner'],[1,0,0,0]);f.setq('fixture_status',0);f.setd('fixture_mark_denial',0)
 result=f.call(b.TSE+0x5ef44,[0,0,0,0]);assert result==0 and f.native_body_entries==1 and f.take_notice()==0
 rows.append({'case':'original_vendor_initializer_without_owner','return':hex(result),'original_save_calls':1})
 # Partial publication fails commit and permits cancellation only after originals are proven restored.
 f=ProductionFixture(install=False);p=f.patches[0];f.uc.mem_write(p['target'],p['replacement'])
 assert f.call(f.exports['save_feedback_commit'],[0,0,0,0])==0
 assert f.call(f.exports['save_feedback_cancel_unpublished'],[0,0,0,0])==0
 f.uc.mem_write(p['target'],p['original']);assert f.call(f.exports['save_feedback_cancel_unpublished'],[0,0,0,0])==1
 assert f.query(4)==0
 rows.append({'case':'partial_publish_commit_rejected_exact_rollback_then_cancel'})
 # Root's terminal rollback after a later browser-loop failure: restore native
 # entries, retire permanently, retain the shared gateway allocation.
 f=ProductionFixture()
 for p in reversed(f.patches):f.uc.mem_write(p['target'],p['original'])
 assert f.call(f.exports['save_feedback_cancel_unpublished'],[0,0,0,0])==0
 f.call(f.exports['save_feedback_retire'],[0,0,0,0]);assert f.query(6)==1 and f.query(5)==0 and f.take_notice()==0
 rows.append({'case':'armed_then_later_failure_reverse_restore_retire_keep_gateway'})
 # Foreign SaveStay entry mutation prevents dirty writes even during common save.
 f=ProductionFixture();f.uc.mem_write(b.TSE+0x440fc,b'\x90');r=f.attempt('CommonSave',True)
 assert r['changed_82789']==0 and f.get('fixture_faults')>0 and f.take_notice()==state.ERR(7)
 rows.append({'case':'foreign_entry_owner_loss_faults_without_dirty_restore','result':r})
 f=ProductionFixture();f.call(f.exports['save_feedback_retire'],[0,0,0,0]);before=f.native_body_entries
 assert f.call(b.TSE+0x142ac,[0,0,0,0])==0 and f.native_body_entries==before
 rows.append({'case':'retired_entry_never_reenters_native_save'})
 report={'status':'PASS_ACTUAL_INTEGRATED04_SAVE_FEEDBACK_WITH_ORIGINAL_ACE', 'case_groups':len(rows),'rows':rows,
  'production_source_sha256':b.sha((DRIVER/'save_feedback.c').read_bytes()),'production_header_sha256':b.sha((DRIVER/'save_feedback.h').read_bytes()),
  'test_dll_sha256':b.sha(DLL.read_bytes()),'test_script_sha256':b.sha(Path(__file__).read_bytes()),'original_amitse_sha256':b.PIN,
  'build_report':'production_build/build.json','build_inputs':build_report['inputs'],
  'gateway':{'shared_page_offset':128,'capacity':128,'save_iterator_used':32,'save_stay_offset_in_gateway':64,'save_stay_used':44,
             'surrounding_page_canaries_preserved':True,'patch_lengths':[18,16]},
  'scope':'Actual integrated04 source, original cache refresh/OEM handlers and cached entry callers; UEFI services/context are local doubles.',
  'limitations':['Physical ASUS protocols, HII dynamic rebuilding and UI popup are not exercised.','Existing production guard policy is represented by an explicit-denial I/O fixture; integration guard tests remain required.',
   'Test-only exports/query add observation access without changing normal feedback logic.','No flash, original PE mutation, NVRAM rollback or production activation is performed by this script.']}
 out=HERE/'production_candidate_verification.json';out.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'groups':len(rows),'output':str(out),'sha256':b.sha(out.read_bytes()),'production_source_sha256':report['production_source_sha256']},indent=2))


if __name__=='__main__':main()
