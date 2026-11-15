"""ACE original-byte owner regression; local Unicorn only, no hardware access.

Adapts the previously reviewed SAGE test to the independently resolved ACE
addresses. Retains baseline counterexamples and executes real compiled UI,
owner, HII and persistence code; OEM services/full browser are explicit fixtures.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct,uuid,zlib

HERE=Path(__file__).resolve().parent
CASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
REFERENCE_DRIVER=CASE.parent/'lock_1904_history02/driver'
SAGE=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness'
RUNTIME_TEMPLATE=SAGE/'runtime_navigation/verify_runtime_paths.py'
OWNER_TEMPLATE=SAGE/'late_attach_candidate/verify_late_attach.py'
HISTORY_TEMPLATE=REFERENCE_DRIVER/'verify_history.py'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

# These mappings are independently confirmed against ACE original PE bytes in
# this adaptation's REA and history review. No address is inferred at runtime.
ADDRESS_MAP={
 '0x83468':'0x82628','0x6b928':'0x6af78','0x6b930':'0x6af80',
 '0x6b840':'0x6ae90','0x626c':'0x62bc','0x34b2c':'0x34b7c',
 '0x15320':'0x15370','0xe1b8':'0xe208','0x835a0':'0x82760',
 '0x835b8':'0x82778','0x10220':'0x10270','0x1a6000':'0x1a4000',
}

def adapt_addresses(text):
 for old,new in ADDRESS_MAP.items():text=text.replace(old,new)
 return text.replace('Pro WS W790E-SAGE SE','Pro WS W790-ACE')

def load_adapter(build_folder):
 text=(REFERENCE_DRIVER/'verify_adapter.py').read_text(encoding='utf8').split('\nchecks=[]',1)[0]
 text=text.replace("HERE/'build/driver.map'","BINDING_BUILD/'driver.map'").replace("HERE/'build/AiTweakerLock1904.efi'","BINDING_BUILD/'AiTweakerLock1904.efi'")
 ns={'__file__':str(REFERENCE_DRIVER/'verify_adapter.py'),'BINDING_BUILD':build_folder}
 exec(compile(text,str(REFERENCE_DRIVER/'verify_adapter.py'),'exec'),ns)
 return ns

def load_runtime(build_folder):
 source=RUNTIME_TEMPLATE.read_text(encoding='utf8').split('\nv=RuntimeVM();v.guard()',1)[0]
 source=source.replace("HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];DRIVER=CASE/'driver'","DRIVER=REFERENCE_DRIVER")
 source=re.sub(r"^assert hashlib\.sha256\(.*\n",'',source,flags=re.M)
 start=source.index("prefix=(DRIVER/'verify_adapter.py')")
 end=source.index("for name in ['VM'",start)
 source=source[:start]+"ns=load_adapter(BINDING_BUILD)\n"+source[end:]
 source=adapt_addresses(source)
 # The integrated entry now binds FormBrowser2 to the original ACE interface.
 # Return that relocated original object, rather than the old heap stand-in.
 assert "q(HEAP+0x1b0000)" in source
 source=source.replace("q(HEAP+0x1b0000)","q(TSE+0x6b528)")
 marker='self.setup_discovery()'
 assert source.count(marker)==1
 source=source.replace(marker,marker+"\n  # Owner review assumes initialization already succeeded; EBS initialization\n  # and its event-order faults have their own isolated test suite.\n  if 'services_initialized' in symbols:self.u.mem_write(symbols['services_initialized'],d(1))\n  raw=bytearray(self.u.mem_read(self.rt,0x88));raw[16:20]=bytes(4);self.u.mem_write(self.rt+16,d(zlib.crc32(raw)))")
 ns={'__file__':str(RUNTIME_TEMPLATE),'REFERENCE_DRIVER':REFERENCE_DRIVER,'BINDING_BUILD':build_folder,'load_adapter':load_adapter}
 exec(compile(source,str(RUNTIME_TEMPLATE),'exec'),ns)
 return ns

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--build-folder',type=Path,default=HERE/'build');parser.add_argument('--output',type=Path,default=HERE/'owner_regression.json');args=parser.parse_args()
 build_folder=args.build_folder.resolve()
 build=json.loads((build_folder/'build.json').read_text(encoding='utf8'))
 assert sha(build_folder/'AiTweakerLock1904.efi')==build['efi_sha256']
 if build_folder==(HERE/'build').resolve():
  for name,digest in build['sources'].items():assert sha(HERE/'snapshot'/name)==digest,name
 else:
  for name,digest in build['sources'].items():assert sha(build_folder.parent.parent/name)==digest,name
 runtime=load_runtime(build_folder)
 ns={'__file__':str(Path(__file__).resolve()),'Path':Path,'hashlib':hashlib,'json':json,'struct':struct,'uuid':uuid,
     'DRIVER':REFERENCE_DRIVER,'REFERENCE_DRIVER':REFERENCE_DRIVER,'BUILD_FOLDER':build_folder,'load_runtime':load_runtime,'load_adapter':load_adapter,'sha':sha}
 for name in ['RuntimeVM','U','R','TSE','SETUP','HEAP','STOP','symbols','q','d','w','GET','SET','OC','OCGUID','MEM','MEMGUID','ERR']:ns[name]=runtime[name]
 source=OWNER_TEMPLATE.read_text(encoding='utf8')
 body=source[source.index('CALLBACK='):source.index("# Reuse the actual OEM history/ESC fixture")]
 old="oldns={'__file__':str(runtime)}\nexec(compile(runtime.read_text(encoding='utf8').split('\\nv=RuntimeVM();v.guard()',1)[0],str(runtime),'exec'),oldns)"
 assert old in body
 body=body.replace(old,"oldns=load_runtime(REFERENCE_DRIVER/'build')")
 body=adapt_addresses(body)
 (HERE/'effective_owner_cases.py').write_text(body,encoding='utf8')
 exec(compile(body,str(HERE/'effective_owner_cases.py'),'exec'),ns)
 checks=ns['checks'];check=ns['check'];TestVM=ns['TestVM']
 TSE,SETUP,HEAP,STOP,symbols,q,d,w,ERR=(ns[n] for n in ['TSE','SETUP','HEAP','STOP','symbols','q','d','w','ERR'])

 # Original ACE history and PageInput still execute in the ownerless case.
 hns=load_adapter(build_folder)
 hns.update(HISTORY=HEAP+0x180000,OUT=HEAP+0x190000,CAPACITY=28,NOT_FOUND=ERR(14),check=check,checks=checks,uuid=uuid)
 history=HISTORY_TEMPLATE.read_text(encoding='utf8')
 history=history[history.index('class NativeHistoryVM'):history.index('\nv=NativeHistoryVM();v.poll()')]
 exec(compile(history,str(HISTORY_TEMPLATE),'exec'),hns)
 h=hns['NativeHistoryVM']();h.u.mem_write(symbols['loop_depth'],d(0));h.u.mem_write(symbols['password_core']+201,b'\1')
 h.poll();check('unowned stale grant redirects to Main using original ACE history',h.getd(h.app+0x28)==1 and h.calls['ui']==0)
 h.current(3);h.call(TSE+0x10270,1,3);check('unowned Security parent remains verified Main',h.parent(3)==(0,1))
 h.esc(3);check('unowned original ACE Security ESC returns Main',h.getd(h.app+0x28)==1 and h.getd(TSE+0x82778)==1)
 check('original ACE append/parent/PageInput/dispatcher executed',all(h.native_counts[n]>0 for n in h.native_counts))

 # A successful AllocatePages result has not yet published any pointer. The
 # API conservatively stops retrying before the first guard write, regardless
 # of whether that attempted publication is subsequently reported successful.
 class BoundaryVM(TestVM):
  def __init__(self):
   self.alloc_fail=False;self.trampoline_unwritable=False;self.guard_fail=False;self.guard_entries=0
   super().__init__(False)
  def hook(self,u,address,size,data):
   if address==STOP+0x100 and self.alloc_fail:self.ret(ERR(9));return
   # INTEGRATED04 also prepares the two save gateways in the same page.
   if address==symbols['memory_present'] and self.trampoline_unwritable and self.arg(0)==HEAP+0x300000 and self.arg(1)==256:self.ret(0);return
   if address==symbols['install_variable_guard']:
    self.guard_entries+=1
    if self.guard_fail:self.ret(0);return
   super().hook(u,address,size,data)
 def attach(v):return v.call(symbols['attach_platform'],TSE,0xa2000,SETUP,0x1a4000)
 for name,flag in [('allocation failure','alloc_fail'),('unwritable unpublished trampoline','trampoline_unwritable')]:
  v=BoundaryVM();setattr(v,flag,True)
  check(name+': attach fails before publication',attach(v)==0 and not v.patches and v.guard_entries==0)
  check(name+': retry API permits a later bounded attempt',v.call(symbols['platform_attach_retry_safe'])==1)
  setattr(v,flag,False)
  check(name+': subsequent successful attach publishes once',attach(v)==1 and v.guard_entries==1)
  check(name+': published state is never automatically retryable',v.call(symbols['platform_attach_retry_safe'])==0)
 v=BoundaryVM();v.guard_fail=True
 check('guard publication failure returns failure',attach(v)==0 and v.guard_entries==1)
 check('guard publication failure irreversibly closes retry boundary',v.call(symbols['platform_attach_retry_safe'])==0)
 v.guard_fail=False
 check('guard publication failure is not reattempted by direct attach',attach(v)==0 and v.guard_entries==1)
 v=BoundaryVM();v.patch_fail_target=TSE+0x6af78
 check('OEM slot publication failure returns failure',attach(v)==0)
 patch_count=len(v.patches);v.patch_fail_target=None
 check('OEM slot failure cannot be treated as safe retry after rollback',v.call(symbols['platform_attach_retry_safe'])==0 and attach(v)==0 and len(v.patches)==patch_count)
 v=BoundaryVM();v.u.mem_write(symbols['boot_services_ended'],d(1))
 check('EBS forbids attach and retries without publication',attach(v)==0 and v.call(symbols['platform_attach_retry_safe'])==0 and not v.patches)

 result={'status':'PASS_ACE_OWNER_AND_PREPUBLICATION_RETRY_REVIEW','checks':len(checks),'check_names':checks,
  'candidate_driver_sha256':sha(build_folder/'AiTweakerLock1904.efi'),'build_manifest_sha256':sha(build_folder/'build.json'),
  'baseline_defect':ns['baseline'],'address_map':ADDRESS_MAP,'native_history_counts':h.native_counts,
  'test_sources':{str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__).resolve(),RUNTIME_TEMPLATE,OWNER_TEMPLATE,HISTORY_TEMPLATE,REFERENCE_DRIVER/'verify_adapter.py',HERE/'effective_owner_cases.py']},
  'hardware_tested':False,'limits':['Original ACE module bytes and compiled driver execute in Unicorn; full OEM browser, firmware services and positive navigation password outcomes are fixtures.',
   'Actual negative UI entry and owner-loss-before-crypto/persistence run real compiled code; stale core state is injected robustness input, not observed hardware.',
   'Service initialization is modeled as already successful with a valid RT CRC; EBS sequencing has a separate test suite.',
   'Direct attach retry boundary is verified; discovery scheduling/max attempts are owned and tested separately by the parent.',
   'A rejected writable-page check retains at most one unpublished trampoline page per attempt; discovery is required to bound attempts.',
   'No claim of full rollback atomicity, first active-browser protection, permanent Del/F2 integration, normal boot/save compatibility or physical deployment.']}
 args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
 print(json.dumps({k:result[k] for k in ['status','checks','candidate_driver_sha256']}))

if __name__=='__main__':main()
