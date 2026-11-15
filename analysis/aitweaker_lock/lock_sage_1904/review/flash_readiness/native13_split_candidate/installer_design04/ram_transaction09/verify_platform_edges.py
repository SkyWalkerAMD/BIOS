"""Final app provider-publication and terminal-result edges, modeled StartImage.
No native provider initialization or GUI claim is made by this supplement.
"""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import verify_platform as T
U,R,S=T.U,T.R,T.S
class VM(T.VM):
 def __init__(self):
  self.query_flags=1;self.object_offset=0;self.bad_method=None;self.start_badtext=False;self.query_return_tpl=None
  super().__init__();address=T.PBASE+T.PROVIDER_SYMBOLS['provider_query'];self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=address,end=address)
 def hook(self,u,a,n,data):
  if a==T.SERV['start']:
   if self.start_badtext:u.mem_write(self.bases[0]+0x300,b'\xcc')
   if self.bad_method is not None:u.mem_write(T.PBASE+T.PROVIDER_SYMBOLS['native_provider']+16+self.bad_method*8,T.q(T.PBASE+0x1001))
   self.finish_service('start',0);return
  if a==T.SERV['locate']:
   obj=T.PBASE+T.PROVIDER_SYMBOLS['native_provider']
   if self.object_offset:u.mem_write(T.DATA+0x8000,bytes(u.mem_read(obj,56)));obj=T.DATA+0x8000
   u.mem_write(self.arg(2),T.q(obj));self.finish_service('locate',0);return
  if a==T.PBASE+T.PROVIDER_SYMBOLS['provider_query']:
   self.finish_service('provider_query_model',self.query_flags)
   if self.query_return_tpl is not None:self.tpl=self.query_return_tpl
   return
  super().hook(u,a,n,data)
def main():
 checks=[]
 def check(name,ok):assert ok,name;checks.append(name)
 def prepared():
  v=VM();assert v.prepare(1)==1;assert v.call('platform_install',v.session(1))==0;v.calls=[];return v
 v=prepared();check('exact relocated provider object and five methods plus READY accepted',v.call('platform_start_provider',v.session(1))==1)
 boundaries=len(v.calls);check('published provider is attempted only once',v.call('platform_start_provider',v.session(1))==0 and len(v.calls)==boundaries)
 check('mode2 installed hooks can restore after successful modeled attach',v.call('platform_remove',v.session(1))==2 and v.originals())
 for i in range(5):
  x=prepared();x.bad_method=i;check('executable but wrong exact provider method '+str(i)+' rejected',x.call('platform_start_provider',x.session(1))==0 and not any(n=='provider_query_model'for n,t in x.calls))
 x=prepared();x.object_offset=1;check('structurally identical foreign provider object rejected',x.call('platform_start_provider',x.session(1))==0)
 for flags in [0,3,5,9,17,33,65,129]:
  x=prepared();x.query_flags=flags;check('provider initial flags '+str(flags)+' refused',x.call('platform_start_provider',x.session(1))==0)
 for at in range(1,boundaries+1):
  x=prepared();x.fault=at;check('ending after attach boundary '+str(at)+' has no later service',x.call('platform_start_provider',x.session(1))=='HOLD'and x.fired and len(x.calls)==at)
 for prior in [8,16,31]:
  x=prepared();x.query_return_tpl=prior;check('query returning at unexpected TPL '+str(prior)+' holds before map or menu',x.call('platform_start_provider',x.session(1))=='HOLD'and x.tpl==31 and x.calls[-1][0]=='raise')
 x=prepared();x.u.mem_write(x.session(1)+8,T.d(0));check('unexpected remove state is terminal hold',x.call('platform_remove',x.session(1))=='HOLD')
 for prior in [8,16,31]:
  x=VM();assert x.prepare()==1;x.tpl=prior;check('nonapplication transaction priorTPL '+str(prior)+' cannot return to menu',x.call('platform_install',x.session())=='HOLD'and not x.foreign_writes)
 x=VM();assert x.prepare()==1;x.u.mem_write(x.session()+12,T.d(1));check('reentrant busy install is terminal with all owned blocks retained',x.call('platform_install',x.session())=='HOLD'and not x.foreign_writes and len(x.allocated)==3)
 x=prepared();x.start_badtext=True;check('unknown OEM code after provider start cannot be accepted',x.call('platform_start_provider',x.session(1))==0)
 before=len(x.foreign_writes);check('unknown OEM code cannot be silently restored or released',x.call('platform_remove',x.session(1))=='HOLD'and len(x.foreign_writes)==before)
 result={'status':'PASS_FINAL_APP_PUBLICATION_AND_TERMINAL_EDGES_WITH_MODELED_PROVIDER_START','checks':len(checks),'check_names':checks,'efi_sha256':T.sha(T.FILE),'build_sha256':T.sha(T.BUILD/'app_build.json'),'test_sha256':T.sha(Path(__file__)),'base_fixture_sha256':T.sha(HERE/'verify_platform.py'),'limits':['Exact final app allocator, transaction, object/method pinning and post-callback gates execute. StartImage success and provider query return are explicit models.','No actual provider EFI initialization/HII/GUI in this supplement; those have separate real OVMF P15 evidence.','Initial inventory/CPU/services/SHA acceleration are the same explicit models documented by verify_platform.py.','No hardware or flash action.']}
 (T.BUILD/'platform_edges.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'checks':len(checks),'efi_sha256':result['efi_sha256']}))
if __name__=='__main__':main()
