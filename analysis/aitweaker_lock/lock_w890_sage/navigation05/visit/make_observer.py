"""Generate a reviewable local derivative; never edit frozen/other-agent files."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parents[1]
src=B/'integration05/observer05.c';text=src.read_text()
text=text.replace('#include "observer.h"','#include "restricted_profile.h"')
text=text.replace('#include "../password/','#include "../../password/').replace('#include "../installer04/','#include "../../installer04/')
text=text.replace('#include "profile_windows.h"','#include "../../native_observer04/profile_windows.h"')
old='uint32_t kind,depth;uint8_t begun;} FRAME;';new='uint32_t kind,depth;uint8_t begun,restricted;} FRAME;'
assert old in text;text=text.replace(old,new)
old='uint64_t epoch,sequence,provider_token,pubtoken;';assert old in text;text=text.replace(old,'uint64_t epoch,sequence,provider_token,pubtoken,native_visit,visit_sequence;')
assert 'q.session=s.provider_token;'in text;text=text.replace('q.session=s.provider_token;','q.session=s.native_visit;')
old='static FRAME *push(uint32_t kind,uintptr_t caller,uintptr_t stack){';assert old in text;text=text.replace(old,'#include "restricted_check.inc"\n'+old)
old='if(kind==NO_LOOP){s.loops++;s.pending_begin=1;'
new='if(kind==NO_LOOP){if(!s.loops){if(s.visit_sequence==UINT64_MAX){s.depth--;zero(f,sizeof(*f));return 0;}s.native_visit=++s.visit_sequence;}s.loops++;s.pending_begin=1;'
assert old in text;text=text.replace(old,new)
old='ES r=no_provider_begin_call(s.install.provider,&f->token);s.pending_begin=0;if(FAILED(r)){s.loops--;s.depth--;zero(f,sizeof(*f));return 0;}f->begun=1;if(s.loops==1)s.provider_token=f->token;'
new='''ES r=no_provider_begin_call(s.install.provider,&f->token);s.pending_begin=0;
  if(r!=0){
   uint32_t flags=s.install.provider->query(s.install.provider);
   if(flags==(W890_PROVIDER_READY|W890_PROVIDER_FAULT)&&!w890_password_core.busy&&restricted_profile_live()){
    /* A real private native visit, with no credential token and no grant.
     * Every protected effect continues to consult the faulted provider. */
    f->restricted=1;f->token=0;
   }else{s.loops--;if(!s.loops)s.native_visit=0;s.depth--;zero(f,sizeof(*f));return 0;}
  }else{f->begun=1;if(s.loops==1)s.provider_token=f->token;}'''
assert old in text;text=text.replace(old,new)
old='if(!s.loops)s.provider_token=0;';assert old in text;text=text.replace(old,'if(!s.loops){s.provider_token=0;s.native_visit=0;}')
text+='''
int EA no_native_visit_identity(uint64_t *visit,uint32_t *restricted){
 if(!frame_active()||!s.native_visit||!identity_live(0)||!no_range((uintptr_t)visit,8,NO_WRITE)||!no_range((uintptr_t)restricted,4,NO_WRITE))return 0;
 uint32_t limited=0;for(unsigned i=0;i<s.depth;i++)if(s.frames[i].kind==NO_LOOP&&s.frames[i].restricted)limited=1;
 *visit=s.native_visit;*restricted=limited;return 1;
}
#include "form_descriptor.inc"
'''
out=H/'observer_visit05.c';out.write_text(text)
(H/'derivation.json').write_text(json.dumps({'source':str(src),'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'derived_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'changes':['private native visit identity distinct from provider token','Begin error may continue only after immutable complete fixed-location guard catalogue proves installed targets and complete guard code hashes','current catalogue intentionally incomplete; pending HII producer unresolved; no failed-Begin body is permitted','native-management type27/vtable95620 checks inherited from integration05'],'status':'INCOMPLETE_CLOSURE_NO_INSTALL'},indent=2)+'\n')
print(hashlib.sha256(out.read_bytes()).hexdigest())
