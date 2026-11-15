#include "save_guard05.h"
#include "../password/w890_policy.h"
#include "catalog05.inc"
#define DENIED UINT64_C(0x800000000000000f)
#define NOT_FOUND UINT64_C(0x800000000000000e)
#define MAX_OC 22955u
#define RETADDR() ((uintptr_t)__builtin_return_address(0))
typedef struct {uintptr_t data;UN size;} PAIR;
typedef struct {uint32_t index,present;uint8_t descriptor[124];PAIR pair;uint8_t old[MAX_OC],pending[MAX_OC];} OC;
void *ws05_save_replay,*ws05_save_cancel;
static struct {
 uint32_t prepared,busy,ended,replay_bytes;W890_PROVIDER *provider;W890_PROVIDER pinned;
 uint8_t replay_hash[32];NO_TICKET *ticket;NO_IDENTITY id;
 WS05_PATH paths[5];uint8_t path_hashes[5][32];
 uintptr_t profile_return;uint8_t profile_call_window[32];
 uintptr_t table,cache;uint32_t count;uint32_t offsets[121];
 PAIR pairs[121];OC oc[3];uint8_t scratch[MAX_OC];WS05_REPORT report;
} s;
static void cp(void *p,const void *q,UN n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;}
static int eq(const void *p,const void *q,UN n){const uint8_t *a=p,*b=q;uint8_t x=0;while(n--)x|=*a++^*b++;return !x;}
static uint32_t u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int fail(uint32_t r){s.report.reason=r;return 0;}
static int rd(uintptr_t p,void *out,UN n){return n&&no_copy(s.ticket,p,out,n);}
static int rva(uint32_t r,void *out,UN n){return r<s.id.tse_size&&n<=s.id.tse_size-r&&s.id.tse_base<=UINTPTR_MAX-r&&rd(s.id.tse_base+r,out,n);}
static int plus(uintptr_t p,UN n,uintptr_t *out){if(p<4096||n>UINTPTR_MAX-p)return 0;*out=p+n;return 1;}
static int provider(uint32_t *flags){
 W890_PROVIDER p;if(!rd((uintptr_t)s.provider,&p,sizeof p)||!eq(&p,&s.pinned,sizeof p)||!no_range((uintptr_t)p.query,1,NO_EXEC)||!no_scope_validate(s.ticket))return fail(WS05_PROVIDER);
 *flags=p.query(s.provider);
 if(!no_scope_validate(s.ticket)||(*flags&(W890_PROVIDER_BUSY|W890_PROVIDER_FAULT|W890_PROVIDER_ENDED))||(*flags&(W890_PROVIDER_READY|W890_PROVIDER_OWNED))!=(W890_PROVIDER_READY|W890_PROVIDER_OWNED))return fail(WS05_PROVIDER);
 return 1;
}
static int targets(void){
 uint8_t h[32];if((uintptr_t)ws05_save_cancel!=s.id.tse_base+0x202f4||!no_range((uintptr_t)ws05_save_cancel,29,NO_READ|NO_EXEC)||!no_range((uintptr_t)ws05_save_replay,s.replay_bytes,NO_READ|NO_EXEC))return fail(WS05_PROFILE);
 ap_sha256(ws05_save_replay,s.replay_bytes,h);if(!eq(h,s.replay_hash,32))return fail(WS05_PROFILE);
 return 1;
}
ES EA ws05_prepare(const WS05_BINDING *input){
 if(s.prepared||s.busy||s.ended||!input||!no_range((uintptr_t)input,sizeof *input,NO_READ))return DENIED;
 WS05_BINDING b=*input;W890_PROVIDER p;
 if(b.revision!=5||b.size!=sizeof b||b.reserved||b.provider!=&w890_provider||!no_range((uintptr_t)b.provider,sizeof p,NO_READ)||!b.save_replay||b.replay_bytes<19||b.replay_bytes>192||!no_range((uintptr_t)b.save_replay,b.replay_bytes,NO_READ|NO_EXEC)||!no_identity(&s.id))return DENIED;
 p=*b.provider;if(p.magic!=W890_PROVIDER_MAGIC||p.revision!=1||p.size!=sizeof p||!p.query||!p.request||!no_range((uintptr_t)p.query,1,NO_EXEC)||!no_range((uintptr_t)p.request,1,NO_EXEC)||s.id.tse_base>UINTPTR_MAX-0x20311)return DENIED;
 s.provider=b.provider;s.pinned=p;s.replay_bytes=b.replay_bytes;ws05_save_replay=b.save_replay;ws05_save_cancel=(void *)(s.id.tse_base+0x202f4);
 WS05_PATH paths[5]={b.dispatch,b.defaults,b.load_defaults_save,b.profile,b.profile_policy};
 for(uint32_t i=0;i<5;i++){
  if(paths[i].reserved||((paths[i].entry==0)!=(paths[i].bytes==0)))return DENIED;
  if(paths[i].entry){if(paths[i].bytes<14||paths[i].bytes>192||!no_range((uintptr_t)paths[i].entry,paths[i].bytes,NO_READ|NO_EXEC))return DENIED;ap_sha256(paths[i].entry,paths[i].bytes,s.path_hashes[i]);}
  s.paths[i]=paths[i];
 }
 if(b.profile_bridge_return){
  uintptr_t ret=(uintptr_t)b.profile_bridge_return;
  if(ret<16||!no_range(ret-16,32,NO_READ|NO_EXEC))return DENIED;
  s.profile_return=ret;cp(s.profile_call_window,(void *)(ret-16),32);
 }
 ap_sha256(b.save_replay,b.replay_bytes,s.replay_hash);s.prepared=1;return 0;
}
void EA ws05_end_boot(void){s.ended=1;}
static int begin(uintptr_t caller){
 if(!s.prepared||s.busy||s.ended)return 0;s.busy=1;s.ticket=0;s.report=(WS05_REPORT){0};
 if(!no_scope_enter(NO_EFFECT,caller,&s.ticket)||!no_identity(&s.id)||!no_scope_validate(s.ticket))return fail(WS05_OWNER);
 s.report.epoch=s.id.epoch;return targets();
}
static int finish(int result){
 if(s.ticket)no_scope_leave(s.ticket);s.ticket=0;
 ap_secure_zero(s.oc,sizeof s.oc);ap_secure_zero(s.scratch,sizeof s.scratch);s.busy=0;return result;
}
static int capture(void){
 if(!rva(0xbaaf8,&s.table,8)||!rva(0xafcd8,&s.cache,8)||!rd(s.table,&s.count,4)||s.count!=121||!rd(s.table+4,s.offsets,sizeof s.offsets)||!rd(s.cache,s.pairs,sizeof s.pairs))return fail(WS05_PROFILE);
 for(uint32_t i=0;i<121;i++){
  uint8_t raw[124];uintptr_t p;
  if(s.offsets[i]<488||!plus(s.table,s.offsets[i],&p)||!rd(p,raw,124)||!eq(raw,ws05_native_descriptors[i],112)||!eq(raw+120,ws05_native_descriptors[i]+120,4))return fail(WS05_PROFILE);
 }
 const uint32_t indices[3]={94,99,95};
 for(uint32_t k=0;k<3;k++){
  OC *o=&s.oc[k];o->index=indices[k];o->pair=s.pairs[o->index];uintptr_t p;
  if(!plus(s.table,s.offsets[o->index],&p)||!rd(p,o->descriptor,124))return fail(WS05_CACHE);
  uint32_t size=o->descriptor[120]|((uint32_t)o->descriptor[121]<<8);
  if(!o->pair.data||o->pair.size!=size||!size||size>MAX_OC||u32(o->descriptor+96)!=7||!rd(o->pair.data,o->pending,size))return fail(WS05_CACHE);
  UN n=size;uint32_t attrs=0;GUID g;cp(&g,o->descriptor,16);
  ES result=no_read_variable(s.ticket,(C16 *)(o->descriptor+16),&g,&attrs,&n,o->old);
  if(result==NOT_FOUND){o->present=0;continue;}
  if(result||attrs!=7||n!=size)return fail(WS05_VARIABLE);o->present=1;
 }
 return 1;
}
static int differences(void){
 for(uint32_t k=0;k<2;k++){
  OC *o=&s.oc[k];size_t chars=0;C16 *name=(C16 *)(o->descriptor+16);while(chars<40&&name[chars])chars++;
  /* Absence is its own observed state, never invented zero-valued old data.
   * Creating a protected store requires grant or a real disabled provider. */
  if(!o->present){s.report.protected_change=1;continue;}
  W890_POLICY p=w890_variable_change(name,chars,o->descriptor,7,o->old,o->pair.size,7,o->pending,o->pair.size);
  if(p==W890_UNKNOWN||p==W890_CREDENTIAL)return fail(WS05_POLICY);
  if(p==W890_PROTECTED)s.report.protected_change=1;
 }
 /* OcSetup is a distinct native descriptor with unclosed derived-write
  * semantics. A changed alias requires authorization too; it is not silently
  * classified as ordinary merely because it is absent from the IFR store IDs. */
 if(!s.oc[2].present||!eq(s.oc[2].old,s.oc[2].pending,s.oc[2].pair.size))s.report.alias_change=1;
 return 1;
}
static int unchanged(void){
 uintptr_t table,cache;uint32_t n;PAIR pairs[121];uint32_t offsets[121];
 if(!rva(0xbaaf8,&table,8)||!rva(0xafcd8,&cache,8)||table!=s.table||cache!=s.cache||!rd(table,&n,4)||n!=121||!rd(table+4,offsets,sizeof offsets)||!eq(offsets,s.offsets,sizeof offsets)||!rd(cache,pairs,sizeof pairs)||!eq(pairs,s.pairs,sizeof pairs))return fail(WS05_STALE);
 for(uint32_t k=0;k<3;k++){
  OC *o=&s.oc[k];uintptr_t p;uint8_t raw[124];
  if(!plus(table,s.offsets[o->index],&p)||!rd(p,raw,124)||!eq(raw,o->descriptor,124)||!rd(o->pair.data,s.scratch,o->pair.size)||!eq(s.scratch,o->pending,o->pair.size))return fail(WS05_STALE);
  UN size=o->pair.size;uint32_t attrs=0;GUID g;cp(&g,o->descriptor,16);
  ES result=no_read_variable(s.ticket,(C16 *)(o->descriptor+16),&g,&attrs,&size,s.scratch);
  if(!o->present){if(result!=NOT_FOUND)return fail(WS05_STALE);}
  else if(result||size!=o->pair.size||attrs!=7||!eq(s.scratch,o->old,size))return fail(WS05_STALE);
 }
 return no_scope_validate(s.ticket)||fail(WS05_OWNER);
}
static int cached_unchanged(void){
 /* This path intentionally invokes no firmware service between the last
  * copied-cache comparison and returning to the native notification point. */
 if(!no_scope_validate_cached(s.ticket)||!no_range(s.id.tse_base+0xbaaf8,8,NO_READ)||!no_range(s.id.tse_base+0xafcd8,8,NO_READ)||*(uintptr_t *)(s.id.tse_base+0xbaaf8)!=s.table||*(uintptr_t *)(s.id.tse_base+0xafcd8)!=s.cache||!no_range(s.table,488,NO_READ)||u32((void *)s.table)!=121||!eq((void *)(s.table+4),s.offsets,sizeof s.offsets)||!no_range(s.cache,sizeof s.pairs,NO_READ)||!eq((void *)s.cache,s.pairs,sizeof s.pairs))return fail(WS05_STALE);
 for(uint32_t k=0;k<3;k++){
  OC *o=&s.oc[k];uintptr_t p;
  if(!plus(s.table,s.offsets[o->index],&p)||!no_range(p,124,NO_READ)||!eq((void *)p,o->descriptor,124)||!no_range(o->pair.data,o->pair.size,NO_READ)||!eq((void *)o->pair.data,o->pending,o->pair.size))return fail(WS05_STALE);
 }
 return no_scope_validate_cached(s.ticket)||fail(WS05_OWNER);
}
static int authorize(int required){
 uint32_t flags;if(!provider(&flags))return 0;
 if(required&&!(flags&(W890_PROVIDER_GRANTED|W890_PROVIDER_DISABLED))){
  s.report.prompted=1;
  if(!no_range((uintptr_t)s.pinned.request,1,NO_EXEC)||ws05_provider_request_call()!=0||!provider(&flags)||!(flags&(W890_PROVIDER_GRANTED|W890_PROVIDER_DISABLED)))return fail(WS05_POLICY);
 }
 return 1;
}
int EA ws05_before_save(void){
 /* Called at native RVA1FD58 after confirmation/validation, before the first
  * pre-Save notification and every Save-loop write. Ordinary diffs reach the
  * unmodified original body. This is no longer an unconditional Save denial. */
 if(s.busy||s.ended)return 0;if(!begin(RETADDR()))return finish(0);
 int ok=capture()&&differences();
 if(ok)ok=authorize(s.report.protected_change||s.report.alias_change);
 if(ok)ok=unchanged()&&targets();
 if(ok){uint32_t flags;ok=provider(&flags);if(ok&&(s.report.protected_change||s.report.alias_change)&&!(flags&(W890_PROVIDER_GRANTED|W890_PROVIDER_DISABLED)))ok=fail(WS05_POLICY);}
 /* Service-free final recheck narrows the interval. It does not claim AP/SMM
  * exclusion, nor that subsequent vendor notifications have no OC effects. */
 if(ok)ok=cached_unchanged();
 return finish(ok);
}
int EA ws05_before_protected_action(void){
 if(s.busy||s.ended)return 0;if(!begin(RETADDR()))return finish(0);
 int ok=authorize(1)&&no_scope_validate(s.ticket)&&no_scope_validate_cached(s.ticket);
 return finish(ok);
}
int EA ws05_profile_callback_gate(CONFIG *config,UN action,uint16_t qid,uint8_t type,void *value,UN *request,void *native_caller){
 /* Setup1457C's context predicate: REF type0x0c executes only CHANGING(0);
  * other types execute only CHANGED(1). All remaining actions delegate with
  * original values. Setup143AC's private48180 flag changes its action filter,
  * so every callback for its sole2BFF QID requires authentication. */
 if(qid!=0x2bfb&&qid!=0x2bfd&&qid!=0x2bfe&&qid!=0x2bff)return 1;
 if(qid!=0x2bff&&(type==0x0c?action!=0:action!=1))return 1;
 /* The callback arguments are data, never an owner credential. Bind both
  * actual compiled call chain and native ConfigAccess callback dispatch. */
 uintptr_t ret=RETADDR();NO_IDENTITY id;
 if(!s.prepared||s.ended||s.busy||!s.profile_return||ret!=s.profile_return||
    !no_range(ret-16,32,NO_READ|NO_EXEC)||!eq((void *)(ret-16),s.profile_call_window,32)||
    !no_identity(&id)||config!=id.config||id.tse_base>UINTPTR_MAX-0x3e4f0||
    (uintptr_t)native_caller!=id.tse_base+0x3e4f0||
    !no_range((uintptr_t)value,1,NO_READ)||!no_range((uintptr_t)request,sizeof *request,NO_WRITE))return 0;
 return ws05_before_protected_action();
}
int EA ws05_last_report(WS05_REPORT *out){if(s.busy||!out||!no_range((uintptr_t)out,sizeof *out,NO_WRITE))return 0;*out=s.report;return 1;}
static int path_live(uint32_t kind){
 uint8_t hash[32];if(kind>=5||!s.prepared||s.ended||!s.paths[kind].entry||!no_range((uintptr_t)s.paths[kind].entry,s.paths[kind].bytes,NO_READ|NO_EXEC))return 0;
 ap_sha256(s.paths[kind].entry,s.paths[kind].bytes,hash);return eq(hash,s.path_hashes[kind],32);
}
void EA ws05_native_dispatch(uint64_t selector,void *fallback,void *a,void *b){
 /* FD6C is generic. Only the exactly identified defaults group is gated;
  * all other selectors keep all four original arguments. This is not a
  * complete classification of every other caller/action in the firmware. */
 if(!path_live(0))return;
 if(selector==UINT64_C(0xffff001d)&&!ws05_before_protected_action())return;
 if(!path_live(0))return;
 ((void(EA *)(uint64_t,void *,void *,void *))s.paths[0].entry)(selector,fallback,a,b);
}
void EA ws05_native_defaults(void *cache,void *confirmation){
 if(!path_live(1)||!ws05_before_protected_action()||!path_live(1))return;
 ((void(EA *)(void *,void *))s.paths[1].entry)(cache,confirmation);
}
ES EA ws05_native_load_defaults_save(void *request,UN context){
 /* Native851A4 mutates state and calls8221C before its FD6C/Save calls, so
  * it requires a separate entry gate. On cancellation preserve its native
  * EFI_ABORTED result without entering any of those earlier operations. */
 if(!path_live(2)||!ws05_before_protected_action()||!path_live(2))return UINT64_C(0x8000000000000015);
 return ((ES(EA *)(void *,UN))s.paths[2].entry)(request,context);
}
ES EA ws05_native_profile(void *hii,UN a,UN b,uint16_t qid){
 /* Original Setup callback table2CA40/50/60 binds2BFE/2BFD/2BFB to1457C.
  * Gate the handler before flags, profile protocols, file/slot load or writes.
  * No ConfigAccess callback pointer competition with the management bridge. */
 if(qid!=0x2bfb&&qid!=0x2bfd&&qid!=0x2bfe)return DENIED;
 if(!path_live(3)||!ws05_before_protected_action()||!path_live(3))return DENIED;
 return ((ES(EA *)(void *,UN,UN,uint16_t))s.paths[3].entry)(hii,a,b,qid);
}
ES EA ws05_native_profile_policy(void *hii,UN a,UN b,uint16_t qid){
 if(qid!=0x2bff||!path_live(4)||!ws05_before_protected_action()||!path_live(4))return DENIED;
 return ((ES(EA *)(void *,UN,UN,uint16_t))s.paths[4].entry)(hii,a,b,qid);
}
