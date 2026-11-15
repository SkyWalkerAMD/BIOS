#include "native_bridge04.h"
#define ARENA_BYTES 262144u
#define RETADDR() ((uintptr_t)__builtin_return_address(0))
typedef struct {uintptr_t data;uint64_t size;} CACHE_PAIR;
typedef struct {
 uintptr_t descriptor,data;uint32_t index,offset;uint64_t size;
 uint8_t raw[124],before_hash[32],after_hash[32];
} SAVED;
static struct {
 uint32_t prepared,busy,ended; W890_PROVIDER *provider;W890_PROVIDER saved_provider;
 NO_TICKET *ticket;NO_IDENTITY identity;uintptr_t table,cache;uint32_t count;
 CACHE_PAIR cache_snapshot[WS_MAX_BATCH];
 WS_INTENT vars[WS_MAX_BATCH];SAVED snapshots[WS_MAX_BATCH];
 uint32_t used,entries;uint8_t arena[ARENA_BYTES],scratch[WS_MAX_VARIABLE_BYTES];
 C16 configuration[WS_MAX_CONFIG_UNITS];size_t config_units;
 WS04_REPORT last;
} s;
static void zero(void *p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *p,const void *q,size_t n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;}
static int equal(const void *p,const void *q,size_t n){const uint8_t *a=p,*b=q;uint8_t x=0;while(n--)x|=*a++^*b++;return !x;}
static uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t *p){return u16(p)|((uint32_t)u16(p+2)<<16);}
static uint64_t u64(const uint8_t *p){return u32(p)|((uint64_t)u32(p+4)<<32);}
static int plus(uintptr_t a,UN b,uintptr_t *out){if(a<4096||b>UINTPTR_MAX-a)return 0;*out=a+(uintptr_t)b;return 1;}
static int rd(uintptr_t p,void *out,UN n){return n&&no_copy(s.ticket,p,out,n);}
static int rva(uint32_t r,void *out,UN n){uintptr_t p;return r<s.identity.tse_size&&n<=s.identity.tse_size-r&&plus(s.identity.tse_base,r,&p)&&rd(p,out,n);}
static int fail(uint32_t why){s.last.reason=why;return 0;}
static int provider_flags(uint32_t *flags){
 W890_PROVIDER p;
 if(!rd((uintptr_t)s.provider,&p,sizeof p)||!equal(&p,&s.saved_provider,sizeof p)||
    !no_range((uintptr_t)p.query,1,NO_EXEC)||!no_scope_validate(s.ticket))return fail(WS04_PROVIDER);
 *flags=p.query(s.provider);
 if(!no_scope_validate(s.ticket))return fail(WS04_OWNER);
 return 1;
}
static int begin(uint32_t op,uintptr_t caller){
 if(!s.prepared||s.busy||s.ended)return 0;
 s.busy=1;s.ticket=0;s.used=0;s.entries=0;s.config_units=0;zero(&s.last,sizeof s.last);
 s.last.operation=op;s.last.policy.first_rejected=0xffffffffu;
 if(!no_scope_enter(NO_EFFECT,caller,&s.ticket)||!no_identity(&s.identity)||
    !no_scope_validate(s.ticket))return fail(WS04_OWNER);
 s.last.epoch=s.identity.epoch;return 1;
}
static int end(int ok,WS04_REPORT *out){
 if(s.ticket)no_scope_leave(s.ticket);s.ticket=0;
 if(out&&no_range((uintptr_t)out,sizeof *out,NO_WRITE))*out=s.last;
 zero(s.arena,s.used);zero(s.scratch,sizeof s.scratch);
 zero(s.configuration,s.config_units*sizeof(C16));zero(s.vars,sizeof s.vars);
 zero(s.snapshots,sizeof s.snapshots);s.used=0;s.entries=0;s.busy=0;
 return ok;
}
WS_API ES EA ws04_prepare(const WS04_INSTALL *p){
 if(s.prepared||s.busy||s.ended||!p||!no_range((uintptr_t)p,sizeof *p,NO_READ))return WS04_ACCESS_DENIED;
 WS04_INSTALL v=*p;W890_PROVIDER q;
 if(v.revision!=4||v.size!=sizeof v||!v.provider||!no_range((uintptr_t)v.provider,sizeof q,NO_READ))return WS04_ACCESS_DENIED;
 q=*v.provider;
 if(q.magic!=W890_PROVIDER_MAGIC||q.revision!=1||q.size!=sizeof q||!q.query||!no_range((uintptr_t)q.query,1,NO_EXEC))return WS04_ACCESS_DENIED;
 s.provider=v.provider;s.saved_provider=q;s.prepared=1;return 0;
}
WS_API void EA ws04_end_boot(void){s.ended=1;}
static int table(void){
 if(!rva(0xbaaf8,&s.table,8)||!rd(s.table,&s.count,4)||!s.count||s.count>WS_MAX_BATCH||!rva(0xafcd8,&s.cache,8))return fail(WS04_NATIVE);
 return 1;
}
static int descriptor(uint32_t index,SAVED *snap,WS_INTENT *v){
 uintptr_t p;if(index>=s.count||!plus(s.table,4+(uint64_t)index*4,&p)||!rd(p,&snap->offset,4)||
    snap->offset<4+s.count*4||!plus(s.table,snap->offset,&snap->descriptor)||!rd(snap->descriptor,snap->raw,124))return fail(WS04_NATIVE);
 snap->index=index;if(ws04_descriptor(snap->raw,v)!=WS_SAFE)return fail(WS04_VARIABLE);
 uint32_t flags=u32(snap->raw+0x68);
 if(flags&2u)return fail(WS04_EFFECTS_UNCLOSED); /* native bookkeeping remains unclassified */
 if((flags&0x1000u)||(index<=0x39&&((UINT64_C(0x3ff800003fcfffe)>>index)&1u)))v->route=WS_SET_VARIABLE;
 else {
  if((flags&0x2000u)||u64(snap->raw+0x70)!=(uintptr_t)s.identity.hii)return fail(WS04_EFFECTS_UNCLOSED);
  v->route=WS_SETUP_ROUTE;
 }
 return 1;
}
static int old_value(WS_INTENT *v){
 if(!v->size||v->size>WS_MAX_VARIABLE_BYTES||v->size>(ARENA_BYTES-s.used)/2)return fail(WS04_CAPACITY);
 v->before=s.arena+s.used;s.used+=v->size;v->after=s.arena+s.used;s.used+=v->size;
 UN size=v->size;uint32_t attrs=0;GUID g;copy(&g,v->guid,16);
 ES e=no_read_variable(s.ticket,v->name,&g,&attrs,&size,(void *)v->before);
 if(e||size!=v->size||attrs!=v->attributes)return fail(WS04_VARIABLE);
 v->old_size=(uint32_t)size;v->old_attributes=attrs;return 1;
}
static int capture(uint32_t index,uintptr_t data,UN size){
 if(s.entries>=WS_MAX_BATCH)return fail(WS04_CAPACITY);uint32_t k=s.entries;
 SAVED *p=&s.snapshots[k];WS_INTENT *v=&s.vars[k];zero(p,sizeof *p);zero(v,sizeof *v);
 if(!descriptor(index,p,v)||size!=v->size||!data)return fail(WS04_VARIABLE);
 p->data=data;p->size=size;if(!old_value(v)||!rd(data,(void *)v->after,size))return fail(WS04_VARIABLE);
 ap_sha256(v->before,v->size,p->before_hash);ap_sha256(v->after,v->size,p->after_hash);s.entries++;s.last.observed++;return 1;
}
static int unchanged(void){
 uintptr_t t,c;uint32_t n;
 if(!rva(0xbaaf8,&t,8)||t!=s.table||!rd(t,&n,4)||n!=s.count||!rva(0xafcd8,&c,8)||c!=s.cache)return fail(WS04_CHANGED);
 if(s.last.operation==WS04_SAVE){
  if(!rd(c,s.scratch,(UN)n*sizeof(CACHE_PAIR))||!equal(s.scratch,s.cache_snapshot,(UN)n*sizeof(CACHE_PAIR)))return fail(WS04_CHANGED);
 }
 for(uint32_t k=0;k<s.entries;k++){
  SAVED *p=&s.snapshots[k];WS_INTENT *v=&s.vars[k];uint8_t raw[124],hash[32];uint32_t off;uintptr_t at;
  if(!plus(t,4+(UN)p->index*4,&at)||!rd(at,&off,4)||off!=p->offset||!rd(p->descriptor,raw,124)||!equal(raw,p->raw,124))return fail(WS04_CHANGED);
  if(!rd(p->data,s.scratch,v->size))return fail(WS04_CHANGED);ap_sha256(s.scratch,v->size,hash);if(!equal(hash,p->after_hash,32))return fail(WS04_CHANGED);
  UN size=v->size;uint32_t attrs=0;GUID g;copy(&g,v->guid,16);
  if(no_read_variable(s.ticket,v->name,&g,&attrs,&size,s.scratch)||size!=v->size||attrs!=v->attributes)return fail(WS04_CHANGED);
  ap_sha256(s.scratch,v->size,hash);if(!equal(hash,p->before_hash,32))return fail(WS04_CHANGED);
  if(!rd(p->data,s.scratch,v->size))return fail(WS04_CHANGED);ap_sha256(s.scratch,v->size,hash);if(!equal(hash,p->after_hash,32))return fail(WS04_CHANGED);
 }
 return no_scope_validate(s.ticket)||fail(WS04_OWNER);
}
static int check_policy(void){uint32_t flags;
 if(!provider_flags(&flags))return 0;
 if(ws04_preflight(s.vars,s.entries,flags,&s.last.policy)!=WS_SAFE)return fail(WS04_POLICY);
 s.last.checked=s.entries;return 1;
}
WS_API int EA ws04_check_commit(uint32_t index,void *data,UN size,WS04_REPORT *out){
 if(s.busy||s.ended)return 0;
 if(!begin(WS04_COMMIT,RETADDR()))return end(0,out);
 int ok=table()&&capture(index,(uintptr_t)data,size)&&check_policy()&&unchanged();
 if(ok)s.last.reason=WS04_EXECUTION_LEASE_MISSING;return end(ok,out);
}
static int config_copy(C16 *input){
 if(!input)return fail(WS04_NATIVE);
 for(size_t k=0;k<WS_MAX_CONFIG_UNITS;){
  uintptr_t at;if(!plus((uintptr_t)input,k*2,&at))return fail(WS04_NATIVE);
  UN units=WS_MAX_CONFIG_UNITS-k;if(units>64)units=64;
  if(!no_range(at,units*2,NO_READ))units=1;
  if(!rd(at,&s.configuration[k],units*2))return fail(WS04_NATIVE);
  for(UN j=0;j<units;j++){s.config_units=k+j+1;if(!s.configuration[k+j])return 1;}k+=units;
 }
 return fail(WS04_CAPACITY);
}
static int route_check(CONFIG *this,C16 *input){
 if(this!=s.identity.config||!config_copy(input))return fail(WS04_NATIVE);
 WS_INTENT *v=&s.vars[0];zero(v,sizeof *v);size_t blocks;
 if(ws04_route_header(s.configuration,s.config_units,v->guid,v->name,&blocks)!=WS_SAFE)return fail(WS04_VARIABLE);
 /* RouteConfig has no trustworthy caller-provided native index. Resolve its
  * exact name/GUID against live native descriptors; duplicates must agree. */
 if(!table())return 0;int found=0;
 for(uint32_t k=0;k<s.count;k++){
  uintptr_t p,d;uint32_t off;uint8_t raw[124];WS_INTENT candidate;
  if(!plus(s.table,4+(UN)k*4,&p)||!rd(p,&off,4)||off<4+s.count*4||!plus(s.table,off,&d)||!rd(d,raw,124))return fail(WS04_NATIVE);
  if(!equal(raw,v->guid,16)||!equal(raw+16,v->name,80))continue;
  if(ws04_descriptor(raw,&candidate)!=WS_SAFE||u64(raw+0x70)!=(uintptr_t)s.identity.hii||(u32(raw+0x68)&0x2002u))return fail(WS04_EFFECTS_UNCLOSED);
  if(found&&(v->attributes!=candidate.attributes||v->size!=candidate.size))return fail(WS04_NATIVE);
  v->attributes=candidate.attributes;v->size=candidate.size;found=1;
 }
 if(!found||!old_value(v))return fail(WS04_VARIABLE);v->route=WS_SETUP_ROUTE;
 if(ws04_route_apply(s.configuration,s.config_units,blocks,v->before,v->size,(uint8_t *)v->after,v->size)!=WS_SAFE)return fail(WS04_VARIABLE);
 s.entries=1;s.last.observed=1;
 if(!check_policy())return 0;
 /* Validate the original variable a second time. This is observation only,
  * not an exclusion lease and not a promise about a later native dispatch. */
 UN size=v->size;uint32_t attrs=0;GUID g;copy(&g,v->guid,16);
 if(no_read_variable(s.ticket,v->name,&g,&attrs,&size,s.scratch)||size!=v->size||attrs!=v->attributes||!equal(s.scratch,v->before,v->size)||!no_scope_validate(s.ticket))return fail(WS04_CHANGED);
 s.last.reason=WS04_EXECUTION_LEASE_MISSING;return 1;
}
WS_API int EA ws04_check_route(CONFIG *this,C16 *input,WS04_REPORT *out){
 if(s.busy||s.ended)return 0;if(!begin(WS04_ROUTE,RETADDR()))return end(0,out);int ok=route_check(this,input);return end(ok,out);
}
WS_API int EA ws04_check_save(WS04_REPORT *out){
 if(s.busy||s.ended)return 0;if(!begin(WS04_SAVE,RETADDR()))return end(0,out);
 int ok=table();
 if(ok&&!rd(s.cache,s.cache_snapshot,(UN)s.count*sizeof(CACHE_PAIR)))ok=fail(WS04_NATIVE);
 for(uint32_t k=0;ok&&k<s.count;k++){
  CACHE_PAIR p=s.cache_snapshot[k];
  if(!p.data&&!p.size)continue;if(!p.data||!p.size){ok=fail(WS04_NATIVE);break;}
  /* Save handles these indices separately, including arbitrary Boot#### and
   * Driver#### values. Whole action remains denied, before its notification. */
  if(k==7||k==23||k==8){ok=fail(WS04_EFFECTS_UNCLOSED);break;}
  ok=capture(k,p.data,p.size);
 }
 if(ok)ok=check_policy()&&unchanged();
 if(ok)s.last.reason=WS04_EFFECTS_UNCLOSED;return end(ok,out);
}
WS_API ES EA ws04_native_commit(uint32_t index,void *data,UN size){
 WS04_REPORT report;int ok=ws04_check_commit(index,data,size,&report);
 return ok?WS04_UNSUPPORTED:WS04_ACCESS_DENIED;
}
WS_API ES EA ws04_setup_route(CONFIG *this,C16 *input,C16 **progress){
 /* No progress output is changed on refusal: caller storage is untrusted. */
 (void)progress;WS04_REPORT report;int ok=ws04_check_route(this,input,&report);
 return ok?WS04_UNSUPPORTED:WS04_ACCESS_DENIED;
}
WS_API uint8_t EA ws04_native_save(void){WS04_REPORT report;(void)ws04_check_save(&report);return 0;}
WS_API int EA ws04_last_report(WS04_REPORT *out){
 if(s.busy||!out||!no_range((uintptr_t)out,sizeof *out,NO_WRITE))return 0;*out=s.last;return 1;
}
