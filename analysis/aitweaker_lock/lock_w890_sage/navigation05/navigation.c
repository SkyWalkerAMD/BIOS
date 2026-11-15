#include "navigation.h"
#include "../password/w890_policy.h"
#define RA ((uintptr_t)__builtin_return_address(0))
#define CAP_MAX 4116u
#define LIFE_MAX 64u
typedef struct {uintptr_t pointer,app;UN bytes;uint64_t session,epoch,serial;uint32_t depth,live;} LIFE;
typedef struct {NO_IDENTITY id;WG_SNAPSHOT source,main;uintptr_t app,array,history;uint32_t count,index,main_index,capacity,used,root;uint8_t app_bytes[96],source_bytes[104],main_bytes[104];LIFE *owned,witness;} PLAN;
static LIFE life[LIFE_MAX];static NO_IDENTITY bound;static unsigned bound_ok,busy;static PLAN a,b;
static uint64_t serial;
uintptr_t n05_history_global,n05_menu_free_resume,n05_loop_free_resume;
static void copy(void *d,const void *s,UN n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;}
static void zero(void *d,UN n){uint8_t *x=d;while(n--)*x++=0;}
static int equal(const void *a,const void *b,UN n){const uint8_t*x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint64_t u64(uintptr_t p){uint64_t x;copy(&x,(void *)p,8);return x;}
static uint32_t u32(uintptr_t p){uint32_t x;copy(&x,(void *)p,4);return x;}
static uint16_t u16(uintptr_t p){uint16_t x;copy(&x,(void *)p,2);return x;}
static void w32(uintptr_t p,uint32_t x){copy((void *)p,&x,4);}
static int identity(NO_IDENTITY *id){return bound_ok&&no_identity(id)&&!id->ended&&!id->fault&&id->loop_depth&&id->st==bound.st&&id->database==bound.database&&id->hii==bound.hii&&id->tse_base==bound.tse_base&&id->setup_base==bound.setup_base;}
static int detour(uint32_t rva,unsigned n,uint8_t opcode,uintptr_t wanted){
 uintptr_t p=bound.tse_base+rva;if(!no_range(p,n,NO_READ|NO_EXEC)||*(uint8_t *)p!=opcode)return 0;
 for(unsigned i=5;i<n;i++)if(*((uint8_t *)p+i)!=0x90)return 0;
 int32_t displacement;copy(&displacement,(void *)(p+1),4);uintptr_t target=p+5;
 if(displacement<0){UN back=(UN)(-(int64_t)displacement);if(target<back)return 0;target-=back;}
 else{if(target>UINTPTR_MAX-(uint32_t)displacement)return 0;target+=(uint32_t)displacement;}
 if(target==wanted)return no_range(target,1,NO_READ|NO_EXEC);
 static const uint8_t indirect[6]={0xff,0x25,0,0,0,0};
 return no_range(target,14,NO_READ|NO_EXEC)&&equal((void *)target,indirect,6)&&u64(target+6)==wanted;
}
static int tracking_installed(void){
 return detour(0x194cf,5,0xe8,(uintptr_t)n05_history_allocate)&&detour(0x1b988,5,0xe8,(uintptr_t)n05_history_allocate)&&
 detour(0x195ac,5,0xe8,(uintptr_t)n05_history_reallocate)&&detour(0x1ba79,5,0xe8,(uintptr_t)n05_history_reallocate)&&
 detour(0x22862,11,0xe9,(uintptr_t)n05_menu_free_stub)&&detour(0x19a5d,10,0xe9,(uintptr_t)n05_loop_free_stub);
}
static int snapshot(NO_IDENTITY *id,WG_SNAPSHOT *s){return identity(id)&&tracking_installed()&&no_observe(0,WG_FIRST,0,0,s)&&s->native_base==bound.tse_base&&s->session&&s->hii==(uintptr_t)bound.hii;}
static LIFE *find(uintptr_t p,const NO_IDENTITY *id,const WG_SNAPSHOT *s){for(unsigned i=0;i<LIFE_MAX;i++){LIFE*l=&life[i];if(l->live&&l->pointer==p&&l->app==s->application&&l->session==s->session&&l->epoch==id->epoch&&l->depth==id->loop_depth)return l;}return 0;}
static LIFE *reserve(const NO_IDENTITY *id,const WG_SNAPSHOT *s){for(unsigned i=0;i<LIFE_MAX;i++)if(!life[i].live||life[i].session!=s->session||life[i].epoch!=id->epoch){zero(&life[i],sizeof(LIFE));return &life[i];}return 0;}
ES EA n05_bind(void){if(bound_ok||!no_identity(&bound)||bound.fault||bound.ended||!bound.tse_base||!bound.st||bound.loop_depth)return NO_DENIED;
 n05_history_global=bound.tse_base+0xafde8;n05_menu_free_resume=bound.tse_base+0x2286d;n05_loop_free_resume=bound.tse_base+0x19a67;bound_ok=1;return 0;}
void *EA n05_history_allocate(void *context,UN bytes){
 uintptr_t caller=RA;NO_IDENTITY id;WG_SNAPSHOT s;LIFE *slot;
 if(!bound_ok||(caller!=bound.tse_base+0x194d4&&caller!=bound.tse_base+0x1b98d)||!snapshot(&id,&s)||!no_range(s.application,96,NO_READ))return 0;
 uint32_t count=u32(s.application+0x2c),cap=u32(bound.tse_base+0xafde0);
 if(count>4096||cap!=count+20||cap>CAP_MAX||bytes!=(UN)cap*32||u64(n05_history_global)||!(slot=reserve(&id,&s)))return 0;
 void *p=((void *(EA *)(void *,UN))(bound.tse_base+0x59b50))(context,bytes);
 NO_IDENTITY after;WG_SNAPSHOT now;if(!p)return 0;
 /* The allocator is original code and services. We own only its successful
  * result at these exact two callers, within this same private native visit. */
 if(!snapshot(&after,&now)||after.epoch!=id.epoch||after.loop_depth!=id.loop_depth||!equal(&s,&now,sizeof(s))||!no_range((uintptr_t)p,bytes,NO_READ|NO_WRITE))return 0;
 *slot=(LIFE){(uintptr_t)p,s.application,bytes,s.session,id.epoch,++serial,id.loop_depth,1};return p;
}
void *EA n05_history_reallocate(void *old,UN old_count,UN new_count){
 uintptr_t caller=RA;NO_IDENTITY id;WG_SNAPSHOT s;LIFE*l;
 if(!bound_ok||(caller!=bound.tse_base+0x195b1&&caller!=bound.tse_base+0x1ba7e)||!snapshot(&id,&s)||!(l=find((uintptr_t)old,&id,&s))||old_count>CAP_MAX||new_count>CAP_MAX||new_count!=old_count+20||l->bytes!=old_count*32||u64(n05_history_global)!=(uintptr_t)old||u32(bound.tse_base+0xafde0)!=new_count)return 0;
 /* FC40 takes BYTE sizes. The original two history callers pass record
  * counts. Convert only this reviewed, lifetime-bound history invocation. */
 LIFE previous=*l;l->live=0;
 void *p=((void *(EA *)(void *,UN,UN))(bound.tse_base+0xfc40))(old,old_count*32,new_count*32);
 NO_IDENTITY after;WG_SNAPSHOT now;if(!p){*l=previous;return 0;}
 if(!snapshot(&after,&now)||after.epoch!=id.epoch||after.loop_depth!=id.loop_depth||!equal(&s,&now,sizeof(s))||!no_range((uintptr_t)p,new_count*32,NO_READ|NO_WRITE))return 0;
 *l=(LIFE){(uintptr_t)p,s.application,new_count*32,s.session,id.epoch,++serial,id.loop_depth,1};return p;
}
extern uint8_t n05_menu_forget_return[],n05_loop_forget_return[];
void EA n05_forget_history(void *p){uintptr_t r=RA;if(r!=(uintptr_t)n05_menu_forget_return&&r!=(uintptr_t)n05_loop_forget_return)return;for(unsigned i=0;i<LIFE_MAX;i++)if(life[i].pointer==(uintptr_t)p)life[i].live=0;}
static int prepare(PLAN *p){
 zero(p,sizeof(*p));if(!snapshot(&p->id,&p->source))return 0;p->app=p->source.application;p->index=p->source.application_index;
 if(!no_range(p->app,96,NO_READ|NO_WRITE))return 0;copy(p->app_bytes,(void *)p->app,96);p->count=u32(p->app+0x2c);p->array=u64(p->app+0x30);
 if(!p->count||p->count>4096||p->index>=p->count||!no_range(p->array,8u*p->count,NO_READ)||!no_range(p->source.page,104,NO_READ))return 0;copy(p->source_bytes,(void *)p->source.page,104);
 p->history=u64(n05_history_global);p->capacity=u32(bound.tse_base+0xafde0);p->used=u32(bound.tse_base+0xafe00);p->root=u32(bound.tse_base+0xafddc);
 if(!no_range(bound.tse_base+0xafddc,0x28,NO_READ|NO_WRITE))return 0;
 if(p->history){p->owned=find(p->history,&p->id,&p->source);if(!p->owned||p->capacity>CAP_MAX||p->used>p->capacity||p->owned->bytes!=(UN)p->capacity*32||!no_range(p->history,p->owned->bytes,NO_READ|NO_WRITE))return 0;p->witness=*p->owned;}
 else if(p->used)return 0;
 unsigned matches=0;for(uint32_t i=0;i<p->count;i++){uintptr_t page=u64(p->array+i*8u);if(!page)continue;if(!no_range(page,104,NO_READ))return 0;if(u16(page+0x2a)!=0x2712||u64(page+0x20)!=p->source.hii)continue;
  if(u16(page+0x30)!=i||u16(page+0x32)||(u16(page+0x34)&1)||!no_observe(0,WG_RENDER,page,0,&p->main)||w890_classify_form(p->main.formset,p->main.form)!=W890_UNPROTECTED)return 0;
  p->main_index=i;copy(p->main_bytes,(void *)page,104);matches++;}
 return matches==1;
}
static int cached(const PLAN*p){return no_range(p->app,96,NO_READ|NO_WRITE)&&no_range(p->array,8u*p->count,NO_READ)&&no_range(bound.tse_base+0xafddc,0x28,NO_READ|NO_WRITE)&&no_range(p->source.page,104,NO_READ)&&no_range(p->main.page,104,NO_READ)&&
 u64(bound.tse_base+0xafdd0)==p->app&&equal((void *)p->app,p->app_bytes,96)&&equal((void *)p->source.page,p->source_bytes,104)&&equal((void *)p->main.page,p->main_bytes,104)&&
 u64(p->array+p->index*8u)==p->source.page&&u64(p->array+p->main_index*8u)==p->main.page&&u64(n05_history_global)==p->history&&u32(bound.tse_base+0xafde0)==p->capacity&&u32(bound.tse_base+0xafe00)==p->used&&u32(bound.tse_base+0xafddc)==p->root&&(!p->history||(equal(p->owned,&p->witness,sizeof(LIFE))&&no_range(p->history,p->owned->bytes,NO_WRITE)));}
uint32_t EA n05_fallback_main(void){
 if(busy)return N05_UNKNOWN;busy=1;uint32_t result=N05_UNKNOWN;NO_TICKET*t=0;
 if(!prepare(&a)||!prepare(&b)||!equal(&a,&b,sizeof(a))||!no_scope_enter(NO_EFFECT,a.app,&t))goto done;
 UN tpl=a.id.st->bs->raise_tpl(16);
 if(tpl==4&&no_scope_validate_cached(t)&&cached(&a)){
  /* Owned storage only. No FreePool, allocation, HII or variable service is
   * called while excluded. No native exit/reset flags or settings are changed. */
  if(a.history){zero((void *)a.history,a.owned->bytes);copy((void *)a.history,&a.main.hii,8);w32(a.history+8,a.main.form);w32(bound.tse_base+0xafe00,1);w32(bound.tse_base+0xafddc,a.main_index);}
  else{w32(bound.tse_base+0xafe00,0);w32(bound.tse_base+0xafddc,0);}
  w32(a.app+0x28,a.main_index);*((uint8_t *)(a.app+0x58))=1;w32(a.app+0x5c,1);result=N05_MAIN;
 }
 a.id.st->bs->restore_tpl(tpl);no_scope_leave(t);
 if(result==N05_MAIN){NO_IDENTITY after;WG_SNAPSHOT now;
  /* RestoreTPL may deliver a queued notification. Do not release a native
   * continuation if that invalidated the just-completed safe-page transfer. */
  if(!snapshot(&after,&now)||after.epoch!=a.id.epoch||now.page!=a.main.page||now.application!=a.app||now.application_index!=a.main_index)result=N05_UNKNOWN;
 }
done:zero(&a,sizeof(a));zero(&b,sizeof(b));busy=0;return result;
}
ES EA n05_check(uint32_t point,uintptr_t object,uintptr_t auxiliary){
 NO_IDENTITY id;WG_SNAPSHOT first,last;if(!identity(&id)||!no_observe(0,point,object,auxiliary,&first))return NO_DENIED;
 int kind=point==WG_CONTROL_INPUT?w890_classify_control(first.formset,first.form,first.ifr,first.ifr_size):w890_classify_form(first.formset,first.form);
 if(kind!=W890_PROTECTED&&kind!=W890_UNPROTECTED)return NO_DENIED;
 /* A credential storage/UI fault must not disable proven safe BIOS pages. */
 if(kind==W890_PROTECTED){uint32_t flags=w890_provider.query(&w890_provider);
  if((flags&3)!=3||(flags&112))return NO_DENIED;if(!(flags&12)&&w890_provider.request(&w890_provider)!=0)return NO_DENIED;
  flags=w890_provider.query(&w890_provider);if((flags&3)!=3||(flags&112)||!(flags&12))return NO_DENIED;}
 if(!no_observe(0,point,object,auxiliary,&last)||!equal(&first,&last,sizeof(first)))return NO_DENIED;return 0;
}
uint32_t EA n05_first(void){if(n05_check(WG_FIRST,0,0)==0)return N05_CONTINUE;return n05_fallback_main();}
ES EA n05_menu(void *app,void *control,void *cookie){if(n05_check(WG_MENU,(uintptr_t)control,(uintptr_t)cookie))return NO_DENIED;((void(EA*)(void*,void*,void*))(bound.tse_base+0x22818))(app,control,cookie);return 0;}
