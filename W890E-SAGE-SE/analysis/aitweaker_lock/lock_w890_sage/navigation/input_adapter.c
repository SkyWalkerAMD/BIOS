#include "input_adapter.h"
#include "../password/w890_policy.h"
#include "input_registry_data.h"
static void zero(void *p,size_t n){uint8_t *x=p;while(n--)*x++=0;}
static int eq(const void *p,const void *q,size_t n){const uint8_t *a=p,*b=q;uint8_t d=0;while(n--)d|=*a++^*b++;return d==0;}
static uintptr_t ptr(uintptr_t a){uintptr_t v=0;uint8_t *x=(uint8_t *)&v;const uint8_t *y=(const uint8_t *)a;for(size_t i=0;i<sizeof(v);i++)x[i]=y[i];return v;}
static uint16_t word(uintptr_t a){const uint8_t *p=(const uint8_t *)a;return(uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static int live(uint32_t f){return(f&3u)==3u&&!(f&112u);}
static int granted(uint32_t f){return live(f)&&(f&12u);}
static int range(WI_BINDING *b,uintptr_t a,size_t n){return a&&n<=UINTPTR_MAX-a&&b->range(b->opaque,a,n,1);}
static int valid(WI_BINDING *b){return b&&b->abi==WI_ABI&&!b->reserved&&b->native_base&&!(b->native_base&4095u)&&b->native_base<=UINTPTR_MAX-0xde000u&&b->gate&&b->gate->abi==WG_ABI&&!b->gate->reserved&&b->gate->native_base==b->native_base&&b->check&&b->range&&b->scope&&b->effects&&b->gate->query&&b->gate->provider&&b->gate->observe;}
static int snapshot(WI_BINDING *b,uintptr_t c,uintptr_t e,WG_SNAPSHOT *s){
 if(!b->gate->observe(b->gate->opaque,WG_CONTROL_INPUT,c,e,s))return -1;
 if((s->proof&63u)!=63u||s->owner!=WG_OWNER_SETUP||!s->session||s->native_base!=b->native_base||!s->application||!s->page||!s->hii||s->control!=c||s->ifr_size<2||s->ifr_size>sizeof(s->ifr))return -1;
 return w890_classify_control(s->formset,s->form,s->ifr,s->ifr_size);
}
static int silent(WI_BINDING *b,uintptr_t c,uintptr_t e){
 WG_SNAPSHOT a,z;uint32_t expected=0,f;int x,y,result=0;
 if(!__atomic_compare_exchange_n(&b->gate->busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))return 0;
 zero(&a,sizeof(a));zero(&z,sizeof(z));f=b->gate->query(b->gate->provider);if(!live(f))goto done;
 x=snapshot(b,c,e,&a);if(x<0||(x==W890_PROTECTED&&!granted(f)))goto done;
 y=snapshot(b,c,e,&z);if(x!=y||!eq(&a,&z,sizeof(a)))goto done;
 f=b->gate->query(b->gate->provider);if(!live(f)||(x==W890_PROTECTED&&!granted(f)))goto done;result=1;
done:zero(&a,sizeof(a));zero(&z,sizeof(z));__atomic_store_n(&b->gate->busy,0,__ATOMIC_RELEASE);return result;
}
WG_API WI_BINDING *wi_binding;
WG_API uint64_t wi_control(void *object,void *event){
 WI_BINDING *b=wi_binding;uintptr_t c=(uintptr_t)object,e=(uintptr_t)event,table,target=0;uint16_t type,kind;uint32_t expected=0;uint64_t result=0;
 /* Zero is intentional: consume denied input at BOTH native layers. Returning
  * ACCESS_DENIED or ABORTED lets PageInput continue extra/hotkey processing. */
 if(!valid(b)||!__atomic_compare_exchange_n(&b->busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))return 0;
 if(!range(b,c,0x50)||!range(b,e,0x30))goto done;
 table=ptr(c);type=word(c+0x34);kind=word(e+8);if(kind!=1&&kind!=2)goto done;
 for(size_t i=0;i<sizeof(wi_types)/sizeof(wi_types[0]);i++)if(type==wi_types[i].type&&table==b->native_base+wi_types[i].table){target=b->native_base+wi_types[i].input;break;}
 if(!target||!range(b,table+0x20,8)||ptr(table+0x20)!=(uintptr_t)wi_control||!b->scope(b->opaque,c,e,type,table,target))goto done;
 if(type==14){
  /* Native6AF98 reaches a page change only through6AF54 -> object callback.
   * The separately guarded callback must already be installed on BOTH the
   * factory descriptor and this existing menu object before pass-through. */
  if(!b->menu_callback||!range(b,b->native_base+0x94408,8)||ptr(b->native_base+0x94408)!=b->menu_callback||ptr(c+8)!=b->menu_callback||!live(b->gate->query(b->gate->provider)))goto done;
 }else{
  if(kind==2){if(!silent(b,c,e))goto done;}
  else if(b->check(b->gate,WG_CONTROL_INPUT,c,e))goto done;
 }
 if(!b->scope(b->opaque,c,e,type,table,target)||!range(b,c,0x50)||!range(b,table+0x20,8))goto done;
 /* Scope validation may itself encounter a revoked visit. Recheck silently
  * after it; an input callback must never introduce a second challenge. */
 if(type==14){if(!live(b->gate->query(b->gate->provider)))goto done;}
 else if(!silent(b,c,e))goto done;
 if(ptr(c)!=table||word(c+0x34)!=type||ptr(table+0x20)!=(uintptr_t)wi_control)goto done;
 if(type==14&&(ptr(c+8)!=b->menu_callback||ptr(b->native_base+0x94408)!=b->menu_callback))goto done;
 result=((uint64_t (*)(void *,void *))target)(object,event);
done:__atomic_store_n(&b->busy,0,__ATOMIC_RELEASE);return result;
}
WG_API uint64_t wi_pending(void *a,void *c,void *d){
 WI_BINDING *b=wi_binding;WI_EFFECTS x,z;uint32_t expected=0,f;uint64_t result=WG_DENIED;
 if(!valid(b)||!__atomic_compare_exchange_n(&b->busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))return result;
 zero(&x,sizeof(x));zero(&z,sizeof(z));f=b->gate->query(b->gate->provider);if(!live(f))goto done;
 if(!b->effects(b->opaque,&x)||x.proof!=31||!x.session||!x.epoch||x.reserved||x.classification>1||(x.classification==1&&!granted(f)))goto done;
 if(!b->effects(b->opaque,&z)||!eq(&x,&z,sizeof(x)))goto done;
 f=b->gate->query(b->gate->provider);if(!live(f)||(x.classification==1&&!granted(f)))goto done;
 result=((uint64_t (*)(void *,void *,void *))(b->native_base+0x40094))(a,c,d);
done:zero(&x,sizeof(x));zero(&z,sizeof(z));__atomic_store_n(&b->busy,0,__ATOMIC_RELEASE);return result;
}
WG_API size_t wi_binding_bytes(void){return sizeof(WI_BINDING);}
