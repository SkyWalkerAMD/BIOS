#include "gate_adapter.h"
#include "../password/w890_policy.h"
enum {P_READY=1,P_OWNED=2,P_GRANTED=4,P_DISABLED=8,P_BUSY=16,P_FAULT=32,P_ENDED=64};
static void zero(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;uint8_t d=0;while(n--)d|=*x++^*y++;return d==0;}
static int live(uint32_t f){return(f&(P_READY|P_OWNED))==(P_READY|P_OWNED)&&!(f&(P_BUSY|P_FAULT|P_ENDED));}
static int grant(uint32_t f){return live(f)&&(f&(P_GRANTED|P_DISABLED));}
static int snapshot_valid(const WG_GATE *g,const WG_SNAPSHOT *s,uint32_t route){
 uint32_t must=WG_IDENTITY|WG_SESSION|WG_EXTENTS|WG_PAGE|WG_HII;
 if((s->proof&must)!=must||!s->session||s->native_base!=g->native_base||!s->application||!s->page||!s->hii||!s->form)return 0;
 if(s->page_index>0xffffu||s->ifr_size>sizeof(s->ifr))return 0;
 if(route==WG_CONTROL_INPUT&&(!(s->proof&WG_CONTROL)||!s->control||s->ifr_size<2))return 0;
 if(route!=WG_CONTROL_INPUT&&s->ifr_size)return 0;
 return 1;
}
static int classification(const WG_SNAPSHOT *s,uint32_t route){
 if(s->owner==WG_OWNER_FOREIGN)
  return(s->proof&WG_FOREIGN_NO_SETUP)?W890_UNPROTECTED:W890_UNKNOWN;
 if(s->owner!=WG_OWNER_SETUP)return W890_UNKNOWN;
 if(route==WG_CONTROL_INPUT)return w890_classify_control(s->formset,s->form,s->ifr,s->ifr_size);
 return w890_classify_form(s->formset,s->form);
}
WG_API uint64_t wg_check(WG_GATE *g,uint32_t route,uintptr_t object,uintptr_t auxiliary){
 WG_SNAPSHOT a,b;uint64_t result=WG_DENIED;uint32_t expected=0,flags;int cls;
 if(!g||g->abi!=WG_ABI||g->reserved||!g->observe||!g->query||!g->request||!g->provider||!g->native_base||(g->native_base&4095)||g->native_base>UINTPTR_MAX-0xde000u||route<WG_FIRST||route>WG_NAVIGATION)return WG_DENIED;
 if(!__atomic_compare_exchange_n(&g->busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))return WG_DENIED;
 zero(&a,sizeof(a));zero(&b,sizeof(b));
 flags=g->query(g->provider);if(!live(flags))goto done;
 if(!g->observe(g->opaque,route,object,auxiliary,&a)||!snapshot_valid(g,&a,route))goto done;
 cls=classification(&a,route);if(cls!=W890_UNPROTECTED&&cls!=W890_PROTECTED)goto done;
 if(cls==W890_PROTECTED&&!grant(flags)){
  if(g->request(g->provider)!=0)goto done;
 }
 flags=g->query(g->provider);if(!live(flags)||(cls==W890_PROTECTED&&!grant(flags)))goto done;
 /* Prompting can enter other callbacks or end this visit. Reobserve the exact
  * source/target/history identity and classify again before any native effect. */
 if(!g->observe(g->opaque,route,object,auxiliary,&b)||!snapshot_valid(g,&b,route)||!eq(&a,&b,sizeof(a))||classification(&b,route)!=cls)goto done;
 flags=g->query(g->provider);if(!live(flags)||(cls==W890_PROTECTED&&!grant(flags)))goto done;
 result=0;
done:
 zero(&a,sizeof(a));zero(&b,sizeof(b));__atomic_store_n(&g->busy,0,__ATOMIC_RELEASE);return result;
}
WG_API uint64_t wg_menu(WG_GATE *g,void *arg1,void *control,void *cookie){
 if(wg_check(g,WG_MENU,(uintptr_t)control,(uintptr_t)cookie)!=0)return WG_DENIED;
 ((WG_MENU_ORIGINAL)(g->native_base+0x22818u))(arg1,control,cookie);return 0;
}
WG_API WG_GATE *wg_binding;
WG_API void wg_native_menu_thunk(void *arg1,void *control,void *cookie){
 (void)wg_menu(wg_binding,arg1,control,cookie);
}
WG_API size_t wg_snapshot_bytes(void){return sizeof(WG_SNAPSHOT);}
WG_API size_t wg_gate_bytes(void){return sizeof(WG_GATE);}
