#include "first_fallback.h"
#include "../password/w890_policy.h"
enum {APP_BYTES=0x60,PAGE_BYTES=0x68,MAX_PAGES=4096};
typedef struct {
 uintptr_t app,array,source,main,hii;
 uint32_t count,index,main_index,history_capacity;
 uint64_t epoch;
 uint8_t app_bytes[APP_BYTES],source_bytes[PAGE_BYTES],main_bytes[PAGE_BYTES];
} PLAN;
static void zero(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;uint8_t d=0;while(n--)d|=*x++^*y++;return d==0;}
static uint16_t u16(const void *p){const uint8_t *b=p;return(uint16_t)(b[0]|((uint16_t)b[1]<<8));}
static uint32_t u32(const void *p){const uint8_t *b=p;return(uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);}
static uintptr_t ptr(const void *p){uintptr_t v=0;copy(&v,p,sizeof(v));return v;}
static int live(uint32_t f){return(f&3u)==3u&&!(f&112u);}
static int range(WF_BINDING *b,uintptr_t a,size_t n,uint32_t mode){return a&&n&&n<=UINTPTR_MAX-a&&b->range(b->opaque,a,n,mode);}
static int read(WF_BINDING *b,uintptr_t a,void *out,size_t n){if(!range(b,a,n,WF_READ))return 0;copy(out,(const void *)a,n);return 1;}
static int valid(WF_BINDING *b){
 return b&&b->abi==WF_ABI&&!b->reserved&&b->native_base&&!(b->native_base&4095u)&&b->native_base<=UINTPTR_MAX-0xde000u&&b->application&&b->session_token&&b->provider&&b->gate&&b->query&&b->check_first&&b->identity&&b->session&&b->range&&b->hii;
}
static int prepare(WF_BINDING *b,PLAN *p){
 uint8_t page[PAGE_BYTES],guid[16];uintptr_t app=0,page_address=0,history=0;uint32_t used=0,root=0;uint64_t epoch=0;uint32_t matches=0;
 if(!b->identity(b->opaque,b->native_base,b->application)||!b->session(b->opaque,b->session_token,b->application)||!live(b->query(b->provider)))return 0;
 if(!read(b,b->native_base+0xafdd0u,&app,8)||app!=b->application)return 0;
 if(!read(b,app,p->app_bytes,APP_BYTES)||!range(b,app+0x28u,4,WF_WRITE)||!range(b,app+0x58u,8,WF_WRITE))return 0;
 p->app=app;p->index=u32(p->app_bytes+0x28);p->count=u32(p->app_bytes+0x2c);p->array=ptr(p->app_bytes+0x30);
 if(!p->count||p->count>MAX_PAGES||p->index>=p->count||!range(b,p->array,(size_t)p->count*8u,WF_READ))return 0;
 if(!read(b,p->array+(uintptr_t)p->index*8u,&p->source,8)||!read(b,p->source,p->source_bytes,PAGE_BYTES))return 0;
 p->hii=ptr(p->source_bytes+0x20);
 if(!p->hii||u16(p->source_bytes+0x30)!=p->index||(p->source_bytes[0x34]&1u)||!b->hii(b->opaque,p->hii,guid,&p->epoch)||!p->epoch||w890_classify_form(guid,u16(p->source_bytes+0x2a))!=W890_PROTECTED)return 0;
 /* First-entry only. A nonempty history is an unsupported nested/reentry
  * state; never free a pool whose lifetime has not been established here. */
 if(!read(b,b->native_base+0xafde8u,&history,8)||!read(b,b->native_base+0xafe00u,&used,4)||!read(b,b->native_base+0xafddcu,&root,4)||!read(b,b->native_base+0xafde0u,&p->history_capacity,4)||history||used||root)return 0;
 if(!range(b,b->native_base+0xafde8u,8,WF_WRITE)||!range(b,b->native_base+0xafe00u,4,WF_WRITE)||!range(b,b->native_base+0xafddcu,4,WF_WRITE))return 0;
 for(uint32_t i=0;i<p->count;i++){
  if(!read(b,p->array+(uintptr_t)i*8u,&page_address,8))return 0;
  if(!page_address)continue;
  if(!read(b,page_address,page,PAGE_BYTES))return 0;
  if(u16(page+0x2a)!=0x2712u||ptr(page+0x20)!=p->hii)continue;
  if(u16(page+0x30)!=i||u16(page+0x32)!=0||(page[0x34]&1u))return 0;
  if(!b->hii(b->opaque,ptr(page+0x20),guid,&epoch)||epoch!=p->epoch||w890_classify_form(guid,0x2712u)!=W890_UNPROTECTED)return 0;
  matches++;p->main=page_address;p->main_index=i;copy(p->main_bytes,page,PAGE_BYTES);
 }
 return matches==1&&p->main!=p->source&&p->main_index!=p->index;
}
WG_API uint32_t wf_main_fallback(WF_BINDING *b){
 PLAN a,z;uint32_t expected=0,result=WF_CANNOT_RECOVER;uint8_t cookie[12]={8,0,0,0,0,0,0,0,0,0,0,0};
 if(!valid(b)||!__atomic_compare_exchange_n(&b->busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))return result;
 zero(&a,sizeof(a));zero(&z,sizeof(z));
 if(!prepare(b,&a)||!prepare(b,&z)||!equal(&a,&z,sizeof(a)))goto done;
 if(!b->session(b->opaque,b->session_token,b->application)||!live(b->query(b->provider)))goto done;
 /* All memory extents were checked before dereference. After the last host
  * callback, recheck the data used by the original effect without another
  * external callback or allocation in between. */
 if(ptr((const void *)(b->native_base+0xafdd0u))!=a.app||!equal((const void *)a.app,a.app_bytes,APP_BYTES)||!equal((const void *)a.source,a.source_bytes,PAGE_BYTES)||!equal((const void *)a.main,a.main_bytes,PAGE_BYTES)||ptr((const void *)(a.array+(uintptr_t)a.index*8u))!=a.source||ptr((const void *)(a.array+(uintptr_t)a.main_index*8u))!=a.main||ptr((const void *)(b->native_base+0xafde8u))||u32((const void *)(b->native_base+0xafe00u))||u32((const void *)(b->native_base+0xafddcu)))goto done;
 cookie[8]=(uint8_t)a.main_index;cookie[9]=(uint8_t)(a.main_index>>8);
 ((WG_MENU_ORIGINAL)(b->native_base+0x22818u))((void *)a.app,0,cookie);
 result=WF_MAIN_SELECTED;
done:
 zero(&a,sizeof(a));zero(&z,sizeof(z));zero(cookie,sizeof(cookie));__atomic_store_n(&b->busy,0,__ATOMIC_RELEASE);return result;
}
WG_API uint32_t wf_first(WF_BINDING *b){
 if(!valid(b))return WF_CANNOT_RECOVER;
 if(b->check_first((WG_GATE *)b->gate,WG_FIRST,b->application,0)==0)return WF_CONTINUE;
 return wf_main_fallback(b);
}
WG_API size_t wf_binding_bytes(void){return sizeof(WF_BINDING);}
