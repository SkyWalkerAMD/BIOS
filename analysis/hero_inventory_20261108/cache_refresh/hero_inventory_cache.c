#include "hero_inventory_cache.h"
static void cr_zero(void *p,uint32_t n){uint8_t *q=p;while(n--)*q++=0;}
static int cr_eq(const void *a,const void *b,uint32_t n){const uint8_t *x=a,*y=b;for(uint32_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static uint32_t cr_len(const char *s){uint32_t n=0;while(s[n])n++;return n;}
static int cr_same(const char *a,const char *b){uint32_t n=cr_len(a);return n==cr_len(b)&&cr_eq(a,b,n);}
static uint32_t cr_crc(const void *p,uint32_t n){const uint8_t *s=p;uint32_t c=~0u;for(uint32_t i=0;i<n;i++){c^=s[i];for(unsigned b=0;b<8;b++)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}return ~c;}
#include "cache_json.h"
#define CR_MAGIC 0x31435248u
typedef struct {
 uint32_t magic,bound,binding_crc,reserved;
 uint64_t epoch;
 HICR_STATE state;
 char etag[96];
 CJ actual,expected;
} CR_CONTEXT;
static const char *const cr_paths[]={
 "/redfish/v1/GlobalLuaTables","/redfish/v1/Systems/Self",
 "/redfish/v1/Systems/Self/Processors","/redfish/v1/Systems/Self/Memory",
 "/redfish/v1/Systems/Self/Processors/DevType1_CPU",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM"
};
static const char cr_cpu_body[]="{\"Prefixes\":[\"Redfish:Systems:Self:Processors:SRK\"]}";
static const char cr_memory_body[]="{\"Prefixes\":[\"Redfish:Systems:Self:Memory:SRK\"]}";
uint32_t HeroInventoryCacheContextSize(void){return sizeof(CR_CONTEXT);}
static int cr_context(const void *p){return p&&!((uintptr_t)p&7u)&&((const CR_CONTEXT *)p)->magic==CR_MAGIC;}
int HeroInventoryCacheInit(void *p,uint32_t bytes,uint64_t epoch){
 if(!p||((uintptr_t)p&7u)||bytes<sizeof(CR_CONTEXT)||!epoch)return HICR_ARGUMENT;
 cr_zero(p,sizeof(CR_CONTEXT));CR_CONTEXT *c=p;c->magic=CR_MAGIC;c->epoch=epoch;c->state.version=1;return HICR_READY;
}
int HeroInventoryCacheState(const void *p,HICR_STATE *s){
 if(!cr_context(p)||!s)return HICR_ARGUMENT;
 const HICR_STATE *t=&((const CR_CONTEXT *)p)->state;uint8_t *a=(void *)s;const uint8_t *b=(const void *)t;
 for(unsigned i=0;i<sizeof(*s);i++)a[i]=b[i];return HICR_READY;
}
int HeroInventoryCachePath(uint32_t resource,uint32_t index,char *out,uint32_t cap){
 if(!out||resource>HICR_DIMM_ITEM||(resource<4&&index)||
    (resource==HICR_CPU_ITEM&&index>=HIC_MAX_CPUS)||(resource==HICR_DIMM_ITEM&&index>=HIC_MAX_DIMMS))return 0;
 unsigned n=cr_len(cr_paths[resource]),extra=resource<4?0:index<10?1:2;
 if(n+extra+1>cap)return 0;for(unsigned i=0;i<n;i++)out[i]=cr_paths[resource][i];
 if(extra==2)out[n++]=(char)('0'+index/10);if(extra)out[n++]=(char)('0'+index%10);out[n]=0;return 1;
}
static int cr_etag(const char *s,uint32_t n){
 if(!s||n<3||n>=96||s[0]!='"'||s[n-1]!='"')return 0;
 for(unsigned i=1;i<n-1;i++){unsigned c=(uint8_t)s[i];if(c<33||c>126||c=='"'||c=='\\')return 0;}return 1;
}
int HeroInventoryCacheWriteAllowed(uint32_t method,uint32_t resource,uint32_t index,const char *body,uint32_t bytes,const char *tag,uint32_t tag_bytes){
 if(method!=HICR_DELETE_CACHE||resource!=HICR_GLOBAL_TABLES||index||!body||!cr_etag(tag,tag_bytes))return 0;
 return (bytes==sizeof(cr_cpu_body)-1&&cr_eq(body,cr_cpu_body,bytes))||
        (bytes==sizeof(cr_memory_body)-1&&cr_eq(body,cr_memory_body,bytes));
}
static unsigned cr_items(const HIC_CATALOG *cat,unsigned target){return target==HICR_CPU?cat->cpu_count:cat->dimm_count;}
static unsigned cr_item_offset(const HIC_CATALOG *cat,unsigned target){return target==HICR_CPU?1:1+cat->cpu_count;}
static int cr_catalog(CR_CONTEXT *c,const HIC_CATALOG *cat){
 if(!cat||cat->version!=1||cat->valid!=1||cat->result||!cat->cpu_count||!cat->dimm_count||
    cat->cpu_count>HIC_MAX_CPUS||cat->dimm_count>HIC_MAX_DIMMS||cat->item_count!=1+cat->cpu_count+cat->dimm_count||
    !cat->json_bytes||cat->json_bytes>HIC_JSON_BYTES||!cat->table_bytes||cat->table_bytes>HIC_MAX_TABLE)return 0;
 unsigned next=0;
 for(unsigned i=0;i<cat->item_count;i++){
  const HIC_ITEM *p=&cat->items[i];unsigned kind=!i?1:i<=cat->cpu_count?2:3,index=!i?0:i<=cat->cpu_count?i-1:i-cat->cpu_count-1;
  if(p->kind!=kind||p->index!=index||p->json_offset!=next||!p->json_bytes||p->json_bytes>=cat->json_bytes-next)return 0;
  next+=p->json_bytes+1;if(cat->json[next-1]||!cj_parse(&c->expected,cat->json+p->json_offset,p->json_bytes)||c->expected.tokens[0].kind!='{')return 0;
  if(!i){static const char *keys[]={"Model","Manufacturer","BiosVersion","UUID"};for(unsigned k=0;k<4;k++){unsigned t=cj_find(&c->expected,0,keys[k]);if(t>=c->expected.count||c->expected.tokens[t].kind!='s'||c->expected.tokens[t].begin==c->expected.tokens[t].end)return 0;}}
 }
 return next==cat->json_bytes;
}
static int cr_source(CR_CONTEXT *c,const HIC_CATALOG *cat,const HICR_OPS *ops){
 return cr_crc(cat,sizeof(*cat))==c->binding_crc&&ops->source_valid(ops->user,c->epoch,cat)==1;
}
static int cr_request(CR_CONTEXT *c,const HIC_CATALOG *cat,const HICR_OPS *ops,unsigned method,unsigned resource,unsigned index,const char *body,unsigned bytes,HICR_REPLY *r){
 if(!cr_source(c,cat,ops))return HICR_SOURCE;
 cr_zero(r,sizeof(*r));c->state.exchanges++;
 int e=ops->exchange(ops->user,method,resource,index,body,bytes,method?c->etag:0,method?cr_len(c->etag):0,r);
 c->state.last_http_status=e?0:r->status;return e?HICR_TRANSPORT:HICR_READY;
}
static int cr_get(CR_CONTEXT *c,const HIC_CATALOG *cat,const HICR_OPS *ops,unsigned resource,unsigned index,HICR_REPLY *r){
 int e=cr_request(c,cat,ops,HICR_GET,resource,index,0,0,r);if(e)return e;if(r->status!=200)return HICR_HTTP;
 if(!cj_parse(&c->actual,r->body,r->bytes)||c->actual.tokens[0].kind!='{'||cj_find(&c->actual,0,"error")<c->actual.count)return HICR_JSON;
 char path[128];if(!HeroInventoryCachePath(resource,index,path,sizeof(path))||!cj_is(&c->actual,cj_find(&c->actual,0,"@odata.id"),path))return HICR_IDENTITY;
 return HICR_READY;
}
static int cr_match(CR_CONTEXT *c,const HIC_CATALOG *cat,unsigned item){
 const HIC_ITEM *p=&cat->items[item];return cj_parse(&c->expected,cat->json+p->json_offset,p->json_bytes)&&cj_subset(&c->expected,0,&c->actual,0,0);
}
static int cr_objects(CR_CONTEXT *c,unsigned target,const HIC_CATALOG *cat,const HICR_OPS *ops){
 HICR_REPLY r;int e=cr_get(c,cat,ops,HICR_SYSTEM,0,&r);if(e)return e;if(!cr_match(c,cat,0))return HICR_IDENTITY;
 if(!cj_is(&c->actual,cj_find(&c->actual,cj_find(&c->actual,0,"Processors"),"@odata.id"),cr_paths[HICR_CPUS])||
    !cj_is(&c->actual,cj_find(&c->actual,cj_find(&c->actual,0,"Memory"),"@odata.id"),cr_paths[HICR_DIMMS]))return HICR_IDENTITY;
 unsigned n=cr_items(cat,target),base=cr_item_offset(cat,target),resource=target==HICR_CPU?HICR_CPU_ITEM:HICR_DIMM_ITEM;
 for(unsigned i=0;i<n;i++){e=cr_get(c,cat,ops,resource,i,&r);if(e)return e;if(!cr_match(c,cat,base+i))return HICR_MEMBER;}
 return HICR_READY;
}
static int cr_collection(CR_CONTEXT *c,unsigned target,const HIC_CATALOG *cat,const HICR_OPS *ops,int *complete){
 HICR_REPLY r;int e=cr_get(c,cat,ops,target==HICR_CPU?HICR_CPUS:HICR_DIMMS,0,&r);if(e)return e;
 CJ *j=&c->actual;unsigned a=cj_find(j,0,"Members"),count=0,n=0;uint32_t seen=0;
 if(a>=j->count||j->tokens[a].kind!='['||!cj_uint(j,cj_find(j,0,"Members@odata.count"),&count)||
    cj_find(j,0,"Members@odata.nextLink")<j->count||cj_find(j,0,"@odata.nextLink")<j->count)return HICR_COLLECTION;
 for(unsigned t=a+1;t<j->tokens[a].after;t=j->tokens[t].after){
  if(j->tokens[t].kind!='{')return HICR_COLLECTION;unsigned found=HIC_MAX_DIMMS;
  for(unsigned i=0;i<cr_items(cat,target);i++){char path[128];HeroInventoryCachePath(target==HICR_CPU?HICR_CPU_ITEM:HICR_DIMM_ITEM,i,path,sizeof(path));if(cj_is(j,cj_find(j,t,"@odata.id"),path)){found=i;break;}}
  if(found==HIC_MAX_DIMMS||(seen&(1u<<found)))return HICR_COLLECTION;seen|=1u<<found;n++;
 }
 if(n!=count)return HICR_COLLECTION;*complete=n==cr_items(cat,target);return HICR_READY;
}
static int cr_capability(CR_CONTEXT *c,unsigned target,const HIC_CATALOG *cat,const HICR_OPS *ops){
 HICR_REPLY r;int e=cr_get(c,cat,ops,HICR_GLOBAL_TABLES,0,&r);if(e)return e;
 CJ *j=&c->actual;unsigned a=cj_find(j,0,"Members"),count=0,n=0,found=0;
 if(a>=j->count||j->tokens[a].kind!='['||!cj_uint(j,cj_find(j,0,"Members@odata.count"),&count)||
    cj_find(j,0,"Members@odata.nextLink")<j->count||cj_find(j,0,"@odata.nextLink")<j->count)return HICR_JSON;
 for(unsigned t=a+1;t<j->tokens[a].after;t=j->tokens[t].after){
  unsigned u=cj_find(j,t,"@odata.id");if(u>=j->count||j->tokens[u].kind!='s')return HICR_JSON;
  for(unsigned prev=a+1;prev<t;prev=j->tokens[prev].after)if(cj_strings(j,cj_find(j,prev,"@odata.id"),j,u,0))return HICR_JSON;
  if(cj_is(j,u,cr_paths[target==HICR_CPU?HICR_CPUS:HICR_DIMMS]))found++;n++;
 }
 if(n!=count)return HICR_JSON;if(found!=1)return HICR_NO_CACHE;
 if(!cj_ascii(j,cj_find(j,0,"@odata.etag"),c->etag,sizeof(c->etag))||!cr_etag(c->etag,cr_len(c->etag)))return HICR_ETAG;
 if(r.etag||r.etag_bytes){if(!r.etag||r.etag_bytes!=cr_len(c->etag)||!cr_eq(r.etag,c->etag,r.etag_bytes))return HICR_ETAG;}
 return HICR_READY;
}
static int cr_end(CR_CONTEXT *c,int result){c->state.last_result=(uint32_t)result;return result;}
static int cr_run(void *context,unsigned target,const HIC_CATALOG *cat,const HICR_OPS *ops,int write){
 if(!cr_context(context)||!ops||!ops->source_valid||!ops->reserve||!ops->exchange||(target!=HICR_CPU&&target!=HICR_MEMORY))return HICR_ARGUMENT;
 CR_CONTEXT *c=context;c->state.target=target;c->state.phase=HICR_IDLE;c->state.exchanges=0;c->state.last_http_status=0;
 if(write&&c->state.hold)return cr_end(c,HICR_HELD);
 if(write&&(c->state.attempted_mask&target))return cr_end(c,HICR_REPLAY_BLOCKED);
 if(!cr_catalog(c,cat))return cr_end(c,HICR_CATALOG);
 uint32_t fingerprint=cr_crc(cat,sizeof(*cat));if(c->bound&&c->binding_crc!=fingerprint)return cr_end(c,HICR_SOURCE);
 c->bound=1;c->binding_crc=fingerprint;if(!cr_source(c,cat,ops))return cr_end(c,HICR_SOURCE);
 if(ops->reserve(ops->user,write?2*cr_items(cat,target)+6:cr_items(cat,target)+3)!=1)return cr_end(c,HICR_BUDGET);
 c->state.phase=HICR_BASELINE;c->state.verified_mask&=~target;
 int e=cr_objects(c,target,cat,ops);if(e)return cr_end(c,e);int complete=0;
 e=cr_collection(c,target,cat,ops,&complete);if(e)return cr_end(c,e);
 if(complete){c->state.verified_mask|=target;c->state.phase=HICR_FINISHED;return cr_end(c,HICR_COMPLETE);}
 c->state.phase=HICR_CAPABILITY;e=cr_capability(c,target,cat,ops);if(e)return cr_end(c,e);
 if(!write)return cr_end(c,HICR_READY);
 /* Latch BEFORE crossing into transport. A response or transport failure must
  * never allow a second DELETE, even if readback subsequently looks healthy. */
 const char *body=target==HICR_CPU?cr_cpu_body:cr_memory_body;unsigned bytes=cr_len(body);
 if(!HeroInventoryCacheWriteAllowed(HICR_DELETE_CACHE,HICR_GLOBAL_TABLES,0,body,bytes,c->etag,cr_len(c->etag)))return cr_end(c,HICR_ARGUMENT);
 if(!cr_source(c,cat,ops))return cr_end(c,HICR_SOURCE);
 c->state.phase=HICR_ATTEMPTED;c->state.attempted_mask|=target;c->state.hold=1;c->state.delete_target=target;
 HICR_REPLY r;int sent=cr_request(c,cat,ops,HICR_DELETE_CACHE,HICR_GLOBAL_TABLES,0,body,bytes,&r);
 c->state.delete_transport_failed=sent?1u:0;c->state.delete_http_status=sent?0:r.status;
 int ack=!sent&&r.status==204&&!r.bytes;if(ack)c->state.acknowledged_mask|=target;
 c->state.phase=HICR_READBACK;
 /* Exactly one readback sequence, including after an uncertain response.
  * No retry delay, DELETE replay, resource creation, rollback or fallback. */
 e=cr_collection(c,target,cat,ops,&complete);if(e)return cr_end(c,e);
 e=cr_objects(c,target,cat,ops);if(e)return cr_end(c,e);
 if(complete)c->state.verified_mask|=target;
 if(!ack)return cr_end(c,HICR_RESPONSE_UNCONFIRMED);
 if(!complete)return cr_end(c,HICR_INDEX_INCOMPLETE);
 c->state.hold=0;c->state.phase=HICR_FINISHED;return cr_end(c,HICR_REFRESHED);
}
int HeroInventoryCacheInspect(void *c,uint32_t target,const HIC_CATALOG *cat,const HICR_OPS *ops){return cr_run(c,target,cat,ops,0);}
int HeroInventoryCacheRefresh(void *c,uint32_t target,const HIC_CATALOG *cat,const HICR_OPS *ops){return cr_run(c,target,cat,ops,1);}
