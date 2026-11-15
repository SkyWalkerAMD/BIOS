#include "hero_inventory_publish.h"
static void zero(void *p,uint32_t n){uint8_t *q=p;while(n--)*q++=0;}
static void copy(void *d,const void *s,uint32_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
static int cr_eq(const void *a,const void *b,uint32_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint32_t length(const char *s){uint32_t n=0;while(s[n])n++;return n;}
static int cr_same(const char *a,const char *b){uint32_t n=length(a);return n==length(b)&&cr_eq(a,b,n);}
static uint32_t crc(const void *p,uint32_t n){const uint8_t *s=p;uint32_t c=~0u;while(n--){c^=*s++;for(unsigned b=0;b<8;b++)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}return ~c;}
#include "publish_json.h"
#define MAGIC 0x31504948u
enum PH {ROOT=1,SYSTEMS,SYSTEM_READ,SYSTEM_WRITE,SYSTEM_VERIFY,CHASSIS_READ,
 OBJECT_READ,PARENT_READ,OBJECT_RECHECK,OBJECT_WRITE,OBJECT_VERIFY,
 LINKS_READ,LINKS_WRITE,LINKS_VERIFY,COLLECTION_READ,CACHE_CAP,CACHE_WRITE,
 COLLECTION_VERIFY,FINAL_OBJECT,DONE,HELD,SUMMARY_READ,SUMMARY_WRITE,SUMMARY_VERIFY};
typedef struct {
 uint32_t magic,plan_crc,max_requests,max_ms,last_ms,sequence,body_bytes,request_body_crc,request_tag_crc,request_uri_crc;
 uint64_t epoch;const HIP_PLAN_DATA *plan;HIP_STATE state;
 uint8_t verified[HIP_RESOURCE_MAX],indexed[HIP_RESOURCE_MAX],link_done[HIP_RESOURCE_MAX];
 uint16_t collections[HIP_RESOURCE_MAX];uint32_t collection_count,collection_index;
 uint32_t group_index;char uri[HIP_URI_MAX],etag[128],body[HIP_BODY_MAX];
 HIP_REQUEST current;CJ actual,expected;
} CONTEXT;
static int context(const void *p){return p&&!((uintptr_t)p&7u)&&((const CONTEXT *)p)->magic==MAGIC;}
static int stop(CONTEXT *c,int e){c->state.result=(uint32_t)e;c->state.phase=HELD;c->state.inflight=0;return e;}
static int safe_uri(const char *s,int fragment){
 unsigned n=0,start=0;int hash=0;if(!s)return 0;
 while(n<HIP_URI_MAX&&s[n]){unsigned ch=(uint8_t)s[n];if(ch=='#'&&fragment&&!hash){hash=1;start=n+1;}
  else if(ch=='/'){if(n>start&&((n-start==1&&s[start]=='.')||(n-start==2&&s[start]=='.'&&s[start+1]=='.')))return 0;start=n+1;}
  else if(!((ch>='a'&&ch<='z')||(ch>='A'&&ch<='Z')||(ch>='0'&&ch<='9')||ch=='_'||ch=='-'||ch=='.'||ch=='~'))return 0;n++;
 }
 return n>12&&n<HIP_URI_MAX&&s[0]=='/'&&s[n-1]!='/'&&cr_eq(s,"/redfish/v1/",12)&&!(n-start==1&&s[start]=='.')&&!(n-start==2&&s[start]=='.'&&s[start+1]=='.');
}
static int joined(const char *actual,const char *base,const char *suffix){unsigned a=length(base),b=length(suffix);return length(actual)==a+b&&cr_eq(actual,base,a)&&cr_eq(actual+a,suffix,b);}
static int child(const char *full,const char *base){unsigned n=length(base);if(length(full)<=n+1||!cr_eq(full,base,n)||full[n]!='/')return 0;for(unsigned i=n+1;full[i];i++)if(full[i]=='/')return 0;return 1;}
static int overlaps(const void *a,uint32_t an,const void *b,uint32_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 1;return x<y+bn&&y<x+an;}
static int etag_ok(const char *s,unsigned n){if(!s||n<3||n>=128||s[0]!='"'||s[n-1]!='"')return 0;for(unsigned i=1;i<n-1;i++)if((uint8_t)s[i]<33||(uint8_t)s[i]>126||s[i]=='"'||s[i]=='\\')return 0;return 1;}
static int uint_value(const CJ *j,unsigned t,unsigned *out){if(t>=j->count||j->tokens[t].kind!='d')return 0;unsigned n=0,a=j->tokens[t].begin,b=j->tokens[t].end;if(b-a>6)return 0;while(a<b){unsigned x=(uint8_t)j->text[a++];if(x<'0'||x>'9')return 0;n=n*10+x-'0';}*out=n;return 1;}
static int parse(CONTEXT *c,const HIP_RESPONSE *r,const char *uri){
 if(r->http_status!=200||!cj_parse(&c->actual,r->body,r->body_bytes)||c->actual.tokens[0].kind!='{'||cj_find(&c->actual,0,"error")<c->actual.count)return 0;
 return !uri||cj_is(&c->actual,cj_find(&c->actual,0,"@odata.id"),uri);
}
static int read_tag(CONTEXT *c,const HIP_RESPONSE *r){unsigned t=cj_find(&c->actual,0,"@odata.etag");
 if(!cj_ascii(&c->actual,t,c->etag,sizeof(c->etag))||!etag_ok(c->etag,length(c->etag)))return 0;
 return (!r->etag&&!r->etag_bytes)||(r->etag&&r->etag_bytes==length(c->etag)&&cr_eq(r->etag,c->etag,r->etag_bytes));
}
static int expected(CONTEXT *c,unsigned i){const HIP_RESOURCE *p=&c->plan->resources[i];return cj_parse(&c->expected,p->body,p->body_bytes)&&cj_subset(&c->expected,0,&c->actual,0,0);}
static int allowed_keys(const CJ *j,const char *keys){
 for(unsigned t=1;t<j->tokens[0].after;t=j->tokens[t+1].after){char key[96];if(!cj_ascii(j,t,key,sizeof(key)))return 0;
  unsigned n=length(key),p=0,found=0;while(keys[p]){unsigned a=p;while(keys[p]&&keys[p]!='|')p++;if(p-a==n&&cr_eq(keys+a,key,n))found=1;if(keys[p])p++;}if(!found)return 0;
 }return 1;
}
static int body_valid(CONTEXT *c,const HIP_RESOURCE *r){
 static const char *const keys[]={"", "Model|Manufacturer|BiosVersion|UUID|SerialNumber|SKU",
 "Id|Name|Socket|ProcessorType|ProcessorArchitecture|InstructionSet|Manufacturer|Model|TotalCores|TotalEnabledCores|TotalThreads|Status",
 "Id|Name|MemoryDeviceType|MemoryType|BaseModuleType|CapacityMiB|DataWidthBits|BusWidthBits|AllowedSpeedsMHz|OperatingSpeedMhz|Manufacturer|SerialNumber|PartNumber|DeviceLocator|MemoryLocation|Status",
 "Id|Name", "Id|Name|FunctionId|VendorId|DeviceId|ClassCode|RevisionId|SubsystemId|SubsystemVendorId",
 "Id|Name|StorageControllers", "Id|Name|Model|SerialNumber|Revision|CapacityBytes|BlockSizeBytes|Protocol|MediaType"};
 if(!r->body||!r->body_bytes||r->body_bytes>=HIP_BODY_MAX||r->kind<1||r->kind>7||r->body_crc32!=crc(r->body,r->body_bytes)||!cj_parse(&c->expected,r->body,r->body_bytes)||c->expected.tokens[0].kind!='{'||!allowed_keys(&c->expected,keys[r->kind]))return 0;
 if(r->kind==HIP_SYSTEM){static const char *const required[]={"Model","Manufacturer","BiosVersion","UUID"};for(unsigned k=0;k<4;k++){unsigned t=cj_find(&c->expected,0,required[k]);if(t>=c->expected.count||c->expected.tokens[t].kind!='s'||c->expected.tokens[t].begin==c->expected.tokens[t].end)return 0;}return 1;}
 const char *id=r->member_uri;for(unsigned p=0;r->member_uri[p];p++)if(r->member_uri[p]=='/')id=r->member_uri+p+1;
 unsigned name=cj_find(&c->expected,0,"Name");return cj_is(&c->expected,cj_find(&c->expected,0,"Id"),id)&&name<c->expected.count&&c->expected.tokens[name].kind=='s'&&c->expected.tokens[name].begin<c->expected.tokens[name].end;
}
static int resource_route(const HIP_PLAN_DATA *p,unsigned i){const HIP_RESOURCE *r=&p->resources[i];
 if(!safe_uri(r->member_uri,0)||!safe_uri(r->collection_uri,0)||r->reserved||r->post_to_collection>1)return 0;
 if(!i)return r->kind==HIP_SYSTEM&&r->parent_index==HIP_NONE&&!r->post_to_collection&&cr_same(r->member_uri,p->system_uri)&&cr_same(r->collection_uri,"/redfish/v1/Systems");
 if(!child(r->member_uri,r->collection_uri))return 0;
 switch(r->kind){
 case HIP_CPU:return r->parent_index==0&&r->post_to_collection&&joined(r->collection_uri,p->system_uri,"/Processors");
 case HIP_MEMORY:return r->parent_index==0&&r->post_to_collection&&joined(r->collection_uri,p->system_uri,"/Memory");
 case HIP_PCIE_DEVICE:return r->parent_index==HIP_NONE&&!r->post_to_collection&&joined(r->collection_uri,p->chassis_uri,"/PCIeDevices");
 case HIP_STORAGE:return r->parent_index==0&&r->post_to_collection&&joined(r->collection_uri,p->system_uri,"/Storage");
 case HIP_PCIE_FUNCTION:case HIP_DRIVE:
  return !r->post_to_collection&&r->parent_index>0&&r->parent_index<i&&p->resources[r->parent_index].kind==(r->kind==HIP_DRIVE?HIP_STORAGE:HIP_PCIE_DEVICE)&&joined(r->collection_uri,p->resources[r->parent_index].member_uri,r->kind==HIP_DRIVE?"/Drives":"/PCIeFunctions");
 default:return 0;
 }
}
static int link_valid(const HIP_PLAN_DATA *p,const HIP_LINK *l){
 if(l->parent_index>=p->resource_count||!safe_uri(l->member_uri,1))return 0;
 unsigned parent=p->resources[l->parent_index].kind,want=0;
 switch(l->field){
 case HIP_SYSTEM_DEVICES:if(parent!=HIP_SYSTEM)return 0;want=HIP_PCIE_DEVICE;break;
 case HIP_SYSTEM_FUNCTIONS:if(parent!=HIP_SYSTEM)return 0;want=HIP_PCIE_FUNCTION;break;
 case HIP_DEVICE_CHASSIS:return parent==HIP_PCIE_DEVICE&&cr_same(l->member_uri,p->chassis_uri);
 case HIP_DEVICE_FUNCTIONS:if(parent!=HIP_PCIE_DEVICE)return 0;want=HIP_PCIE_FUNCTION;break;
 case HIP_STORAGE_DRIVES:if(parent!=HIP_STORAGE)return 0;want=HIP_DRIVE;break;
 case HIP_FUNCTION_DRIVES:if(parent!=HIP_PCIE_FUNCTION)return 0;want=HIP_DRIVE;break;
 case HIP_FUNCTION_CONTROLLERS:
  if(parent!=HIP_PCIE_FUNCTION)return 0;
  for(unsigned i=1;i<p->resource_count;i++)if(p->resources[i].kind==HIP_STORAGE&&joined(l->member_uri,p->resources[i].member_uri,"#/StorageControllers/0"))return 1;return 0;
 default:return 0;
 }
 for(unsigned i=1;i<p->resource_count;i++){
  if(p->resources[i].kind==want&&cr_same(l->member_uri,p->resources[i].member_uri)){
   if((l->field==HIP_DEVICE_FUNCTIONS||l->field==HIP_STORAGE_DRIVES)&&p->resources[i].parent_index!=l->parent_index)return 0;return 1;
  }
 }
 return 0;
}
uint32_t HeroInventoryPublishContextSize(void){return sizeof(CONTEXT);}
int HeroInventoryPublishState(const void *p,HIP_STATE *s){if(!context(p)||!s)return HIP_ARGUMENT;copy(s,&((const CONTEXT *)p)->state,sizeof(*s));return HIP_READY;}
int HeroInventoryPublishInit(void *p,uint32_t bytes,const HIP_PLAN_DATA *plan,uint64_t epoch,uint32_t max_requests,uint32_t max_ms){
 if(!p||((uintptr_t)p&7u)||bytes<sizeof(CONTEXT)||!plan||!epoch||max_requests<8||max_requests>8192||max_ms<1000||max_ms>600000)return HIP_ARGUMENT;
 if(overlaps(p,sizeof(CONTEXT),plan,sizeof(*plan)))return HIP_ARGUMENT;
 if(plan->resource_count>HIP_RESOURCE_MAX)return HIP_PLAN;
 for(unsigned i=0;i<plan->resource_count;i++)if(overlaps(p,sizeof(CONTEXT),plan->resources[i].body,plan->resources[i].body_bytes))return HIP_ARGUMENT;
 CONTEXT *c=p;zero(c,sizeof(*c));c->magic=MAGIC;c->plan=plan;c->epoch=epoch;c->max_requests=max_requests;c->max_ms=max_ms;c->state.version=1;
 if(plan->version!=1||plan->resource_count<1||plan->resource_count>HIP_RESOURCE_MAX||plan->link_count>HIP_LINK_MAX||!plan->source_crc32||!safe_uri(plan->system_uri,0)||!safe_uri(plan->chassis_uri,0)||!child(plan->system_uri,"/redfish/v1/Systems")||!child(plan->chassis_uri,"/redfish/v1/Chassis"))return stop(c,HIP_PLAN);
 for(unsigned i=0;i<plan->resource_count;i++){
  if(!resource_route(plan,i)||!body_valid(c,&plan->resources[i]))return stop(c,HIP_PLAN);
  for(unsigned k=0;k<i;k++)if(cr_same(plan->resources[k].member_uri,plan->resources[i].member_uri))return stop(c,HIP_PLAN);
  if(i&&plan->resources[i].kind!=HIP_DRIVE){unsigned k=0;for(;k<c->collection_count;k++)if(cr_same(plan->resources[c->collections[k]].collection_uri,plan->resources[i].collection_uri))break;if(k==c->collection_count)c->collections[c->collection_count++]=(uint16_t)i;}
 }
 for(unsigned i=0;i<plan->link_count;i++){
  if(!link_valid(plan,&plan->links[i]))return stop(c,HIP_PLAN);
  for(unsigned k=0;k<i;k++)if(plan->links[k].parent_index==plan->links[i].parent_index&&plan->links[k].field==plan->links[i].field&&cr_same(plan->links[k].member_uri,plan->links[i].member_uri))return stop(c,HIP_PLAN);
 }
 c->plan_crc=crc(plan,sizeof(*plan));c->state.resource_count=plan->resource_count;c->state.link_count=plan->link_count;c->state.phase=ROOT;return HIP_READY;
}
static const char *link_key(unsigned field){static const char *const names[]={"","PCIeDevices","PCIeFunctions","Chassis","PCIeFunctions","Drives","Drives","StorageControllers"};return field<8?names[field]:"";}
static int nested_link(unsigned field){return field==HIP_DEVICE_CHASSIS||field==HIP_DEVICE_FUNCTIONS||field==HIP_FUNCTION_DRIVES||field==HIP_FUNCTION_CONTROLLERS;}
static unsigned link_field(const CONTEXT *c,const char *key,int nested){
 for(unsigned i=0;i<c->plan->link_count;i++){const HIP_LINK *l=&c->plan->links[i];if(l->parent_index==c->group_index&&nested_link(l->field)==nested&&cr_same(key,link_key(l->field)))return l->field;}return 0;
}
static int put(CONTEXT *c,const char *s,unsigned n){if(n>=sizeof(c->body)-c->body_bytes)return 0;copy(c->body+c->body_bytes,s,n);c->body_bytes+=n;c->body[c->body_bytes]=0;return 1;}
static int literal(CONTEXT *c,const char *s){return put(c,s,length(s));}
static int quoted(CONTEXT *c,const char *s){return literal(c,"\"")&&literal(c,s)&&literal(c,"\"");}
static int number(CONTEXT *c,unsigned n){char s[10];unsigned z=0;do{s[z++]=(char)('0'+n%10);n/=10;}while(n);while(z)if(!put(c,s+--z,1))return 0;return 1;}
static int raw_token(CONTEXT *c,const CJ *j,unsigned t){if(t>=j->count)return 0;unsigned a=j->tokens[t].begin,b=j->tokens[t].end;if(j->tokens[t].kind=='s'){a--;b++;}return put(c,j->text+a,b-a);}
static int has_link(const CJ *j,unsigned array,const char *uri){if(array>=j->count||j->tokens[array].kind!='[')return 0;for(unsigned t=array+1;t<j->tokens[array].after;t=j->tokens[t].after)if(cj_is(j,cj_find(j,t,"@odata.id"),uri))return 1;return 0;}
static int array_valid(const CJ *j,unsigned array,unsigned *count){
 *count=0;if(array==CJ_MAX)return 1;if(array>=j->count||j->tokens[array].kind!='[')return 0;
 for(unsigned t=array+1;t<j->tokens[array].after;t=j->tokens[t].after){char uri[HIP_URI_MAX];unsigned id=cj_find(j,t,"@odata.id");
  if(!cj_ascii(j,id,uri,sizeof(uri))||!safe_uri(uri,1)||++*count>HIP_LINK_MAX)return 0;
  for(unsigned k=array+1;k<t;k=j->tokens[k].after)if(cj_strings(j,cj_find(j,k,"@odata.id"),j,id,0))return 0;
 }return 1;
}
/* Redfish link arrays originate in Redis sets on this BMC, so readback may
 * reorder them. Preserve every expected URI and per-entry property; reject
 * duplicates. Ordinary scalar arrays retain the strict ordered comparison.
 * This helper is only for the exact link PATCH readback, never source data. */
static int merged_links_subset(const CJ *a,unsigned x,const CJ *b,unsigned y,unsigned depth){
 if(depth>12||x>=a->count||y>=b->count||a->tokens[x].kind!=b->tokens[y].kind)return 0;
 char kind=a->tokens[x].kind;
 if(kind=='{'){
  for(unsigned k=x+1;k<a->tokens[x].after;k=a->tokens[k+1].after){char key[96];if(!cj_ascii(a,k,key,sizeof(key)))return 0;
   if(!merged_links_subset(a,k+1,b,cj_find(b,y,key),depth+1))return 0;
  }return 1;
 }
 if(kind=='['&&x+1<a->tokens[x].after&&a->tokens[x+1].kind=='{'&&cj_find(a,x+1,"@odata.id")<a->count){
  unsigned an=0,bn=0;if(!array_valid(a,x,&an)||!array_valid(b,y,&bn)||bn<an)return 0;
  for(unsigned p=x+1;p<a->tokens[x].after;p=a->tokens[p].after){unsigned id=cj_find(a,p,"@odata.id"),found=0;
   for(unsigned q=y+1;q<b->tokens[y].after;q=b->tokens[q].after){
    if(cj_strings(a,id,b,cj_find(b,q,"@odata.id"),0)){if(!merged_links_subset(a,p,b,q,depth+1))return 0;found=1;break;}
   }if(!found)return 0;
  }return 1;
 }
 return cj_subset(a,x,b,y,depth);
}
static int merged_array(CONTEXT *c,unsigned field,unsigned array,unsigned *changes,unsigned *count){
 unsigned n=0;if(!array_valid(&c->actual,array,&n)||!literal(c,"["))return 0;unsigned written=0;
 if(array<c->actual.count)for(unsigned t=array+1;t<c->actual.tokens[array].after;t=c->actual.tokens[t].after){if(written++&&!literal(c,","))return 0;if(!raw_token(c,&c->actual,t))return 0;}
 for(unsigned i=0;i<c->plan->link_count;i++){const HIP_LINK *l=&c->plan->links[i];if(l->parent_index!=c->group_index||l->field!=field||has_link(&c->actual,array,l->member_uri))continue;
  if(written++&&!literal(c,","))return 0;if(!literal(c,"{\"@odata.id\":")||!quoted(c,l->member_uri)||!literal(c,"}"))return 0;(*changes)++;n++;
 }*count=n;return literal(c,"]");
}
/* Snapshot and merge all current link arrays. URI-equivalent existing entries
 * are copied byte-for-byte, with every unrelated Links member preserved.
 * System PCIe arrays and Storage.Drives are ROOT properties, not Links. */
static int merge_links(CONTEXT *c,unsigned *changes){
 CJ *j=&c->actual;unsigned fields[8]={0},nested=0,written=0;*changes=0;c->body_bytes=0;
 for(unsigned i=0;i<c->plan->link_count;i++)if(c->plan->links[i].parent_index==c->group_index){unsigned f=c->plan->links[i].field;fields[f]=1;if(nested_link(f))nested=1;}
 if(!literal(c,"{"))return 0;
 for(unsigned f=1;f<8;f++)if(fields[f]&&!nested_link(f)){unsigned count=0;if(written++&&!literal(c,","))return 0;if(!quoted(c,link_key(f))||!literal(c,":")||!merged_array(c,f,cj_find(j,0,link_key(f)),changes,&count))return 0;}
 if(nested){
  if(written++&&!literal(c,","))return 0;if(!literal(c,"\"Links\":{"))return 0;
  unsigned links=cj_find(j,0,"Links"),members=0,seen[8]={0},counts[8]={0};
  if(links<j->count&&j->tokens[links].kind!='{')return 0;
  if(links<j->count)for(unsigned t=links+1;t<j->tokens[links].after;t=j->tokens[t+1].after){char key[96];if(!cj_ascii(j,t,key,sizeof(key)))return 0;unsigned f=link_field(c,key,1);
   /* Counts are regenerated after their target arrays, never copied stale. */
   unsigned annotation=0;for(unsigned k=1;k<8;k++)if(fields[k]&&nested_link(k)&&joined(key,link_key(k),"@odata.count"))annotation=k;
   if(annotation)continue;if(members++&&!literal(c,","))return 0;if(!raw_token(c,j,t)||!literal(c,":"))return 0;
   if(f){if(!merged_array(c,f,t+1,changes,&counts[f]))return 0;seen[f]=1;}else if(!raw_token(c,j,t+1))return 0;
  }
  for(unsigned f=1;f<8;f++)if(fields[f]&&nested_link(f)&&!seen[f]){if(members++&&!literal(c,","))return 0;if(!quoted(c,link_key(f))||!literal(c,":")||!merged_array(c,f,CJ_MAX,changes,&counts[f]))return 0;}
  if(links<j->count)for(unsigned f=1;f<8;f++)if(fields[f]&&nested_link(f)){
   char key[96];unsigned n=length(link_key(f));copy(key,link_key(f),n);copy(key+n,"@odata.count",13);
   if(cj_find(j,links,key)<j->count){if(members++&&!literal(c,","))return 0;if(!quoted(c,key)||!literal(c,":")||!number(c,counts[f]))return 0;}
  }
  if(!literal(c,"}"))return 0;
 }return written&&literal(c,"}");
}
static int links_present(CONTEXT *c){
 for(unsigned i=0;i<c->plan->link_count;i++){const HIP_LINK *l=&c->plan->links[i];if(l->parent_index!=c->group_index)continue;unsigned obj=nested_link(l->field)?cj_find(&c->actual,0,"Links"):0;
  if(!has_link(&c->actual,cj_find(&c->actual,obj,link_key(l->field)),l->member_uri))return 0;
 }return 1;
}
static void next_group(CONTEXT *c){
 while(c->group_index<c->plan->resource_count){unsigned found=0;for(unsigned i=0;i<c->plan->link_count;i++)if(c->plan->links[i].parent_index==c->group_index)found=1;
  if(found&&!c->link_done[c->group_index])break;c->group_index++;
 }
 c->state.current_link_group=c->group_index;c->state.phase=c->group_index<c->plan->resource_count?LINKS_READ:COLLECTION_READ;
}
static void mark_verified(CONTEXT *c,unsigned i){if(!c->verified[i]){c->verified[i]=1;c->state.verified++;}}
static void begin_links(CONTEXT *c){c->group_index=0;next_group(c);}
static void next_object(CONTEXT *c){c->state.current_resource++;c->state.phase=c->state.current_resource<c->plan->resource_count?OBJECT_READ:SUMMARY_READ;}
static int summary_body(CONTEXT *c){
 unsigned cpus=0,first=HIP_NONE,model=CJ_MAX;
 for(unsigned i=1;i<c->plan->resource_count;i++)if(c->plan->resources[i].kind==HIP_CPU){if(!c->verified[i])return 0;cpus++;if(first==HIP_NONE)first=i;}
 if(!cpus||first==HIP_NONE||!cj_parse(&c->expected,c->plan->resources[first].body,c->plan->resources[first].body_bytes))return 0;
 /* HERO has one populated CPU. Multiple sockets may publish Count, but a
  * single advertised model must not be invented from heterogeneous CPUs. */
 if(cpus==1)model=cj_find(&c->expected,0,"Model");
 if(model<c->expected.count&&c->expected.tokens[model].kind!='s')return 0;
 c->body_bytes=0;if(!literal(c,"{\"ProcessorSummary\":{\"Count\":")||!number(c,cpus))return 0;
 if(model<c->expected.count&&(!literal(c,",\"Model\":")||!raw_token(c,&c->expected,model)))return 0;
 unsigned summary=cj_find(&c->actual,0,"ProcessorSummary");
 if(summary<c->actual.count&&c->actual.tokens[summary].kind!='{')return 0;
 if(summary<c->actual.count){
  for(unsigned t=summary+1;t<c->actual.tokens[summary].after;t=c->actual.tokens[t+1].after){
   if(cj_is(&c->actual,t,"Count")||(model<c->expected.count&&cj_is(&c->actual,t,"Model")))continue;
   if(!literal(c,",")||!raw_token(c,&c->actual,t)||!literal(c,":")||!raw_token(c,&c->actual,t+1))return 0;
  }
 }
 return literal(c,"}}");
}
static int issue(CONTEXT *c,unsigned method,unsigned index,const char *uri,const char *body,unsigned bytes,HIP_REQUEST *out){
 unsigned n=length(uri);if(n>=sizeof(c->uri))return stop(c,HIP_PLAN);copy(c->uri,uri,n+1);
 c->current=(HIP_REQUEST){++c->sequence,method,index,bytes,c->uri,body,method==HIP_PATCH||method==HIP_DELETE_EXACT_CACHE?c->etag:0,method==HIP_PATCH||method==HIP_DELETE_EXACT_CACHE?length(c->etag):0};
 c->request_body_crc=crc(body,bytes);c->request_tag_crc=crc(c->current.if_match,c->current.if_match_bytes);c->request_uri_crc=crc(c->uri,n+1);
 c->state.inflight=1;c->state.requests++;if(method)c->state.writes++;copy(out,&c->current,sizeof(*out));return HIP_READY;
}
int HeroInventoryPublishNext(void *p,uint64_t epoch,int source_ok,uint32_t elapsed_ms,HIP_REQUEST *out){
 if(!context(p)||!out)return HIP_ARGUMENT;CONTEXT *c=p;zero(out,sizeof(*out));
 if(c->state.phase==HELD)return (int)c->state.result;if(c->state.phase==DONE)return HIP_COMPLETE;
 if(c->state.inflight)return HIP_WAIT;
 if(epoch!=c->epoch||source_ok!=1||c->plan_crc!=crc(c->plan,sizeof(*c->plan)))return stop(c,HIP_SOURCE);
 for(unsigned i=0;i<c->plan->resource_count;i++){const HIP_RESOURCE *r=&c->plan->resources[i];if(r->body_crc32!=crc(r->body,r->body_bytes))return stop(c,HIP_SOURCE);}
 if(elapsed_ms<c->last_ms||elapsed_ms>=c->max_ms||c->state.requests>=c->max_requests)return stop(c,HIP_BUDGET);c->last_ms=elapsed_ms;
 const HIP_RESOURCE *r=&c->plan->resources[c->state.current_resource<c->plan->resource_count?c->state.current_resource:0];
 switch(c->state.phase){
 case ROOT:return issue(c,HIP_GET,0,"/redfish/v1/",0,0,out);
 case SYSTEMS:return issue(c,HIP_GET,0,"/redfish/v1/Systems",0,0,out);
 case SYSTEM_READ:case SYSTEM_VERIFY:return issue(c,HIP_GET,0,c->plan->system_uri,0,0,out);
 case SYSTEM_WRITE:return issue(c,HIP_PATCH,0,c->plan->system_uri,c->plan->resources[0].body,c->plan->resources[0].body_bytes,out);
 case SUMMARY_READ:case SUMMARY_VERIFY:return issue(c,HIP_GET,0,c->plan->system_uri,0,0,out);
 case SUMMARY_WRITE:return issue(c,HIP_PATCH,0,c->plan->system_uri,c->body,c->body_bytes,out);
 case CHASSIS_READ:return issue(c,HIP_GET,HIP_NONE,c->plan->chassis_uri,0,0,out);
 case OBJECT_READ:case OBJECT_RECHECK:case OBJECT_VERIFY:case FINAL_OBJECT:return issue(c,HIP_GET,c->state.current_resource,r->member_uri,0,0,out);
 case PARENT_READ:{const char *uri=r->kind==HIP_PCIE_FUNCTION||r->kind==HIP_DRIVE?c->plan->resources[r->parent_index].member_uri:r->collection_uri;return issue(c,HIP_GET,c->state.current_resource,uri,0,0,out);}
 case OBJECT_WRITE:return issue(c,HIP_POST,c->state.current_resource,r->post_to_collection?r->collection_uri:r->member_uri,r->body,r->body_bytes,out);
 case LINKS_READ:case LINKS_VERIFY:return issue(c,HIP_GET,c->group_index,c->plan->resources[c->group_index].member_uri,0,0,out);
 case LINKS_WRITE:return issue(c,HIP_PATCH,c->group_index,c->plan->resources[c->group_index].member_uri,c->body,c->body_bytes,out);
 case COLLECTION_READ:case COLLECTION_VERIFY:
  if(c->collection_index>=c->collection_count){c->state.phase=FINAL_OBJECT;c->state.current_resource=0;return issue(c,HIP_GET,0,c->plan->system_uri,0,0,out);}
  return issue(c,HIP_GET,c->collections[c->collection_index],c->plan->resources[c->collections[c->collection_index]].collection_uri,0,0,out);
 case CACHE_CAP:return issue(c,HIP_GET,HIP_NONE,"/redfish/v1/GlobalLuaTables",0,0,out);
 case CACHE_WRITE:return issue(c,HIP_DELETE_EXACT_CACHE,HIP_NONE,"/redfish/v1/GlobalLuaTables",c->body,c->body_bytes,out);
 default:return stop(c,HIP_PLAN);
 }
}
int HeroInventoryPublishAuthorize(void *p,const HIP_REQUEST *r,uint64_t epoch,int source_ok,uint32_t elapsed_ms){
 if(!context(p)||!r)return HIP_ARGUMENT;CONTEXT *c=p;HIP_REQUEST *q=&c->current;
 if(c->state.phase==HELD)return (int)c->state.result;
 if(!c->state.inflight||r->sequence!=q->sequence||r->method!=q->method||r->resource_index!=q->resource_index||r->body_bytes!=q->body_bytes||r->uri!=q->uri||r->body!=q->body||r->if_match!=q->if_match||r->if_match_bytes!=q->if_match_bytes)return stop(c,HIP_REPLAY);
 if(epoch!=c->epoch||source_ok!=1||c->plan_crc!=crc(c->plan,sizeof(*c->plan)))return stop(c,HIP_SOURCE);
 for(unsigned i=0;i<c->plan->resource_count;i++){const HIP_RESOURCE *item=&c->plan->resources[i];if(item->body_crc32!=crc(item->body,item->body_bytes))return stop(c,HIP_SOURCE);}
 if((!cr_same(q->uri,"/redfish/v1/")&&!safe_uri(q->uri,0))||crc(q->uri,length(q->uri)+1)!=c->request_uri_crc||crc(q->body,q->body_bytes)!=c->request_body_crc||crc(q->if_match,q->if_match_bytes)!=c->request_tag_crc)return stop(c,HIP_SOURCE);
 if(elapsed_ms<c->last_ms||elapsed_ms>=c->max_ms)return stop(c,HIP_BUDGET);c->last_ms=elapsed_ms;return HIP_READY;
}
static int nullable(const CJ *j,unsigned t){return t==CJ_MAX||(t<j->count&&(j->tokens[t].kind=='n'||cj_is(j,t,"")||cj_is(j,t," ")||cj_is(j,t,"NA")||cj_is(j,t,"N/A")));}
static int identity_safe(CONTEXT *c){
 if(!cj_parse(&c->expected,c->plan->resources[0].body,c->plan->resources[0].body_bytes))return 0;
 for(unsigned t=1;t<c->expected.tokens[0].after;t=c->expected.tokens[t+1].after){char key[96];if(!cj_ascii(&c->expected,t,key,sizeof(key)))return 0;unsigned v=cj_find(&c->actual,0,key);
  if(nullable(&c->actual,v))continue;if(cr_same(key,"UUID")){if(!cj_strings(&c->expected,t+1,&c->actual,v,1))return 0;}else if(!cj_subset(&c->expected,t+1,&c->actual,v,0))return 0;
 }return 1;
}
static int discovered(const CJ *j,unsigned obj,const char *key,const char *uri){return cj_is(j,cj_find(j,cj_find(j,obj,key),"@odata.id"),uri);}
static int system_routes(CONTEXT *c){
 char uri[HIP_URI_MAX];unsigned n=length(c->plan->system_uri);if(n+12>=sizeof(uri))return 0;copy(uri,c->plan->system_uri,n);copy(uri+n,"/Processors",12);
 if(!discovered(&c->actual,0,"Processors",uri))return 0;copy(uri+n,"/Memory",8);if(!discovered(&c->actual,0,"Memory",uri))return 0;
 copy(uri+n,"/Storage",9);if(!discovered(&c->actual,0,"Storage",uri))return 0;
 unsigned a=cj_find(&c->actual,cj_find(&c->actual,0,"Links"),"Chassis"),count=0;return array_valid(&c->actual,a,&count)&&has_link(&c->actual,a,c->plan->chassis_uri);
}
static int collection(CONTEXT *c,const char *uri,unsigned *missing){
 CJ *j=&c->actual;unsigned a=cj_find(j,0,"Members"),count=0,declared=0;*missing=0;
 if(a>=j->count||!array_valid(j,a,&count)||!uint_value(j,cj_find(j,0,"Members@odata.count"),&declared)||count!=declared||cj_find(j,0,"Members@odata.nextLink")<j->count||cj_find(j,0,"@odata.nextLink")<j->count)return 0;
 unsigned wanted=0,found=0;
 for(unsigned i=1;i<c->plan->resource_count;i++)if(c->plan->resources[i].kind!=HIP_DRIVE&&cr_same(c->plan->resources[i].collection_uri,uri)){
  wanted++;if(has_link(j,a,c->plan->resources[i].member_uri)){found++;if(!c->indexed[i]){c->indexed[i]=1;c->state.indexed++;}}else(*missing)++;
 }
 if(found>wanted||found>count)return 0;c->state.extra_collection_members+=count-found;return 1;
}
static int ack(CONTEXT *c,const HIP_RESPONSE *r,const char *location){
 if(r->http_status!=200&&r->http_status!=201&&r->http_status!=204)return 0;
 if(r->location||r->location_bytes){if(!location||!r->location||r->location_bytes!=length(location)||!cr_eq(r->location,location,r->location_bytes))return 0;}
 if(r->http_status==204&&r->body_bytes)return 0;
 if(r->body_bytes){if(!cj_parse(&c->actual,r->body,r->body_bytes)||c->actual.tokens[0].kind!='{'||cj_find(&c->actual,0,"error")<c->actual.count)return 0;unsigned id=cj_find(&c->actual,0,"@odata.id");if(location&&id<c->actual.count&&!cj_is(&c->actual,id,location))return 0;}
 return 1;
}
static int cache_body(CONTEXT *c,const char *uri){
 c->body_bytes=0;if(!safe_uri(uri,0)||!literal(c,"{\"Prefixes\":[\"Redfish:"))return 0;
 for(unsigned i=12;uri[i];i++){char x=uri[i]=='/'?':':uri[i];if(!put(c,&x,1))return 0;}
 return literal(c,":SRK\"]}");
}
int HeroInventoryPublishAccept(void *p,const HIP_RESPONSE *r){
 if(!context(p)||!r)return HIP_ARGUMENT;CONTEXT *c=p;
 if(c->state.phase==HELD)return (int)c->state.result;if(c->state.phase==DONE)return HIP_COMPLETE;
 if(!c->state.inflight||r->sequence!=c->sequence){if(c->state.inflight&&c->current.method)c->state.unknown_write=1;return stop(c,HIP_REPLAY);}
 c->state.inflight=0;c->state.last_http=r->transport_result?0:r->http_status;
 if(r->transport_result){if(c->current.method){c->state.unknown_write=1;return stop(c,HIP_UNCONFIRMED);}return stop(c,HIP_TRANSPORT);}
 if(r->body_bytes>HIP_BODY_MAX||(!r->body&&r->body_bytes)){if(c->current.method)c->state.unknown_write=1;return stop(c,HIP_JSON);}
 unsigned i=c->state.current_resource;const HIP_RESOURCE *resource=&c->plan->resources[i<c->plan->resource_count?i:0];
 switch(c->state.phase){
 case ROOT:{
  if(!parse(c,r,"/redfish/v1/"))return stop(c,HIP_JSON);CJ *j=&c->actual;unsigned oem=cj_find(j,0,"Oem"),ami=cj_find(j,oem,"Ami");
  if(!cj_is(j,cj_find(j,0,"RedfishVersion"),"1.8.0")||!cj_is(j,cj_find(j,ami,"RtpVersion"),"1.8.a")||!discovered(j,0,"Systems","/redfish/v1/Systems")||!discovered(j,0,"Chassis","/redfish/v1/Chassis"))return stop(c,HIP_IDENTITY);
  c->state.phase=SYSTEMS;break;}
 case SYSTEMS:{
  if(!parse(c,r,"/redfish/v1/Systems"))return stop(c,HIP_JSON);unsigned a=cj_find(&c->actual,0,"Members"),n=0,count=0;
  if(!array_valid(&c->actual,a,&n)||n!=1||!cj_uint(&c->actual,cj_find(&c->actual,0,"Members@odata.count"),&count)||count!=1||!has_link(&c->actual,a,c->plan->system_uri)||cj_find(&c->actual,0,"Members@odata.nextLink")<c->actual.count)return stop(c,HIP_IDENTITY);
  c->state.phase=SYSTEM_READ;break;}
 case SYSTEM_READ:case SYSTEM_VERIFY:
  if(!parse(c,r,c->plan->system_uri)||!system_routes(c))return stop(c,HIP_IDENTITY);
  if(expected(c,0)){mark_verified(c,0);c->state.phase=CHASSIS_READ;break;}
  if(c->state.phase==SYSTEM_VERIFY||!identity_safe(c))return stop(c,HIP_CONFLICT);
  if(!read_tag(c,r))return stop(c,HIP_ETAG);c->state.phase=SYSTEM_WRITE;break;
 case SYSTEM_WRITE:
  if(!ack(c,r,c->plan->system_uri)){c->state.unknown_write=1;return stop(c,HIP_UNCONFIRMED);}c->state.phase=SYSTEM_VERIFY;break;
 case CHASSIS_READ:{
  if(!parse(c,r,c->plan->chassis_uri))return stop(c,HIP_IDENTITY);CJ *j=&c->actual;unsigned links=cj_find(j,0,"Links"),a=cj_find(j,links,"ComputerSystems"),count=0;
  if(!array_valid(j,a,&count)||!has_link(j,a,c->plan->system_uri))return stop(c,HIP_IDENTITY);
  char uri[HIP_URI_MAX];unsigned n=length(c->plan->chassis_uri);if(n+13>=sizeof(uri))return stop(c,HIP_PLAN);copy(uri,c->plan->chassis_uri,n);copy(uri+n,"/PCIeDevices",13);
  if(!discovered(j,0,"PCIeDevices",uri))return stop(c,HIP_IDENTITY);c->state.current_resource=0;next_object(c);break;}
 case OBJECT_READ:case OBJECT_RECHECK:case OBJECT_VERIFY:
  if(r->http_status==404){if(c->state.phase==OBJECT_VERIFY)return stop(c,HIP_UNCONFIRMED);c->state.phase=c->state.phase==OBJECT_READ?PARENT_READ:OBJECT_WRITE;break;}
  if(!parse(c,r,resource->member_uri)||!expected(c,i))return stop(c,HIP_CONFLICT);mark_verified(c,i);next_object(c);break;
 case PARENT_READ:
  if(resource->kind==HIP_PCIE_FUNCTION||resource->kind==HIP_DRIVE){unsigned parent=resource->parent_index;if(!c->verified[parent]||!parse(c,r,c->plan->resources[parent].member_uri)||!expected(c,parent))return stop(c,HIP_CONFLICT);}
  else{unsigned missing=0;if(!parse(c,r,resource->collection_uri)||!collection(c,resource->collection_uri,&missing))return stop(c,HIP_JSON);if(has_link(&c->actual,cj_find(&c->actual,0,"Members"),resource->member_uri))return stop(c,HIP_CONFLICT);}
  c->state.phase=OBJECT_RECHECK;break;
 case OBJECT_WRITE:
  if(!ack(c,r,resource->member_uri)){c->state.unknown_write=1;return stop(c,HIP_UNCONFIRMED);}c->state.phase=OBJECT_VERIFY;break;
 case SUMMARY_READ:
  if(!parse(c,r,c->plan->system_uri)||!expected(c,0))return stop(c,HIP_CONFLICT);
  if(!summary_body(c)||!cj_parse(&c->expected,c->body,c->body_bytes))return stop(c,HIP_JSON);
  if(cj_subset(&c->expected,0,&c->actual,0,0)){begin_links(c);break;}
  if(!read_tag(c,r))return stop(c,HIP_ETAG);c->state.phase=SUMMARY_WRITE;break;
 case SUMMARY_WRITE:
  if(!ack(c,r,c->plan->system_uri)){c->state.unknown_write=1;return stop(c,HIP_UNCONFIRMED);}c->state.phase=SUMMARY_VERIFY;break;
 case SUMMARY_VERIFY:
  if(!parse(c,r,c->plan->system_uri)||!expected(c,0)||!cj_parse(&c->expected,c->body,c->body_bytes)||!cj_subset(&c->expected,0,&c->actual,0,0))return stop(c,HIP_CONFLICT);begin_links(c);break;
 case LINKS_READ:{
  unsigned g=c->group_index;if(!parse(c,r,c->plan->resources[g].member_uri)||!expected(c,g))return stop(c,HIP_CONFLICT);unsigned changes=0;
  if(!merge_links(c,&changes))return stop(c,HIP_OVERFLOW);
  if(!changes){if(!links_present(c))return stop(c,HIP_CONFLICT);c->link_done[g]=1;c->group_index++;next_group(c);break;}
  if(!read_tag(c,r))return stop(c,HIP_ETAG);c->state.phase=LINKS_WRITE;break;}
 case LINKS_WRITE:
  if(!ack(c,r,c->plan->resources[c->group_index].member_uri)){c->state.unknown_write=1;return stop(c,HIP_UNCONFIRMED);}c->state.phase=LINKS_VERIFY;break;
 case LINKS_VERIFY:
  if(!parse(c,r,c->plan->resources[c->group_index].member_uri)||!expected(c,c->group_index)||!cj_parse(&c->expected,c->body,c->body_bytes)||!merged_links_subset(&c->expected,0,&c->actual,0,0)||!links_present(c))return stop(c,HIP_CONFLICT);
  c->link_done[c->group_index]=1;c->group_index++;next_group(c);break;
 case COLLECTION_READ:case COLLECTION_VERIFY:{
  const char *uri=c->plan->resources[c->collections[c->collection_index]].collection_uri;unsigned missing=0;
  if(!parse(c,r,uri)||!collection(c,uri,&missing))return stop(c,HIP_JSON);
  if(missing){if(c->state.phase==COLLECTION_VERIFY)return stop(c,HIP_INDEX_PENDING);c->state.phase=CACHE_CAP;break;}
  c->collection_index++;c->state.phase=COLLECTION_READ;break;}
 case CACHE_CAP:{
  if(!parse(c,r,"/redfish/v1/GlobalLuaTables"))return stop(c,HIP_JSON);unsigned a=cj_find(&c->actual,0,"Members"),n=0,declared=0;const char *uri=c->plan->resources[c->collections[c->collection_index]].collection_uri;
  if(!array_valid(&c->actual,a,&n)||!uint_value(&c->actual,cj_find(&c->actual,0,"Members@odata.count"),&declared)||n!=declared||!has_link(&c->actual,a,uri)||cj_find(&c->actual,0,"Members@odata.nextLink")<c->actual.count)return stop(c,HIP_INDEX_PENDING);
  if(!read_tag(c,r))return stop(c,HIP_ETAG);if(!cache_body(c,uri))return stop(c,HIP_OVERFLOW);c->state.phase=CACHE_WRITE;break;}
 case CACHE_WRITE:
  if(r->http_status!=204||r->body_bytes){c->state.unknown_write=1;return stop(c,HIP_UNCONFIRMED);}c->state.phase=COLLECTION_VERIFY;break;
 case FINAL_OBJECT:
  if(!parse(c,r,resource->member_uri)||!expected(c,i))return stop(c,HIP_CONFLICT);c->group_index=i;if(!links_present(c))return stop(c,HIP_CONFLICT);
  if(i==0&&(!summary_body(c)||!cj_parse(&c->expected,c->body,c->body_bytes)||!cj_subset(&c->expected,0,&c->actual,0,0)))return stop(c,HIP_CONFLICT);
  if(++c->state.current_resource==c->plan->resource_count){c->state.phase=DONE;c->state.result=HIP_COMPLETE;return HIP_COMPLETE;}break;
 default:return stop(c,HIP_PLAN);
 }c->state.result=HIP_READY;return HIP_READY;
}
