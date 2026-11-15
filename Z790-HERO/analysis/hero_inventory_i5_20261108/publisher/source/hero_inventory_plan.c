#include "hero_inventory_plan.h"
static void clear(void *p,uint32_t n){uint8_t *q=p;while(n--)*q++=0;}
static void cp(void *d,const void *s,uint32_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
static uint32_t len(const char *s){uint32_t n=0;while(s[n])n++;return n;}
static int eq(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static uint32_t crc(const void *p,uint32_t n){const uint8_t *s=p;uint32_t c=~0u;while(n--){c^=*s++;for(unsigned b=0;b<8;b++)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}return ~c;}
static int bounded(const char *s,uint32_t cap){if(!s)return 0;for(unsigned i=0;i<cap;i++)if(!s[i])return i>0;return 0;}
static int join(char *out,const char *a,const char *b){unsigned n=len(a),m=len(b);if(n+m>=HIP_URI_MAX)return 0;cp(out,a,n);cp(out+n,b,m+1);return 1;}
static int numstr(char *out,uint32_t n){char s[10];unsigned z=0,k=0;do{s[z++]=(char)('0'+n%10);n/=10;}while(n);while(z)out[k++]=s[--z];out[k]=0;return 1;}
static int body(const char *pool,uint32_t pool_bytes,uint32_t offset,uint32_t bytes,const char **value){if(!bytes||offset>=pool_bytes||bytes>=pool_bytes-offset||pool[offset+bytes])return 0;*value=pool+offset;return 1;}
static uint32_t find(const HIP_PLAN_DATA *p,const char *uri){for(unsigned i=0;i<p->resource_count;i++)if(eq(p->resources[i].member_uri,uri))return i;return HIP_NONE;}
static int add(HIP_PLAN_DATA *p,unsigned kind,unsigned parent,unsigned post,const char *member,const char *collection,const char *json,unsigned bytes){
 if(p->resource_count==HIP_RESOURCE_MAX||!bounded(member,HIP_URI_MAX)||!bounded(collection,HIP_URI_MAX))return 0;HIP_RESOURCE *r=&p->resources[p->resource_count++];r->kind=kind;r->parent_index=parent;r->post_to_collection=post;cp(r->member_uri,member,len(member)+1);cp(r->collection_uri,collection,len(collection)+1);r->body=json;r->body_bytes=bytes;r->body_crc32=crc(json,bytes);return 1;
}
static int link(HIP_PLAN_DATA *p,unsigned field,const char *parent,const char *member){
 unsigned i=find(p,parent);if(i==HIP_NONE||p->link_count==HIP_LINK_MAX||!bounded(member,HIP_URI_MAX))return 0;HIP_LINK *l=&p->links[p->link_count++];l->field=field;l->parent_index=i;cp(l->member_uri,member,len(member)+1);return 1;
}
static int fail(HIP_PLAN_DATA *p){p->version=0;p->resource_count=0;p->link_count=0;return HIP_PLAN;}
static int overlap(const void *a,uint32_t an,const void *b,uint32_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 1;return x<y+bn&&y<x+an;}
int HeroInventoryPlanBuild(const HIC_CATALOG *sm,const HPC_CATALOG *pci,const HSC_CATALOG *sata,const char *system,const char *chassis,HIP_PLAN_DATA *p){
 if(!sm||!p||!bounded(system,HIP_URI_MAX)||!bounded(chassis,HIP_URI_MAX)||(sata&&!pci)||overlap(p,sizeof(*p),sm,sizeof(*sm))||(pci&&overlap(p,sizeof(*p),pci,sizeof(*pci)))||(sata&&overlap(p,sizeof(*p),sata,sizeof(*sata)))||overlap(p,sizeof(*p),system,len(system)+1)||overlap(p,sizeof(*p),chassis,len(chassis)+1))return HIP_ARGUMENT;
 clear(p,sizeof(*p));p->version=1;p->source_crc32=sm->table_crc32;cp(p->system_uri,system,len(system)+1);cp(p->chassis_uri,chassis,len(chassis)+1);
 if(sm->version!=1||sm->valid!=1||sm->result||!sm->cpu_count||!sm->dimm_count||sm->cpu_count>HIC_MAX_CPUS||sm->dimm_count>HIC_MAX_DIMMS||sm->item_count!=1+sm->cpu_count+sm->dimm_count||sm->json_bytes>HIC_JSON_BYTES)return fail(p);
 unsigned offset=0;for(unsigned i=0;i<sm->item_count;i++){
  const HIC_ITEM *r=&sm->items[i];const char *json=0;unsigned kind=!i?1:i<=sm->cpu_count?2:3,index=!i?0:i<=sm->cpu_count?i-1:i-sm->cpu_count-1;char member[HIP_URI_MAX],collection[HIP_URI_MAX],suffix[40],decimal[11];
  if(r->kind!=kind||r->index!=index||r->json_offset!=offset||!body(sm->json,sm->json_bytes,r->json_offset,r->json_bytes,&json))return fail(p);offset+=r->json_bytes+1;
  if(!i){if(!add(p,HIP_SYSTEM,HIP_NONE,0,system,"/redfish/v1/Systems",json,r->json_bytes))return fail(p);continue;}
  if(!join(collection,system,kind==2?"/Processors":"/Memory"))return fail(p);numstr(decimal,index);const char *prefix=kind==2?"/DevType1_CPU":"/DevType2_DIMM";cp(suffix,prefix,len(prefix));cp(suffix+len(prefix),decimal,len(decimal)+1);
  if(!join(member,collection,suffix)||!add(p,kind,0,1,member,collection,json,r->json_bytes))return fail(p);
 }
 if(offset!=sm->json_bytes)return fail(p);
 if(pci){
  if(pci->version!=1||pci->valid!=1||pci->result||pci->item_count>HPC_ITEM_MAX||pci->link_count>HPC_LINK_MAX||pci->json_bytes>HPC_JSON_MAX||pci->item_count!=pci->device_count+pci->function_count+pci->storage_count)return fail(p);offset=0;p->hardware_crc32=pci->source_crc32;
  for(unsigned i=0;i<pci->item_count;i++){
   const HPC_ITEM *r=&pci->items[i];const char *json=0;unsigned kind=r->kind==HPC_DEVICE?HIP_PCIE_DEVICE:r->kind==HPC_FUNCTION?HIP_PCIE_FUNCTION:r->kind==HPC_STORAGE?HIP_STORAGE:0,parent=kind==HIP_PCIE_DEVICE?HIP_NONE:0;
   if(!kind||!bounded(r->member_uri,HPC_URI_MAX)||!bounded(r->collection_uri,HPC_URI_MAX)||r->json_offset!=offset||!body(pci->json,pci->json_bytes,r->json_offset,r->json_bytes,&json)||r->method!=(kind==HIP_STORAGE?HPC_POST_COLLECTION:HPC_POST_INSTANCE))return fail(p);offset+=r->json_bytes+1;
   if(kind==HIP_PCIE_FUNCTION){char owner[HIP_URI_MAX];unsigned n=len(r->collection_uri),suffix=len("/PCIeFunctions");if(n<=suffix)return fail(p);cp(owner,r->collection_uri,n-suffix);owner[n-suffix]=0;parent=find(p,owner);if(parent==HIP_NONE)return fail(p);}
   if(!add(p,kind,parent,kind==HIP_STORAGE,r->member_uri,r->collection_uri,json,r->json_bytes))return fail(p);
  }
  if(offset!=pci->json_bytes)return fail(p);
  for(unsigned i=0;i<pci->link_count;i++){const HPC_LINK_ADDITION *l=&pci->links[i];unsigned field=l->kind==HPC_SYSTEM_DEVICE?HIP_SYSTEM_DEVICES:l->kind==HPC_SYSTEM_FUNCTION?HIP_SYSTEM_FUNCTIONS:l->kind==HPC_DEVICE_FUNCTION?HIP_DEVICE_FUNCTIONS:l->kind==HPC_DEVICE_CHASSIS?HIP_DEVICE_CHASSIS:0;
   if(!field||l->flags!=HPC_LINK_MERGE_REQUIRED||!bounded(l->parent_uri,HPC_URI_MAX)||!link(p,field,l->parent_uri,l->member_uri))return fail(p);
  }
 }
 if(sata){
  if(sata->version!=1||sata->valid!=1||sata->result||sata->item_count>HSC_DRIVE_MAX||sata->link_count>HSC_DRIVE_MAX*3||sata->json_bytes>HSC_JSON_MAX)return fail(p);offset=0;p->hardware_crc32^=crc(sata->source_crc32,sizeof(sata->source_crc32));
  for(unsigned i=0;i<sata->item_count;i++){
   const HSC_ITEM *r=&sata->items[i];const char *json=0;char owner[HIP_URI_MAX];
   if(r->method!=HPC_POST_INSTANCE||!bounded(r->member_uri,HPC_URI_MAX)||!bounded(r->collection_uri,HPC_URI_MAX)||r->json_offset!=offset||!body(sata->json,sata->json_bytes,r->json_offset,r->json_bytes,&json))return fail(p);offset+=r->json_bytes+1;
   unsigned n=len(r->collection_uri),suffix=len("/Drives");if(n<=suffix)return fail(p);cp(owner,r->collection_uri,n-suffix);owner[n-suffix]=0;unsigned parent=find(p,owner);
   if(parent==HIP_NONE||!add(p,HIP_DRIVE,parent,0,r->member_uri,r->collection_uri,json,r->json_bytes))return fail(p);
  }
  if(offset!=sata->json_bytes)return fail(p);
  for(unsigned i=0;i<sata->link_count;i++){const HSC_LINK *l=&sata->links[i];unsigned field=l->kind==HSC_STORAGE_DRIVE?HIP_STORAGE_DRIVES:l->kind==HSC_FUNCTION_DRIVE?HIP_FUNCTION_DRIVES:l->kind==HSC_FUNCTION_CONTROLLER?HIP_FUNCTION_CONTROLLERS:0;
   if(!field||l->flags!=HPC_LINK_MERGE_REQUIRED||!bounded(l->parent_uri,HPC_URI_MAX)||!link(p,field,l->parent_uri,l->member_uri))return fail(p);
  }
 }
 return HIP_READY;
}
