#include "hero_pcie_catalog.h"
static void clear(void *p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
static int overlap(const void *a,size_t an,const void *b,size_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y||(x<y+bn&&y<x+an);}
uint32_t HeroPcieCrc32(const void *p,size_t n){const uint8_t *b=p;uint32_t c=~0U;while(n--){c^=*b++;for(unsigned k=0;k<8;k++)c=(c>>1)^(0xedb88320U&(0U-(c&1)));}return ~c;}
uint32_t HeroPcieCatalogSize(void){return sizeof(HPC_CATALOG);}uint32_t HeroPcieScratchSize(void){return sizeof(HPC_SCRATCH);}uint32_t HeroPcieRecordSize(void){return sizeof(HPC_PCI_RECORD);}
typedef struct {char *p;uint32_t n,cap;int bad;} STR;
static void bytes(STR *s,const char *p,size_t n){if(n>=s->cap-s->n){s->bad=1;return;}copy(s->p+s->n,p,n);s->n+=(uint32_t)n;s->p[s->n]=0;}
static void text(STR *s,const char *p){size_t n=0;while(p[n])n++;bytes(s,p,n);}
static void hex(STR *s,uint32_t v,unsigned n){char b[8];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-1-i)*4))&15];bytes(s,b,n);}
static void decimal(STR *s,uint32_t v){char b[10];unsigned n=0;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);while(n)bytes(s,&b[--n],1);}
static int route(const char *p,uint32_t n,const char *prefix){
 if(!p||n<1||n>96)return 0;uint32_t k=0;while(prefix[k])k++;
 if(n<=k||!equal(p,prefix,k)||n-k>64)return 0;
 if((n-k==1&&p[k]=='.')||(n-k==2&&p[k]=='.'&&p[k+1]=='.'))return 0;
 for(uint32_t i=k;i<n;i++){char c=p[i];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'||c=='~'))return 0;}return 1;
}
static uint32_t bdf(const HPC_PCI_RECORD *r){return ((uint32_t)r->segment<<16)|((uint32_t)r->bus<<8)|((uint32_t)r->device<<3)|r->function;}
static int path_valid(const HPC_PCI_RECORD *r){
 uint32_t at=0;unsigned nodes=0,last_dev=255,last_fun=255;
 while(at<r->path_bytes&&nodes++<128){
  if(r->path_bytes-at<4)return 0;const uint8_t *p=r->path+at;uint32_t n=u16(p+2);
  if(n<4||n>r->path_bytes-at)return 0;
  if(p[0]==0x7f)return p[1]==0xff&&n==4&&at+4==r->path_bytes&&last_dev==r->device&&last_fun==r->function;
  if(p[0]==1&&p[1]==1){if(n!=6||p[4]>7||p[5]>31)return 0;last_fun=p[4];last_dev=p[5];}
  /* A PCI protocol handle's path must not be a disk, USB or media child. */
  if(p[0]==3||p[0]==4)return 0;
  at+=n;
 }return 0;
}
static int config_valid(const uint8_t *p){
 if(!u16(p)||u16(p)==65535)return 0;unsigned header=p[14]&127;
 if(header>1||!(p[6]&16))return 1;
 uint8_t seen[32];clear(seen,sizeof(seen));unsigned pos=p[52],pcie=0;
 for(unsigned k=0;k<48;k++){
  if(!pos)return 1;if(pos<64||pos>252||(pos&3)||(seen[pos/8]&(1U<<(pos%8))))return 0;
  seen[pos/8]|=(uint8_t)(1U<<(pos%8));
  if(p[pos]==16){if(++pcie>1)return 0;unsigned port=(u16(p+pos+2)>>4)&15;
   if((port==0||port==1||(port>=4&&port<=8))&&pos>236)return 0;
  }pos=p[pos+1];
 }return !pos;
}
static int fail(HPC_CATALOG *c,int e,uint32_t index){c->valid=0;c->result=(uint32_t)e;c->error_index=index;return e;}
static void device_id(STR *s,const HPC_PCI_RECORD *r){text(s,"HERO_PCI_");hex(s,r->segment,4);text(s,"_");hex(s,r->bus,2);text(s,"_");hex(s,r->device,2);}
static void bdf_name(STR *s,const HPC_PCI_RECORD *r,int function){hex(s,r->segment,4);text(s,":");hex(s,r->bus,2);text(s,":");hex(s,r->device,2);if(function){text(s,".");decimal(s,r->function);}}
static int add_link(HPC_CATALOG *c,unsigned kind,unsigned source,const char *parent,const char *member){
 if(c->link_count>=HPC_LINK_MAX)return 0;HPC_LINK_ADDITION *l=&c->links[c->link_count++];l->kind=kind;l->flags=HPC_LINK_MERGE_REQUIRED;l->source_item=source;
 STR a={l->parent_uri,0,HPC_URI_MAX,0},b={l->member_uri,0,HPC_URI_MAX,0};text(&a,parent);text(&b,member);return !a.bad&&!b.bad;
}
static HPC_ITEM *start(HPC_CATALOG *c,const HPC_PCI_RECORD *r,unsigned kind,unsigned group){
 if(c->item_count>=HPC_ITEM_MAX)return 0;HPC_ITEM *i=&c->items[c->item_count++];
 i->kind=kind;i->method=kind==HPC_STORAGE?HPC_POST_COLLECTION:HPC_POST_INSTANCE;i->source_index=r->source_index;i->device_index=group;
 i->config_crc32=r->config_crc32;i->path_crc32=r->path_crc32;i->segment=r->segment;i->bus=r->bus;i->device=r->device;i->function=r->function;i->json_offset=c->json_bytes;return i;
}
static int finish(HPC_CATALOG *c,HPC_ITEM *i,STR *j){
 if(j->bad||j->n>HPC_OBJECT_MAX||j->n+1>HPC_JSON_MAX-c->json_bytes)return 0;
 i->json_bytes=j->n;c->json_bytes+=j->n+1;return 1;
}
int HeroPcieCatalogBuild(const HPC_PCI_RECORD *r,uint32_t count,const HPC_ROUTES *routes,const HPC_CAPTURE *capture,HPC_CATALOG *c,HPC_SCRATCH *s){
 if(!c||!s||!routes||!capture||(count&&!r)||count>HPC_PCI_MAX||!routes->system_uri||!routes->chassis_uri||routes->system_bytes>96||routes->chassis_bytes>96)return HPC_ARGUMENT;
 size_t records=(size_t)count*sizeof(*r);
 if(overlap(c,sizeof(*c),s,sizeof(*s))||overlap(c,sizeof(*c),r,records)||overlap(s,sizeof(*s),r,records)||
    overlap(c,sizeof(*c),routes,sizeof(*routes))||overlap(s,sizeof(*s),routes,sizeof(*routes))||overlap(c,sizeof(*c),capture,sizeof(*capture))||overlap(s,sizeof(*s),capture,sizeof(*capture))||
    overlap(c,sizeof(*c),routes->system_uri,routes->system_bytes)||overlap(c,sizeof(*c),routes->chassis_uri,routes->chassis_bytes)||
    overlap(s,sizeof(*s),routes->system_uri,routes->system_bytes)||overlap(s,sizeof(*s),routes->chassis_uri,routes->chassis_bytes))return HPC_OVERLAP;
 clear(c,sizeof(*c));clear(s,sizeof(*s));c->version=1;c->source_crc32=capture->source_crc32;c->source_bytes=capture->source_bytes;c->error_index=UINT32_MAX;
 if(capture->source_bytes>HPC_CAPTURE_MAX)return fail(c,HPC_BOUND,0);
 if(capture->version!=1||capture->reserved||capture->pci_complete!=1||capture->pci_truncated||capture->cleanup_status||
    capture->pci_captured!=count||capture->pci_declared!=count||
    (capture->pci_status&&!(capture->pci_status==0x800000000000000eULL&&count==0)))return fail(c,HPC_INCOMPLETE,0);
 if(!route(routes->system_uri,routes->system_bytes,"/redfish/v1/Systems/")||!route(routes->chassis_uri,routes->chassis_bytes,"/redfish/v1/Chassis/"))return fail(c,HPC_ROUTE,0);
 char system[97],chassis[97];copy(system,routes->system_uri,routes->system_bytes);system[routes->system_bytes]=0;
 copy(chassis,routes->chassis_uri,routes->chassis_bytes);chassis[routes->chassis_bytes]=0;
 for(uint32_t i=0;i<count;i++){
  if(r[i].source_index>=count||r[i].flags!=HPC_CAPTURE_VALID||!r[i].source_handle||r[i].device>31||r[i].function>7||r[i].reserved||r[i].pad[0]||r[i].pad[1]||r[i].pad[2])return fail(c,HPC_FORMAT,i);
  if(r[i].path_bytes<4||r[i].path_bytes>HPC_PATH_MAX)return fail(c,HPC_BOUND,i);
  if(HeroPcieCrc32(r[i].config,256)!=r[i].config_crc32||HeroPcieCrc32(r[i].path,r[i].path_bytes)!=r[i].path_crc32)return fail(c,HPC_CRC,i);
  if(!path_valid(&r[i]))return fail(c,HPC_PATH,i);
  if(!config_valid(r[i].config))return fail(c,HPC_CONFIG,i);
  for(uint32_t j=0;j<i;j++)if(bdf(&r[i])==bdf(&r[j])||r[i].source_index==r[j].source_index||r[i].source_handle==r[j].source_handle||
      (r[i].path_bytes==r[j].path_bytes&&equal(r[i].path,r[j].path,r[i].path_bytes)))return fail(c,HPC_DUPLICATE,i);
  uint32_t at=i;while(at&&bdf(&r[s->order[at-1]])>bdf(&r[i])){s->order[at]=s->order[at-1];at--;}s->order[at]=i;
 }
 for(uint32_t k=0;k<count;k++){
  uint32_t i=s->order[k];unsigned group;
  if(k&&((bdf(&r[i])&~7U)==(bdf(&r[s->order[k-1]])&~7U)))group=s->device_of[s->order[k-1]];
  else{if(c->device_count==HPC_DEVICE_MAX)return fail(c,HPC_CAPACITY,i);group=c->device_count++;s->device_first[group]=i;}
  s->device_of[i]=group;
 }
 for(uint32_t g=0;g<c->device_count;g++){
  const HPC_PCI_RECORD *p=&r[s->device_first[g]];s->device_item[g]=c->item_count;HPC_ITEM *i=start(c,p,HPC_DEVICE,g);if(!i)return fail(c,HPC_CAPACITY,p->source_index);
  STR coll={i->collection_uri,0,HPC_URI_MAX,0},uri={i->member_uri,0,HPC_URI_MAX,0};text(&coll,chassis);text(&coll,"/PCIeDevices");text(&uri,i->collection_uri);text(&uri,"/");device_id(&uri,p);
  STR j={c->json+c->json_bytes,0,HPC_JSON_MAX-c->json_bytes,0};text(&j,"{\"Id\":\"");device_id(&j,p);text(&j,"\",\"Name\":\"PCI device ");bdf_name(&j,p,0);text(&j,"\"}");
  if(coll.bad||uri.bad||!finish(c,i,&j)||!add_link(c,HPC_SYSTEM_DEVICE,s->device_item[g],system,i->member_uri)||!add_link(c,HPC_DEVICE_CHASSIS,s->device_item[g],i->member_uri,chassis))return fail(c,HPC_CAPACITY,p->source_index);
 }
 for(uint32_t k=0;k<count;k++){
  uint32_t index=s->order[k],g=s->device_of[index];const HPC_PCI_RECORD *p=&r[index];s->function_item[index]=c->item_count;
  HPC_ITEM *i=start(c,p,HPC_FUNCTION,g);if(!i)return fail(c,HPC_CAPACITY,index);
  const char *parent=c->items[s->device_item[g]].member_uri;
  STR coll={i->collection_uri,0,HPC_URI_MAX,0},uri={i->member_uri,0,HPC_URI_MAX,0};text(&coll,parent);text(&coll,"/PCIeFunctions");text(&uri,i->collection_uri);text(&uri,"/F");decimal(&uri,p->function);
  STR j={c->json+c->json_bytes,0,HPC_JSON_MAX-c->json_bytes,0};text(&j,"{\"Id\":\"F");decimal(&j,p->function);text(&j,"\",\"Name\":\"PCI function ");bdf_name(&j,p,1);
  text(&j,"\",\"FunctionId\":");decimal(&j,p->function);text(&j,",\"VendorId\":\"0x");hex(&j,u16(p->config),4);text(&j,"\",\"DeviceId\":\"0x");hex(&j,u16(p->config+2),4);
  text(&j,"\",\"ClassCode\":\"0x");hex(&j,((uint32_t)p->config[11]<<16)|((uint32_t)p->config[10]<<8)|p->config[9],6);text(&j,"\",\"RevisionId\":\"0x");hex(&j,p->config[8],2);text(&j,"\"");
  if((p->config[14]&127)==0){text(&j,",\"SubsystemVendorId\":\"0x");hex(&j,u16(p->config+44),4);text(&j,"\",\"SubsystemId\":\"0x");hex(&j,u16(p->config+46),4);text(&j,"\"");}
  text(&j,"}");
  if(coll.bad||uri.bad||!finish(c,i,&j)||!add_link(c,HPC_DEVICE_FUNCTION,s->function_item[index],parent,i->member_uri)||!add_link(c,HPC_SYSTEM_FUNCTION,s->function_item[index],system,i->member_uri))return fail(c,HPC_CAPACITY,index);
  c->function_count++;
 }
 /* Storage is controller-only. No invented model, port, disk or capacity. */
 for(uint32_t k=0;k<count;k++){
  uint32_t index=s->order[k];const HPC_PCI_RECORD *p=&r[index];if(p->config[11]!=1)continue;
  if(c->storage_count==HPC_STORAGE_MAX)return fail(c,HPC_CAPACITY,index);
  HPC_ITEM *i=start(c,p,HPC_STORAGE,s->device_of[index]);if(!i)return fail(c,HPC_CAPACITY,index);
  STR coll={i->collection_uri,0,HPC_URI_MAX,0},uri={i->member_uri,0,HPC_URI_MAX,0};text(&coll,system);text(&coll,"/Storage");text(&uri,i->collection_uri);text(&uri,"/");device_id(&uri,p);text(&uri,"_F");decimal(&uri,p->function);
  STR j={c->json+c->json_bytes,0,HPC_JSON_MAX-c->json_bytes,0};text(&j,"{\"Id\":\"");device_id(&j,p);text(&j,"_F");decimal(&j,p->function);text(&j,"\",\"Name\":\"PCI storage controller ");bdf_name(&j,p,1);
  text(&j,"\",\"StorageControllers\":[{\"MemberId\":\"0\",\"Name\":\"PCI storage controller ");bdf_name(&j,p,1);text(&j,"\",\"Status\":{}}]}");
  if(coll.bad||uri.bad||!finish(c,i,&j))return fail(c,HPC_CAPACITY,index);c->storage_count++;
 }
 c->result=0;c->valid=1;return 0;
}
