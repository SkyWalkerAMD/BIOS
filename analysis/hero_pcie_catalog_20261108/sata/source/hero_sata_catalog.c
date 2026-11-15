#include "hero_sata_catalog.h"
static void clear(void *p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t *p){return u16(p)|((uint32_t)u16(p+2)<<16);}
static uint64_t u64(const uint8_t *p){return u32(p)|((uint64_t)u32(p+4)<<32);}
static int overlap(const void *a,size_t an,const void *b,size_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y||(x<y+bn&&y<x+an);}
uint32_t HeroSataCrc32(const void *p,size_t n){const uint8_t *b=p;uint32_t c=~0U;while(n--){c^=*b++;for(unsigned k=0;k<8;k++)c=(c>>1)^(0xedb88320U&(0U-(c&1)));}return ~c;}
uint32_t HeroSataSourceSize(void){return sizeof(HSC_SOURCE);}uint32_t HeroSataCatalogSize(void){return sizeof(HSC_CATALOG);}
static const uint8_t ahci_guid[16]={0x32,0x89,0x49,0x9e,0xbc,0x4a,0xaf,0x45,0xa3,0x4d,0x02,0x47,0x78,0x7b,0xe7,0xc6};
int HeroSataSourceInit(HSC_SOURCE *s){if(!s)return HSC_ARGUMENT;clear(s,sizeof(*s));s->version=1;return 0;}
static int reject(HSC_SOURCE *s,int e){s->rejected=(uint32_t)e;return e;}
static int path_view(const HHS_PATH_VIEW *p){return p->valid==1&&p->stable==1&&!p->protocol_status&&!p->first_status&&!p->second_status&&p->first&&p->second&&
 p->first_bytes>=4&&p->first_bytes<=HPC_PATH_MAX&&p->second_bytes==p->first_bytes&&p->first_crc32==p->second_crc32&&
 p->first_crc32==HeroSataCrc32(p->first,p->first_bytes)&&equal(p->first,p->second,p->first_bytes);}
int HeroSataVisit(void *user,const HHS_RECORD *r){
 HSC_SOURCE *s=user;if(!s||!r)return HSC_ARGUMENT;
 if(s->version!=1||s->rejected||s->reserved[0]||s->reserved[1]||s->reserved[2])return HSC_FORMAT;
 if(overlap(s,sizeof(*s),r,sizeof(*r)))return HSC_OVERLAP;
 if(r->version!=HHS_VERSION||r->bytes!=sizeof(*r))return reject(s,HSC_FORMAT);
 if(r->kind==HHS_PCI)return 0;
 if(r->kind!=HHS_BLOCK&&r->kind!=HHS_DISK)return reject(s,HSC_FORMAT);
 if(!r->source_handle||r->protocol_status||r->protocol_readable!=1||r->incomplete||r->issues)return reject(s,HSC_INCOMPLETE);
 if(!path_view(&r->path))return reject(s,HSC_PATH);
 if(overlap(s,sizeof(*s),r->path.first,r->path.first_bytes)||overlap(s,sizeof(*s),r->path.second,r->path.second_bytes))return reject(s,HSC_OVERLAP);
 if(r->kind==HHS_BLOCK){
  const HHS_BLOCK_VIEW *b=&r->data.block;
  if(s->block_seen>=HHS_BLOCK_LIMIT||r->source_index!=s->block_seen)return reject(s,HSC_BOUND);
  if(r->valid!=1||!b->first||!b->second||b->readable!=1||b->stable!=1||b->reserved||b->revision<0x10000||b->revision!=b->revision_after||!b->media_pointer||b->media_pointer!=b->media_pointer_after||
     b->media_bytes!=(b->revision>=0x2001f?48U:b->revision>=0x20001?44U:32U)||!equal(b->first,b->second,b->media_bytes))return reject(s,HSC_MEDIA);
  if(overlap(s,sizeof(*s),b->first,b->media_bytes)||overlap(s,sizeof(*s),b->second,b->media_bytes))return reject(s,HSC_OVERLAP);
  HSC_BLOCK *v=&s->blocks[s->block_seen];v->source_index=r->source_index;v->source_handle=r->source_handle;v->path_bytes=r->path.first_bytes;v->path_crc32=r->path.first_crc32;v->revision=b->revision;v->media_bytes=b->media_bytes;v->media_crc32=HeroSataCrc32(b->first,b->media_bytes);
  copy(v->path,r->path.first,v->path_bytes);copy(v->media,b->first,b->media_bytes);s->block_seen++;return 0;
 }
 const HHS_DISK_VIEW *d=&r->data.disk;
 if(s->disk_seen>=HHS_DISK_LIMIT||r->source_index!=s->disk_seen)return reject(s,HSC_BOUND);
 s->disk_seen++;
 if(!equal(d->interface_guid_le,ahci_guid,16))return 0;
 if(s->ata_count>=HHS_DISK_LIMIT||r->valid!=1||d->skip||d->allowlisted!=1||d->identify_status||d->expected_bytes!=512||d->returned_bytes!=512||d->captured_bytes!=512||!d->identify||d->buffer_guards_ok!=1||d->format_size_match!=1)return reject(s,HSC_IDENTIFY);
 if(overlap(s,sizeof(*s),d->identify,512))return reject(s,HSC_OVERLAP);
 if(HeroSataCrc32(d->identify,512)!=d->crc32)return reject(s,HSC_CRC);
 HSC_DISK *v=&s->ata[s->ata_count++];v->source_index=r->source_index;v->source_handle=r->source_handle;v->path_bytes=r->path.first_bytes;v->path_crc32=r->path.first_crc32;v->identify_crc32=d->crc32;
 copy(v->path,r->path.first,v->path_bytes);copy(v->identify,d->identify,512);return 0;
}
static int group_valid(const HHS_GROUP *g,uint32_t kind,uint32_t limit,uint32_t count){
 return g->kind==kind&&g->limit==limit&&g->declared==count&&g->captured==count&&g->declared<=limit&&g->valid_records<=count&&g->complete==1&&g->stable==1&&!g->truncated&&!g->incomplete_records&&!g->cleanup_status&&!g->issues&&!g->reserved&&!g->reserved_map&&!g->reserved2&&
 (g->enum_status==0||(g->enum_status==0x800000000000000eULL&&!count));
}
typedef struct {char *p;uint32_t n,cap;int bad;} STR;
static void bytes(STR *s,const char *p,size_t n){if(s->n>=s->cap||n>=s->cap-s->n){s->bad=1;return;}copy(s->p+s->n,p,n);s->n+=(uint32_t)n;s->p[s->n]=0;}
static void text(STR *s,const char *p){size_t n=0;while(p[n])n++;bytes(s,p,n);}
static void hex(STR *s,uint32_t v,unsigned n){char b[8];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-1-i)*4))&15];bytes(s,b,n);}
static void decimal(STR *s,uint64_t v){char b[20];unsigned n=0;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);while(n)bytes(s,&b[--n],1);}
static int route(const char *p,uint32_t n,const char *prefix){
 if(!p||!n||n>96)return 0;uint32_t k=0;while(prefix[k])k++;if(n<=k||n-k>64||!equal(p,prefix,k))return 0;
 if((n-k==1&&p[k]=='.')||(n-k==2&&p[k]=='.'&&p[k+1]=='.'))return 0;
 for(uint32_t i=k;i<n;i++){char c=p[i];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'||c=='~'))return 0;}return 1;
}
static void device_id(STR *s,const HPC_PCI_RECORD *p){text(s,"HERO_PCI_");hex(s,p->segment,4);text(s,"_");hex(s,p->bus,2);text(s,"_");hex(s,p->device,2);}
static void drive_id(STR *s,const HSC_ITEM *i){text(s,"SATA_P");decimal(s,i->port);text(s,"_M");hex(s,i->pmp,4);text(s,"_L");decimal(s,i->lun);}
static int same_z(const char *p,const char *q,uint32_t cap){for(uint32_t i=0;i<cap;i++){if(p[i]!=q[i])return 0;if(!p[i])return 1;}return 0;}
static int path_check(const uint8_t *p,uint32_t n,int sata,uint32_t *offset){
 if(n<4||n>HPC_PATH_MAX)return 0;uint32_t at=0;unsigned nodes=0,pcis=0,satas=0;
 while(at<n&&nodes++<128){if(n-at<4)return 0;uint32_t z=u16(p+at+2);if(z<4||z>n-at)return 0;
  if(p[at]==127)return p[at+1]==255&&z==4&&at+4==n&&pcis&&satas==(unsigned)sata;
  if(p[at]==1&&p[at+1]==1){if(z!=6||p[at+4]>7||p[at+5]>31||satas)return 0;pcis++;}
  if(p[at]==3){if(!sata||p[at+1]!=18||z!=10||satas++||at+14!=n||!pcis)return 0;*offset=at;}
  if(p[at]==4||p[at]>5)return 0;at+=z;
 }return 0;
}
static int ata_string(const uint8_t *p,uint32_t off,uint32_t n,char *out){
 uint32_t begin=0,end=n;for(uint32_t i=0;i<n;i++){uint8_t b=p[off+(i^1U)];if(b<32||b>126){out[0]=0;return 0;}out[i]=(char)b;}
 while(begin<end&&out[begin]==' ')begin++;while(end>begin&&out[end-1]==' ')end--;
 for(uint32_t i=begin;i<end;i++)out[i-begin]=out[i];out[end-begin]=0;return end>begin;
}
static void json_string(STR *s,const char *p){text(s,"\"");while(*p){if(*p=='"'||*p=='\\')text(s,"\\");bytes(s,p++,1);}text(s,"\"");}
static int ata_capacity(const uint8_t *p,uint32_t *sector,uint64_t *count){
 if((u16(p)&0x8080U)||!(u16(p+98)&0x200))return 0;
 uint32_t sum=0;for(unsigned i=0;i<512;i++)sum+=p[i];if(p[510]==0xa5&&(sum&255))return 0;
 uint16_t support=u16(p+166);uint64_t sectors;
 if((support&0xc000)==0x4000&&(support&0x400)){sectors=u64(p+200);if(!sectors||sectors>0x0000ffffffffffffULL)return 0;}
 else{sectors=u32(p+120);if(!sectors||sectors>0x0fffffffU)return 0;}
 uint32_t logical=512;
 if((u16(p+212)&0xd000)==0x5000){uint32_t words=u32(p+234);if(words>0x800000U)return 0;logical=words*2;}
 if(logical<512||logical>0x1000000U||(logical&(logical-1))||sectors>UINT64_MAX/logical)return 0;
 *sector=logical;*count=sectors;return 1;
}
static int fail(HSC_CATALOG *c,int e,uint32_t idx){c->valid=0;c->result=(uint32_t)e;c->error_index=idx;return e;}
static int link(HSC_CATALOG *c,uint32_t kind,uint32_t index,const char *parent,const char *member){
 if(c->link_count>=HSC_DRIVE_MAX*3)return 0;HSC_LINK *l=&c->links[c->link_count++];l->kind=kind;l->flags=HPC_LINK_MERGE_REQUIRED;l->item_index=index;
 STR a={l->parent_uri,0,HPC_URI_MAX,0},b={l->member_uri,0,HPC_URI_MAX,0};text(&a,parent);text(&b,member);return !a.bad&&!b.bad;
}
int HeroSataCatalogBuild(const HSC_SOURCE *s,const HHS_RESULT *r,const HPC_PCI_RECORD *pci,uint32_t count,const HPC_CATALOG *pc,const HPC_ROUTES *routes,HSC_CATALOG *c){
 if(!s||!r||!pc||!routes||!c||(count&&!pci)||count>HPC_PCI_MAX||!routes->system_uri||!routes->chassis_uri||routes->system_bytes>96||routes->chassis_bytes>96)return HSC_ARGUMENT;
 if(overlap(c,sizeof(*c),s,sizeof(*s))||overlap(c,sizeof(*c),r,sizeof(*r))||overlap(c,sizeof(*c),pc,sizeof(*pc))||overlap(c,sizeof(*c),pci,(size_t)count*sizeof(*pci))||overlap(c,sizeof(*c),routes,sizeof(*routes))||overlap(c,sizeof(*c),routes->system_uri,routes->system_bytes)||overlap(c,sizeof(*c),routes->chassis_uri,routes->chassis_bytes))return HSC_OVERLAP;
 clear(c,sizeof(*c));c->version=1;c->error_index=UINT32_MAX;
 if(s->version!=1||s->rejected||s->reserved[0]||s->reserved[1]||s->reserved[2]||s->block_seen>HHS_BLOCK_LIMIT||s->disk_seen>HHS_DISK_LIMIT||s->ata_count>s->disk_seen||
    r->version!=HHS_VERSION||r->bytes!=sizeof(*r)||r->complete!=1||r->incomplete||r->status||r->visitor_aborted||r->reserved[0]||r->reserved[1]||
    !group_valid(&r->groups[0],HHS_PCI,HHS_PCI_LIMIT,count)||r->groups[0].valid_records!=count||
    !group_valid(&r->groups[1],HHS_BLOCK,HHS_BLOCK_LIMIT,s->block_seen)||r->groups[1].valid_records!=s->block_seen||
    !group_valid(&r->groups[2],HHS_DISK,HHS_DISK_LIMIT,s->disk_seen))return fail(c,HSC_INCOMPLETE,0);
 if(pc->version!=1||pc->valid!=1||pc->result||pc->function_count!=count||pc->item_count>HPC_ITEM_MAX||pc->source_crc32!=r->groups[0].source_crc32||pc->source_bytes!=r->groups[0].source_bytes)return fail(c,HSC_PCI,0);
 if(!route(routes->system_uri,routes->system_bytes,"/redfish/v1/Systems/")||!route(routes->chassis_uri,routes->chassis_bytes,"/redfish/v1/Chassis/"))return fail(c,HSC_ROUTE,0);
 for(unsigned g=0;g<3;g++)c->source_crc32[g]=r->groups[g].source_crc32;
 for(uint32_t k=0;k<count;k++){
  const HPC_PCI_RECORD *p=&pci[k];uint32_t ignored=0;
  if(p->source_index>=count||!p->source_handle||p->flags!=7||p->reserved||p->pad[0]||p->pad[1]||p->pad[2]||p->device>31||p->function>7||!path_check(p->path,p->path_bytes,0,&ignored))return fail(c,HSC_PCI,k);
  if(HeroSataCrc32(p->config,256)!=p->config_crc32||HeroSataCrc32(p->path,p->path_bytes)!=p->path_crc32)return fail(c,HSC_CRC,k);
  for(uint32_t j=0;j<k;j++)if(p->source_index==pci[j].source_index||p->source_handle==pci[j].source_handle||(p->path_bytes==pci[j].path_bytes&&equal(p->path,pci[j].path,p->path_bytes)))return fail(c,HSC_DUPLICATE,k);
 }
 for(uint32_t b=0;b<s->block_seen;b++){
  const HSC_BLOCK *p=&s->blocks[b];if(p->source_index!=b||!p->source_handle||p->reserved||p->path_bytes<4||p->path_bytes>HPC_PATH_MAX||p->revision<0x10000||p->media_bytes!=(p->revision>=0x2001f?48U:p->revision>=0x20001?44U:32U))return fail(c,HSC_BOUND,b);
  if(HeroSataCrc32(p->path,p->path_bytes)!=p->path_crc32||HeroSataCrc32(p->media,p->media_bytes)!=p->media_crc32)return fail(c,HSC_CRC,b);
  for(unsigned j=4;j<=8;j++)if(p->media[j]>1)return fail(c,HSC_MEDIA,b);
  for(uint32_t j=0;j<b;j++)if(p->source_handle==s->blocks[j].source_handle||(p->path_bytes==s->blocks[j].path_bytes&&equal(p->path,s->blocks[j].path,p->path_bytes)))return fail(c,HSC_DUPLICATE,b);
 }
 for(uint32_t d=0;d<s->ata_count;d++){
  const HSC_DISK *disk=&s->ata[d];uint32_t offset=0;
  if(disk->source_index>=s->disk_seen||!disk->source_handle||disk->path_bytes<4||disk->path_bytes>HPC_PATH_MAX)return fail(c,HSC_BOUND,d);
  if(HeroSataCrc32(disk->path,disk->path_bytes)!=disk->path_crc32||HeroSataCrc32(disk->identify,512)!=disk->identify_crc32)return fail(c,HSC_CRC,d);
  for(uint32_t j=0;j<d;j++)if(disk->source_index==s->ata[j].source_index||disk->source_handle==s->ata[j].source_handle||(disk->path_bytes==s->ata[j].path_bytes&&equal(disk->path,s->ata[j].path,disk->path_bytes)))return fail(c,HSC_DUPLICATE,d);
  /* AHCI metadata on a non-direct-SATA path is not promoted to a drive. */
  if(!path_check(disk->path,disk->path_bytes,1,&offset)){c->skipped++;continue;}
  uint16_t port=u16(disk->path+offset+4),pmp=u16(disk->path+offset+6),lun=u16(disk->path+offset+8);
  if(port>31||pmp!=65535||lun){c->skipped++;continue;}
  uint32_t bmatch=UINT32_MAX,pmatch=UINT32_MAX;
  for(uint32_t b=0;b<s->block_seen;b++){const HSC_BLOCK *p=&s->blocks[b];if(p->source_handle==disk->source_handle&&p->path_bytes==disk->path_bytes&&equal(p->path,disk->path,disk->path_bytes)){if(bmatch!=UINT32_MAX)return fail(c,HSC_ASSOCIATION,d);bmatch=b;}}
  for(uint32_t k=0;k<count;k++){const HPC_PCI_RECORD *p=&pci[k];if(p->path_bytes==offset+4&&equal(p->path,disk->path,offset)){if(pmatch!=UINT32_MAX)return fail(c,HSC_ASSOCIATION,d);pmatch=k;}}
  if(bmatch==UINT32_MAX||pmatch==UINT32_MAX)return fail(c,HSC_ASSOCIATION,d);
  const HSC_BLOCK *block=&s->blocks[bmatch];const HPC_PCI_RECORD *p=&pci[pmatch];
  if(p->config[11]!=1||p->config[10]!=6||p->config[9]!=1||(p->config[14]&127)!=0)return fail(c,HSC_PCI,d);
  if(block->media[4]||!block->media[5]||block->media[6]||block->media[7]){c->skipped++;continue;}
  uint32_t logical;uint64_t sectors;
  if(!ata_capacity(disk->identify,&logical,&sectors))return fail(c,HSC_IDENTIFY,d);
  if(u32(block->media+12)!=logical||u64(block->media+24)==UINT64_MAX||u64(block->media+24)+1!=sectors)return fail(c,HSC_MEDIA,d);
  if(c->item_count>=HSC_DRIVE_MAX)return fail(c,HSC_CAPACITY,d);
  HSC_ITEM *i=&c->items[c->item_count];i->method=HPC_POST_INSTANCE;i->disk_index=disk->source_index;i->block_index=block->source_index;i->pci_index=p->source_index;i->path_crc32=disk->path_crc32;i->identify_crc32=disk->identify_crc32;i->source_handle=disk->source_handle;i->capacity_bytes=sectors*logical;i->logical_sector_bytes=logical;
  i->segment=p->segment;i->bus=p->bus;i->device=p->device;i->function=p->function;i->port=port;i->pmp=pmp;i->lun=lun;
  char storage[HPC_URI_MAX],function[HPC_URI_MAX],controller[HPC_URI_MAX];
  STR st={storage,0,sizeof(storage),0},fn={function,0,sizeof(function),0};bytes(&st,routes->system_uri,routes->system_bytes);text(&st,"/Storage/");device_id(&st,p);text(&st,"_F");decimal(&st,p->function);
  bytes(&fn,routes->chassis_uri,routes->chassis_bytes);text(&fn,"/PCIeDevices/");device_id(&fn,p);text(&fn,"/PCIeFunctions/F");decimal(&fn,p->function);
  if(st.bad||fn.bad)return fail(c,HSC_CAPACITY,d);
  unsigned found_st=0,found_fn=0;
  for(uint32_t k=0;k<pc->item_count;k++){const HPC_ITEM *a=&pc->items[k];if(a->source_index==p->source_index&&a->config_crc32==p->config_crc32&&a->path_crc32==p->path_crc32){if(a->kind==HPC_STORAGE&&same_z(a->member_uri,storage,HPC_URI_MAX))found_st++;if(a->kind==HPC_FUNCTION&&same_z(a->member_uri,function,HPC_URI_MAX))found_fn++;}}
  if(found_st!=1||found_fn!=1)return fail(c,HSC_PCI,d);
  STR coll={i->collection_uri,0,HPC_URI_MAX,0},uri={i->member_uri,0,HPC_URI_MAX,0},ctr={controller,0,HPC_URI_MAX,0};text(&coll,storage);text(&coll,"/Drives");text(&uri,i->collection_uri);text(&uri,"/");drive_id(&uri,i);text(&ctr,storage);text(&ctr,"#/StorageControllers/0");
  if(coll.bad||uri.bad||ctr.bad)return fail(c,HSC_CAPACITY,d);
  char model[41],serial[21],revision[9];int m=ata_string(disk->identify,54,40,model),sn=ata_string(disk->identify,20,20,serial),rv=ata_string(disk->identify,46,8,revision);
  i->json_offset=c->json_bytes;STR j={c->json+c->json_bytes,0,HSC_JSON_MAX-c->json_bytes,0};text(&j,"{\"Id\":\"");drive_id(&j,i);text(&j,"\",\"Name\":\"SATA drive port ");decimal(&j,port);text(&j,"\",\"Protocol\":\"SATA\",\"CapacityBytes\":");decimal(&j,i->capacity_bytes);text(&j,",\"BlockSizeBytes\":");decimal(&j,logical);
  if(m){text(&j,",\"Model\":");json_string(&j,model);}if(sn){text(&j,",\"SerialNumber\":");json_string(&j,serial);}if(rv){text(&j,",\"Revision\":");json_string(&j,revision);}if(u16(disk->identify+434)==1)text(&j,",\"MediaType\":\"SSD\"");text(&j,"}");
  if(j.bad||j.n>HSC_OBJECT_MAX||j.n+1>HSC_JSON_MAX-c->json_bytes)return fail(c,HSC_CAPACITY,d);i->json_bytes=j.n;c->json_bytes+=j.n+1;
  if(!link(c,HSC_STORAGE_DRIVE,c->item_count,storage,i->member_uri)||!link(c,HSC_FUNCTION_DRIVE,c->item_count,function,i->member_uri)||!link(c,HSC_FUNCTION_CONTROLLER,c->item_count,function,controller))return fail(c,HSC_CAPACITY,d);
  c->item_count++;
 }
 c->valid=1;return 0;
}
