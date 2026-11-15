/* Independent current-boot typed source. Interface whitelist is inherited
 * from frozen I4; only the output sink and buffer ownership changed. */
#include "hhs_common.h"
#include "hhs_read_abi.h"
#include "hero_hardware_source.h"
#define MAGIC 0x31534848U
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID path_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID block_guid={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID disk_guid={0xd432a67f,0x14dc,0x484b,{0xb3,0xbb,0x3f,2,0x91,0x84,0x93,0x27}};
static GUID nvme_guid={0x3ab14680,0x5d3f,0x4a4d,{0xbc,0xdc,0xcc,0x38,0,0x18,0xc7,0xf7}};
static GUID ahci_guid={0x9e498932,0x4abc,0x45af,{0xa3,0x4d,2,0x47,0x78,0x7b,0xe7,0xc6}};
static GUID ide_guid={0x5e948fe3,0x26d3,0x42b5,{0xaf,0x17,0x61,2,0x87,0x18,0x8d,0xec}};
typedef struct {
 uint32_t magic,version,busy,reserved;
 I4_MAP map;HHS_RECORD record;
 PCI pci;I4_BLOCK block_a,block_b;I4_DISK disk;
 uint8_t memory_map[I4_MAP_CAP],path_a[I4_PATH_CAP],path_b[I4_PATH_CAP];
 uint8_t config[256],media_a[48],media_b[48];
 struct {uint64_t pre[2];uint8_t bytes[I4_IDENTIFY_CAP];uint64_t post[2];} identify;
} WORK;
typedef struct {ST *st;WORK *w;HHS_VISITOR visitor;HHS_RESULT result;ES cleanup;} CTX;
static void sample(void *dest,const void *src,size_t n){uint8_t *d=dest;const volatile uint8_t *s=src;for(size_t i=0;i<n;i++)d[i]=s[i];}
static int overlap(const void *a,size_t an,const void *b,size_t bn){
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 1;return x<y+bn&&y<x+an;
}
size_t HeroHardwareSourceWorkspaceSize(void){return sizeof(WORK);}
int HeroHardwareSourceInit(void *workspace,size_t bytes){
 if(!workspace||((uintptr_t)workspace&15)||bytes<sizeof(WORK)||bytes>UINTPTR_MAX-(uintptr_t)workspace)return 1;
 WORK *w=workspace;if(w->magic==MAGIC&&w->version==HHS_VERSION&&w->busy)return 2;
 memset(w,0,sizeof(*w));w->magic=MAGIC;w->version=HHS_VERSION;return 0;
}
static void issue(HHS_RECORD *r,uint32_t flag){r->incomplete=1;r->issues|=flag;}
static ES refresh_map(CTX *c,HHS_GROUP *g){
 typedef ES(EA *GET_MAP)(UN *,void *,UN *,UN *,uint32_t *);
 UN n=sizeof(c->w->memory_map),key=0,ds=0;uint32_t version=0;
 ES e=((GET_MAP)c->st->bs->get_memory_map)(&n,c->w->memory_map,&key,&ds,&version);
 g->memory_map_status=e;g->memory_map_bytes=n;g->descriptor_bytes=ds;g->memory_map_version=version;
 c->w->map=(I4_MAP){c->w->memory_map,(size_t)n,(size_t)ds};
 if(FAILED(e)||version!=1||ds<sizeof(I4_MD)||ds>256||(ds&7)||!n||n>I4_MAP_CAP||n%ds||n/ds>I4_MAP_ENTRIES){
  c->w->map.bytes=0;g->issues|=HHS_MEMORY_MAP;return FAILED(e)?e:ERR(2);
 }return 0;
}
static int fn_ok(CTX *c,const void *fn){return fn&&hhs_range_readable(&c->w->map,fn,1);}
static void path_record(CTX *c,HANDLE handle){
 WORK *w=c->w;HHS_RECORD *r=&w->record;HHS_PATH_VIEW *p=&r->path;const uint8_t *path=0;
 p->protocol_status=c->st->bs->handle_protocol(handle,&path_guid,(void **)&path);p->pointer=(uintptr_t)path;
 p->first_status=ERR(6);p->second_status=ERR(6);p->first=w->path_a;p->second=w->path_b;
 if(FAILED(p->protocol_status)||!path){issue(r,HHS_PATH);return;}
 size_t an=0,bn=0;p->first_status=hhs_path_copy(&w->map,path,w->path_a,&an);p->second_status=hhs_path_copy(&w->map,path,w->path_b,&bn);
 p->first_bytes=(uint32_t)an;p->second_bytes=(uint32_t)bn;
 p->first_crc32=probe_crc32(w->path_a,an);p->second_crc32=probe_crc32(w->path_b,bn);
 p->valid=!FAILED(p->first_status)&&!FAILED(p->second_status);
 p->stable=p->valid&&an==bn&&eq(w->path_a,w->path_b,an);
 if(!p->valid)issue(r,HHS_PATH);else if(!p->stable)issue(r,HHS_PATH_CHANGED);
}
static void pci_record(CTX *c,HANDLE handle){
 WORK *w=c->w;HHS_RECORD *r=&w->record;HHS_PCI_VIEW *v=&r->data.pci;PCI *p=0;
 r->protocol_status=c->st->bs->handle_protocol(handle,&pci_guid,(void **)&p);r->protocol_pointer=(uintptr_t)p;
 v->location_status=ERR(6);v->config_status=ERR(6);v->segment=v->bus=v->device=v->function=UINT64_MAX;
 v->config=w->config;
 if(FAILED(r->protocol_status)||!hhs_range_readable(&w->map,p,0x78)){issue(r,HHS_PROTOCOL);return;}
 r->protocol_readable=1;memset(&w->pci,0,sizeof(w->pci));sample(&w->pci,p,0x78);
 v->location_status=fn_ok(c,(const void *)w->pci.location)?w->pci.location(p,&v->segment,&v->bus,&v->device,&v->function):ERR(3);
 if(!FAILED(v->location_status)&&v->segment<=65535&&v->bus<=255&&v->device<=31&&v->function<=7)v->flags|=HHS_PCI_LOCATION_VALID;else issue(r,HHS_LOCATION);
 memset(w->config,0,sizeof(w->config));
 v->config_status=fn_ok(c,(const void *)w->pci.pci.read)?w->pci.pci.read(p,0,0,sizeof(w->config),w->config):ERR(3);
 if(!FAILED(v->config_status)){v->flags|=HHS_PCI_CONFIG_VALID;v->config_bytes=sizeof(w->config);v->config_crc32=probe_crc32(w->config,sizeof(w->config));}else issue(r,HHS_CONFIG);
 path_record(c,handle);if(r->path.valid&&r->path.stable)v->flags|=HHS_PCI_PATH_VALID;
 r->valid=v->flags==HHS_PCI_VALID;
}
static void block_record(CTX *c,HANDLE handle){
 WORK *w=c->w;HHS_RECORD *r=&w->record;HHS_BLOCK_VIEW *v=&r->data.block;I4_BLOCK *p=0;
 r->protocol_status=c->st->bs->handle_protocol(handle,&block_guid,(void **)&p);r->protocol_pointer=(uintptr_t)p;
 v->first=w->media_a;v->second=w->media_b;
 if(FAILED(r->protocol_status)||!hhs_range_readable(&w->map,p,16)){issue(r,HHS_PROTOCOL);return;}
 r->protocol_readable=1;memset(&w->block_a,0,sizeof(w->block_a));memset(&w->block_b,0,sizeof(w->block_b));sample(&w->block_a,p,16);
 v->revision=w->block_a.revision;v->media_pointer=(uintptr_t)w->block_a.media;v->media_bytes=(uint32_t)hhs_media_bytes(v->revision);
 if(!v->media_bytes||!hhs_range_readable(&w->map,w->block_a.media,v->media_bytes)){issue(r,HHS_MEDIA);path_record(c,handle);return;}
 memset(w->media_a,0,sizeof(w->media_a));memset(w->media_b,0,sizeof(w->media_b));
 sample(w->media_a,w->block_a.media,v->media_bytes);sample(w->media_b,w->block_a.media,v->media_bytes);sample(&w->block_b,p,16);
 v->readable=1;v->revision_after=w->block_b.revision;v->media_pointer_after=(uintptr_t)w->block_b.media;
 v->stable=w->block_a.revision==w->block_b.revision&&w->block_a.media==w->block_b.media&&hhs_media_fields_equal(v->revision,w->media_a,w->media_b);
 if(!v->stable)issue(r,HHS_MEDIA_CHANGED);path_record(c,handle);r->valid=v->stable&&r->path.valid&&r->path.stable;
}
static void disk_record(CTX *c,HANDLE handle){
 WORK *w=c->w;HHS_RECORD *r=&w->record;HHS_DISK_VIEW *v=&r->data.disk;I4_DISK *p=0;
 r->protocol_status=c->st->bs->handle_protocol(handle,&disk_guid,(void **)&p);r->protocol_pointer=(uintptr_t)p;
 v->identify_status=ERR(6);v->identify=w->identify.bytes;
 if(FAILED(r->protocol_status)||!hhs_range_readable(&w->map,p,sizeof(*p))){issue(r,HHS_PROTOCOL);return;}
 r->protocol_readable=1;sample(&w->disk,p,sizeof(w->disk));memcpy(v->interface_guid_le,&w->disk.interface,16);
 v->expected_bytes=eq(v->interface_guid_le,&nvme_guid,16)?4096:((eq(v->interface_guid_le,&ide_guid,16)||eq(v->interface_guid_le,&ahci_guid,16))?512:0);
 v->allowlisted=v->expected_bytes!=0;path_record(c,handle);
 if(!v->allowlisted){v->skip=HHS_DISK_UNSUPPORTED;return;}
 if(!fn_ok(c,(const void *)w->disk.identify)){v->skip=HHS_DISK_GETTER_UNAVAILABLE;issue(r,HHS_IDENTIFY);return;}
 memset(&w->identify,0,sizeof(w->identify));w->identify.pre[0]=0x3150524547554152ULL;w->identify.pre[1]=0x3250524547554152ULL;
 w->identify.post[0]=0x31504f5354475541ULL;w->identify.post[1]=0x32504f5354475541ULL;
 if(v->expected_bytes<sizeof(w->identify.bytes))memset(w->identify.bytes+v->expected_bytes,0xa6,sizeof(w->identify.bytes)-v->expected_bytes);
 v->returned_bytes=v->expected_bytes;v->identify_status=w->disk.identify(p,w->identify.bytes,&v->returned_bytes);
 v->buffer_guards_ok=w->identify.pre[0]==0x3150524547554152ULL&&w->identify.pre[1]==0x3250524547554152ULL&&w->identify.post[0]==0x31504f5354475541ULL&&w->identify.post[1]==0x32504f5354475541ULL;
 for(size_t i=v->expected_bytes;i<sizeof(w->identify.bytes);i++)if(w->identify.bytes[i]!=0xa6)v->buffer_guards_ok=0;
 v->format_size_match=!FAILED(v->identify_status)&&v->returned_bytes==v->expected_bytes;
 if(v->buffer_guards_ok&&!FAILED(v->identify_status)&&v->returned_bytes&&v->returned_bytes<=v->expected_bytes){v->captured_bytes=v->returned_bytes;v->crc32=probe_crc32(w->identify.bytes,v->captured_bytes);}
 if(!v->buffer_guards_ok)issue(r,HHS_BUFFER);if(!v->format_size_match)issue(r,HHS_IDENTIFY);
 r->valid=v->format_size_match&&v->buffer_guards_ok&&r->path.valid&&r->path.stable;
}
/* Audit stream per group: LE u32 kind,index; LE u64 handle,protocol_status;
 * LE u32 issues,path_first_bytes; path_first bytes; then kind-specific raw data:
 * PCI four LE u64 BDF values + config bytes; Block revision u64 + two media
 * samples; Disk interface GUID + captured Identify bytes. Not authentication. */
static void audit(HHS_GROUP *g,const void *data,size_t n){const uint8_t *p=data;uint32_t crc=~g->source_crc32;
 for(size_t i=0;i<n;i++){crc^=p[i];for(unsigned k=0;k<8;k++)crc=(crc>>1)^(0xedb88320U&(0U-(crc&1)));}
 g->source_crc32=~crc;g->source_bytes+=n;
}
static void audit_record(HHS_GROUP *g,const HHS_RECORD *r){
 audit(g,&r->kind,4);audit(g,&r->source_index,4);audit(g,&r->source_handle,8);audit(g,&r->protocol_status,8);audit(g,&r->issues,4);audit(g,&r->path.first_bytes,4);
 if(r->path.first_bytes)audit(g,r->path.first,r->path.first_bytes);
 if(r->kind==HHS_PCI){audit(g,&r->data.pci.segment,32);if(r->data.pci.config_bytes)audit(g,r->data.pci.config,r->data.pci.config_bytes);}
 else if(r->kind==HHS_BLOCK){audit(g,&r->data.block.revision,8);if(r->data.block.readable){audit(g,r->data.block.first,r->data.block.media_bytes);audit(g,r->data.block.second,r->data.block.media_bytes);}}
 else{audit(g,r->data.disk.interface_guid_le,16);if(r->data.disk.captured_bytes)audit(g,r->data.disk.identify,r->data.disk.captured_bytes);}
}
static void enumerate(CTX *c,HHS_GROUP *g,GUID *guid,void (*read_record)(CTX *,HANDLE)){
 HANDLE *handles=0;UN count=0;ES e=c->st->bs->locate_handles(2,guid,0,&count,&handles);g->enum_status=e;g->declared=count;g->stable=1;
 if(!FAILED(e)&&count&&handles){
  if(!FAILED(refresh_map(c,g))&&count<=UINT64_MAX/sizeof(HANDLE)&&hhs_range_readable(&c->w->map,handles,(size_t)count*sizeof(HANDLE))){
   UN take=count;if(take>g->limit){take=g->limit;g->truncated=1;g->issues|=HHS_LIMIT;}
   for(UN i=0;i<take;i++){
    HANDLE h=0;sample(&h,handles+i,sizeof(h));HHS_RECORD *r=&c->w->record;memset(r,0,sizeof(*r));
    r->version=HHS_VERSION;r->bytes=sizeof(*r);r->kind=g->kind;r->source_index=(uint32_t)i;r->source_handle=(uintptr_t)h;
    r->protocol_status=ERR(6);r->path.protocol_status=ERR(6);r->path.first_status=ERR(6);r->path.second_status=ERR(6);
    read_record(c,h);audit_record(g,r);c->result.visitor_calls++;
    if(c->visitor.visit(c->visitor.user,r)!=0){c->result.visitor_aborted=1;g->issues|=HHS_VISITOR_ABORTED;break;}
    g->captured++;g->valid_records+=r->valid!=0;g->incomplete_records+=r->incomplete!=0;g->issues|=r->issues;
    if(!r->path.stable||(r->kind==HHS_BLOCK&&!r->data.block.stable))g->stable=0;
   }
  }else g->issues|=HHS_MEMORY_MAP;
 }else if(e!=ERR(14)&&!(e==0&&count==0))g->issues|=HHS_ENUMERATION;
 /* A NOT_FOUND with nonzero count is not an empty complete observation. */
 if(e==ERR(14)&&count)g->issues|=HHS_ENUMERATION;
 if(handles){g->cleanup_status=c->st->bs->free_pool(handles);if(FAILED(g->cleanup_status)){g->issues|=HHS_CLEANUP;if(!c->cleanup)c->cleanup=g->cleanup_status;}}
 g->complete=g->issues==0&&g->captured==g->declared&&!g->truncated;
}
uint64_t HeroHardwareSourceCollect(void *system_table,void *workspace,size_t bytes,const HHS_VISITOR *visitor,HHS_RESULT *result){
 if(!workspace||((uintptr_t)workspace&15)||bytes<sizeof(WORK)||!visitor||!result||visitor->version!=HHS_VERSION||visitor->bytes!=sizeof(*visitor)||!visitor->visit||
    overlap(workspace,bytes,visitor,sizeof(*visitor))||overlap(workspace,bytes,result,sizeof(*result))||overlap(visitor,sizeof(*visitor),result,sizeof(*result)))return ERR(2);
 WORK *w=workspace;ST *st=system_table;
 if(w->magic!=MAGIC||w->version!=HHS_VERSION||!st||!st->bs||!st->bs->get_memory_map||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(2);
 if(w->busy)return ERR(20);w->busy=1;
 CTX c;memset(&c,0,sizeof(c));c.st=st;c.w=w;c.visitor=*visitor;c.result.version=HHS_VERSION;c.result.bytes=sizeof(c.result);
 for(unsigned i=0;i<3;i++){c.result.groups[i].kind=i+1;c.result.groups[i].limit=i==0?HHS_PCI_LIMIT:(i==1?HHS_BLOCK_LIMIT:HHS_DISK_LIMIT);c.result.groups[i].enum_status=ERR(6);c.result.groups[i].memory_map_status=ERR(6);}
 enumerate(&c,&c.result.groups[0],&pci_guid,pci_record);
 if(!c.result.visitor_aborted)enumerate(&c,&c.result.groups[1],&block_guid,block_record);
 if(!c.result.visitor_aborted)enumerate(&c,&c.result.groups[2],&disk_guid,disk_record);
 c.result.complete=c.result.groups[0].complete&&c.result.groups[1].complete&&c.result.groups[2].complete;
 c.result.incomplete=!c.result.complete;
 ES status=c.result.visitor_aborted?ERR(21):(c.cleanup?c.cleanup:(c.result.incomplete?ERR(6):0));
 c.result.status=status;*result=c.result;w->busy=0;return status;
}
