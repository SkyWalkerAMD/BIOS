/* Read-only protocol catalogue. No PCI writes, BAR accesses, block operations,
 * pass-through, variable operations, driver load/connect or protocol install. */
#include "collector.h"
#include "i4_collect.h"
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID path_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID block_guid={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID disk_guid={0xd432a67f,0x14dc,0x484b,{0xb3,0xbb,0x3f,2,0x91,0x84,0x93,0x27}};
static GUID nvme_guid={0x3ab14680,0x5d3f,0x4a4d,{0xbc,0xdc,0xcc,0x38,0,0x18,0xc7,0xf7}};
static GUID ahci_guid={0x9e498932,0x4abc,0x45af,{0xa3,0x4d,2,0x47,0x78,0x7b,0xe7,0xc6}};
static GUID ide_guid={0x5e948fe3,0x26d3,0x42b5,{0xaf,0x17,0x61,2,0x87,0x18,0x8d,0xec}};
static uint8_t map_buf[I4_MAP_CAP];
static uint8_t path_a[I4_PATH_CAP],path_b[I4_PATH_CAP];
static struct {uint64_t pre[2];uint8_t bytes[I4_IDENTIFY_CAP];uint64_t post[2];} identify;
static int busy;
typedef struct {ST *st;I4_APPEND append;void *user;I4_MAP map;unsigned bad,partial;ES cleanup;} CTX;
static void copy_volatile(void *dest,const void *src,size_t n){
 uint8_t *d=dest;const volatile uint8_t *s=src;for(size_t i=0;i<n;i++)d[i]=s[i];
}
static int map_shape(const I4_MAP *map){
 return map&&map->data&&map->descriptor_bytes>=sizeof(I4_MD)&&map->descriptor_bytes<=256&&
 !(map->descriptor_bytes&7)&&map->bytes&&map->bytes<=I4_MAP_CAP&&
 !(map->bytes%map->descriptor_bytes)&&map->bytes/map->descriptor_bytes<=I4_MAP_ENTRIES;
}
int i4_range_readable(const I4_MAP *map,const void *ptr,size_t n){
 uint64_t pos=(uintptr_t)ptr,end;if(!ptr||!n||!map_shape(map)||n>UINT64_MAX-pos)return 0;end=pos+n;
 for(size_t step=0;step<=map->bytes/map->descriptor_bytes;step++){
  uint64_t next=pos;
  for(size_t off=0;off<map->bytes;off+=map->descriptor_bytes){
   I4_MD d;memcpy(&d,map->data+off,sizeof(d));
   if(d.type<1||d.type>6||(d.attributes&0x2000U)||!d.pages||d.pages>(UINT64_MAX-d.physical)/4096)continue;
   uint64_t top=d.physical+d.pages*4096;
   if(d.physical<=pos&&top>next)next=top;
  }
  if(next==pos)return 0;if(next>=end)return 1;pos=next;
 }
 return 0;
}
ES i4_path_copy(const I4_MAP *map,const uint8_t *src,uint8_t *dest,size_t *length){
 if(!length)return ERR(2);*length=0;if(!src||!dest||(uintptr_t)src>UINT64_MAX-I4_PATH_CAP)return ERR(2);
 size_t used=0;
 for(unsigned node=0;node<128;node++){
  uint8_t h[4];if(used>I4_PATH_CAP-4||!i4_range_readable(map,src+used,4))return ERR(2);
  copy_volatile(h,src+used,4);size_t n=(size_t)h[2]|((size_t)h[3]<<8);
  if(n<4||n>I4_PATH_CAP-used||!i4_range_readable(map,src+used,n))return ERR(4);
  copy_volatile(dest+used,src+used,n);
  if(!eq(h,dest+used,4))return ERR(13);
  used+=n;*length=used;
  if(h[0]==0x7f){if(n!=4||(h[1]!=1&&h[1]!=0xff))return ERR(4);if(h[1]==0xff)return 0;}
 }
 return ERR(4);
}
size_t i4_media_bytes(uint64_t rev){if(rev<0x10000)return 0;return rev>=0x2001f?48:(rev>=0x20001?44:32);}
int i4_media_fields_equal(uint64_t rev,const uint8_t *a,const uint8_t *b){
 size_t n=i4_media_bytes(rev);if(!n||!a||!b)return 0;
 return eq(a,b,9)&&eq(a+12,b+12,8)&&eq(a+24,b+24,n-24);
}
static void put(CTX *c,const char *s,size_t n){if(!c->bad&&!c->append(c->user,s,n))c->bad=1;}
static void text(CTX *c,const char *s){size_t n=0;while(s[n])n++;put(c,s,n);}
static void field(CTX *c,const char *name,uint64_t v,unsigned digits){
 char b[16];text(c,name);text(c,"=");for(unsigned i=0;i<digits;i++)b[i]="0123456789ABCDEF"[(v>>((digits-1-i)*4))&15];
 put(c,b,digits);text(c,"\r\n");
}
static void bytes(CTX *c,const char *name,const uint8_t *b,size_t n){
 text(c,name);text(c,"_HEX_BEGIN\r\n");char row[66];
 for(size_t i=0;i<n;){size_t count=n-i;if(count>32)count=32;
  for(size_t j=0;j<count;j++){row[j*2]="0123456789ABCDEF"[b[i+j]>>4];row[j*2+1]="0123456789ABCDEF"[b[i+j]&15];}
  row[count*2]='\r';row[count*2+1]='\n';put(c,row,count*2+2);i+=count;
 }text(c,name);text(c,"_HEX_END\r\n");
}
static ES refresh_map(CTX *c){
 typedef ES(EA *MAP)(UN *,void *,UN *,UN *,uint32_t *);
 UN size=sizeof(map_buf),key=0,ds=0;uint32_t ver=0;
 ES e=((MAP)c->st->bs->get_memory_map)(&size,map_buf,&key,&ds,&ver);
 field(c,"MEMORY_MAP_STATUS",e,16);field(c,"MEMORY_MAP_BYTES",size,8);
 field(c,"MEMORY_MAP_DESCRIPTOR_BYTES",ds,8);field(c,"MEMORY_MAP_VERSION",ver,8);
 c->map=(I4_MAP){map_buf,(size_t)size,(size_t)ds};
 if(FAILED(e)||ver!=1||!map_shape(&c->map)){c->map.bytes=0;c->partial=1;return FAILED(e)?e:ERR(2);}
 return 0;
}
static void capture_path(CTX *c,HANDLE handle){
 const uint8_t *path=0;ES e=c->st->bs->handle_protocol(handle,&path_guid,(void **)&path);
 field(c,"PATH_PROTOCOL_STATUS",e,16);field(c,"PATH_POINTER",(uintptr_t)path,16);
 if(FAILED(e)||!path)return;
 size_t an=0,bn=0;ES ae=i4_path_copy(&c->map,path,path_a,&an),be=i4_path_copy(&c->map,path,path_b,&bn);
 field(c,"PATH_FIRST_STATUS",ae,16);field(c,"PATH_SECOND_STATUS",be,16);
 field(c,"PATH_FIRST_BYTES",an,8);field(c,"PATH_SECOND_BYTES",bn,8);
 int stable=!FAILED(ae)&&!FAILED(be)&&an==bn&&eq(path_a,path_b,an);
 field(c,"PATH_STABLE",stable,2);
 if(an)bytes(c,"PATH_FIRST",path_a,an);
 if(!stable&&bn)bytes(c,"PATH_SECOND",path_b,bn);
 if(!stable)c->partial=1;
}
static int fn_ok(CTX *c,const void *fn){return fn&&i4_range_readable(&c->map,fn,1);}
static void pci_one(CTX *c,HANDLE h){
 PCI *p=0;ES e=c->st->bs->handle_protocol(h,&pci_guid,(void **)&p);
 field(c,"PROTOCOL_STATUS",e,16);field(c,"PROTOCOL_POINTER",(uintptr_t)p,16);
 if(FAILED(e)||!i4_range_readable(&c->map,p,0x78)){c->partial=1;return;}
 PCI local;memset(&local,0,sizeof(local));copy_volatile(&local,p,0x78);
 UN seg=UINT64_MAX,bus=UINT64_MAX,dev=UINT64_MAX,fun=UINT64_MAX;
 e=fn_ok(c,(const void *)local.location)?local.location(p,&seg,&bus,&dev,&fun):ERR(3);
 field(c,"LOCATION_STATUS",e,16);field(c,"SEGMENT",seg,16);field(c,"BUS",bus,16);field(c,"DEVICE",dev,16);field(c,"FUNCTION",fun,16);
 field(c,"LOCATION_VALID",!FAILED(e)&&seg<=65535&&bus<=255&&dev<=31&&fun<=7,2);
 uint8_t config[256];memset(config,0,sizeof(config));
 /* Uint8 width, byte offset zero, fixed 256-byte read. BARs never sized/written. */
 e=fn_ok(c,(const void *)local.pci.read)?local.pci.read(p,0,0,sizeof(config),config):ERR(3);
 field(c,"CONFIG_STATUS",e,16);if(!FAILED(e)){bytes(c,"CONFIG",config,sizeof(config));field(c,"CONFIG_CRC32",probe_crc32(config,sizeof(config)),8);}else c->partial=1;
 capture_path(c,h);
}
static void block_one(CTX *c,HANDLE h){
 I4_BLOCK *p=0;ES e=c->st->bs->handle_protocol(h,&block_guid,(void **)&p);
 field(c,"PROTOCOL_STATUS",e,16);field(c,"PROTOCOL_POINTER",(uintptr_t)p,16);
 if(FAILED(e)||!i4_range_readable(&c->map,p,16)){c->partial=1;return;}
 I4_BLOCK a,b;memset(&a,0,sizeof(a));memset(&b,0,sizeof(b));copy_volatile(&a,p,16);
 size_t n=i4_media_bytes(a.revision);field(c,"REVISION",a.revision,16);field(c,"MEDIA_POINTER",(uintptr_t)a.media,16);
 field(c,"MEDIA_BYTES",n,8);
 if(!n||!i4_range_readable(&c->map,a.media,n)){field(c,"MEDIA_READABLE",0,2);c->partial=1;capture_path(c,h);return;}
 uint8_t first[48]={0},second[48]={0};copy_volatile(first,a.media,n);
 /* No Stall, ReadBlocks or refresh command: compare the firmware's existing
  * metadata twice. Presence may remain stale until another driver refreshes it. */
 copy_volatile(second,a.media,n);copy_volatile(&b,p,16);
 int same=a.revision==b.revision&&a.media==b.media&&i4_media_fields_equal(a.revision,first,second);
 field(c,"MEDIA_READABLE",1,2);field(c,"MEDIA_FIELDS_STABLE",same,2);field(c,"MEDIA_REVISION_AFTER",b.revision,16);field(c,"MEDIA_POINTER_AFTER",(uintptr_t)b.media,16);
 bytes(c,"MEDIA_FIRST",first,n);bytes(c,"MEDIA_SECOND",second,n);if(!same)c->partial=1;
 capture_path(c,h);
}
static void disk_one(CTX *c,HANDLE h){
 I4_DISK *p=0;ES e=c->st->bs->handle_protocol(h,&disk_guid,(void **)&p);
 field(c,"PROTOCOL_STATUS",e,16);field(c,"PROTOCOL_POINTER",(uintptr_t)p,16);
 if(FAILED(e)||!i4_range_readable(&c->map,p,sizeof(*p))){c->partial=1;return;}
 I4_DISK local;copy_volatile(&local,p,sizeof(local));bytes(c,"INTERFACE_GUID_LE",(const uint8_t *)&local.interface,16);
 unsigned expected=eq(&local.interface,&nvme_guid,16)?4096:((eq(&local.interface,&ide_guid,16)||eq(&local.interface,&ahci_guid,16))?512:0);
 field(c,"IDENTIFY_EXPECTED_BYTES",expected,8);capture_path(c,h);
 if(!expected){text(c,"IDENTIFY_SKIPPED=INTERFACE_NOT_ALLOWLISTED\r\n");return;}
 if(!fn_ok(c,(const void *)local.identify)){text(c,"IDENTIFY_SKIPPED=GETTER_UNAVAILABLE\r\n");c->partial=1;return;}
 memset(&identify,0,sizeof(identify));identify.pre[0]=0x3150524547554152ULL;identify.pre[1]=0x3250524547554152ULL;
 identify.post[0]=0x31504F5354475541ULL;identify.post[1]=0x32504F5354475541ULL;
 /* A fixed initialized buffer, one call, no size-query retry and no PassThru.
  * For ATA the remainder is an additional overrun sentinel. */
 if(expected<sizeof(identify.bytes))memset(identify.bytes+expected,0xa6,sizeof(identify.bytes)-expected);
 uint32_t size=expected;e=local.identify(p,identify.bytes,&size);
 field(c,"IDENTIFY_STATUS",e,16);field(c,"IDENTIFY_RETURNED_BYTES",size,8);
 int guards=identify.pre[0]==0x3150524547554152ULL&&identify.pre[1]==0x3250524547554152ULL&&identify.post[0]==0x31504F5354475541ULL&&identify.post[1]==0x32504F5354475541ULL;
 for(size_t i=expected;i<sizeof(identify.bytes);i++)if(identify.bytes[i]!=0xa6)guards=0;
 field(c,"IDENTIFY_BUFFER_GUARDS_OK",guards,2);
 field(c,"IDENTIFY_FORMAT_SIZE_MATCH",!FAILED(e)&&size==expected,2);
 text(c,"IDENTIFY_SOURCE=STANDARD_DISKINFO_GETTER\r\nAMI_CACHE_IMPLEMENTATION_PROVEN=0\r\n");
 if(guards&&!FAILED(e)&&size&&size<=expected){bytes(c,"IDENTIFY",identify.bytes,size);field(c,"IDENTIFY_CRC32",probe_crc32(identify.bytes,size),8);}
 if(!guards||FAILED(e)||size!=expected)c->partial=1;
}
static void enumerate(CTX *c,const char *kind,GUID *guid,unsigned limit,void (*one)(CTX *,HANDLE)){
 HANDLE *handles=0;UN count=0;ES e=c->st->bs->locate_handles(2,guid,0,&count,&handles);
 text(c,"ENUM_BEGIN=");text(c,kind);text(c,"\r\n");field(c,"ENUM_STATUS",e,16);field(c,"ENUM_COUNT",count,16);field(c,"ENUM_LIMIT",limit,8);
 if(!FAILED(e)&&count&&handles){
  if(!FAILED(refresh_map(c))&&count<=UINT64_MAX/sizeof(HANDLE)&&i4_range_readable(&c->map,handles,(size_t)count*sizeof(HANDLE))){
   UN take=count;if(take>limit){take=limit;c->partial=1;}field(c,"ENUM_CAPTURED",take,8);field(c,"ENUM_TRUNCATED",take!=count,2);
   for(UN i=0;i<take&&!c->bad;i++){
    HANDLE h=0;copy_volatile(&h,handles+i,sizeof(h));text(c,kind);text(c,"_BEGIN\r\n");field(c,"INDEX",i,8);field(c,"HANDLE",(uintptr_t)h,16);
    one(c,h);text(c,kind);text(c,"_END\r\n");
   }
  }else{field(c,"ENUM_BUFFER_REJECTED",1,2);c->partial=1;}
 }else if(e!=ERR(14)&&!(e==0&&count==0)){c->partial=1;}
 if(handles){ES f=c->st->bs->free_pool(handles);field(c,"ENUM_FREE_STATUS",f,16);if(FAILED(f)){c->cleanup=f;c->partial=1;}}
 text(c,"ENUM_END=");text(c,kind);text(c,"\r\n");
}
ES pcie_storage_collect(ST *st,I4_APPEND append,void *user){
 if(busy)return ERR(20);
 if(!st||!st->bs||!append||!st->bs->get_memory_map||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(2);
 busy=1;CTX c={st,append,user,{0,0,0},0,0,0};
 text(&c,"I4_CATALOG_BEGIN\r\nSCHEMA=I4-READONLY-1\r\nPUBLICATION_ALLOWED=0\r\n");
 field(&c,"PCI_HANDLE_LIMIT",I4_PCI_LIMIT,8);field(&c,"BLOCK_HANDLE_LIMIT",I4_BLOCK_LIMIT,8);field(&c,"DISK_HANDLE_LIMIT",I4_DISK_LIMIT,8);
 field(&c,"DEVICE_PATH_LIMIT",I4_PATH_CAP,8);field(&c,"IDENTIFY_LIMIT",I4_IDENTIFY_CAP,8);
 enumerate(&c,"PCI",&pci_guid,I4_PCI_LIMIT,pci_one);
 if(!c.bad)enumerate(&c,"BLOCK",&block_guid,I4_BLOCK_LIMIT,block_one);
 if(!c.bad)enumerate(&c,"DISK",&disk_guid,I4_DISK_LIMIT,disk_one);
 field(&c,"COLLECTION_PARTIAL",c.partial,2);field(&c,"CLEANUP_STATUS",c.cleanup,16);text(&c,"I4_CATALOG_END\r\n");
 busy=0;return c.bad?ERR(5):(FAILED(c.cleanup)?c.cleanup:0);
}
