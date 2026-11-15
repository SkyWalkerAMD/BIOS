/* One synchronous READ CAPACITY(10), only through an existing SCSI_IO owner.
 * No raw USB/BOT fallback, controller connection, block data, file access,
 * SCSI write/reset, pass-through execution, PCI/SPI or RuntimeServices calls. */
#include "capacity_abi.h"
#include "kvm.h"
#include <string.h>
#define MAX_HANDLES 128
#define MAX_PATH 2048
#define MAX_NODES 64
#define LOG_SIZE 32768
#define TIMEOUT_100NS 20000000ULL
static GUID usb_guid={0x2b2f68d6,0x0cd2,0x44cf,{0x8e,0x8b,0xbb,0xa2,0x0b,0x1b,0x5b,0x75}};
static GUID bio_guid={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID scsi_guid={0x932f47e6,0x2362,0x4002,{0x80,0x3e,0x3c,0xd5,0x4b,0x13,0x8f,0x85}};
static GUID ext_guid={0x143b7632,0xb81b,0x4cb7,{0xab,0xd3,0xb6,0x25,0xa5,0xb9,0xbf,0xfe}};
static GUID ata_guid={0x2e3ab8b6,0xac9d,0x4d70,{0xa6,0x75,0x54,0xf5,0x2f,0xb2,0x2d,0x66}};
/* Complete path observed in USBINV01 on this SAGE system. It is not a
 * portable device selector; another path deliberately refuses execution. */
static const uint8_t pinned_path[]={0x02,0x01,0x0c,0x00,0xd0,0x41,0x03,0x0a,0,0,0,0,0x01,0x01,0x06,0,0,0x14,0x03,0x05,0x06,0,0x0c,0,0x03,0x05,0x06,0,0x01,0,0x7f,0xff,0x04,0};
typedef struct {
 HANDLE handle;uint8_t origin,id_match,path_valid,extra_instances;
 uint16_t path_len;uint8_t path[MAX_PATH],dev[18],iface[9];
 USBIO *usb;SCSI_IO *scsi;void *ext,*ata;BIO *bio;
 MEDIA cached;unsigned have_media;
} ITEM;
static ITEM items[MAX_HANDLES];static unsigned count,reported,uncertain,overflow,commands,rc_valid;
static char logbuf[LOG_SIZE];static size_t used,limit;
/* A 4096-aligned input buffer, with independently checked guards on both
 * sides. The provider is trusted firmware; guards detect bounded corruption,
 * not arbitrary malicious memory writes. */
_Alignas(4096) static uint8_t data_guard[12288];
static uint8_t cdb_guard[64];
void *memset(void *p,int c,size_t n){uint8_t *b=p;while(n--)*b++=(uint8_t)c;return p;}
void *memcpy(void *p,const void *q,size_t n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;return p;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t be32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static void put(const char *s){while(*s){if(used+1>=limit){overflow=1;return;}logbuf[used++]=*s++;}}
static void hex(uint64_t v,unsigned digits){char b[17];if(digits>16)digits=16;for(unsigned i=0;i<digits;i++)b[i]="0123456789ABCDEF"[(v>>(4*(digits-i-1)))&15];b[digits]=0;put(b);}
static void field(const char *s,uint64_t v,unsigned digits){put(s);hex(v,digits);put("\r\n");}
static void bytes(const uint8_t *b,unsigned n){for(unsigned i=0;i<n&&!overflow;i++)hex(b[i],2);}
static int missing(ES s){return s==ERR(3)||s==ERR(14);}
static ES protocol(BS *bs,HANDLE h,GUID *g,void **p,const char *name){
 *p=0;ES s=bs->handle_protocol(h,g,p);field(name,s,16);
 if((s!=0&&!missing(s))||(s==0&&!*p)){uncertain=1;put("PROTOCOL_UNCERTAIN=1\r\n");}
 return s;
}
/* Accept one complete, bounded device path. Multi-instance paths can be
 * inventoried but cannot authorize the fixed device. */
static int copy_path(const uint8_t *p,uint8_t *out,uint16_t *len,uint8_t *instances){
 unsigned total=0,nodes=0;*instances=0;*len=0;
 for(;nodes<MAX_NODES;nodes++){
  if(total>MAX_PATH-4)return 0;
  unsigned n=u16(p+total+2);if(n<4||n>MAX_PATH-total)return 0;
  uint8_t type=p[total],sub=p[total+1];
  if(type==0x7f){
   if(n!=4)return 0;
   if(sub==1)(*instances)++;else if(sub==0xff){total+=n;memcpy(out,p,total);*len=(uint16_t)total;return 1;}else return 0;
  }
  total+=n;
 }
 return 0;
}
static ES gather(BS *bs){
 GUID *g[]={&usb_guid,&scsi_guid,&ext_guid,&ata_guid};
 const char *names[]={"LOCATE_USB_IO=","LOCATE_SCSI_IO=","LOCATE_EXT_SCSI_PASS_THRU=","LOCATE_ATA_PASS_THRU="};
 ES result=0;
 for(unsigned group=0;group<4;group++){
  HANDLE *found=0;UN n=0;ES s=bs->locate_handles(2,g[group],0,&n,&found);field(names[group],s,16);field("RETURNED_HANDLES=",n,4);
  if(s==ERR(14)&&!n&&!found)continue;
  if(s!=0||!found||!n||n>MAX_HANDLES){uncertain=1;result=ERR(7);put("HANDLE_ENUMERATION_REJECTED=1\r\n");}
  else for(UN i=0;i<n;i++){
   if(!found[i]){uncertain=1;result=ERR(7);put("NULL_HANDLE=1\r\n");continue;}
   unsigned j=0;while(j<count&&items[j].handle!=found[i])j++;
   if(j==count){if(count==MAX_HANDLES){uncertain=1;result=ERR(9);put("HANDLE_UNION_LIMIT_EXCEEDED=1\r\n");break;}items[count++].handle=found[i];}
   items[j].origin|=(uint8_t)(1u<<group);
  }
  if(found){s=bs->free_pool(found);field("HANDLE_BUFFER_FREE=",s,16);if(s!=0){uncertain=1;result=s;}}
 }
 return result;
}
static void show_media(const MEDIA *m){
 field("MEDIA_ID=",m->id,8);field("MEDIA_PRESENT=",m->present,2);field("MEDIA_REMOVABLE=",m->removable,2);field("MEDIA_READ_ONLY=",m->readonly,2);
 field("MEDIA_LOGICAL_PARTITION=",m->partition,2);field("MEDIA_WRITE_CACHING=",m->cache,2);field("MEDIA_BLOCK_BYTES=",m->block,8);field("MEDIA_IO_ALIGN=",m->align,8);field("MEDIA_LAST_BLOCK=",m->last,16);
}
static void inspect(BS *bs,ITEM *a,unsigned index){
 field("HANDLE_BEGIN=",index,4);field("ENUM_SOURCE_MASK=",a->origin,1);
 uint8_t *p=0;ES s=protocol(bs,a->handle,&dp_guid,(void **)&p,"DP_STATUS=");
 if(s==0&&p){a->path_valid=(uint8_t)copy_path(p,a->path,&a->path_len,&a->extra_instances);if(!a->path_valid)uncertain=1;}
 field("DP_VALID=",a->path_valid,1);field("DP_BYTES=",a->path_len,4);field("DP_EXTRA_INSTANCES=",a->extra_instances,2);
 if(a->path_valid){if(used+a->path_len*2+64>=limit){overflow=1;return;}put("DP_HEX=");bytes(a->path,a->path_len);put("\r\n");}
 s=protocol(bs,a->handle,&usb_guid,(void **)&a->usb,"USB_IO_STATUS=");
 if(s==0&&a->usb){
  ES d=a->usb->device?a->usb->device(a->usb,a->dev):ERR(3),f=a->usb->interface?a->usb->interface(a->usb,a->iface):ERR(3);
  field("USB_DEVICE_STATUS=",d,16);field("USB_INTERFACE_STATUS=",f,16);
  if(d==0&&f==0){
   put("USB_DEVICE_HEX=");bytes(a->dev,18);put("\r\nUSB_INTERFACE_HEX=");bytes(a->iface,9);put("\r\n");
   unsigned valid=a->dev[0]==18&&a->dev[1]==1&&a->iface[0]==9&&a->iface[1]==4;
   field("USB_DESCRIPTORS_VALID=",valid,1);if(!valid)uncertain=1;
   if(valid){field("USB_VID=",u16(a->dev+8),4);field("USB_PID=",u16(a->dev+10),4);
    a->id_match=(uint8_t)(u16(a->dev+8)==0x046b&&u16(a->dev+10)==0xff31&&a->iface[5]==8&&a->iface[6]==6&&a->iface[7]==0x50);
   }
  }else uncertain=1;
 }
 field("TARGET_ID_MATCH=",a->id_match,1);
 s=protocol(bs,a->handle,&bio_guid,(void **)&a->bio,"BLOCK_IO_STATUS=");
 if(s==0&&a->bio){field("BLOCK_IO_REVISION=",a->bio->revision,16);if(a->bio->media){memcpy(&a->cached,a->bio->media,sizeof(MEDIA));a->have_media=1;show_media(&a->cached);}else{uncertain=1;put("MEDIA_POINTER_NULL=1\r\n");}}
 void *fs=0;s=protocol(bs,a->handle,&fs_guid,&fs,"SFS_STATUS=");field("SFS_PUBLISHED=",s==0&&fs,1);
 s=protocol(bs,a->handle,&scsi_guid,(void **)&a->scsi,"SCSI_IO_STATUS=");if(s!=0)a->scsi=0;
 s=protocol(bs,a->handle,&ext_guid,&a->ext,"EXT_SCSI_PASS_THRU_STATUS=");if(s!=0)a->ext=0;
 s=protocol(bs,a->handle,&ata_guid,&a->ata,"ATA_PASS_THRU_STATUS=");if(s!=0)a->ata=0;
 if(a->scsi&&(!a->path_valid||a->extra_instances)){uncertain=1;put("SCSI_ASSOCIATION_UNCERTAIN=1\r\n");}
 /* An enumerated protocol must still exist on the returned handle. */
 if(((a->origin&1)&&!a->usb)||((a->origin&2)&&!a->scsi)||((a->origin&4)&&!a->ext)||((a->origin&8)&&!a->ata)){uncertain=1;put("ENUMERATED_PROTOCOL_MISSING=1\r\n");}
 field("HANDLE_END=",index,4);if(!overflow)reported++;
}
/* 1=exact, 2=single LUN0 child, 3=ancestor, 4=other descendant,
 * 0=unrelated, 5=invalid/multi-instance. No prefix alone authorizes a CDB. */
static unsigned association(const ITEM *a,const ITEM *target){
 if(!a->path_valid||!target->path_valid||a->extra_instances||target->extra_instances)return 5;
 unsigned n=target->path_len;
 if(a->path_len==n&&equal(a->path,target->path,n))return 1;
 if(a->path_len==n+5&&equal(a->path,target->path,n-4)&&equal(a->path+n-4,"\x03\x11\x05\x00\x00\x7f\xff\x04\x00",9))return 2;
 if(a->path_len<n&&a->path_len>=4&&equal(a->path,target->path,a->path_len-4))return 3;
 if(a->path_len>n&&equal(a->path,target->path,n-4))return 4;
 return 0;
}
static ES reject(const char *why){put("RC10_BLOCKED=");put(why);put("\r\n");return ERR(3);}
static int recheck_path(BS *bs,ITEM *a){
 uint8_t *p=0,b[MAX_PATH],instances=0;uint16_t n=0;
 ES s=bs->handle_protocol(a->handle,&dp_guid,(void **)&p);
 return s==0&&p&&copy_path(p,b,&n,&instances)&&!instances&&n==a->path_len&&equal(b,a->path,n);
}
static int media_same(const MEDIA *a,const MEDIA *b){
 return a->id==b->id&&a->removable==b->removable&&a->present==b->present&&a->partition==b->partition&&a->readonly==b->readonly&&a->cache==b->cache&&a->block==b->block&&a->align==b->align&&a->last==b->last;
}
static ES observe(BS *bs,ITEM *target,ITEM *owner){
 SCSI_IO *scsi=0;USBIO *usb=0;uint8_t dev[18]={0},iface[9]={0};
 if(bs->handle_protocol(target->handle,&usb_guid,(void **)&usb)!=0||!usb||usb!=target->usb||!usb->device||!usb->interface||
    usb->device(usb,dev)!=0||usb->interface(usb,iface)!=0||!equal(dev,target->dev,18)||!equal(iface,target->iface,9)||!recheck_path(bs,target)||!recheck_path(bs,owner))return reject("TARGET_CHANGED");
 if(bs->handle_protocol(owner->handle,&scsi_guid,(void **)&scsi)!=0||!scsi||scsi!=owner->scsi)return reject("SCSI_OWNER_CHANGED");
 if(!scsi->get_type||!scsi->get_location||!scsi->execute)return reject("SCSI_METHOD_MISSING");
 uint32_t align=scsi->io_align;field("SCSI_IO_ALIGN=",align,8);
 if(align>4096||(align>1&&(align&(align-1))))return reject("SCSI_ALIGNMENT");
 uint8_t type=0xff;ES s=scsi->get_type(scsi,&type);field("GET_DEVICE_TYPE_STATUS=",s,16);field("SCSI_DEVICE_TYPE=",type,2);
 if(s!=0||type!=0)return reject("SCSI_NOT_DIRECT_ACCESS");
 uint8_t *target_id=0;uint64_t lun=~0ULL;s=scsi->get_location(scsi,&target_id,&lun);field("GET_DEVICE_LOCATION_STATUS=",s,16);field("SCSI_LUN=",lun,16);field("SCSI_TARGET_POINTER_PRESENT=",target_id!=0,1);
 /* Target ID storage is owned by the provider and deliberately not read. */
 if(s!=0||!target_id||lun!=0)return reject("SCSI_LOCATION");
 if(overflow||uncertain)return reject("INVENTORY_INCOMPLETE");
 if(target->have_media){BIO *bio=0;if(bs->handle_protocol(target->handle,&bio_guid,(void **)&bio)!=0||bio!=target->bio||!bio||!bio->media||!media_same(&target->cached,bio->media))return reject("CACHED_MEDIA_CHANGED_BEFORE");}
 memset(data_guard,0xa5,sizeof(data_guard));memset(cdb_guard,0x5a,sizeof(cdb_guard));
 uint8_t *data=data_guard+4096,*cdb=cdb_guard+16;memset(data,0,8);memset(cdb,0,10);cdb[0]=0x25;
 SCSI_PACKET packet;memset(&packet,0,sizeof(packet));packet.timeout=TIMEOUT_100NS;packet.in_data=data;packet.cdb=cdb;packet.in_length=8;packet.cdb_length=10;packet.direction=0;packet.host_status=packet.target_status=0xff;
 put("RC10_CDB=25000000000000000000\r\n");field("RC10_TIMEOUT_100NS=",TIMEOUT_100NS,16);put("RC10_EVENT_NULL=1\r\n");
 commands=1;s=scsi->execute(scsi,&packet,0);
 field("RC10_STATUS=",s,16);field("RC10_HOST_STATUS=",packet.host_status,2);field("RC10_TARGET_STATUS=",packet.target_status,2);field("RC10_RETURNED_BYTES=",packet.in_length,8);field("RC10_RETURNED_SENSE_BYTES=",packet.sense_length,2);
 unsigned guards=1;
 for(unsigned i=0;i<sizeof(data_guard);i++)if((i<4096||i>=4104)&&data_guard[i]!=0xa5)guards=0;
 for(unsigned i=0;i<sizeof(cdb_guard);i++)if((i<16||i>=26)&&cdb_guard[i]!=0x5a)guards=0;
 static const uint8_t expected_cdb[10]={0x25,0,0,0,0,0,0,0,0,0};
 unsigned intact=packet.timeout==TIMEOUT_100NS&&packet.in_data==data&&!packet.out_data&&!packet.sense&&packet.cdb==cdb&&packet.out_length==0&&packet.cdb_length==10&&packet.direction==0&&packet.sense_length==0&&equal(cdb,expected_cdb,10);
 field("RC10_GUARDS_OK=",guards,1);field("RC10_PACKET_INPUTS_UNCHANGED=",intact,1);
 if(!guards||!intact){put("RC10_FAILURE=PROVIDER_CONTRACT\r\n");return ERR(7);}
 if(s!=0||packet.host_status||packet.target_status||packet.in_length!=8){put("RC10_FAILURE=TRANSPORT_OR_LENGTH\r\n");return s!=0?s:ERR(7);}
 put("RC10_DATA_HEX=");bytes(data,8);put("\r\n");uint32_t last=be32(data),block=be32(data+4);
 field("RC10_LAST_LBA=",last,8);field("RC10_BLOCK_BYTES=",block,8);
 if(!block||last==0xffffffffU){put("RC10_FAILURE=ZERO_BLOCK_OR_RC16_REQUIRED\r\n");return ERR(3);}
 rc_valid=1;field("RC10_CAPACITY_BYTES=",((uint64_t)last+1)*block,16);
 if(target->have_media){
  field("RC10_MATCHES_CACHED_BEFORE=",last==target->cached.last&&block==target->cached.block,1);
  BIO *bio=0;ES after=bs->handle_protocol(target->handle,&bio_guid,(void **)&bio);field("CACHED_AFTER_STATUS=",after,16);
  if(after!=0||bio!=target->bio||!bio||!bio->media){put("CACHED_AFTER_VALID=0\r\n");return ERR(7);}
  MEDIA m;memcpy(&m,bio->media,sizeof(m));put("CACHED_AFTER_VALID=1\r\nCACHED_AFTER_BEGIN\r\n");show_media(&m);put("CACHED_AFTER_END\r\n");field("CACHED_MEDIA_UNCHANGED=",media_same(&target->cached,&m),1);field("RC10_MATCHES_CACHED_AFTER=",last==m.last&&block==m.block,1);
 }else put("CACHED_MEDIA_COMPARISON=UNAVAILABLE\r\n");
 return 0;
}
ES run_capacity(BS *bs){
 ES s=gather(bs);field("HANDLE_UNION_COUNT=",count,4);
 for(unsigned i=0;i<count&&!overflow;i++)inspect(bs,&items[i],i);
 unsigned matches=0,target_index=0;for(unsigned i=0;i<count;i++)if(items[i].id_match){matches++;target_index=i;}
 field("TARGET_ID_COUNT=",matches,4);
 if(matches!=1)return reject(matches?"TARGET_AMBIGUOUS":"TARGET_ABSENT");
 ITEM *target=&items[target_index];field("TARGET_HANDLE_INDEX=",target_index,4);
 unsigned owners=0,owner_index=0;
 for(unsigned i=0;i<count&&!overflow;i++){
  ITEM *a=&items[i];if(!a->scsi&&!a->ext&&!a->ata)continue;
  unsigned relation=association(a,target);field("ASSOCIATION_HANDLE=",i,4);field("ASSOCIATION_KIND=",relation,1);
  field("ASSOCIATED_SCSI_IO=",a->scsi!=0,1);field("ASSOCIATED_EXT_SCSI=",a->ext!=0,1);field("ASSOCIATED_ATA=",a->ata!=0,1);
  if(a->scsi&&(relation==1||relation==2)){owners++;owner_index=i;}
 }
 field("SCSI_EXECUTABLE_OWNER_COUNT=",owners,4);
 if(overflow||uncertain||s!=0||reported!=count)return reject("INVENTORY_INCOMPLETE");
 if(!target->path_valid||target->extra_instances||target->path_len!=sizeof(pinned_path)||!equal(target->path,pinned_path,sizeof(pinned_path)))return reject("TARGET_PATH_NOT_PINNED");
 if(target->iface[2]||target->iface[3]||target->iface[4]!=2)return reject("TARGET_INTERFACE_NOT_PINNED");
 if(owners!=1)return reject(owners?"SCSI_OWNER_AMBIGUOUS":"NO_STANDARD_SCSI_IO");
 field("SCSI_OWNER_HANDLE_INDEX=",owner_index,4);limit=LOG_SIZE-1024;
 return observe(bs,target,&items[owner_index]);
}
ES EA efi_main(HANDLE,ST *);
static ES(EA *const volatile entry_anchor)(HANDLE,ST *)=efi_main;
ES EA efi_main(HANDLE self,ST *st){
 (void)self;if(entry_anchor!=efi_main)return ERR(3);
 if(!st||!st->bs||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(3);
 memset(items,0,sizeof(items));used=count=reported=uncertain=overflow=commands=rc_valid=0;limit=LOG_SIZE-4096;
 put("MEDIA-CAPACITY-02 STANDARD SCSI OWNER ONLY\r\nOne bounded READ CAPACITY(10); no block data, raw USB, pass-through execution or writes.\r\nSELECTOR_DP_HEX=");bytes(pinned_path,sizeof(pinned_path));put("\r\n");
 typedef ES(EA *WATCHDOG)(UN,uint64_t,UN,C16 *);
 ES s=st->bs->set_watchdog?((WATCHDOG)st->bs->set_watchdog)(0,0,0,0):ERR(3);field("WATCHDOG_DISABLE=",s,16);
 if(s==0)s=run_capacity(st->bs);else uncertain=1;
 unsigned had_overflow=overflow;limit=LOG_SIZE;overflow=0;
 if(had_overflow){put("\r\nLOG_OVERFLOW=1\r\nOBSERVATION_PARTIAL=1\r\n");s=ERR(9);}else put("LOG_OVERFLOW=0\r\n");
 field("HANDLES_REPORTED=",reported,4);field("INVENTORY_COMPLETE=",!had_overflow&&!uncertain&&reported==count,1);field("ENUMERATION_UNCERTAIN=",uncertain,1);
 field("RC10_COMMANDS=",commands,1);field("RC10_VALID=",rc_valid,1);field("TEST_STATUS=",s,16);
 put("FILE_OPS=0 BLOCK_DATA_OPS=0 RAW_USB_OPS=0 CONNECT_OPS=0\r\nSCSI_WRITE_OPS=0 SCSI_RESET_OPS=0 PASSTHRU_COMMANDS=0 RUNTIME_OPS=0\r\nPROBE_COMPLETE\r\n");
 if(overflow)return ERR(9);
 if(st->bs->allocate_pool&&st->bs->locate_protocol){ES shown=kvm_present(st,logbuf,used,s!=0);if(s==0&&shown!=0)s=shown;}
 return s;
}
