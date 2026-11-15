/* Existing UEFI metadata only. No ConnectController, file, BlockIO data, raw
 * USB transfer, PCI/SPI, RuntimeServices, variable or reset calls. */
#include "efi_min.h"
#include "kvm.h"
#include <string.h>
typedef struct {uint32_t id;uint8_t removable,present,partition,readonly,cache;uint8_t pad[3];uint32_t block,align,pad2;uint64_t last;} MEDIA;
typedef struct {uint64_t revision;MEDIA *media;void *reset,*read,*write,*flush;} BIO;
typedef struct USBIO USBIO;
struct USBIO {void *transfer[6];ES(EA *device)(USBIO *,uint8_t *);void *config;ES(EA *interface)(USBIO *,uint8_t *);};
OFF(MEDIA,block,12);OFF(MEDIA,last,24);OFF(BIO,media,8);OFF(USBIO,device,0x30);OFF(USBIO,interface,0x40);
static GUID usb_guid={0x2b2f68d6,0x0cd2,0x44cf,{0x8e,0x8b,0xbb,0xa2,0x0b,0x1b,0x5b,0x75}};
static GUID bio_guid={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
#define MAX_HANDLES 128
#define LOG_SIZE 32768
#define FOOTER_RESERVE 512
#define MAX_PATH 2048
#define MAX_NODES 64
static char logbuf[LOG_SIZE];static size_t used,limit;static unsigned overflow,uncertain;
static HANDLE inventory[MAX_HANDLES];static uint8_t origins[MAX_HANDLES];static unsigned count,reported;
void *memset(void *p,int c,size_t n){uint8_t *b=p;while(n--)*b++=(uint8_t)c;return p;}
void *memcpy(void *p,const void *q,size_t n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;return p;}
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static void put(const char *s){while(*s){if(used+1>=limit){overflow=1;return;}logbuf[used++]=*s++;}}
static void hex(uint64_t v,unsigned digits){char b[17];if(digits>16)digits=16;for(unsigned i=0;i<digits;i++)b[i]="0123456789ABCDEF"[(v>>(4*(digits-i-1)))&15];b[digits]=0;put(b);}
static void field(const char *s,uint64_t v,unsigned digits){put(s);hex(v,digits);put("\r\n");}
static void bytes(const uint8_t *b,unsigned n){for(unsigned i=0;i<n&&!overflow;i++)hex(b[i],2);}
static int missing(ES s){return s==ERR(3)||s==ERR(14);}
static void status(const char *label,ES s,void *p){field(label,s,16);if((FAILED(s)&&!missing(s))||(!FAILED(s)&&!p)){uncertain=1;put("PROTOCOL_UNCERTAIN=1\r\n");}}

/* All protocol providers are inventoried, including non-USB/internal devices.
 * No filtered selection and no implicit controller connection is performed. */
ES gather_handles(BS *bs){
 GUID *g[3]={&usb_guid,&bio_guid,&fs_guid};const char *name[3]={"LOCATE_USB_IO=","LOCATE_BLOCK_IO=","LOCATE_SFS="};
 ES overall=0;
 for(unsigned group=0;group<3;group++){
  HANDLE *found=0;UN n=0;ES s=bs->locate_handles(2,g[group],0,&n,&found);
  field(name[group],s,16);field("RETURNED_HANDLES=",n,4);
  if(s==ERR(14)&&!n&&!found)continue;
  if(FAILED(s)||!found||!n||n>MAX_HANDLES){uncertain=1;overall=ERR(7);put("HANDLE_ENUMERATION_REJECTED=1\r\n");}
  else for(UN i=0;i<n;i++){
   if(!found[i]){uncertain=1;overall=ERR(7);put("NULL_HANDLE=1\r\n");continue;}
   unsigned j=0;while(j<count&&inventory[j]!=found[i])j++;
   if(j==count){if(count==MAX_HANDLES){uncertain=1;overall=ERR(9);put("HANDLE_UNION_LIMIT_EXCEEDED=1\r\n");break;}inventory[count++]=found[i];}
   origins[j]|=(uint8_t)(1u<<group);
  }
  if(found){s=bs->free_pool(found);field("HANDLE_BUFFER_FREE=",s,16);if(FAILED(s)){uncertain=1;overall=s;}}
 }
 return overall;
}

static void show_path(BS *bs,HANDLE handle){
 const uint8_t *p=0;ES s=bs->handle_protocol(handle,&dp_guid,(void **)&p);status("DP_STATUS=",s,(void *)p);
 if(FAILED(s)||!p)return;
 unsigned total=0,nodes=0,usb=0,instances=0;int valid=0;
 for(;nodes<MAX_NODES;nodes++){
  if(total>MAX_PATH-4)break;
  unsigned n=u16(p+total+2);if(n<4||n>MAX_PATH-total)break;
  uint8_t type=p[total],sub=p[total+1];
  if(type==3&&(sub==5||sub==15||sub==16))usb=1;
  if(type==0x7f){if(n!=4)break;if(sub==1)instances++;else if(sub==0xff){total+=n;nodes++;valid=1;break;}else break;}
  total+=n;
 }
 field("DP_VALID=",valid,1);field("DP_BYTES=",total,4);field("DP_NODES=",nodes,2);field("DP_USB_NODE=",usb,1);field("DP_EXTRA_INSTANCES=",instances,2);
 if(!valid){uncertain=1;put("DP_ERROR=MALFORMED_OR_BOUND_EXCEEDED\r\n");return;}
 /* Log each valid path in full or explicitly stop; never silently truncate. */
 if(used+total*2+64>=limit){overflow=1;return;}
 put("DP_HEX=");bytes(p,total);put("\r\n");
}

static void show_usb(BS *bs,HANDLE handle){
 USBIO *usb=0;ES s=bs->handle_protocol(handle,&usb_guid,(void **)&usb);status("USB_IO_STATUS=",s,usb);
 if(FAILED(s)||!usb)return;
 uint8_t dev[18]={0},iface[9]={0};
 s=usb->device?usb->device(usb,dev):ERR(3);field("USB_DEVICE_STATUS=",s,16);
 if(!FAILED(s)){
  put("USB_DEVICE_HEX=");bytes(dev,sizeof(dev));put("\r\n");
  unsigned valid=dev[0]==18&&dev[1]==1;field("USB_DEVICE_VALID=",valid,1);
  if(valid){field("USB_VID=",u16(dev+8),4);field("USB_PID=",u16(dev+10),4);field("USB_DEVICE_CLASS=",dev[4],2);field("USB_DEVICE_SUBCLASS=",dev[5],2);field("USB_DEVICE_PROTOCOL=",dev[6],2);field("VENDOR_HD_ID_MATCH=",u16(dev+8)==0x046b&&u16(dev+10)==0xff31,1);}
  else uncertain=1;
 }else uncertain=1;
 s=usb->interface?usb->interface(usb,iface):ERR(3);field("USB_INTERFACE_STATUS=",s,16);
 if(!FAILED(s)){
  put("USB_INTERFACE_HEX=");bytes(iface,sizeof(iface));put("\r\n");
  unsigned valid=iface[0]==9&&iface[1]==4;field("USB_INTERFACE_VALID=",valid,1);
  if(valid){field("USB_INTERFACE_NUMBER=",iface[2],2);field("USB_INTERFACE_ALT=",iface[3],2);field("USB_ENDPOINTS=",iface[4],2);field("USB_INTERFACE_CLASS=",iface[5],2);field("USB_INTERFACE_SUBCLASS=",iface[6],2);field("USB_INTERFACE_PROTOCOL=",iface[7],2);}
  else uncertain=1;
 }else uncertain=1;
}

static void show_bio(BS *bs,HANDLE handle){
 BIO *bio=0;ES s=bs->handle_protocol(handle,&bio_guid,(void **)&bio);status("BLOCK_IO_STATUS=",s,bio);
 if(FAILED(s)||!bio)return;
 field("BLOCK_IO_REVISION=",bio->revision,16);
 if(!bio->media){uncertain=1;put("MEDIA_POINTER_NULL=1\r\n");return;}
 MEDIA m;memcpy(&m,bio->media,sizeof(m));
 field("MEDIA_ID=",m.id,8);field("MEDIA_PRESENT=",m.present,2);field("MEDIA_REMOVABLE=",m.removable,2);field("MEDIA_READ_ONLY=",m.readonly,2);
 field("MEDIA_LOGICAL_PARTITION=",m.partition,2);field("MEDIA_WRITE_CACHING=",m.cache,2);field("MEDIA_BLOCK_BYTES=",m.block,8);field("MEDIA_IO_ALIGN=",m.align,8);field("MEDIA_LAST_BLOCK=",m.last,16);
 /* BIO data/reset/flush pointers deliberately remain untouched. */
}

ES run_inventory(BS *bs){
 ES s=gather_handles(bs);field("HANDLE_UNION_COUNT=",count,4);
 for(unsigned i=0;i<count&&!overflow;i++){
  put("HANDLE_BEGIN=");hex(i,4);put("\r\n");field("ENUM_SOURCE_MASK=",origins[i],1);
  show_path(bs,inventory[i]);if(overflow)break;show_usb(bs,inventory[i]);if(overflow)break;show_bio(bs,inventory[i]);if(overflow)break;
  FS *fs=0;ES q=bs->handle_protocol(inventory[i],&fs_guid,(void **)&fs);status("SFS_STATUS=",q,fs);
  field("SFS_PUBLISHED=",!FAILED(q)&&fs!=0,1);field("HANDLE_END=",i,4);reported++;
 }
 if(overflow)return ERR(9);return uncertain?ERR(7):s;
}

ES EA efi_main(HANDLE,ST *);
static ES(EA *const volatile entry_anchor)(HANDLE,ST *)=efi_main;
ES EA efi_main(HANDLE self,ST *st){
 (void)self;if(entry_anchor!=efi_main)return ERR(3);
 if(!st||!st->bs||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(3);
 memset(inventory,0,sizeof(inventory));memset(origins,0,sizeof(origins));used=overflow=uncertain=count=reported=0;limit=LOG_SIZE-FOOTER_RESERVE;
 put("MEDIA-USB-INVENTORY-01 EXISTING PROTOCOL METADATA ONLY\r\nNo controller connection, file access, storage data transfer or firmware access.\r\n");
 typedef ES(EA *WATCHDOG)(UN,uint64_t,UN,C16 *);
 ES s=st->bs->set_watchdog?((WATCHDOG)st->bs->set_watchdog)(0,0,0,0):ERR(3);field("WATCHDOG_DISABLE=",s,16);
 if(!FAILED(s))s=run_inventory(st->bs);else uncertain=1;
 unsigned had_overflow=overflow;limit=LOG_SIZE;overflow=0;
 if(had_overflow){put("\r\nLOG_OVERFLOW=1\r\nINVENTORY_PARTIAL=1\r\n");s=ERR(9);}else put("LOG_OVERFLOW=0\r\n");
 field("HANDLES_REPORTED=",reported,4);field("INVENTORY_COMPLETE=",!had_overflow&&!uncertain&&reported==count,1);field("ENUMERATION_UNCERTAIN=",uncertain,1);field("TEST_STATUS=",s,16);
 put("FILE_OPS=0 BLOCK_DATA_OPS=0 RAW_USB_OPS=0 CONNECT_OPS=0\r\nPROBE_COMPLETE\r\n");
 if(overflow)return ERR(9);
 if(st->bs->allocate_pool&&st->bs->locate_protocol){ES shown=kvm_present(st,logbuf,used,FAILED(s)?1:0);if(!FAILED(s)&&FAILED(shown))s=shown;}
 return s;
}
