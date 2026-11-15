/* Bounded disposable-file writeback test. No SPI, PCI or RuntimeServices use. */
#include "efi_min.h"
#include "kvm.h"
#include "probe_core.h"
#include "contract.h"
#include <string.h>
typedef struct {uint32_t id;uint8_t removable,present,partition,readonly,cache;uint8_t pad[3];uint32_t block,align,pad2;uint64_t last;} MEDIA;
typedef struct {uint64_t revision;MEDIA *media;void *reset,*read,*write,*flush;} BIO;
OFF(MEDIA,block,12);OFF(MEDIA,last,24);OFF(BIO,media,8);
typedef struct USBIO USBIO;
struct USBIO {void *unused[8];ES(EA *get_interface)(USBIO *,uint8_t *);};
typedef ES(EA *CONNECT)(HANDLE,HANDLE *,void *,uint8_t);
OFF(USBIO,get_interface,0x40);OFF(BS,connect,0x108);
typedef ES(EA *GET_INFO)(FILEP *,GUID *,UN *,void *);
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID bio_guid={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID usb_guid={0x2b2f68d6,0x0cd2,0x44cf,{0x8e,0x8b,0xbb,0xa2,0x0b,0x1b,0x5b,0x75}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fsinfo_guid={0x09576e93,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fileinfo_guid={0x09576e92,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static char logbuf[4096];static size_t used;static unsigned overflow;
void *memset(void *p,int c,size_t n){uint8_t *b=p;while(n--)*b++=(uint8_t)c;return p;}
void *memcpy(void *p,const void *q,size_t n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;return p;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t u32(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static uint64_t u64(const void *p){uint64_t x;memcpy(&x,p,8);return x;}
static void put(const char *s){while(*s){if(used+1>=sizeof(logbuf)){overflow=1;return;}logbuf[used++]=*s++;}}
static void field(const char *s,uint64_t v){put(s);put("=0x");char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(v>>(60-i*4))&15];b[16]=0;put(b);put("\r\n");}
static int methods(FILEP *f){return f&&f->open&&f->close&&f->read&&f->get_info;}
static int usb_path(const uint8_t *p){
 unsigned total=0,usb=0;if(!p)return -1;
 for(unsigned nodes=0;nodes<64;nodes++){
  unsigned n=u16(p+2);if(n<4||n>4096||total+n>8192)return -1;
  if(p[0]==0x7f)return p[1]==0xff&&n==4?(int)usb:-1;
  if(p[0]==3&&((p[1]==5&&n==6)||(p[1]==15&&n==11)||(p[1]==16&&n>=10)))usb=1;
  total+=n;p+=n;
 }return -1;
}
static int geometry(MEDIA *m){return m&&m->present&&m->partition<=1&&!m->readonly&&m->block==512&&m->last==32767;}
static int absent(ES s){return s==ERR(3)||s==ERR(14);}
/* Never ConnectAll or connect a PCI/USB host controller. Existing USB_IO
 * interface descriptors are cached standard-protocol reads, not raw USB I/O.
 * First expand only unbound SCSI/BOT storage interfaces by one driver level.
 * Then recurse solely below a USB BlockIO with the disposable image geometry.
 * Recursive connection can execute the firmware's existing storage drivers;
 * this diagnostic itself calls no BlockIO WriteBlocks or raw USB transfer. */
ES connect_usb_storage(BS *bs){
 if(!bs||!bs->connect||!bs->locate_handles||!bs->handle_protocol||!bs->free_pool)return ERR(3);
 unsigned connected=0;
 for(unsigned pass=0;pass<2;pass++){
  HANDLE *handles=0;UN count=0;GUID *g=pass?&bio_guid:&usb_guid;
  ES s=bs->locate_handles(2,g,0,&count,&handles);
  if(s==ERR(14)&&!handles&&!count)continue;
  if(FAILED(s)||!handles||!count||count>128){if(handles)bs->free_pool(handles);return ERR(7);}
  field(pass?"CONNECT_BLOCKIO_HANDLES":"CONNECT_USBIO_HANDLES",count);
  ES failure=0;
  for(UN i=0;i<count;i++){
   uint8_t *dp=0;BIO *bio=0;FS *fs=0;
   s=bs->handle_protocol(handles[i],&dp_guid,(void **)&dp);
   if(FAILED(s)||!dp){failure=ERR(7);break;}
   int kind=usb_path(dp);if(kind<0){failure=ERR(7);break;}if(!kind)continue;
   if(!pass){
    USBIO *usb=0;uint8_t desc[9]={0};
    s=bs->handle_protocol(handles[i],&usb_guid,(void **)&usb);
    if(FAILED(s)||!usb||!usb->get_interface){failure=ERR(7);break;}
    s=usb->get_interface(usb,desc);
    if(FAILED(s)||desc[0]!=9||desc[1]!=4){failure=ERR(7);break;}
    if(desc[5]!=8||desc[6]!=6||desc[7]!=0x50||desc[4]!=2)continue;
    s=bs->handle_protocol(handles[i],&bio_guid,(void **)&bio);
    if(!FAILED(s)&&bio)continue;
    if(!absent(s)||bio){failure=ERR(7);break;}
   }else{
    s=bs->handle_protocol(handles[i],&bio_guid,(void **)&bio);
    if(FAILED(s)||!bio||!bio->media){failure=ERR(7);break;}
    if(!geometry(bio->media))continue;
   }
   s=bs->handle_protocol(handles[i],&fs_guid,(void **)&fs);
   if(!FAILED(s)&&fs)continue;
   if(!absent(s)||fs){failure=ERR(7);break;}
   if(++connected>32){failure=ERR(9);break;}
   s=((CONNECT)bs->connect)(handles[i],0,0,(uint8_t)(pass?1:0));
   field(pass?"CONNECT_USB_BLOCK_STATUS":"CONNECT_USB_INTERFACE_STATUS",s);
   if(FAILED(s)){failure=s;break;}
  }
  s=bs->free_pool(handles);if(FAILED(s)&&!FAILED(failure))failure=s;
  if(FAILED(failure))return failure;
 }
 field("CONNECT_SCOPED_CALLS",connected);return 0;
}
static ES info(FILEP *f,GUID *g,uint8_t *buffer,UN *size){
 memset(buffer,0,512);*size=512;ES s=((GET_INFO)f->get_info)(f,g,size,buffer);
 if(FAILED(s))return s;if(*size>512||*size<8||u64(buffer)>*size)return ERR(7);return 0;
}
static ES read_exact(FILEP *f,const uint8_t *expected,size_t length){
 uint8_t data[512];if(length>sizeof(data)||!methods(f))return ERR(2);
 uint8_t metadata[512];UN size=0;ES s=info(f,&fileinfo_guid,metadata,&size);
 if(FAILED(s)||size<82||u64(metadata)<82||u64(metadata+8)!=length||(u64(metadata+72)&0x10))return ERR(7);
 UN n=length;s=f->read(f,&n,data);if(FAILED(s)||n!=length||!equal(data,expected,length))return ERR(7);
 n=1;s=f->read(f,&n,data);return !FAILED(s)&&n==0?0:ERR(7);
}
static ES volume_matches(FILEP *root,int *matches){
 *matches=0;if(!methods(root))return ERR(3);
 uint8_t data[512];UN n=0;ES s=info(root,&fsinfo_guid,data,&n);
 static const C16 label[]=L"WBTEST02";
 field("VOLUME_INFO_STATUS",s);if(!FAILED(s)&&n>=36){field("OBSERVED_VOLUME_BYTES",u64(data+16));field("OBSERVED_VOLUME_BLOCK_SIZE",u32(data+32));}
 if(FAILED(s)||n<36+sizeof(label)||u64(data)<36+sizeof(label))return ERR(7);
 /* EFI_FILE_SYSTEM_INFO describes allocation units, not BlockIO sectors.
  * The pinned FAT16 BPB has 4 sectors/cluster and 8167 data clusters:
  * 2048-byte allocation units, 0xFF3800 managed bytes. Raw BlockIO remains
  * exactly 32768 * 512. EDK II FatGetInfo reports these cluster quantities. */
 if(data[8]||u64(data+16)!=16726016||u32(data+32)!=2048||u64(data+24)<2048||
    u64(data+24)>u64(data+16)||!equal(data+36,label,sizeof(label)))return 0;
 FILEP *marker=0;s=root->open(root,&marker,(C16 *)L"\\IDENTIFY.TXT",1,0);
 if(s==ERR(14)&&!marker)return 0;
 if(FAILED(s)||!marker){if(marker&&marker->close)marker->close(marker);return ERR(7);}
 if(!methods(marker)){if(marker->close)marker->close(marker);return ERR(3);}
 s=read_exact(marker,marker_bytes,sizeof(marker_bytes)-1);
 ES closed=marker->close(marker);if(FAILED(s)||FAILED(closed))return ERR(7);
 *matches=1;return 0;
}
/* This function is separately executed in native-code fault fixtures. */
ES write_selected(FILEP *root){
 if(!methods(root))return ERR(2);
 FILEP *f=0;ES s=root->open(root,&f,(C16 *)L"\\WRBACK.TXT",1,0);
 if(s!=ERR(14)||f){if(f&&f->close)f->close(f);return ERR(15);}
 s=root->open(root,&f,(C16 *)L"\\WRBACK.TXT",0x8000000000000003ULL,0);
 if(FAILED(s)||!f){if(f&&f->close)f->close(f);return FAILED(s)?s:ERR(7);}
 if(!methods(f)||!f->write||!f->flush){if(f->close)f->close(f);return ERR(3);}
 /* UEFI has no CREATE_EXCLUSIVE mode. If another actor created content after
  * our absence check, refuse it before Write. Never truncate or delete. */
 uint8_t metadata[512];UN size=0;s=info(f,&fileinfo_guid,metadata,&size);
 if(FAILED(s)||size<82||u64(metadata)<82||u64(metadata+8)||(u64(metadata+72)&0x11)){
  f->close(f);return ERR(15);
 }
 UN n=sizeof(result_bytes)-1;s=f->write(f,&n,(void *)result_bytes);
 field("FILE_WRITE_STATUS",s);field("FILE_WRITE_BYTES",n);
 if(!FAILED(s)&&n!=sizeof(result_bytes)-1)s=ERR(7);
 if(!FAILED(s)){s=f->flush(f);field("FILE_FLUSH_STATUS",s);}
 ES closed=f->close(f);field("FILE_CLOSE_STATUS",closed);if(!FAILED(s)&&FAILED(closed))s=closed;
 if(FAILED(s))return s;
 f=0;s=root->open(root,&f,(C16 *)L"\\WRBACK.TXT",1,0);
 if(FAILED(s)||!f){if(f&&f->close)f->close(f);return ERR(7);}
 if(!methods(f)){if(f->close)f->close(f);return ERR(3);}
 s=read_exact(f,result_bytes,sizeof(result_bytes)-1);closed=f->close(f);
 if(!FAILED(s)&&FAILED(closed))s=closed;
 field("UEFI_FILE_READBACK_STATUS",s);return s;
}
ES select_and_write(BS *bs){
 if(!bs||!bs->locate_handles||!bs->handle_protocol||!bs->free_pool)return ERR(3);
 HANDLE *handles=0;UN count=0;ES s=bs->locate_handles(2,&fs_guid,0,&count,&handles);
 if(FAILED(s)||!handles||!count||count>128){if(handles)bs->free_pool(handles);return ERR(3);}
 FILEP *chosen=0;HANDLE selected=0;uint32_t media_id=0;unsigned matches=0,uncertain=0;
 field("FILESYSTEM_HANDLES",count);
 for(UN i=0;i<count;i++){
  BIO *bio=0;uint8_t *dp=0;FS *fs=0;FILEP *root=0;
  if(FAILED(bs->handle_protocol(handles[i],&dp_guid,(void **)&dp))||!dp){uncertain=1;continue;}
  int kind=usb_path(dp);if(kind<0){uncertain=1;continue;}if(!kind)continue;
  if(FAILED(bs->handle_protocol(handles[i],&bio_guid,(void **)&bio))||!bio||!bio->media){uncertain=1;continue;}
  MEDIA *m=bio->media;field("MEDIA_BLOCK_BYTES",m->block);field("MEDIA_LAST_BLOCK",m->last);field("MEDIA_PARTITION",m->partition);
  if(!geometry(m))continue;
  field("MATCHING_GEOMETRY_LOGICAL_PARTITION",m->partition);
  if(FAILED(bs->handle_protocol(handles[i],&fs_guid,(void **)&fs))||!fs||!fs->open_volume){uncertain=1;continue;}
  s=fs->open_volume(fs,&root);if(FAILED(s)||!methods(root)){if(root&&root->close)root->close(root);uncertain=1;continue;}
  int matched=0;s=volume_matches(root,&matched);if(FAILED(s))uncertain=1;
  if(matched){
   matches++;if(!chosen){chosen=root;selected=handles[i];media_id=m->id;continue;}
  }
  if(FAILED(root->close(root)))uncertain=1;
 }
 if(FAILED(bs->free_pool(handles)))uncertain=1;
 field("EXACT_MATCHES",matches);field("ENUMERATION_UNCERTAIN",uncertain);
 if(matches!=1||uncertain){if(chosen)chosen->close(chosen);return ERR(15);}
 /* Recheck identity immediately before the only file mutation. */
 BIO *bio=0;uint8_t *dp=0;int matched=0;
 if(FAILED(bs->handle_protocol(selected,&bio_guid,(void **)&bio))||!bio||!geometry(bio->media)||bio->media->id!=media_id||
    FAILED(bs->handle_protocol(selected,&dp_guid,(void **)&dp))||usb_path(dp)!=1||
    FAILED(volume_matches(chosen,&matched))||!matched){chosen->close(chosen);return ERR(15);}
 s=write_selected(chosen);ES closed=chosen->close(chosen);if(!FAILED(s)&&FAILED(closed))s=closed;
 return s;
}
ES EA efi_main(HANDLE,ST *);
static ES(EA *const volatile entry_anchor)(HANDLE,ST *)=efi_main;
ES EA efi_main(HANDLE self,ST *st){
 (void)self;if(entry_anchor!=efi_main)return ERR(3);
 if(!st||!st->bs||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(3);
 used=overflow=0;put("MEDIA-WRITEBACK-01 DISPOSABLE TEST FILE ONLY\r\n");
 put("No flash/PCI/RuntimeServices calls. Only uniquely marked USB 16MiB WBTEST02.\r\n");
 typedef ES(EA *WATCHDOG)(UN,uint64_t,UN,C16 *);
 ES s=st->bs->set_watchdog?((WATCHDOG)st->bs->set_watchdog)(0,0,0,0):ERR(3);
 field("Watchdog.disable",s);if(FAILED(s))goto done;
 s=connect_usb_storage(st->bs);field("CONNECT_USB_STORAGE_STATUS",s);if(FAILED(s))goto done;
 s=select_and_write(st->bs);
done:
 field("TEST_STATUS",s);field("EXPECTED_FILE_BYTES",sizeof(result_bytes)-1);field("EXPECTED_FILE_CRC32",probe_crc32(result_bytes,sizeof(result_bytes)-1));
 put("Local workstation image reopen/hash verification is still required.\r\nPROBE_COMPLETE\r\n");
 if(overflow)return ERR(9);
 if(st->bs->allocate_pool&&st->bs->locate_protocol){ES shown=kvm_present(st,logbuf,used,FAILED(s)?1:0);if(!FAILED(s)&&FAILED(shown))s=shown;}
 return s;
}
