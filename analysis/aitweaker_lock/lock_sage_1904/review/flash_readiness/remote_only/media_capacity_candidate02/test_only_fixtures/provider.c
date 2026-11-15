/* LOCAL OVMF TEST ONLY. Synthetic USB/SCSI provider; never deploy to target.
 * It installs simulated protocol metadata and starts the unchanged production
 * EFI embedded as bytes. No USB/device transport exists in this fixture. */
#include "capacity_abi.h"
#include "candidate_blob.h"
#ifndef FIXTURE_MODE
#define FIXTURE_MODE 0
#endif
void *memset(void *p,int c,size_t n){uint8_t *b=p;while(n--)*b++=(uint8_t)c;return p;}
void *memcpy(void *p,const void *q,size_t n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;return p;}
static GUID usb_guid={0x2b2f68d6,0x0cd2,0x44cf,{0x8e,0x8b,0xbb,0xa2,0x0b,0x1b,0x5b,0x75}};
static GUID bio_guid={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID scsi_guid={0x932f47e6,0x2362,0x4002,{0x80,0x3e,0x3c,0xd5,0x4b,0x13,0x8f,0x85}};
static uint8_t path[]={0x02,0x01,0x0c,0x00,0xd0,0x41,0x03,0x0a,0,0,0,0,0x01,0x01,0x06,0,0,0x14,0x03,0x05,0x06,0,0x0c,0,0x03,0x05,0x06,0,0x01,0,0x7f,0xff,0x04,0};
static MEDIA media={.id=7,.removable=1,.present=1,.block=1024,.last=0x40000};
static BIO bio={.revision=0x2001f,.media=&media};
static unsigned commands;
static ES EA get_device(USBIO *self,uint8_t *p){(void)self;static const uint8_t d[18]={18,1,0,2,0,0,0,64,0x6b,0x04,0x31,0xff,4,5,1,2,3,1};memcpy(p,d,18);return 0;}
static ES EA get_iface(USBIO *self,uint8_t *p){(void)self;static const uint8_t d[9]={9,4,0,0,2,8,6,0x50,5};memcpy(p,d,9);return 0;}
static USBIO usb={.device=get_device,.interface=get_iface};
static ES EA get_type(SCSI_IO *self,uint8_t *type){(void)self;*type=0;return 0;}
static ES EA get_location(SCSI_IO *self,uint8_t **target,uint64_t *lun){(void)self;static uint8_t id[16];*target=id;*lun=0;return 0;}
static ES EA command(SCSI_IO *self,SCSI_PACKET *p,void *event){
 (void)self;if(commands++||event||p->timeout!=20000000||!p->in_data||p->in_length!=8||p->out_data||p->out_length||p->sense||p->sense_length||p->cdb_length!=10||p->direction!=0)return ERR(2);
 const uint8_t *c=p->cdb;if(!c||c[0]!=0x25)return ERR(3);for(unsigned i=1;i<10;i++)if(c[i])return ERR(2);
 p->host_status=p->target_status=0;
 if(FIXTURE_MODE==1){p->in_length=0;return ERR(18);}
 static const uint8_t result[8]={0,0,0x7f,0xff,0,0,2,0};memcpy(p->in_data,result,8);return 0;
}
static SCSI_IO scsi={.get_type=get_type,.get_location=get_location,.execute=command,.io_align=4096};
static void print(ST *st,const char *s){C16 b[256];unsigned i=0;while(s[i]&&i<255){b[i]=(uint8_t)s[i];i++;}b[i]=0;st->out->out(st->out,b);}
ES EA efi_main(HANDLE self,ST *st){
 typedef ES(EA *INSTALL)(HANDLE *,GUID *,uint32_t,void *);
 typedef ES(EA *UNINSTALL)(HANDLE,GUID *,void *);
 typedef ES(EA *LOAD)(uint8_t,HANDLE,void *,void *,UN,HANDLE *);
 typedef ES(EA *START)(HANDLE,UN *,C16 **);
 typedef ES(EA *UNLOAD)(HANDLE);
 if(!st||!st->bs)return ERR(3);BS *bs=st->bs;HANDLE handle=0,app=0;
 GUID *guids[]={&dp_guid,&usb_guid,&bio_guid,&scsi_guid};void *providers[]={path,&usb,&bio,&scsi};unsigned installed=0;
 ES s=0;for(;installed<4;installed++){s=((INSTALL)bs->install_protocol)(&handle,guids[installed],0,providers[installed]);if(s)break;}
 if(!s){print(st,FIXTURE_MODE==1?"LOCAL SYNTHETIC PROVIDER: TIMEOUT\r\n":"LOCAL SYNTHETIC PROVIDER: SUCCESS\r\n");s=((LOAD)bs->load_image)(0,self,0,(void *)candidate_blob,sizeof(candidate_blob),&app);}
 if(!s)s=((START)bs->start_image)(app,0,0);
 if(app)((UNLOAD)bs->unload_image)(app);
 while(installed){installed--;((UNINSTALL)bs->uninstall_protocol)(handle,guids[installed],providers[installed]);}
 print(st,commands==1?"FIXTURE_DONE_COMMANDS_1\r\n":"FIXTURE_DONE_UNEXPECTED_COUNT\r\n");
 return s;
}
