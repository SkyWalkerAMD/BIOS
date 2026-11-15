#include "lock.h"
#include "status.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID end_dxe_guid={0x02ce967a,0xdd7e,0x4ffc,{0x9e,0xe7,0x81,0x0c,0xf0,0x47,0x08,0x80}};
static GUID smbios3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID smbios_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID tse_guid={0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}};
static GUID setup_guid={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
static int scanning,attempted,matching_board;
static uint32_t attach_attempts,late_observed,ambiguous_images;
static EVENT discovery_timer,loaded_event,browser_event,end_dxe_event;
static void *loaded_registration,*browser_registration;
static int equal_ascii(const uint8_t *s,UN size,const char *want) {
 UN i=0;for(;i<size && want[i];i++)if(s[i]!=(uint8_t)want[i])return 0;
 return i<size && !want[i] && !s[i];
}
static int smbios_string(const uint8_t *s,UN n,uint8_t index,const char *wanted) {
 if(!index)return 0;
 UN p=s[1];for(unsigned i=1;i<index;i++) {while(p<n && s[p])p++;if(p+1>=n || !s[p+1])return 0;p++;}
 return p<n && equal_ascii(s+p,n-p,wanted);
}
static int smbios_table(uint8_t *data,UN size) {
 if(size<6 || size>2*1024*1024 || !memory_present(data,size,0))return 0;
 int board=0,version=0;
 for(UN p=0,count=0;p+6<=size && count<4096;count++) {
  uint8_t type=data[p],length=data[p+1];if(length<4 || length>size-p)return 0;
  UN end=p+length;while(end+1<size && (data[end] || data[end+1]))end++;
  if(end+1>=size)return 0;end+=2;
  if(type==0 && length>=6)version=smbios_string(data+p,end-p,data[p+5],"1904");
  if(type==2 && length>=6)board=smbios_string(data+p,end-p,data[p+5],"Pro WS W790-ACE");
  if(type==127)break;p=end;
 }
 return board && version;
}
static int board_matches(void) {
 for(UN i=0;i<system_table->table_count;i++) {
  CT *ct=&system_table->tables[i];uint8_t *p=ct->table;UN length=0,size=0;uint64_t address=0;
  if(!memcmp(&ct->guid,&smbios3_guid,16)) {
   if(!memory_present(p,24,0) || memcmp(p,"_SM3_",5))continue;
   length=p[6];if(length<24 || length>64 || !memory_present(p,length,0))continue;
   uint32_t n;memcpy(&n,p+12,4);size=n;memcpy(&address,p+16,8);
  } else if(!memcmp(&ct->guid,&smbios_guid,16)) {
   if(!memory_present(p,31,0) || memcmp(p,"_SM_",4))continue;
   length=p[5];if(length<31 || length>64 || !memory_present(p,length,0))continue;
   uint16_t n;uint32_t a;memcpy(&n,p+22,2);memcpy(&a,p+24,4);size=n;address=a;
  } else continue;
  uint8_t sum=0;for(UN j=0;j<length;j++)sum=(uint8_t)(sum+p[j]);
  if(!sum && smbios_table((uint8_t *)(uintptr_t)address,size))return 1;
 }
 return 0;
}
static int image_guid(LOADED *image,GUID *out) {
 uint8_t *path=image->filepath;if(!path)return 0;
 for(UN p=0;p<65536;) {
  if(!memory_present(path+p,4,0))return 0;
  uint16_t n=(uint16_t)(path[p+2]|((uint16_t)path[p+3]<<8));if(n<4 || n>65536-p || !memory_present(path+p,n,0))return 0;
  if(path[p]==4 && path[p+1]==6 && n==20){memcpy(out,path+p+4,16);return 1;}
  if(path[p]==0x7f)return 0;p+=n;
 }
 return 0;
}
static void EA discover(EVENT event,void *context) {
 (void)event;(void)context;if(scanning || attempted || platform_ready || boot_services_ended)return;
 scanning=1;
 matching_board=board_matches();if(!matching_board)goto done;
 HANDLE *handles=0;UN count=0;uint8_t *tse=0,*setup=0;UN tse_size=0,setup_size=0;
 unsigned tse_count=0,setup_count=0;
 ES status=system_table->bs->locate_handles(2,&loaded_guid,0,&count,&handles);
 /* Any provider can retire the driver while control is outside this image.
  * After retirement, even releasing the enumeration buffer would be another
  * Boot Services call. Leave it for firmware/OS memory reclamation instead. */
 if(boot_services_ended || FAILED(status) || !handles)goto done;
 if(count>4096){release(handles);goto done;}
 for(UN i=0;i<count;i++) {
  LOADED *li=0;GUID guid;
  status=system_table->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li);
  if(boot_services_ended)goto done;
  if(FAILED(status) || !li || !image_guid(li,&guid))continue;
  if(!memcmp(&guid,&tse_guid,16)){tse_count++;tse=li->image_base;tse_size=li->image_size;}
  if(!memcmp(&guid,&setup_guid,16)){setup_count++;setup=li->image_base;setup_size=li->image_size;}
 }
 release(handles);
 if(boot_services_ended)goto done;
 /* Duplicate module owners cannot be resolved by enumeration order. A later
  * fresh inventory may become unique; no target has been published here. */
 if(tse_count>1 || setup_count>1){ambiguous_images=1;audit(52,((uint64_t)tse_count<<32)|setup_count);goto done;}
 ambiguous_images=0;
 if(tse && setup && tse_size>0x82630 && memory_present(tse,tse_size,0) && memory_present(setup,setup_size,0)) {
  uint32_t stage;memcpy(&stage,tse+0x82628,4);
  if(stage==5){late_observed=1;audit(50,stage);goto done;}
  /* Do not patch before FormBrowser2 is published; PE relocation and AMITSE
   * protocol initialization must have completed. */
  void *browser=0;
  status=system_table->bs->locate_protocol(&browser_guid,0,&browser);
  if(boot_services_ended)goto done;
  if(!FAILED(status) && browser) {
   /* ACE1904's original installer publishes this exact interface and methods.
    * A foreign FormBrowser2 provider does not establish AMITSE readiness. */
   void *send=0,*callback=0;
   if(browser!=tse+0x6b528 || !memory_present(browser,16,0))goto done;
   memcpy(&send,browser,8);memcpy(&callback,(uint8_t *)browser+8,8);
   if(send!=tse+0x20f34 || callback!=tse+0x2168c){audit(53,ERR(3));goto done;}
   /* The locate call can run firmware callbacks. Do not patch a browser that
    * became active while publication readiness was being checked. */
   memcpy(&stage,tse+0x82628,4);
   if(stage==5){late_observed=1;audit(50,stage);goto done;}
   if(attach_attempts>=3 || !platform_attach_retry_safe()){attempted=1;goto done;}
   attach_attempts++;
   int attached=attach_platform(tse,tse_size,setup,setup_size);
   if(boot_services_ended)goto done;
   if(attached)attempted=1;
   else {
    audit(51,attach_attempts);
    /* A failure after any attempted publication is terminal, even when a
     * best-effort rollback appears to have restored the original bytes. */
    if(attach_attempts>=3 || !platform_attach_retry_safe())attempted=1;
   }
  }
 }
done:
 scanning=0;
 if(!boot_services_ended && (attempted || platform_ready) && discovery_timer)system_table->bs->set_timer(discovery_timer,0,0);
}
static ES EA no_unload(HANDLE h) {(void)h;return ERR(15);}
static ES EA query_status(LOCK_STATUS *out) {
 if(!out)return ERR(2);
 *out=(LOCK_STATUS){1,1904,(uint32_t)matching_board,(uint32_t)platform_ready,password_core.mode,password_core.active};return 0;
}
static LOCK_STATUS_PROTOCOL status_protocol={STATUS_SIGNATURE,query_status};
static GUID status_guid=STATUS_GUID;
ES EA efi_main(HANDLE image,ST *st) {
 if(!st || !st->bs || !st->rt)return ERR(2);
 if(boot_services_ended)return 0;
 system_table=st;
 int initialized=initialize_services();
 /* Firmware providers may synchronously signal our Exit/BeforeExit events.
  * A retired image with published callbacks must remain resident; returning
  * loader failure could unload their code. Never clean up via BS here. */
 if(boot_services_ended)return 0;
 if(!initialized)return ERR(7);
 HANDLE status_handle=0;st->bs->install_protocol(&status_handle,&status_guid,0,&status_protocol);
 if(boot_services_ended)return 0;
 LOADED *li=0;ES status=st->bs->handle_protocol(image,&loaded_guid,(void **)&li);
 if(boot_services_ended)return 0;
 if(!FAILED(status) && li)li->unload=(void *)no_unload;
 status=st->bs->create_event(0x200,8,discover,0,&loaded_event);
 if(boot_services_ended)return 0;
 if(!FAILED(status)) {
  st->bs->register_notify(&loaded_guid,loaded_event,&loaded_registration);
  if(boot_services_ended)return 0;
 }
 status=st->bs->create_event(0x200,8,discover,0,&browser_event);
 if(boot_services_ended)return 0;
 if(!FAILED(status)) {
  st->bs->register_notify(&browser_guid,browser_event,&browser_registration);
  if(boot_services_ended)return 0;
 }
 st->bs->create_event_ex(0x200,8,discover,0,&end_dxe_guid,&end_dxe_event);
 if(boot_services_ended)return 0;
 status=st->bs->create_event(0x80000200,8,discover,0,&discovery_timer);
 if(boot_services_ended)return 0;
 if(!FAILED(status)) {
  st->bs->set_timer(discovery_timer,1,1000000);
  if(boot_services_ended)return 0;
 }
 discover(0,0);
 /* A successful Boot Service driver remains resident. Unsupported boards get
  * no patches and no variable writes; timer/notification resources remain ours. */
 return 0;
}
