/* Read-only automatic RAM driver entry. Same entry can be exercised as DXE;
 * the ISO proves only LoadImage/StartImage at TPL_APPLICATION, not DXE timing.
 * No ReadyToBoot callback and no persistent network or BIOS setting changes.
 */
#include "i5.h"
#include "tls_client.h"
static GUID protocol=I5_API_GUID_INIT;
static I5_API api;
static HANDLE published;
static GUID binding_protocol={0x18a031ab,0xb443,0x4d1a,{0xa5,0xc0,0x0c,0x09,0x26,0x1e,0x9f,0x71}};
static GUID trigger_protocol={0x9412c522,0x5b86,0x4cae,{0x87,0x99,0x82,0xee,0x19,0x4b,0x9f,0xa5}};
typedef struct BIND BIND;
struct BIND {ES (EA *supported)(BIND *,HANDLE,void *);ES (EA *start)(BIND *,HANDLE,void *);ES (EA *stop)(BIND *,HANDLE,UN,HANDLE *);uint32_t version;HANDLE image,binding;};
static BIND boot_binding;static HANDLE bound_controller;static unsigned harness_attempted;
static void publish_log(void){api.log=audit;api.log_bytes=audit_len;}
void say(const char *s){(void)s;}
void status(const char *name,ES value){logtext(name);logtext("=0x");loghex(value,16);logtext("\r\n");}
void i5_run_once(HANDLE image){
 if(api.state)return;api.state=1;api.run_count++;
 logtext("SCOPE=SMBIOS_CURRENT_HOST_AND_INTERNAL_USB_TLS_GET_ONLY\r\n");
 api.entry_tpl=i5_current_tpl();status("I5_DRIVER_ENTRY_TPL",api.entry_tpl);
 ES e=api.entry_tpl==4?i5_capture_source():ERR(15);status("I5_CURRENT_HOST_CAPTURE",e);
 if(!FAILED(e)){e=i5_prepare_network(image);status("I5_AUTOMATIC_NETWORK_PREPARATION",e);}
 TLS_REPLY reply;
 if(!FAILED(e)){
  e=private_tls_resource(0,&reply);status("I5_ROOT_GET_RESULT",e);
  if(!FAILED(e)&&reply.status!=200)e=ERR(7);
 }
 if(!FAILED(e)&&!i5_source_valid())e=ERR(15);
 if(!FAILED(e)){
  e=private_tls_resource(1,&reply);status("I5_SYSTEM_GET_RESULT",e);
  if(!FAILED(e)&&reply.status!=200)e=ERR(7);
 }
 /* Keep the driver image resident if firmware cannot release child I/O.
  * This prevents callback targets from being freed when the launcher exits.
  * There is no retry of the GET or network preparation within this boot. */
 ES cleanup=private_tls_cleanup();status("I5_FINAL_TLS_CLEANUP",cleanup);
 if(!FAILED(cleanup)){cleanup=network_cleanup();status("I5_FINAL_NETWORK_CLEANUP",cleanup);}
 if(!FAILED(e)&&FAILED(cleanup))e=cleanup;
 api.result=e;api.state=FAILED(e)?3:2;api.catalog=i5_catalog();
 logtext("I5_DRIVER_RESIDENT_UNTIL_RESET\r\nI5_NO_AUTOMATIC_RETRY_THIS_BOOT\r\n");
 status("I5_FINAL_RESULT",e);publish_log();
}
static ES EA boot_supported(BIND *self,HANDLE controller,void *path){
 (void)path;if(self!=&boot_binding||api.state||i5_current_tpl()>8)return ERR(3);
 HANDLE pair[2];return i5_observe_bmc_usb(pair)&&(controller==pair[0]||controller==pair[1])?0:ERR(3);
}
static ES EA boot_start(BIND *self,HANDLE controller,void *path){
 if(self!=&boot_binding||i5_current_tpl()!=4||api.state)return ERR(3);
 ES e=boot_supported(self,controller,path);if(e)return e;
 ES (EA *open)(HANDLE,GUID *,void **,HANDLE,HANDLE,uint32_t)=(void *)gST->bs->open_protocol;
 if(!open)return ERR(3);
 HANDLE h=controller;e=gST->bs->install_protocol(&h,&trigger_protocol,0,&api);if(e)return e;
 void *p=0;e=open(h,&trigger_protocol,&p,self->binding,h,0x10);
 if(e||p!=&api){gST->bs->uninstall_protocol(h,&trigger_protocol,&api);return e?e:ERR(33);}
 bound_controller=h;api.binding_starts++;status("I5_BINDING_START_CONTROLLER",(UN)h);
 status("I5_BINDING_START_TPL",i5_current_tpl());
 i5_run_once(self->image);return 0;
}
static ES EA boot_stop(BIND *self,HANDLE controller,UN children,HANDLE *handles){
 (void)handles;if(self!=&boot_binding||controller!=bound_controller||children||api.state==1)return ERR(3);
 ES (EA *close)(HANDLE,GUID *,HANDLE,HANDLE)=(void *)gST->bs->close_protocol;
 if(!close)return ERR(3);ES e=close(controller,&trigger_protocol,self->binding,controller);if(e)return e;
 e=gST->bs->uninstall_protocol(controller,&trigger_protocol,&api);if(!e)bound_controller=0;return e;
}
static ES EA connect_probe(void){
 if(harness_attempted||api.state)return ERR(20);harness_attempted=1;
 ES e=ERR(15);HANDLE pair[2];
 if(i5_current_tpl()==4&&i5_observe_bmc_usb(pair)){
  ES (EA *connect)(HANDLE,HANDLE *,void *,uint8_t)=(void *)gST->bs->connect;
  HANDLE priority[2]={boot_binding.binding,0};
  e=connect?connect(pair[0],priority,0,0):ERR(3);
  status("I5_RAM_HARNESS_CONNECT_CONTROLLER",e);
  if(!api.binding_starts)e=ERR(14);
 }
 if(!api.state){api.state=3;api.result=e;status("I5_BINDING_NOT_TRIGGERED",e);}
 publish_log();return e;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;
 if(!gST||!gST->bs||!gST->rt||!gST->bs->install_protocol||!gST->bs->locate_protocol)return ERR(2);
 void *existing=0;ES e=gST->bs->locate_protocol(&protocol,0,&existing);
 if(e==0)return ERR(20);
 if(e!=ERR(14))return e;
 if(i5_current_tpl()!=4)return ERR(3);
 api.magic=I5_MAGIC;api.version=2;api.size=sizeof(api);api.result=ERR(6);api.entry_tpl=4;api.connect_probe=connect_probe;api.binding_handle=image;
 logtext("HERO-INVENTORY-I5D\r\nMODE=AUTOMATIC_RAM_DRIVER_READONLY\r\n");
 logtext("TRIGGER=STANDARD_DRIVER_BINDING_START\r\n");
 e=gST->bs->install_protocol(&published,&protocol,0,&api);if(FAILED(e))return e;
 boot_binding=(BIND){boot_supported,boot_start,boot_stop,0x10,image,image};
 HANDLE bind_handle=image;e=gST->bs->install_protocol(&bind_handle,&binding_protocol,0,&boot_binding);
 if(FAILED(e)){api.state=3;api.result=e;}
 status("I5_DRIVER_BINDING_REGISTERED",e);publish_log();
 /* Entry succeeds even when the probe fails: it leaves a passive report and
  * lets BDS continue, retaining any firmware I/O references until reset. */
 return 0;
}
