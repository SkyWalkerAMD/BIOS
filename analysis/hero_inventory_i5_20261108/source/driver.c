/* Read-only automatic RAM driver entry. Same entry can be exercised as DXE;
 * the ISO proves only LoadImage/StartImage at TPL_APPLICATION, not DXE timing.
 * No ReadyToBoot callback and no persistent network or BIOS setting changes.
 */
#include "i5.h"
#include "tls_client.h"
static GUID protocol=I5_API_GUID_INIT;
static I5_API api;
static HANDLE published;
void say(const char *s){(void)s;}
void status(const char *name,ES value){logtext(name);logtext("=0x");loghex(value,16);logtext("\r\n");}
void i5_run_once(HANDLE image){
 if(api.state)return;api.state=1;
 logtext("HERO-INVENTORY-I5A\r\nMODE=AUTOMATIC_RAM_DRIVER_READONLY\r\n");
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
 status("I5_FINAL_RESULT",e);api.log=audit;api.log_bytes=audit_len;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;
 if(!gST||!gST->bs||!gST->rt||!gST->bs->install_protocol||!gST->bs->locate_protocol)return ERR(2);
 void *existing=0;ES e=gST->bs->locate_protocol(&protocol,0,&existing);
 if(e==0)return ERR(20);
 if(e!=ERR(14))return e;
 api.magic=I5_MAGIC;api.version=1;api.size=sizeof(api);
 e=gST->bs->install_protocol(&published,&protocol,0,&api);if(FAILED(e))return e;
 i5_run_once(image);
 /* Entry succeeds even when the probe fails: it leaves a passive report and
  * lets BDS continue, retaining any firmware I/O references until reset. */
 return 0;
}
