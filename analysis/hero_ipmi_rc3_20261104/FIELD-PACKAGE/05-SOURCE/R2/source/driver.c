/* R2 resident sensor initialization core. HII is not a dependency.
 * USB/CD loads explicitly carry MANUAL_MAGIC: no ReadyToBoot event is created.
 * Firmware dispatch registers one ReadyToBoot callback; no hardware IO on entry.
 */
#include "r2.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID ready_guid={0x7ce88fb3,0x4bd7,0x4679,{0x87,0xa8,0xa8,0xd8,0xde,0xe5,0x0d,0x2b}};
static GUID old_api_guid={0x40823e46,0x8089,0x43f6,{0xaa,0x64,0xa6,0x33,0x42,0x12,0xbb,0x12}};
static HANDLE driver_handle,ready_event;
static uint32_t auto_seen,busy,installed,manual_only;
static ES EA api_run(uint32_t initialize){
 if(initialize>1)return ERR(2);if(busy)return ERR(20);
 busy=1;ES e=engine_run(initialize);busy=0;return e;
}
static const char *EA api_log(UN *n){if(n)*n=audit_len;return audit;}
static ES EA api_status(REPORT *p){if(!p)return ERR(2);*p=report;return 0;}
static ES EA api_config(CONFIG *p,uint32_t *source){
 if(!p||!source)return ERR(2);ES e=config_read(p);*source=config_source;return e;
}
static ES EA api_enable(uint32_t enabled){
 if(enabled>1)return ERR(2);if(busy)return ERR(20);
 CONFIG c={CFG_MAGIC,(uint8_t)enabled,1,{0,0}};
 ES e=config_write(&c);logtext("CONFIG_SAVE enabled=");loghex(enabled,2);logtext(" status=");loghex(e,16);logtext("\r\n");return e;
}
static ES EA api_unlock(void){
 if(busy)return ERR(20);CONFIG c;ES e=config_read(&c);
 if(FAILED(e)||c.enabled)return ERR(15);
 e=lock_write(0);logtext("ATTEMPT_UNLOCK status=");loghex(e,16);logtext("\r\n");return e;
}
static R2_API api={2,sizeof(R2_API),0,0,api_run,api_log,api_status,api_config,api_enable,api_unlock};
static void EA ready_callback(HANDLE event,void *context){
 (void)event;(void)context;if(manual_only||auto_seen||!installed)return;auto_seen=1;
 CONFIG c;ES e=config_read(&c);
 if(FAILED(e)){result("ReadyToBoot: invalid/unreadable configuration; skipped.");return;}
 if(!c.enabled){logtext("READY_TO_BOOT_AUTO_DISABLED\r\n");return;}
 logtext("READY_TO_BOOT_AUTO_ENABLED\r\n");api_run(1);
}
static ES EA unload(HANDLE image){
 (void)image;if(busy)return ERR(15);auto_seen=1;
 if(ready_event){ES e=gST->bs->close_event(ready_event);if(FAILED(e))return e;ready_event=0;}
 if(installed){ES e=gST->bs->uninstall_protocol(driver_handle,&api_guid,&api);if(FAILED(e))return e;installed=0;}
 return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);
 void *existing=0;ES e=gST->bs->locate_protocol(&api_guid,0,&existing);
 if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 e=gST->bs->locate_protocol(&old_api_guid,0,&existing);
 if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 LOADED *loaded=0;
 e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded);
 if(FAILED(e)||!loaded)return FAILED(e)?e:ERR(14);
 if(loaded->options_size){
  if(loaded->options_size!=sizeof(LOAD_OPTIONS)||!loaded->options)return ERR(2);
  LOAD_OPTIONS *o=loaded->options;
  if(o->magic!=MANUAL_MAGIC||o->size!=sizeof(*o))return ERR(2);
  manual_only=1;
 }
 api.manual_only=manual_only;
 logtext("HERO-IPMI-R2 CORE / HERO 3107 / BMC 1.3.13\r\n");
 logtext(manual_only?"LOAD_MODE MANUAL_ONLY; no boot event\r\n":"LOAD_MODE FIRMWARE; ReadyToBoot once\r\n");
 detect_board();result("Core loaded. No hardware query on entry.");
 loaded->unload=unload;
 if(!manual_only){
  e=gST->bs->create_event_ex(0x200,8,ready_callback,0,&ready_guid,&ready_event);
  if(FAILED(e))return e;
 }
 e=gST->bs->install_protocol(&driver_handle,&api_guid,0,&api);
 if(FAILED(e)){
  auto_seen=1; /* Retained code after a failed CloseEvent must never initialize. */
  if(ready_event){ES closed=gST->bs->close_event(ready_event);if(FAILED(closed))return 0;ready_event=0;}
  return e;
 }
 installed=1;return 0;
}
