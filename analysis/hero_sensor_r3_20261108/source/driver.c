/* R3 resident core: no hardware IO or persistent changes on entry.
 * Manual LoadOptions suppress automatic execution; firmware mode registers
 * one ReadyToBoot callback at TPL_CALLBACK. Legacy R2 v2 API is unchanged. */
#include "r2.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID ready_guid={0x7ce88fb3,0x4bd7,0x4679,{0x87,0xa8,0xa8,0xd8,0xde,0xe5,0x0d,0x2b}};
static GUID old_api_guid={0x40823e46,0x8089,0x43f6,{0xaa,0x64,0xa6,0x33,0x42,0x12,0xbb,0x12}};
static HANDLE driver_handle,ready_event;
static uint32_t auto_seen,busy,installed,manual_only,compat_installed,r3_installed;
static ES enter_busy(void){
 if(!installed)return ERR(6);
 UN old=gST->bs->raise_tpl(31);ES e=old>8?ERR(3):busy?ERR(20):0;
 if(!e)busy=1;gST->bs->restore_tpl(old);return e;
}
static ES EA api_run(uint32_t initialize){
 if(initialize>1)return ERR(2);ES e=enter_busy();if(e)return e;
 r3_report.requested|=R3_SENSORS;e=engine_run(initialize);r3_report.sensor_status=e;r3_report.completed|=R3_SENSORS;
 busy=0;return e;
}
static ES EA r3_run(uint32_t flags){
 if(!(flags&3)||(flags&~(R3_SENSORS|R3_DASHBOARD|R3_WRITE)))return ERR(2);
 ES e=enter_busy();if(e)return e;r3_report.requested|=flags&3;ES sensor=0,dmi=0;
 if(flags&R3_SENSORS){sensor=engine_run(!!(flags&R3_WRITE));r3_report.sensor_status=sensor;r3_report.completed|=R3_SENSORS;}
 /* No early return for a sensor lock, already-initialized, or failed SDR gate.
  * The shared engine itself blocks all further access after transport poison. */
 if(flags&R3_DASHBOARD){dmi=engine_dashboard(!!(flags&R3_WRITE));r3_report.dashboard_status=dmi;r3_report.completed|=R3_DASHBOARD;}
 busy=0;return sensor?sensor:dmi;
}
static const char *EA api_log(UN *n){if(n)*n=audit_len;return audit;}
static ES EA api_status(REPORT *p){if(!p)return ERR(2);*p=report;return 0;}
static ES EA r3_status(R3_REPORT *p){if(!p)return ERR(2);*p=r3_report;return 0;}
static ES EA api_config(CONFIG *p,uint32_t *source){if(!p||!source)return ERR(2);ES e=config_read(p);*source=config_source;return e;}
static ES EA api_enable(uint32_t enabled){
 if(enabled>1)return ERR(2);ES e=enter_busy();if(e)return e;
 CONFIG c={CFG_MAGIC,(uint8_t)enabled,1,{0,0}};e=config_write(&c);busy=0;
 logtext("CONFIG_SAVE enabled=");loghex(enabled,2);logtext(" status=");loghex(e,16);logtext("\r\n");return e;
}
static ES EA r3_unlock(uint32_t stages){
 if(!stages||(stages&~3U))return ERR(2);ES e=enter_busy();if(e)return e;
 CONFIG c;e=config_read(&c);if(e||c.enabled){busy=0;return ERR(15);}
 if(stages&R3_SENSORS)e=lock_write(0);
 if(!e&&(stages&R3_DASHBOARD))e=dmi_lock_write(0);
 busy=0;logtext("ATTEMPT_UNLOCK stages=");loghex(stages,2);logtext(" status=");loghex(e,16);logtext("\r\n");return e;
}
static ES EA api_unlock(void){return r3_unlock(R3_SENSORS);}
static R2_API api={2,sizeof(R2_API),0,0,api_run,api_log,api_status,api_config,api_enable,api_unlock};
static R3_API api3={3,sizeof(R3_API),0,0,r3_run,api_log,r3_status,r3_unlock};
static void EA ready_callback(HANDLE event,void *context){
 (void)event;(void)context;if(manual_only||auto_seen||!installed)return;
 auto_seen=1;r3_report.ready_seen=1;CONFIG c;ES e=config_read(&c);
 if(e){result("ReadyToBoot: invalid/unreadable configuration; skipped.");return;}
 if(!c.enabled){logtext("READY_TO_BOOT_AUTO_DISABLED\r\n");return;}
 logtext("READY_TO_BOOT_AUTO_ENABLED R3 sensor+Dashboard\r\n");r3_run(R3_SENSORS|R3_DASHBOARD|R3_WRITE);
}
static ES EA unload(HANDLE image){
 (void)image;if(busy)return ERR(15);auto_seen=1;installed=0;
 if(ready_event){ES e=gST->bs->close_event(ready_event);if(e)return e;ready_event=0;}
 if(compat_installed){ES e=gST->bs->uninstall_protocol(driver_handle,&api_guid,&api);if(e)return e;compat_installed=0;}
 if(r3_installed){ES e=gST->bs->uninstall_protocol(driver_handle,&r3_api_guid,&api3);if(e)return e;r3_installed=0;}
 return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt||!gST->bs->raise_tpl||!gST->bs->restore_tpl)return ERR(2);
 GUID *checks[3]={&r3_api_guid,&api_guid,&old_api_guid};void *existing=0;
 for(unsigned i=0;i<3;i++){ES e=gST->bs->locate_protocol(checks[i],0,&existing);if(e!=ERR(14))return FAILED(e)?e:ERR(20);}
 LOADED *loaded=0;ES e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded);
 if(e||!loaded)return e?e:ERR(14);
 if(loaded->options_size){
  if(loaded->options_size!=sizeof(LOAD_OPTIONS)||!loaded->options)return ERR(2);
  LOAD_OPTIONS *o=loaded->options;if(o->magic!=MANUAL_MAGIC||o->size!=sizeof(*o))return ERR(2);manual_only=1;
 }
 api.manual_only=api3.manual_only=manual_only;
 logtext("HERO-IPMI-R3 CORE / HERO 3107 / BMC 1.3.13\r\n");
 logtext(manual_only?"LOAD_MODE MANUAL_ONLY; no boot event\r\n":"LOAD_MODE FIRMWARE; ReadyToBoot once\r\n");
 detect_board();result("Core loaded. No hardware query on entry.");loaded->unload=unload;
 if(!manual_only){e=gST->bs->create_event_ex(0x200,8,ready_callback,0,&ready_guid,&ready_event);if(e)return e;}
 e=gST->bs->install_protocol(&driver_handle,&r3_api_guid,0,&api3);if(e)goto failed;r3_installed=1;
 e=gST->bs->install_protocol(&driver_handle,&api_guid,0,&api);if(e)goto failed;compat_installed=1;
 installed=1;return 0;
failed:
 /* If cleanup cannot remove a callback/interface, keep code resident but inert. */
 {ES clean=unload(image);if(clean)return 0;return e;}
}
