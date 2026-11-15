/* Firmware resident, exact P5 resource binding. No late HII form mutation. */
#include "p5.h"
static GUID service_guid=P5_API_GUID;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID setup_guid={0x71202eee,0x5f53,0x40d9,{0xab,0x3d,0x9e,0x0c,0x26,0xd9,0x66,0x57}};
typedef ES(EA *REGISTER_NOTIFY)(GUID *,HANDLE,void **);
static HANDLE owner,timer_event,notify_event;static void *registration;
static unsigned active,busy,attempted,ticks;static P5_API api;
static ES EA probe(void){
 if(busy)return ERR(20);busy=1;attempted=1;active=0;
 if(timer_event)gST->bs->set_timer(timer_event,0,0);
 ES e=p1_collect();busy=0;return e;
}
static ES EA refresh(void){
 if(busy)return ERR(20);busy=1;
 ES e=p5_bind();
 logtext("P5_BIND_STATUS=");loghex(e,16);logtext("\r\n");
 if(!FAILED(e)){
  e=p1_collect();ES publish=p5_publish();
  logtext("P5_PUBLISH_STATUS=");loghex(publish,16);logtext("\r\n");
  if(FAILED(publish))e=publish;
 }
 busy=0;return e;
}
static const char *EA get_log(UN *n){if(n)*n=audit_len;return audit;}
static const char *EA get_value(unsigned i){return i<V_COUNT?values[i]:0;}
static void EA on_timer(HANDLE event,void *context){
 (void)event;(void)context;if(!active||attempted||busy)return;
 if(++ticks>20){active=0;gST->bs->set_timer(timer_event,0,0);logtext("P5_NO_MATCHING_NATIVE_RESOURCE\r\n");return;}
 ES e=p5_bind();if(FAILED(e))return;
 attempted=1;active=0;gST->bs->set_timer(timer_event,0,0);
 logtext("P5_SETUP_AUTO_REFRESH\r\n");e=refresh();logtext("P5_SETUP_REFRESH_STATUS=");loghex(e,16);logtext("\r\n");
}
static void EA on_setup(HANDLE event,void *context){
 (void)event;(void)context;if(attempted||active||busy)return;
 active=1;ticks=0;ES e=gST->bs->set_timer(timer_event,1,5000000);
 if(FAILED(e)){active=0;logtext("P5_TIMER_ARM_FAILED\r\n");}
}
static ES EA unload(HANDLE image){
 (void)image;if(busy)return ERR(15);active=0;
 if(timer_event){ES e=gST->bs->close_event(timer_event);if(FAILED(e))return e;timer_event=0;}
 if(notify_event){ES e=gST->bs->close_event(notify_event);if(FAILED(e))return e;notify_event=0;}
 if(owner){ES e=gST->bs->uninstall_protocol(owner,&service_guid,&api);if(FAILED(e))return e;owner=0;}
 p5_release();return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);
 void *present=0;ES e=gST->bs->locate_protocol(&service_guid,0,&present);
 if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 /* DXE may dispatch before SMBIOS records have been published. Board/version
  * gating belongs to p1_collect(), after SetupEnter, not driver entry. */
 LOADED *li=0;e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&li);if(FAILED(e)||!li)return ERR(14);
 li->unload=unload;
 for(unsigned i=0;i<V_COUNT;i++)value_text(i,"Not queried");
 logtext("HERO-IPMI-P5-RC1 / native static resource / BMC reads only\r\n");
 api=(P5_API){5,sizeof(P5_API),image,refresh,probe,get_log,get_value};
 e=gST->bs->create_event(0x80000200,8,on_timer,0,&timer_event);if(FAILED(e))goto fail;
 e=gST->bs->create_event(0x200,8,on_setup,0,&notify_event);if(FAILED(e))goto fail;
 e=((REGISTER_NOTIFY)gST->bs->register_notify)(&setup_guid,notify_event,&registration);if(FAILED(e))goto fail;
 e=gST->bs->install_protocol(&owner,&service_guid,0,&api);if(FAILED(e))goto fail;
 present=0;if(!FAILED(gST->bs->locate_protocol(&setup_guid,0,&present)))on_setup(0,0);
 return 0;
fail:
 /* Never free code while firmware still holds an event/protocol callback. */
 if(FAILED(unload(image)))return 0;
 return e;
}
