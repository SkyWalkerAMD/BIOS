/* Bounded RAM-only observer. Normal firmware events are observed, never
 * signalled or installed. No configuration write, unlock, or firmware hook. */
#include "phase.h"
static GUID phase_guid=PHASE_GUID_INIT;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID notify_guids[2]={
 {0x71202eee,0x5f53,0x40d9,{0xab,0x3d,0x9e,0x0c,0x26,0xd9,0x66,0x57}},
 {0x3677770f,0xefb2,0x43b2,{0xb8,0xae,0xb3,0x02,0xe9,0x60,0x48,0x82}}};
typedef ES (EA *REGISTER_NOTIFY)(GUID *,HANDLE,void **);
static HANDLE events[3],installed_handle;static void *registrations[2];
static PHASE_STATE previous;static uint32_t ticks,records,busy,active=1,has_previous;
static ES take(const char *reason,int force){
 if(busy)return ERR(6);busy=1;PHASE_STATE p;phase_read(&p);
 if((force||!has_previous||!phase_equal(&previous,&p))&&records<64){
  logtext("OBS ");loghex(++records,4);logtext(" tick=");loghex(ticks,4);logtext(" reason=");logtext(reason);logtext("\r\n");phase_log(&p);
  previous=p;has_previous=1;
 }
 busy=0;return 0;
}
static void EA on_timer(HANDLE event,void *context){
 (void)event;(void)context;if(!active)return;
 ++ticks;take("TIMER_CHANGE",0);
 if(ticks>=600){active=0;gST->bs->set_timer(events[0],0,0);logtext("OBSERVER_TIMER_FINISHED_300_SECONDS\r\n");}
}
static void EA on_notify(HANDLE event,void *context){
 (void)event;if(!active)return;take((UN)context==1?"SETUP_ENTER_NOTIFY":"BOOT_PREPARE_NOTIFY",1);
}
static ES EA sample(void){UN old=gST->bs->raise_tpl(8);ES e=take("EXPLICIT_SAMPLE",1);gST->bs->restore_tpl(old);return e;}
static ES EA snapshot(char *buffer,UN *size){
 if(!size)return ERR(2);UN old=gST->bs->raise_tpl(8);ES e=0;
 if(!buffer||*size<audit_len){*size=audit_len;e=ERR(5);}else{*size=audit_len;memcpy(buffer,audit,audit_len);}
 gST->bs->restore_tpl(old);return e;
}
static PHASE_API api={PHASE_MAGIC,1,sizeof(PHASE_API),0,0,sample,snapshot};
static ES EA unload(HANDLE image){
 (void)image;if(busy)return ERR(15);active=0;
 for(unsigned i=0;i<3;i++)if(events[i]){ES e=gST->bs->close_event(events[i]);if(FAILED(e))return e;events[i]=0;}
 if(installed_handle){ES e=gST->bs->uninstall_protocol(installed_handle,&phase_guid,&api);if(FAILED(e))return e;installed_handle=0;}return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);
 void *existing=0;ES e=gST->bs->locate_protocol(&phase_guid,0,&existing);if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 LOADED *loaded=0;e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded);if(FAILED(e)||!loaded)return ERR(14);
 /* Caller-provided manual load marker: never silently start from a firmware FV. */
 if(loaded->options_size!=sizeof(uint32_t)||!loaded->options||*(uint32_t *)loaded->options!=PHASE_MAGIC)return ERR(3);
 loaded->unload=unload;api.image=image;
 logtext("HERO-R4-OBSERVER / READ ONLY / 300 SECOND TIMER / MAX 64 RECORDS\r\n");take("DRIVER_ENTRY",1);
 e=gST->bs->create_event(0x80000200,8,on_timer,0,&events[0]);if(FAILED(e))return e;
 for(unsigned i=0;i<2;i++){
  e=gST->bs->create_event(0x200,8,on_notify,(void *)(UN)(i+1),&events[i+1]);if(FAILED(e))goto fail;
  e=((REGISTER_NOTIFY)gST->bs->register_notify)(&notify_guids[i],events[i+1],&registrations[i]);if(FAILED(e))goto fail;
 }
 e=gST->bs->install_protocol(&installed_handle,&phase_guid,0,&api);if(FAILED(e))goto fail;
 e=gST->bs->set_timer(events[0],1,5000000);if(FAILED(e))goto fail;return 0;
fail:
 /* If firmware refuses cleanup, retain executable code behind live events. */
 if(FAILED(unload(image)))return 0;return e;
}
