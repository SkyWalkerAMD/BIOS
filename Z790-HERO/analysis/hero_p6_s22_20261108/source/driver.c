/* P6 resident driver: native EFI variable editing, separate bounded boot
 * writers, and a read-only log protocol. No late form changes or manual writer. */
#include "settings.h"
static GUID service_guid={0x1f771753,0xbb7b,0x4e4c,{0xb6,0x98,0xe7,0x1e,0x8d,0xb2,0x5e,0x7a}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID setup_guid={0x71202eee,0x5f53,0x40d9,{0xab,0x3d,0x9e,0x0c,0x26,0xd9,0x66,0x57}};
static GUID ready_guid={0x7ce88fb3,0x4bd7,0x4679,{0x87,0xa8,0xa8,0xd8,0xde,0xe5,0x0d,0x2b}};
static GUID before_guid={0x3677770f,0xefb2,0x43b2,{0xb8,0xae,0xb3,0x02,0xe9,0x60,0x48,0x82}};
/* HERO AMITSE publishes this after a boot image returns, including errors. */
static GUID after_guid={0x8c12a959,0x70bc,0x4362,{0xb4,0x37,0xb8,0x05,0x14,0xa1,0x91,0x6e}};
static GUID shell_guid[2]={
 {0x47c7b221,0xc42a,0x11d2,{0x8e,0x57,0x00,0xa0,0xc9,0x69,0x72,0x3b}},
 {0x6302d008,0x7f9b,0x4f30,{0x87,0xac,0x60,0xc9,0xfe,0xf5,0xda,0x4e}}};
typedef ES(EA *REGISTER_NOTIFY)(GUID *,HANDLE,void **);
typedef struct {uint32_t version,size;const char *(EA *log)(UN *);const char *(EA *value)(unsigned);} P6_AUDIT_API;
static HANDLE owner,events[7];static void *registration[5];
static unsigned active,busy,attempted,ticks,resident_ready;static P6_AUDIT_API api;
static const char *EA get_log(UN *n){if(n)*n=audit_len;return audit;}
static const char *EA get_value(unsigned i){return i<V_COUNT?values[i]:0;}
static void EA on_timer(HANDLE event,void *context){
 (void)event;(void)context;if(!resident_ready||!active||attempted||busy)return;
 if(++ticks>20){active=0;gST->bs->set_timer(events[0],0,0);logtext("P6_NO_MATCHING_NATIVE_RESOURCE\r\n");return;}
 ES e=p5_bind();if(FAILED(e))return;
 attempted=1;active=0;gST->bs->set_timer(events[0],0,0);busy=1;
 logtext("P6_SETUP_AUTO_REFRESH\r\n");
 e=p1_collect();logtext("P6_READ_STATUS=");loghex(e,16);logtext("\r\n");
 e=p5_publish();logtext("P6_PUBLISH_STATUS=");loghex(e,16);logtext("\r\n");busy=0;
}
/* Preserve the existing early SetupEnter timer path. AfterBoot has a separate
 * synchronous one-attempt path; it never arms this timer. */
static void arm_refresh(void){
 if(!resident_ready||busy||attempted||active)return;active=1;ticks=0;
 ES e=gST->bs->set_timer(events[0],1,5000000);
 if(FAILED(e)){active=0;logtext("P6_TIMER_ARM_FAILED\r\n");}
}
static void EA on_setup(HANDLE event,void *context){
 (void)event;(void)context;if(!resident_ready||busy)return;
 busy=1;p6_stop_os_watchdog();busy=0;arm_refresh();
}
static void EA on_ready(HANDLE event,void *context){
 (void)event;(void)context;if(!resident_ready||busy)return;
 busy=1;logtext("P6_READY_TO_BOOT\r\n");p6_apply_settings();busy=0;
}
static void EA on_before(HANDLE event,void *context){
 (void)event;(void)context;if(!resident_ready||busy)return;
 busy=1;logtext("P6_AMITSE_BEFORE_BOOT\r\n");p6_start_os_watchdog();busy=0;
}
static void EA on_shell(HANDLE event,void *context){
 (void)event;(void)context;if(!resident_ready||busy)return;
 busy=1;logtext("P6_SHELL_NOTIFICATION\r\n");p6_stop_os_watchdog();busy=0;
}
static void EA on_after(HANDLE event,void *context){
 (void)event;(void)context;if(!resident_ready||busy)return;
 busy=1;logtext("P6_AMITSE_AFTER_BOOT\r\n");p6_stop_os_watchdog();
 if(attempted){busy=0;return;}
 /* Still TPL_CALLBACK (8), on the genuine AMITSE return notification stack.
  * This does not lower TPL or claim synchronous firmware calls can time out.
  * Consume before binding: every failure is terminal for this boot. */
 unsigned was_active=active;attempted=1;active=0;
 ES e;
 if(was_active){
  logtext("P6_AFTER_SYNC_CANCEL_BEGIN\r\n");e=gST->bs->set_timer(events[0],0,0);
  logtext("P6_AFTER_SYNC_CANCEL_STATUS=");loghex(e,16);logtext("\r\n");
  if(FAILED(e))goto done;
 }
 logtext("P6_AFTER_SYNC_BIND_BEGIN\r\n");e=p5_bind();
 logtext("P6_AFTER_SYNC_BIND_STATUS=");loghex(e,16);logtext("\r\n");
 if(FAILED(e))goto done;
 logtext("P6_AFTER_SYNC_READ_BEGIN\r\n");e=p1_collect();
 logtext("P6_AFTER_SYNC_READ_STATUS=");loghex(e,16);logtext("\r\n");
 if(FAILED(e))goto done;
 logtext("P6_AFTER_SYNC_PUBLISH_BEGIN\r\n");e=p5_publish();
 logtext("P6_AFTER_SYNC_PUBLISH_STATUS=");loghex(e,16);logtext("\r\n");
done:
 logtext("P6_AFTER_SYNC_END\r\n");busy=0;
}
static ES EA unload(HANDLE image){
 (void)image;if(busy||resident_ready)return ERR(15);active=0;
 for(unsigned i=0;i<7;i++)if(events[i]){ES e=gST->bs->close_event(events[i]);if(FAILED(e))return e;events[i]=0;}
 if(owner){ES e=gST->bs->uninstall_protocol(owner,&service_guid,&api);if(FAILED(e))return e;owner=0;}
 p5_release();return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);
 void *present=0;ES e=gST->bs->locate_protocol(&service_guid,0,&present);
 if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 LOADED *li=0;e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&li);if(FAILED(e)||!li)return ERR(14);
 li->unload=unload;
 for(unsigned i=0;i<V_COUNT;i++)value_text(i,"Not queried");
 logtext("HERO-IPMI-P6-S22 / dynamic PCI discovery / S21S lifecycle unchanged\r\n");
 /* Seed private defaults before AMITSE caches its EFI varstore. */
 p6_seed_settings();
 api=(P6_AUDIT_API){6,sizeof(api),get_log,get_value};
 e=gST->bs->create_event(0x80000200,8,on_timer,0,&events[0]);if(FAILED(e))goto fail;
 e=gST->bs->create_event(0x200,8,on_setup,0,&events[1]);if(FAILED(e))goto fail;
 e=((REGISTER_NOTIFY)gST->bs->register_notify)(&setup_guid,events[1],&registration[0]);if(FAILED(e))goto fail;
 e=gST->bs->create_event_ex(0x200,8,on_ready,0,&ready_guid,&events[2]);if(FAILED(e))goto fail;
 e=gST->bs->create_event(0x200,8,on_before,0,&events[3]);if(FAILED(e))goto fail;
 e=((REGISTER_NOTIFY)gST->bs->register_notify)(&before_guid,events[3],&registration[1]);if(FAILED(e))goto fail;
 for(unsigned i=0;i<2;i++){
  e=gST->bs->create_event(0x200,8,on_shell,0,&events[4+i]);if(FAILED(e))goto fail;
  e=((REGISTER_NOTIFY)gST->bs->register_notify)(&shell_guid[i],events[4+i],&registration[2+i]);if(FAILED(e))goto fail;
 }
 e=gST->bs->create_event(0x200,8,on_after,0,&events[6]);if(FAILED(e))goto fail;
 e=((REGISTER_NOTIFY)gST->bs->register_notify)(&after_guid,events[6],&registration[4]);if(FAILED(e))goto fail;
 e=gST->bs->install_protocol(&owner,&service_guid,0,&api);if(FAILED(e))goto fail;
 resident_ready=1;
 present=0;if(!FAILED(gST->bs->locate_protocol(&setup_guid,0,&present)))on_setup(0,0);
 return 0;
fail:
 if(FAILED(unload(image)))return 0;return e;
}
