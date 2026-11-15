#include "provider.h"
static GUID provider_guid={0xf29d11ab,0xc12a,0x455a,{0x95,0xd3,0x9a,0x8e,0xcf,0x04,0x5c,0x04}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID end_dxe_guid={0x2ce967a,0xdd7e,0x4ffc,{0x9e,0xe7,0x81,0xc,0xf0,0x47,0x8,0x80}};
static GUID before_exit_guid={0x8be0e274,0x3970,0x4b44,{0x80,0xc5,0x1a,0xb9,0x50,0x2f,0x3b,0xfc}};
static EVENT exit_event,before_event,loaded_event,end_dxe_event,timer_event;
static void *loaded_registration;
static HANDLE provider_handle;
extern int initialize_native_services(ST *);
static ES EA no_unload(HANDLE image){(void)image;return ERR(15);}
static void EA ending(EVENT event,void *context){(void)event;(void)context;provider_end_boot();}
static void EA discover(EVENT event,void *context){
 (void)event;(void)context;if(boot_services_ended)return;
 int installed=install_management();
 if(!boot_services_ended&&installed&&timer_event)system_table->bs->set_timer(timer_event,0,0);
}
ES EA efi_main(HANDLE image,ST *st){
 if(!st||!st->bs||!st->rt||!st->bs->create_event||!st->bs->locate_protocol||!st->bs->install_protocol||!st->bs->handle_protocol||!st->bs->set_timer)return ERR(2);
 if(boot_services_ended)return 0;
 void *existing=0;ES s=st->bs->locate_protocol(&provider_guid,0,&existing);if(boot_services_ended)return 0;if(s!=ERR(14)||existing)return ERR(20);
 int initialized=initialize_native_services(st);if(boot_services_ended)return 0;if(!initialized)return ERR(7);
 LOADED *li=0;
 s=st->bs->handle_protocol(image,&loaded_guid,(void **)&li);if(boot_services_ended)return 0;if(FAILED(s)||!memory_present(li,sizeof(*li),1))return ERR(3);
 li->unload=(void *)no_unload;
 s=st->bs->create_event(0x201,16,ending,0,&exit_event);if(boot_services_ended)return 0;if(FAILED(s))return ERR(7);
 /* Once a callback exists the image returns success and remains resident even
  * if protocol publication fails. No dangling event to an unloaded image. */
 if(st->bs->create_event_ex)st->bs->create_event_ex(0x200,16,ending,0,&before_exit_guid,&before_event);
 if(boot_services_ended)return 0;
 ES published=st->bs->install_protocol(&provider_handle,&provider_guid,0,&native_provider);
 if(boot_services_ended)return 0;
 if(FAILED(published)){provider_fault();audit(2,published);return 0;}
 if(st->bs->register_notify){
  s=st->bs->create_event(0x200,8,discover,0,&loaded_event);if(boot_services_ended)return 0;
  if(!FAILED(s))st->bs->register_notify(&loaded_guid,loaded_event,&loaded_registration);
  if(boot_services_ended)return 0;
 }
 if(st->bs->create_event_ex)st->bs->create_event_ex(0x200,8,discover,0,&end_dxe_guid,&end_dxe_event);
 if(boot_services_ended)return 0;
 s=st->bs->create_event(0x80000200,8,discover,0,&timer_event);if(boot_services_ended)return 0;
 if(!FAILED(s))st->bs->set_timer(timer_event,1,1000000);
 if(boot_services_ended)return 0;
 discover(0,0);return 0;
}
