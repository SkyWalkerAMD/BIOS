#include "split_owner.h"
static GUID provider_guid={0x87e3c6fa,0x11fb,0x4e77,{0xaf,0x2d,0xea,0x50,0xb6,0x40,0xfa,0x13}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID before_exit_guid={0x8be0e274,0x3970,0x4b44,{0x80,0xc5,0x1a,0xb9,0x50,0x2f,0x3b,0xfc}};
static EVENT exit_event,before_event;
static HANDLE provider_handle;
extern int initialize_native_services(ST *);
static ES EA no_unload(HANDLE image){(void)image;return ERR(15);}
void EA split_ending(EVENT event,void *context){(void)event;(void)context;split_owner_end();provider_end_boot();}
ES EA efi_main(HANDLE image,ST *st){
 if(boot_services_ended)return ERR(15);
 if(!st||!st->bs||!st->rt||!st->bs->create_event||!st->bs->locate_protocol||!st->bs->install_protocol||!st->bs->handle_protocol)return ERR(2);
 system_table=st;void *existing=0;
 ES status=st->bs->locate_protocol(&provider_guid,0,&existing);if(boot_services_ended)return 0;if(status!=ERR(14)||existing)return ERR(20);
 LOADED *li=0;status=st->bs->handle_protocol(image,&loaded_guid,(void **)&li);
 if(boot_services_ended)return 0;if(FAILED(status)||!memory_present(li,sizeof(*li),1)||li->options_size!=sizeof(SPLIT_CONTEXT)||!memory_present(li->options,sizeof(SPLIT_CONTEXT),0))return ERR(3);
 /* Once an event is registered the driver always remains resident, including
  * on any subsequent failure. The harness must treat missing protocol as an
  * attach failure and restore/retire its own detours; this driver never does so. */
 li->unload=(void *)no_unload;
 status=st->bs->create_event(0x201,16,split_ending,0,&exit_event);
 if(boot_services_ended)return 0;if(FAILED(status))return ERR(7);
 if(st->bs->create_event_ex)st->bs->create_event_ex(0x200,16,split_ending,0,&before_exit_guid,&before_event);
 if(boot_services_ended)return 0;
 if(!split_owner_bind(li->options,li->image_base,li->image_size)){provider_fault();return 0;}
 int initialized=initialize_native_services(st);if(boot_services_ended)return 0;if(!initialized){provider_fault();return 0;}
 status=st->bs->install_protocol(&provider_handle,&provider_guid,0,&native_provider);
 if(boot_services_ended)return 0;if(FAILED(status)){provider_fault();return 0;}
 install_split_management(image);return 0;
}
