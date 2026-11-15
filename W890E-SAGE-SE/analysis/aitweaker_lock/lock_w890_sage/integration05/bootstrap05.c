#include "static05.h"
#include "internal.h"
#include "../packaging05/layout.h"
#include "../installer04/source/memory.h"
#include "../password_runtime02/source/runtime.h"
#include "../navigation05/navigation.h"
#include "../navigation05/bridges.h"
#include "../write_sinks05/save_guard05.h"
static I04_VM boot_vm;
static ST *entry_st;static BS boot_bs;static HANDLE entry_handle;
static uintptr_t entry_base;static UN entry_bytes;
static unsigned anchored,entry_done,service_state;
static volatile unsigned bootstrap_ended;static EVENT bootstrap_event;
static INPUT *boot_input;static TEXTOUT *boot_output;static INPUT saved_input;static TEXTOUT saved_output;
static MP_STATE management;
static NO_PATCH patches[NO_MAX_PATCHES];static MP_PATCH mp_patches[MP_MAX_PATCHES];
static NO_CALL callers[NO_MAX_CALLS];
static GUID loaded={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID strings_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
/* Provider profile IDs are original file hashes. Live module .text is
 * independently verified and normalized by the observer/static layout. */
static const uint8_t setup_sha[32]={0xc1,0xcf,0x9d,0x75,0x5c,0x2e,0xa0,0x43,0xd4,0x4f,0x19,0xfd,0xf4,0,0x9c,0xf8,0xb1,0x2b,3,0xf8,0x5e,0x89,0x39,3,0x4d,0xe1,0x9e,0xe1,0x82,0x51,0xb7,0x2e};
static const uint8_t tse_sha[32]={0x43,0xf8,0x0b,0xf7,0x38,0xe0,0xb1,0x10,0x14,0x31,0xb7,0x31,0x9a,0x8a,0x9c,0,0x60,0x65,0x5e,0x70,0x8f,0x22,0xf5,0xb6,0x37,0x96,0x20,0xae,0xe8,0x62,0xe6,0xfe};
extern uint8_t mp_call_provider_return[],i05_profile_gate_return[];
MP_STATE *i05_management_state(void){return &management;}
int i05_image_range(uintptr_t base,UN n){
 if(!anchored||base!=entry_base||n!=entry_bytes||!i04_vm_current(&boot_vm)||n>UINTPTR_MAX-base)return 0;
 for(UN at=0;at<n;at+=4096){UN bytes=n-at;if(bytes>4096)bytes=4096;if(!i04_access(&boot_vm,base+at,bytes,0,0))return 0;}return 1;
}
static int anchor_live(void){
 if(bootstrap_ended||!anchored||!entry_st||!i04_vm_current(&boot_vm)||!i04_access(&boot_vm,(uintptr_t)entry_st,sizeof(*entry_st),0,0)||!i04_access(&boot_vm,(uintptr_t)entry_st->bs,sizeof(BS),0,0)||memcmp(entry_st->bs,&boot_bs,sizeof(BS)))return 0;
 LOADED*li=0;if(boot_bs.handle_protocol(entry_handle,&loaded,(void**)&li)!=0||!i04_capture(&boot_vm,entry_st)||!i04_access(&boot_vm,(uintptr_t)li,sizeof(*li),0,0)||li->revision!=0x1000||li->st!=entry_st||li->image_base!=(void*)entry_base||li->image_size!=entry_bytes)return 0;
 return i05_image_range(entry_base,entry_bytes)&&i05_layout_live(entry_base,entry_bytes);
}
static void EA bootstrap_end(EVENT e,void*c){
 (void)e;(void)c;bootstrap_ended=1;boot_vm.ended=1;service_state=3;
 no_end_boot(0,0);w890_runtime_end_boot();mp_end_boot(&management);ws05_end_boot();
}
static int boot_services_live(void){
 return !bootstrap_ended&&i04_vm_current(&boot_vm)&&i04_access(&boot_vm,(uintptr_t)entry_st,sizeof(*entry_st),0,0)&&
  entry_st->bs==boot_vm.bs&&i04_access(&boot_vm,(uintptr_t)boot_vm.bs,sizeof(BS),0,0)&&!memcmp(boot_vm.bs,&boot_bs,sizeof(BS));
}
static int recovery_console(void){
 return !bootstrap_ended&&anchored&&i04_vm_current(&boot_vm)&&
  i04_access(&boot_vm,(uintptr_t)entry_st,sizeof(*entry_st),0,0)&&entry_st->bs==boot_vm.bs&&entry_st->in==boot_input&&entry_st->out==boot_output&&
  i04_access(&boot_vm,(uintptr_t)entry_st->bs,sizeof(BS),0,0)&&!memcmp(entry_st->bs,&boot_bs,sizeof(BS))&&
  i04_access(&boot_vm,(uintptr_t)boot_input,sizeof(INPUT),0,0)&&!memcmp(boot_input,&saved_input,sizeof(INPUT))&&
  i04_access(&boot_vm,(uintptr_t)boot_output,sizeof(TEXTOUT),0,0)&&!memcmp(boot_output,&saved_output,sizeof(TEXTOUT))&&
  saved_input.read&&saved_input.wait&&saved_output.out&&boot_bs.wait&&
  i04_access(&boot_vm,(uintptr_t)saved_input.read,1,0,1)&&i04_access(&boot_vm,(uintptr_t)saved_output.out,1,0,1)&&i04_access(&boot_vm,(uintptr_t)boot_bs.wait,1,0,1);
}
__attribute__((noreturn)) void EA i05_failure(void){
 service_state=3;w890_provider_fault();
 if(recovery_console()){
  saved_output.out(boot_output,U("\r\nAi Tweaker protection could not initialize.\r\nBIOS setup has stopped before using incomplete data.\r\nR: recheck status. Use remote management to restart.\r\n"));
  while(recovery_console()){
   EVENT event=saved_input.wait;UN index=~(UN)0;ES r=boot_bs.wait(1,&event,&index);
   if(r!=0||index||!recovery_console())break;KEY key;
   if(saved_input.read(boot_input,&key)!=0||!recovery_console())break;
   if(key.ch=='r'||key.ch=='R'){
    /* Recheck only. No automatic replay of a partially completed publisher,
     * no reset, and no native continuation through an ignored error return. */
    int same=anchor_live();if(!recovery_console())break;
    saved_output.out(boot_output,same?U("Protection remains stopped. Restart to retry initialization.\r\n"):U("Firmware identity changed. Setup remains stopped.\r\n"));
   }
  }
 }
 for(;;)__asm__ volatile("cli; hlt");
}
int i05_parser_caller(uintptr_t caller){
 if(!anchored)return 0;static const uint32_t sites[]={0x18e46,0x45367,0x7c487,0x82265,0x885cb};
 for(unsigned i=0;i<5;i++)if(caller==entry_base+sites[i])return 1;return 0;
}
ES EA i05_entry(HANDLE image,ST*st){
 if(anchored||!st||!image)return NO_DENIED;
 /* Initial ST is the actual firmware entry argument; after capture all saved
  * pointers are revalidated before dereference and after external services. */
 if(!i04_capture(&boot_vm,st)||!i04_access(&boot_vm,(uintptr_t)st->bs,sizeof(BS),0,0)||!st->bs->handle_protocol)return NO_DENIED;
 entry_st=st;entry_handle=image;boot_bs=*st->bs;LOADED*li=0;
 if(boot_bs.handle_protocol(image,&loaded,(void**)&li)!=0||!i04_capture(&boot_vm,st)||!i04_access(&boot_vm,(uintptr_t)li,sizeof(*li),0,0)||li->revision!=0x1000||li->st!=st)return NO_DENIED;
 entry_base=(uintptr_t)li->image_base;entry_bytes=li->image_size;anchored=1;
 const I05_LAYOUT*l=i05_layout_get();if(!l||entry_base+l->entry_rva!=(uintptr_t)i05_entry||!anchor_live()){service_state=3;return NO_DENIED;}
 ws05_save_cancel=(void*)(entry_base+0x202f4);
 boot_input=st->in;boot_output=st->out;
 if(i04_access(&boot_vm,(uintptr_t)boot_input,sizeof(INPUT),0,0)&&i04_access(&boot_vm,(uintptr_t)boot_output,sizeof(TEXTOUT),0,0)){saved_input=*boot_input;saved_output=*boot_output;}
 if(!boot_services_live()||!boot_bs.create_event||!boot_bs.close_event||!i04_access(&boot_vm,(uintptr_t)boot_bs.create_event,1,0,1)||!i04_access(&boot_vm,(uintptr_t)boot_bs.close_event,1,0,1)||boot_bs.create_event(0x201,16,bootstrap_end,0,&bootstrap_event)!=0||bootstrap_ended||!bootstrap_event)return NO_DENIED;
 ES r=((ES(EA*)(HANDLE,ST*))(entry_base+0x6480))(image,st);
 if(r!=0||!anchor_live()){service_state=3;if(boot_services_live()&&i04_access(&boot_vm,(uintptr_t)boot_bs.close_event,1,0,1)&&boot_bs.close_event(bootstrap_event)==0){bootstrap_event=0;return r?r:NO_DENIED;}i05_failure();}entry_done=1;return 0;
}
static int add_call(uintptr_t address,unsigned kind,unsigned*count){
 if(*count>=NO_MAX_CALLS||address<entry_base+16||address>=entry_base+entry_bytes-16||!no_range(address-16,32,NO_READ|NO_EXEC))return 0;
 NO_CALL*c=&callers[(*count)++];c->address=address;c->kind=kind;c->reserved=0;memcpy(c->window,(void*)(address-16),32);return 1;
}
static void *symbol(const char*name,unsigned kind){uint32_t r=i05_layout_symbol(name,kind);return r?(void*)(entry_base+r):0;}
static int install_callback(CONFIG*c,CALLBACK old,CALLBACK value){
 if(!no_range((uintptr_t)c,sizeof(*c),NO_READ|NO_WRITE)||((uintptr_t)&c->callback&7))return 0;
 UN tpl=boot_bs.raise_tpl(31);int ok=tpl==4;
 if(ok)ok=__atomic_compare_exchange_n((uintptr_t*)&c->callback,(uintptr_t*)&old,(uintptr_t)value,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
 boot_bs.restore_tpl(tpl);return ok;
}
ES EA i05_services(void){
 if(service_state==2)return anchor_live()?0:NO_DENIED;
 if(service_state||!entry_done||!anchor_live())return NO_DENIED;service_state=1;
 if(!i04_access(&boot_vm,entry_base+0xafdd0,8,0,0)||*(uintptr_t*)(entry_base+0xafdd0)||no_initialize(entry_st)!=0)goto failed;
 NO_IDENTITY id;if(!no_identity(&id)||id.tse_base!=entry_base||id.tse_driver!=entry_handle||id.loop_depth||id.send_depth)goto failed;
 const I05_LAYOUT*l=i05_layout_get();if(!l||l->patch_count>NO_MAX_PATCHES||l->patch_count>MP_MAX_PATCHES)goto failed;
 for(unsigned k=0;k<l->patch_count;k++){const I05_PATCH*p=&l->patches[k];if(p->module)goto failed;
  patches[k].module=0;patches[k].rva=p->rva;patches[k].length=p->length;memcpy(patches[k].original,p->original,32);memcpy(patches[k].installed,p->installed,32);memcpy(&mp_patches[k],&patches[k],sizeof(MP_PATCH));}
 unsigned count=0;if(!add_call((uintptr_t)mp_call_provider_return,NO_CALL_SCOPE,&count))goto failed;
 /* The offline builder disassembles the actual linked consumers. Its reviewed
  * return-address aliases are part of the immutable post-link layout, not
  * inputs supplied by an EFI application or by a generic owner callback. */
 for(unsigned i=0;i<l->export_count;i++){const I05_SYMBOL*x=&l->symbols[i];unsigned kind=0;
  if(!memcmp(x->name,"i05_effect_",11))kind=NO_CALL_EFFECT;
  if(!memcmp(x->name,"i05_request_",12))kind=NO_CALL_REQUEST;
  if(kind&&!add_call(entry_base+x->rva,kind,&count))goto failed;}
 NO_INSTALL ni={NO_REVISION,sizeof(ni),symbol("i05_original_loop",1),symbol("i05_original_send",1),(void*)(entry_base+0x6480),&w890_provider,patches,l->patch_count,0,callers,count,0,mp_callback,mp_native_publish,&management};
 if(!ni.loop_trampoline||!ni.send_trampoline||no_prepare(&ni)!=0)goto failed;
 W890_HOST host=no_host();AP_STATUS credential=w890_runtime_bind(entry_st,&host,setup_sha,tse_sha);
 if(credential!=AP_OK&&credential!=AP_UNCONFIGURED)goto failed; /* FAULT restricted visit requires complete guard closure. */
 STRINGS*strings=0;if(boot_bs.locate_protocol(&strings_guid,0,(void**)&strings)!=0||!no_range((uintptr_t)strings,sizeof(*strings),NO_READ))goto failed;
 MP_BINDING mb={entry_st,id.database,strings,id.hii,id.setup_driver,id.config,(void*)id.setup_base,id.setup_size,id.tse_driver,(void*)id.tse_base,id.tse_size,mp_patches,l->patch_count,0};
 MP_AUTHORITY ma={MP_REVISION,sizeof(ma),0,no_publication_validate,no_publication_finished,no_restoration_finished,no_management_enter,no_management_valid,no_management_leave};
 if(mp_bind(&management,&mb,&ma)!=MP_OK||!install_callback(id.config,(CALLBACK)(id.setup_base+0x2250),mp_callback))goto failed;
 if(!mp_identity(&management,1)||n05_bind()!=0||n05_bridges_bind()!=0)goto rollback;
 n05_form_open_trampoline=(uintptr_t)symbol("i05_original_form_open",1);
 WS05_BINDING wb={0};wb.revision=5;wb.size=sizeof(wb);wb.provider=&w890_provider;wb.save_replay=symbol("i05_original_save",1);wb.replay_bytes=24;
 wb.dispatch=(WS05_PATH){symbol("i05_original_dispatch",1),21,0};wb.defaults=(WS05_PATH){symbol("i05_original_defaults",1),19,0};wb.load_defaults_save=(WS05_PATH){symbol("i05_original_load_defaults_save",1),20,0};wb.profile_bridge_return=i05_profile_gate_return;
 if(!n05_form_open_trampoline||!wb.save_replay||!wb.dispatch.entry||!wb.defaults.entry||!wb.load_defaults_save.entry||ws05_prepare(&wb)!=0)goto rollback;
 service_state=2;return 0;
rollback:install_callback(id.config,mp_callback,(CALLBACK)(id.setup_base+0x2250));
failed:service_state=3;w890_provider_fault();return NO_DENIED;
}
ES EA i05_loop(void){if(i05_services()!=0)i05_failure();__attribute__((musttail)) return no_native_loop();}
ES EA i05_send(void*a,HANDLE*b,UN c,GUID*d,uint16_t e,void*f,UN*g){if(i05_services()!=0)i05_failure();__attribute__((musttail)) return no_native_send_form(a,b,c,d,e,f,g);}
void EA i05_dispatch(uint64_t action,void*b,void*c,void*d){
 if(service_state==2){ws05_native_dispatch(action,b,c,d);return;}
 /* FD6C also dispatches ordinary callbacks during original DXE/BDS init.
  * No password/defaults authority follows from this pre-UI forwarding path. */
 if(service_state==3||action==UINT64_C(0xffff001d)||!anchored||!i05_image_range(entry_base,entry_bytes)||!i05_layout_live(entry_base,entry_bytes))return;
 void*target=symbol("i05_original_dispatch",1);if(!target)return;
 ((void(EA*)(uint64_t,void*,void*,void*))target)(action,b,c,d);
}
