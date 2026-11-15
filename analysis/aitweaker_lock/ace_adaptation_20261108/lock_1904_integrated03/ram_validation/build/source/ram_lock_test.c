/* Maintenance-only application. No flash code or filesystem writes.
 * Credential persistence is RAM-only. Runtime SetVariable table calls are
 * blocked before hooks attach. After arming, this image never unloads: reset
 * is the only way out, so no resident hook can reference freed application code.
 */
#include "lock.h"
#include "probe_core.h"
#include "target_detect.h"
#include "build_identity.h"
extern ES kvm_present(ST *,const char *,size_t,unsigned);
typedef struct BROWSER BROWSER;
struct BROWSER {ES(EA *send)(BROWSER *,HANDLE *,UN,GUID *,uint16_t,void *,UN *);void *callback;};
static BROWSER *browser;
static uint8_t ram_record[AP_RECORD_BYTES];
static size_t ram_size;
static int ram_self_test;
static EVENT ram_exit_event;
static unsigned blocked_writes,checks,failures;
static char log_data[32768];static size_t log_size;
static uint8_t *tse_image,*setup_image;static UN tse_size,setup_size;
static GUID formset={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
static void print(C16 *s) {system_table->out->out(system_table->out,s);}
static void add(const char *s) {while(*s && log_size<sizeof(log_data)-1)log_data[log_size++]=*s++;log_data[log_size]=0;}
static void hex(uint64_t v) {const char h[]="0123456789ABCDEF";for(unsigned i=0;i<16;i++){char t[2]={h[(v>>(60-4*i))&15],0};add(t);}}
static void field(const char *name,uint64_t v) {add(name);add("=0x");hex(v);add("\r\n");}
static int check(int value,const char *label) {checks++;if(!value)failures++;add(value?"PASS ":"FAIL ");add(label);add("\r\n");return value;}
static KEY read_key(void) {KEY key={0,0};for(;;){ES e=system_table->in->read(system_table->in,&key);if(!FAILED(e))return key;system_table->bs->stall(1000);}}
static void show_log(void) {size_t prior=log_size;field("Checks",checks);field("Failures",failures);field("BlockedSetVariableCalls",blocked_writes);add("PROBE_COMPLETE\r\n");kvm_present(system_table,log_data,log_size,failures);log_size=prior;log_data[log_size]=0;}
static void reset(void) {ap_secure_zero(ram_record,sizeof(ram_record));ap_secure_zero(&password_core,sizeof(password_core));void(EA *fn)(uint32_t,ES,UN,void *)=system_table->rt->reset;fn(0,0,0,0);for(;;)__asm__ volatile("hlt");}
static __attribute__((noreturn)) void EA refuse_os_handoff(EVENT event,void *context) {
 (void)event;(void)context;
 /* deny_variable is application memory, not a Runtime driver. Never let an
  * OS reclaim this image while that maintenance callback can be referenced.
  * Final EBS uses no provider, console, allocation, reset or Boot Service. */
 end_platform();ap_session_end(&password_core);
 ap_secure_zero(password_core.record,sizeof(password_core.record));
 ap_secure_zero(ram_record,sizeof(ram_record));ram_size=0;ram_self_test=0;
 boot_services_ended=1;
 for(;;)__asm__ volatile("cli; hlt");
}
static AP_READ_RESULT ram_read(void *opaque,uint8_t *out,size_t capacity,size_t *size) {
 (void)opaque;*size=ram_size;if(!ram_size)return AP_READ_NOT_FOUND;
 if(capacity<ram_size)return AP_READ_ERROR;memcpy(out,ram_record,ram_size);return AP_READ_OK;
}
static int ram_persist(void *opaque,const uint8_t *data,size_t n) {
 (void)opaque;
 if(boot_services_ended || n!=AP_RECORD_BYTES || (!ram_self_test && !platform_session_owned()))return 1;
 memcpy(ram_record,data,n);ram_size=n;return 0;
}
static ES EA deny_variable(C16 *name,GUID *guid,uint32_t attributes,UN n,void *data) {
 (void)name;(void)guid;(void)attributes;(void)n;(void)data;blocked_writes++;return ERR(8);
}
static int block_variable_table(void) {
 if(!ram_exit_event || boot_services_ended)return 0;
 RT copy=*system_table->rt;
 if(copy.hdr.size<offsetof(RT,set_variable)+8 || copy.hdr.size>sizeof(copy))return 0;
 copy.set_variable=deny_variable;copy.hdr.crc=0;
 if(FAILED(system_table->bs->crc32(&copy,copy.hdr.size,&copy.hdr.crc)) || !patch_memory(system_table->rt,&copy,copy.hdr.size))return 0;
 original_set_variable=deny_variable;return 1;
}
typedef struct {ES status;UN size;uint32_t attributes;uint8_t hash[32];} VAR_HASH;
static VAR_HASH before_vars[3];
static C16 *var_names[]={L"VARSTORE_OCMR_SETTINGS_NAME",L"SocketMemoryConfig",L"AiTweakerPassword1904"};
static GUID *var_guids[]={&oc_guid,&memory_guid,&credential_guid};
static int snapshot(unsigned index,VAR_HASH *v) {
 uint8_t *data=alloc(32768);if(!data)return 0;memset(v,0,sizeof(*v));v->size=32768;
 v->status=system_table->rt->get_variable(var_names[index],var_guids[index],&v->attributes,&v->size,data);
 int ok=(!FAILED(v->status) && v->size<=32768)||v->status==ERR(14);
 if(!FAILED(v->status))ap_sha256(data,v->size,v->hash);
 if(v->status==ERR(14)){v->size=0;v->attributes=0;}
 ap_secure_zero(data,32768);release(data);return ok;
}
static void verify_variables(void) {
 for(unsigned i=0;i<3;i++){VAR_HASH after;int ok=snapshot(i,&after)&&!memcmp(&before_vars[i],&after,sizeof(after));field("VariableIndex",i);check(ok,"variable metadata and SHA256 unchanged");}
}
static int browser_ready(void) {
 BROWSER *found=0;uint32_t stage;
 if(boot_services_ended || !tse_image || !memory_present(tse_image+0x82628,4,0))return 0;
 memcpy(&stage,tse_image+0x82628,4);if(stage==5)return 0;
 if(FAILED(system_table->bs->locate_protocol(&browser_guid,0,(void **)&found)) ||
    found!=(void *)(tse_image+0x6b528) || !memory_present(found,sizeof(*found),0))return 0;
 if(found->send!=(void *)(tse_image+0x20f34) || found->callback!=(void *)(tse_image+0x2168c))return 0;
 /* LocateProtocol and permission discovery may call firmware. */
 memcpy(&stage,tse_image+0x82628,4);
 if(stage==5 || boot_services_ended)return 0;
 browser=found;return 1;
}
static int find_targets(void) {
 HANDLE *handles=0;UN count=0;
 if(FAILED(system_table->bs->locate_handles(2,&loaded_guid,0,&count,&handles))||!handles)return 0;
 if(count>4096){release(handles);return 0;}
 for(UN i=0;i<count;i++){LOADED *li=0;GUID guid;
  if(FAILED(system_table->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li))||!li||!image_guid(li,&guid))continue;
  if(!memcmp(&guid,&tse_guid,16)){if(tse_image){release(handles);return 0;}tse_image=li->image_base;tse_size=li->image_size;}
  if(!memcmp(&guid,&setup_guid,16)){if(setup_image){release(handles);return 0;}setup_image=li->image_base;setup_size=li->image_size;}
 }
 release(handles);IMAGE_INFO a,b;
 if(!tse_image||!setup_image||tse_size<0x92b10||!memory_present(tse_image,tse_size,0)||!memory_present(setup_image,setup_size,0))return 0;
 if(!probe_image(tse_image,tse_size,&a)||!probe_image(setup_image,setup_size,&b))return 0;
 field("AMITSE.text_crc",a.text_crc);field("AMITSE.text_rva",a.text_rva);field("AMITSE.text_size",a.text_size);field("AMITSE.entry",a.entry);
 field("Setup.text_crc",b.text_crc);field("Setup.text_rva",b.text_rva);field("Setup.text_size",b.text_size);field("Setup.entry",b.entry);
 if(a.text_crc!=0x760c4005||a.text_rva!=0x2c0||a.text_size!=0x69ecf||a.entry!=0x5a0||
    b.text_crc!=0x9e141291||b.text_rva!=0x2c0||b.text_size!=0x2746f||b.entry!=0x590)return 0;
 uint32_t stage;memcpy(&stage,tse_image+0x82628,4);field("AMITSE.stage",stage);if(stage==5)return 0;
 return browser_ready();
}
static int self_test_ram(void) {
 AP_ENV env=password_core.env;env.read=ram_read;env.persist=ram_persist;env.opaque=0;
 uint8_t sample[32];uint64_t first=0,last=0;
 if(!check(!env.entropy(0,sample,sizeof(sample)),"platform cryptographic entropy available"))return 0;
 ap_secure_zero(sample,sizeof(sample));
 int timed=!env.now_ms(0,&first);system_table->bs->stall(100000);timed=timed&&!env.now_ms(0,&last)&&last>first;
 if(!check(timed,"monotonic password retry clock"))return 0;
 check(ap_init(&password_core,&env)==AP_UNCONFIGURED,"RAM-only credential starts absent");
 uint64_t token=ap_session_begin(&password_core);
 const uint8_t pass[]="temporary-fixture-1904",bad[]="wrong-fixture-1904",next[]="temporary-changed-1904";
 if(!check(ap_set_password(&password_core,token,0,0,pass,sizeof(pass)-1)==AP_OK,"enroll credential in RAM using production entropy and PBKDF2"))return 0;
 check(!ap_can_enter(&password_core),"enrollment leaves Ai Tweaker locked");
 check(ap_unlock(&password_core,token,bad,sizeof(bad)-1)==AP_DENIED,"wrong password denied");
 check(ap_unlock(&password_core,token,pass,sizeof(pass)-1)==AP_RATE_LIMITED,"immediate retry rate limited");
 system_table->bs->stall(5200000);
 check(ap_unlock(&password_core,token,pass,sizeof(pass)-1)==AP_OK&&ap_can_enter(&password_core),"correct password unlocks after delay");
 check(!platform_session_owned()&&!platform_can_enter(),"core-only self-test grant is not a native browser owner");
 ap_session_end(&password_core);token=ap_session_begin(&password_core);
 check(!ap_can_enter(&password_core),"new BIOS session relocks");
 check(ap_set_password(&password_core,token,pass,sizeof(pass)-1,next,sizeof(next)-1)==AP_OK,"authenticated password change in RAM");
 check(ap_clear_password(&password_core,token,next,sizeof(next)-1)==AP_OK&&password_core.mode==AP_MODE_DISABLED,"authenticated clear in RAM");
 ap_secure_zero(ram_record,sizeof(ram_record));ram_size=0;
 check(ap_init(&password_core,&env)==AP_UNCONFIGURED,"discard self-test credential before interactive test");
 return !failures;
}
ES EA efi_main(HANDLE image,ST *st) {
 (void)image;system_table=st;if(!st||!st->bs||!st->rt||!st->in||!st->out)return ERR(2);
 st->bs->set_watchdog(0,0,0,0);add("AITWEAKER-PROBE-P3-KVM\r\nACE1904-INTEGRATED03-RAM\r\nDriverSHA256=" RAM_TEST_DRIVER_SHA "\r\nCredentialStorage=RAM_ONLY\r\nSPI_WRITES=NONE\r\n");
 int target=board_matches();field("Production.SMBIOS.board_match",target);
 if(!target){add("UNSUPPORTED_BOARD_NO_HOOKS_NO_WRITES\r\n");show_log();return ERR(3);}
 if(!check(find_targets(),"exact W790-ACE 1904 modules, browser interface and both methods")){show_log();return ERR(3);}
 field("CPU.RDSEED.supported",cpu_entropy_supported());
 for(unsigned i=0;i<3;i++)if(!check(snapshot(i,&before_vars[i]),"capture initial variable metadata and hash")){show_log();return ERR(7);}
 if(!check(before_vars[2].status==ERR(14),"no existing independent credential to interfere with")){show_log();return ERR(15);}
 if(!check(initialize_services(),"initialize production services")){show_log();reset();}
 if(!check(!FAILED(st->bs->create_event(EVT_SIGNAL_EXIT_BOOT_SERVICES,TPL_NOTIFY,refuse_os_handoff,0,&ram_exit_event))&&ram_exit_event,"maintenance application blocks OS handoff before table replacement")){show_log();reset();}
 ram_self_test=1;int tested=self_test_ram();ram_self_test=0;
 if(!tested){show_log();reset();}
 check(ram_persist(0,password_core.record,sizeof(password_core.record))!=0&&!ram_size,"RAM persistence rejects calls outside native browser owner");
 verify_variables();show_log();
 if(failures)reset();
 print(U("Ai Tweaker ACE1904 INTEGRATED03 - RAM TEST\r\n\r\nPreflight passed. No permanent password has been set.\r\nPress L to arm temporary hooks. ESC cold reboots without hooks.\r\nExit requires a cold reboot to release firmware callbacks.\r\n"));
 KEY key;do {key=read_key();if(key.scan==0x17)reset();}while(key.ch!='l'&&key.ch!='L');
 if(!check(browser_ready(),"exact browser remains idle immediately before arming")||
    !check(block_variable_table(),"Runtime SetVariable table calls blocked for maintenance")||
    !check(browser_ready(),"exact browser remains idle after variable table replacement")||
    !check(attach_platform(tse_image,tse_size,setup_image,setup_size),"production navigation hooks attached")) {show_log();reset();}
 field("HII.manager_present",setup_hii!=0);if(!setup_hii){check(0,"Security management HII publication");show_log();reset();}
 for(;;) {
  st->out->attribute(st->out,7);st->out->clear(st->out);
  print(U("Ai Tweaker ACE1904 INTEGRATED03 - RAM TEST\r\n\r\n1: Open Setup at Main\r\n2: Open Setup at Ai Tweaker (initial-page gate)\r\n3: Open Setup at Favorites\r\n4: Open Setup at ASUS Profile\r\nQ: Show diagnostic log\r\nR: Cold reboot and remove all temporary hooks/password\r\n\r\nUse Security to set/change/clear the independent RAM password.\r\nDo not change OC values or select Save & Reset.\r\nHistory check: choose 2, cancel, open Security, then ESC to Main.\r\n"));
  key=read_key();uint16_t form=key.ch=='1'?0x2713:key.ch=='2'?0x2714:key.ch=='3'?0x2712:key.ch=='4'?0x272c:0;
  if(form){
   if(!check(browser_ready(),"exact browser remains idle before SendForm")){show_log();reset();}
   field("SendForm.initial_form",form);UN request=0;ES result=browser->send(browser,&setup_hii,1,&formset,form,0,&request);
   field("SendForm.status",result);field("SendForm.request",request);field("Credential.mode",password_core.mode);
   field("Credential.active_after_return",password_core.active);field("Credential.unlocked_after_return",password_core.unlocked);
   check(!password_core.active&&!password_core.unlocked&&!platform_session_owned(),"native browser return retires owner and grant");
   verify_variables();
  }
  else if(key.ch=='q'||key.ch=='Q'){verify_variables();show_log();}
  else if(key.ch=='r'||key.ch=='R'){verify_variables();show_log();reset();}
 }
}
