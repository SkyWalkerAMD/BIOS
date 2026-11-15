/* NVRAM maintenance application, NOT RAM-only and NOT the production driver.
 * No AMITSE/HII hooks or SendForm. Real frozen password/service/UI objects use
 * an explicit console-owner adapter. Only the credential gate can call native
 * SetVariable. After residency starts this application never returns/unloads.
 */
#include "nv_guard.h"
#include "probe_core.h"
#include "target_detect.h"
#include "build_identity.h"
extern ES kvm_present(ST *,const char *,size_t,unsigned);
static EVENT maintenance_exit_event,maintenance_before_event;
static GUID maintenance_before_guid=BEFORE_EXIT_BOOT_SERVICES_GUID;
static __attribute__((noreturn)) void EA refuse_os_handoff(EVENT,void *);
static uint32_t console_depth,console_retired,resident;
static uint64_t console_token;
static unsigned checks,failures,session_count;
static char log_data[32768];static size_t log_size;
static void add(const char *s) {while(*s && log_size<sizeof(log_data)-1)log_data[log_size++]=*s++;log_data[log_size]=0;}
static void hex(uint64_t n) {const char h[]="0123456789abcdef";for(unsigned i=0;i<16;i++){char t[2]={h[(n>>(60-i*4))&15],0};add(t);}}
static void field(const char *s,uint64_t n) {add(s);add("=0x");hex(n);add("\r\n");}
static void hash_field(const char *s,const uint8_t h[32]) {const char digits[]="0123456789abcdef";add(s);add("=");for(unsigned i=0;i<32;i++){char t[3]={digits[h[i]>>4],digits[h[i]&15],0};add(t);}add("\r\n");}
static int check(int result,const char *label) {checks++;if(!result)failures++;add(result?"PASS ":"FAIL ");add(label);add("\r\n");return result;}
static void print(C16 *s) {if(boot_services_ended)refuse_os_handoff(0,0);system_table->out->out(system_table->out,s);if(boot_services_ended)refuse_os_handoff(0,0);}
static KEY read_key(void) {KEY key={0,0};for(;;){if(boot_services_ended)refuse_os_handoff(0,0);ES s=system_table->in->read(system_table->in,&key);if(boot_services_ended)refuse_os_handoff(0,0);if(!FAILED(s))return key;system_table->bs->stall(1000);}}

/* Deliberate harness ABI adapter: this is NOT the native browser owner. It
 * prevents production persist_record and UI calls outside our explicit menu
 * session. Frozen platform.obj is intentionally not linked. */
int platform_session_owned(void) {
 return console_depth==1 && !console_retired && !boot_services_ended &&
        password_core.active && console_token && console_token==password_core.session_token;
}
int platform_can_enter(void) {
 if(console_retired || boot_services_ended || password_core.busy)return 0;
 if(password_core.mode==AP_MODE_DISABLED)return 1;
 return platform_session_owned() && ap_can_enter(&password_core);
}
void end_platform(void) {console_retired=1;console_depth=0;console_token=0;}
int begin_console_session(void) {
 if(console_retired || boot_services_ended || password_core.busy || nv_status()->fault)return 0;
 ap_session_end(&password_core);console_depth=0;console_token=ap_session_begin(&password_core);
 if(!console_token || !password_core.active)return 0;
 console_depth=1;session_count++;
 return !password_core.unlocked && platform_session_owned();
}
void end_console_session(void) {console_depth=0;console_token=0;ap_session_end(&password_core);}
static __attribute__((noreturn)) void EA refuse_os_handoff(EVENT event,void *context) {
 (void)event;(void)context;nv_retire();end_platform();ap_session_end(&password_core);
 ap_secure_zero(password_core.record,sizeof(password_core.record));boot_services_ended=1;
 for(;;)__asm__ volatile("cli; hlt");
}
static ES EA refuse_unload(HANDLE image) {(void)image;return ERR(15);}
static __attribute__((noreturn)) void EA refuse_reset(uint32_t kind,ES status,UN size,void *data) {
 (void)kind;(void)status;(void)size;(void)data;refuse_os_handoff(0,0);
}
static ES EA refuse_capsule(void *capsules,UN count,uint64_t scatter) {(void)capsules;(void)count;(void)scatter;return ERR(8);}
static int make_resident(HANDLE image) {
 LOADED *loaded=0;void *unload=(void *)refuse_unload;
 if(FAILED(system_table->bs->handle_protocol(image,&loaded_guid,(void **)&loaded)) ||
    !loaded || !memory_present(loaded,sizeof(*loaded),0))return 0;
 if(FAILED(system_table->bs->create_event(EVT_SIGNAL_EXIT_BOOT_SERVICES,TPL_NOTIFY,refuse_os_handoff,0,&maintenance_exit_event)) ||
    !maintenance_exit_event)return 0;
 /* From this point even an error must remain resident. */
 resident=1;
 if(!system_table->bs->create_event_ex ||
    FAILED(system_table->bs->create_event_ex(EVT_NOTIFY_SIGNAL,TPL_NOTIFY,refuse_os_handoff,0,&maintenance_before_guid,&maintenance_before_event)) ||
    !maintenance_before_event || boot_services_ended)return 0;
 return !boot_services_ended && patch_memory(&loaded->unload,&unload,sizeof(unload));
}
static int publish_runtime_guards(void) {
 if(!maintenance_exit_event || !maintenance_before_event || !resident || boot_services_ended)return 0;
 RT copy=*system_table->rt;
 if(copy.hdr.size<offsetof(RT,update_capsule)+8 || copy.hdr.size>sizeof(copy))return 0;
 copy.set_variable=nv_guard_set;copy.reset=(void *)refuse_reset;copy.update_capsule=(void *)refuse_capsule;
 copy.hdr.crc=0;
 if(FAILED(system_table->bs->crc32(&copy,copy.hdr.size,&copy.hdr.crc)) ||
    boot_services_ended || !patch_memory(system_table->rt,&copy,copy.hdr.size))return 0;
 original_set_variable=nv_guard_set;
 return !boot_services_ended && install_variable_guard();
}

typedef struct {ES status;UN size;uint32_t attributes,padding;uint8_t hash[32];} VAR_META;
static VAR_META initial_variables[2];
static C16 *variable_names[]={L"VARSTORE_OCMR_SETTINGS_NAME",L"SocketMemoryConfig"};
static GUID *variable_guids[]={&oc_guid,&memory_guid};
static int snapshot(unsigned index,VAR_META *v) {
 uint8_t *data=alloc(32768);if(!data)return 0;memset(v,0,sizeof(*v));v->size=32768;
 v->status=system_table->rt->get_variable(variable_names[index],variable_guids[index],&v->attributes,&v->size,data);
 if(boot_services_ended)refuse_os_handoff(0,0);
 int okay=(v->status==0 && v->size<=32768)||v->status==ERR(14);
 if(v->status==0 && v->size<=32768)ap_sha256(data,v->size,v->hash);
 if(v->status==ERR(14)){v->size=0;v->attributes=0;}
 ap_secure_zero(data,32768);release(data);return okay;
}
static int check_other_variables(void) {
 for(unsigned i=0;i<2;i++){VAR_META after;field("MonitoredVariableIndex",i);
  if(!check(snapshot(i,&after) && !memcmp(&after,&initial_variables[i],sizeof(after)),"OC/memory variable metadata and SHA256 unchanged"))return 0;}
 return 1;
}
static int exact_modules(void) {
 HANDLE *handles=0;UN count=0;uint8_t *tse=0,*setup=0;UN tn=0,sn=0;
 if(FAILED(system_table->bs->locate_handles(2,&loaded_guid,0,&count,&handles))||!handles)return 0;
 if(count>4096){release(handles);return 0;}
 for(UN i=0;i<count;i++){LOADED *li=0;GUID id;
  if(FAILED(system_table->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li))||!li||!image_guid(li,&id))continue;
  if(!memcmp(&id,&tse_guid,16)){if(tse){release(handles);return 0;}tse=li->image_base;tn=li->image_size;}
  if(!memcmp(&id,&setup_guid,16)){if(setup){release(handles);return 0;}setup=li->image_base;sn=li->image_size;}
 }
 release(handles);IMAGE_INFO a,b;
 if(!tse||!setup||tn<0x92b10||!memory_present(tse,tn,0)||!memory_present(setup,sn,0)||
    !probe_image(tse,tn,&a)||!probe_image(setup,sn,&b))return 0;
 field("AMITSE.text_crc",a.text_crc);field("Setup.text_crc",b.text_crc);
 uint32_t stage;memcpy(&stage,tse+0x82628,4);field("AMITSE.stage",stage);
 return a.text_crc==0x760c4005 && a.text_rva==0x2c0 && a.text_size==0x69ecf && a.entry==0x5a0 &&
        b.text_crc==0x9e141291 && b.text_rva==0x2c0 && b.text_size==0x2746f && b.entry==0x590 && stage!=5;
}
static void record_status(void) {
 const NV_STATUS *s=nv_status();field("Stage",s->phase);field("CredentialAttributes",s->attributes);
 field("CredentialBytes",s->size);hash_field("CredentialSHA256",s->hash);
 field("CredentialGeneration",s->generation);field("AcceptedWrites",s->commits);field("NativeSetAttempts",s->attempts);
 field("BlockedWrites",s->blocked);field("LastNativeSetStatus",s->last_set_status);field("LastNativeGetStatus",s->last_get_status);
 field("OwnershipKnown",s->owned);field("Fault",s->fault);field("CleanupDeleteAttempts",s->delete_attempts);
 field("CleanupRestoredAbsence",s->cleanup_complete);field("ConsoleSessions",session_count);
 field("CredentialMode",password_core.mode);field("ConsoleOwnerActive",platform_session_owned());
 field("CoreActive",password_core.active);field("CoreUnlocked",password_core.unlocked);
 if(s->phase==1 && s->sealed && s->commits==1 && !s->fault && s->owned && s->size==128 && s->attributes==3)
  add("Phase1Receipt=COMMITTED_EXACT_READBACK\r\n");
}
static void show_log(void) {
 if(boot_services_ended)refuse_os_handoff(0,0);
 size_t prior=log_size;record_status();field("Checks",checks);field("Failures",failures);add("PROBE_COMPLETE\r\n");
 kvm_present(system_table,log_data,log_size,failures);if(boot_services_ended)refuse_os_handoff(0,0);log_size=prior;log_data[log_size]=0;
}
static __attribute__((noreturn)) void stopped(void) {
 nv_retire();end_platform();ap_session_end(&password_core);
 for(;;){print(U("\r\nMaintenance stopped. Q: diagnostic QR. External power-off is required.\r\n"));
  KEY key=read_key();if(key.ch=='q'||key.ch=='Q')show_log();}
}
ES EA efi_main(HANDLE image,ST *st) {
 system_table=st;if(!st||!st->bs||!st->rt||!st->in||!st->out)return ERR(2);
 st->bs->set_watchdog(0,0,0,0);
 add("AITWEAKER-PROBE-P3-KVM\r\n" NV_BUILD_ID "\r\nDriverSHA256=" NV_DRIVER_SHA "\r\n");
 add("SourceBundleSHA256=" NV_SOURCE_BUNDLE_SHA "\r\nStorage=NVRAM_ONE_NAMED_TEST_CREDENTIAL\r\nOwner=ISOLATED_CONSOLE_ADAPTER\r\nAMITSE_SendForm=NOT_CALLED\r\n");
 add("AllowedVariable=AiTweakerPassword1904\r\nAllowedGUID=750e9d9d-f2d8-4e14-9b53-8923a7190461\r\n");
 add("OtherRuntimeSetVariable=DENIED\r\nDirectSPI=NOT_IMPLEMENTED\r\n");
 field("RequestedStage",NV_STAGE);add("Phase1ReceiptLogSHA256=" NV_RECEIPT_LOG_SHA "\r\n");
 if(!check(board_matches(),"exact SMBIOS Pro WS W790-ACE BIOS 1904")){add("UNSUPPORTED_BOARD_NO_HOOKS_NO_WRITES\r\n");show_log();return ERR(3);}
 if(!check(exact_modules(),"exact original ACE1904 module fingerprints; no AMITSE hooks")){show_log();return ERR(3);}
 for(unsigned i=0;i<2;i++)if(!check(snapshot(i,&initial_variables[i]),"initial OC/memory variable metadata and SHA256")){show_log();return ERR(7);}
 GETVAR native_get=st->rt->get_variable;SETVAR native_set=st->rt->set_variable;
 if(!check(make_resident(image),"final EBS resident guard and unload refusal")){show_log();if(resident)stopped();return ERR(7);}
 if(!check(initialize_services(),"frozen production services and real AP_ENV")) {show_log();stopped();}
 if(!check(publish_runtime_guards(),"credential gate, other-variable denial, ResetSystem and capsule refusal")){show_log();stopped();}
 if(!check(nv_prepare(native_get,native_set,NV_STAGE,NV_EXPECTED_RECORD),"phase-specific original credential ownership proof")){show_log();stopped();}
 if(!check(nv_activate(),"explicit NVRAM maintenance activation") || !check(begin_console_session(),"new console owner session starts locked")){show_log();stopped();}
 show_log();
 for(;;){
  st->out->attribute(st->out,7);st->out->clear(st->out);
  print(U("ACE1904 CANDIDATE05 - NVRAM PERSISTENCE TEST\r\n\r\nThis test WRITES one independent password variable.\r\nNo Setup/OC/SaveReset interface is started.\r\nPassword input is masked by the unchanged production UI.\r\n\r\nM: Set/change test password\r\nU: Verify/unlock within this console session\r\nN: End session and begin a fresh locked session\r\nC: Authenticated clear to disabled tombstone (stage 2 only)\r\nD: End session; delete our proven disabled tombstone (stage 2)\r\nQ: Show metadata/hash diagnostic QR\r\n\r\nAfter stage 1, record QR then use external cold power-off.\r\nThis application never unloads or boots an OS.\r\n"));
  KEY key=read_key();
  if(key.ch=='q'||key.ch=='Q'){check_other_variables();show_log();continue;}
  if(nv_status()->fault || failures){show_log();stopped();}
  if(key.ch=='m'||key.ch=='M'||key.ch=='c'||key.ch=='C') {
   int clear=key.ch=='c'||key.ch=='C';uint32_t action=clear?NV_ACTION_CLEAR:NV_ACTION_SET;
   if(nv_begin_action(action)){int result=manage_password(clear);nv_end_action();field(clear?"ClearResult":"SetOrChangeResult",result);
    if(NV_STAGE==1 && nv_status()->sealed){end_console_session();add("STAGE1_COMMITTED_NO_MORE_CREDENTIAL_WRITES\r\n");show_log();}}
   else {add("ACTION_REFUSED_BY_STAGE_OR_OWNER\r\n");print(U("Action unavailable in this stage/session.\r\n"));}
  } else if(key.ch=='u'||key.ch=='U') {
   int result=ensure_unlocked();field("UnlockResult",result);field("UnlockedAfter",password_core.unlocked);
  } else if(key.ch=='n'||key.ch=='N') {
   if(NV_STAGE==2)check(begin_console_session(),"explicit new console session relocks");
  } else if(key.ch=='d'||key.ch=='D') {
   if(NV_STAGE==2){end_console_session();check(nv_cleanup_tombstone(),"exact owned disabled tombstone removed; original absence restored");
    check_other_variables();show_log();stopped();}
  }
  if(!check_other_variables() || nv_status()->fault){show_log();stopped();}
 }
}
