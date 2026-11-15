/* RAM-only test controller. The application, its events and every allocation
 * ever published through a native pointer remain resident until BMC power-off.
 * No path returns to firmware after event registration. No recovery output or
 * service call occurs from TX_HOLD/ENDED or a raised-TPL failure.
 */
#include "app.h"
extern ES kvm_present(ST *,const char *,size_t,unsigned);
ST *app_st;HANDLE app_image,app_setup_hii;void *app_browser;
volatile int app_ended;
ENTRY_CAPTURE captured_entry;
RAM_SESSION app_sessions[2];
static EVENT exit_event,before_event;
static GUID before_guid={0x8be0e274,0x3970,0x4b44,{0x80,0xc5,0x1a,0xb9,0x50,0x2f,0x3b,0xfc}};
static char journal[22016],snapshot[24576];static UN journal_bytes,snapshot_bytes;
static unsigned log_overflow,warnings,used_modes,mode,inventory_ok,credential_ready,ui_active;
static uint64_t snapshot_id,operation_id;
volatile uint32_t app_hold_reason;
static void append(char *dest,UN *count,UN limit,const char *s){while(*s&&*count<limit)dest[(*count)++]=*s++;if(*s)log_overflow=1;dest[*count]=0;}
void app_log(const char *s){append(journal,&journal_bytes,sizeof(journal)-1,s);}
static void hex_into(char *dest,UN *count,UN limit,uint64_t value){const char digits[]="0123456789ABCDEF";for(int i=15;i>=0;i--){char s[]={digits[(value>>(i*4))&15],0};append(dest,count,limit,s);}}
void app_number(const char *name,uint64_t value){app_log(name);app_log("=");hex_into(journal,&journal_bytes,sizeof(journal)-1,value);app_log("\r\n");}
void app_result(const char *name,int ok){app_log(ok?"PASS ":"FAIL ");app_log(name);app_log("\r\n");if(!ok)warnings++;}
__attribute__((noreturn)) void app_hold(uint32_t reason){
 /* A visible progress line was emitted before entering the transaction. The
  * exact reason stays only in this preallocated RAM field. Never try to render
  * a QR screen, call ResetSystem or restore TPL from this terminal path. */
 app_hold_reason=reason;for(;;)__asm__ volatile("pause");
}
void app_require_services(void){
 if(app_ended||app_sessions[0].tx.held||app_sessions[1].tx.held)app_hold(0xe0000001u);
}
static void EA ending(EVENT event,void *context){
 (void)event;(void)context;app_ended=1;tx_end(&app_sessions[0].tx);tx_end(&app_sessions[1].tx);
}
static void output(C16 *s){app_require_services();ES status=app_st->out->out(app_st->out,s);app_require_services();if(FAILED(status))app_hold(0xe0000002u);}
static void display_number(uint64_t n){C16 text[17];const char digits[]="0123456789ABCDEF";for(unsigned i=0;i<16;i++)text[i]=(C16)digits[(n>>((15-i)*4))&15];text[16]=0;output(text);}
static void show_menu(void){
 app_require_services();app_st->out->attribute(app_st->out,7);app_require_services();app_st->out->clear(app_st->out);app_require_services();
 output(U("SAGE N13 RAM TEST05\r\nMODE="));display_number(mode);output(U("  OPERATION_ID="));display_number(operation_id);output(U("\r\n\r\n"));
 if(inventory_ok&&!ui_active&&!(used_modes&1))output(U("1  Install / check / rollback (no password writes)\r\n"));
 if(inventory_ok&&credential_ready&&!ui_active&&!(used_modes&2))output(U("2  Start password and native UI test\r\n"));
 if(ui_active){
  if(!app_sessions[1].failed){output(U("M  Independent password management\r\n"));output(U("B  Original ASUS Setup - browse only, ESC to return\r\n"));}
  output(U("R  Restore temporary credential and RAM hooks\r\n"));
 }
 output(U("Q  View complete log as QR (T for text inside viewer)\r\n\r\n"));
 if(!inventory_ok)output(U("Preflight refused. No native patch is permitted.\r\n"));
 if(!credential_ready)output(U("Password test unavailable: inspect preflight log.\r\n"));
 if(!ui_active&&(used_modes&2))output(U("Password test ended. Capture the log.\r\n"));
 output(U("This application stays resident. Use BMC power off to exit.\r\n"));
 output(U("Do not save BIOS changes or select a boot override.\r\n"));
}
static void snapshot_number(const char *name,uint64_t n){append(snapshot,&snapshot_bytes,sizeof(snapshot)-1,name);append(snapshot,&snapshot_bytes,sizeof(snapshot)-1,"=");hex_into(snapshot,&snapshot_bytes,sizeof(snapshot)-1,n);append(snapshot,&snapshot_bytes,sizeof(snapshot)-1,"\r\n");}
static void show_log(void){
 app_require_services();if(snapshot_id==UINT64_MAX)app_hold(0xe0000003u);snapshot_id++;snapshot_bytes=0;
 append(snapshot,&snapshot_bytes,sizeof(snapshot)-1,"AITWK-P3-KVM\r\nSAGE_NATIVE13_RAM_TEST05\r\n");
 snapshot_number("SNAPSHOT_ID",snapshot_id);snapshot_number("MODE",mode);snapshot_number("OPERATION_ID",operation_id);
 append(snapshot,&snapshot_bytes,sizeof(snapshot)-1,journal);
 append(snapshot,&snapshot_bytes,sizeof(snapshot)-1,log_overflow?"LOG_OVERFLOW=YES\r\nLOG_COMPLETE=NO\r\n":"LOG_OVERFLOW=NO\r\nLOG_COMPLETE=YES\r\n");
 snapshot_number("Warnings",warnings);append(snapshot,&snapshot_bytes,sizeof(snapshot)-1,"SAGE_NATIVE13_RAM_TEST05_END\r\n");
 /* Snapshot is immutable until this viewer returns; the running journal never
  * receives an old SNAPSHOT_ID, footer or END record. */
 kvm_present(app_st,snapshot,snapshot_bytes,warnings);app_require_services();
}
static void next_action(unsigned next,const char *label){
 app_require_services();if(operation_id==UINT64_MAX)app_hold(0xe0000004u);operation_id++;mode=next;
 app_number("Operation",operation_id);app_log("ACTION=");app_log(label);app_log("\r\n");
}
static uint32_t installed(RAM_SESSION *s){
 output(U("Preparing exclusive RAM and exact 12-site transaction...\r\n"));
 if(!platform_prepare(s,s->mode)){s->failed=1;app_result("exclusive preparation",0);return TX_REFUSED;}
 output(U("Installing exact 12 RAM guards. If held, power off via BMC.\r\n"));
 uint32_t result=platform_install(s);if(result==TX_HOLD||result==TX_ENDED)app_hold(0xe1000000u|result);
 app_require_services();app_number("InstallResult",result);return result;
}
static void mode_one(void){
 used_modes|=1;next_action(1,"INSTALL_CHECK_ROLLBACK");RAM_SESSION *s=&app_sessions[0];s->mode=1;
 uint32_t result=installed(s);
 if(result==TX_OK){
  output(U("Exact targets installed. Restoring original bytes...\r\n"));
  result=platform_remove(s);if(result==TX_HOLD||result==TX_ENDED)app_hold(0xe2000000u|result);
  if(result==TX_BUSY)app_hold(0xe2000003u);
  app_require_services();app_result("mode1 exact twelve-site restoration",result==TX_ROLLED_BACK);
 }
 s->finished=1;app_log("MODE1_PROVIDER_STARTED=NO\r\nMODE1_PASSWORD_WRITES=NO\r\nMODE1_RESULT_DOES_NOT_ACCEPT_MODE2\r\n");
}
static void mode_two(void){
 used_modes|=2;next_action(2,"START_PASSWORD_NATIVE_TEST");RAM_SESSION *s=&app_sessions[1];s->mode=2;
 if(!ui_compare_original_stores()){s->failed=1;s->finished=1;return;}
 uint32_t result=installed(s);if(result!=TX_OK){s->failed=1;s->finished=1;return;}
 /* The start may publish protocols/events even when later work fails. It is
  * attempted once, never followed by UnloadImage or a new provider instance. */
 ui_active=1;
 if(!platform_start_provider(s)){s->failed=1;app_result("single resident provider attach",0);return;}
 app_result("single resident provider attach",1);
}
static void finish_two(void){
 RAM_SESSION *s=&app_sessions[1];next_action(2,"RESTORE_CREDENTIAL_AND_HOOKS");
 int restored=ui_restore_credential(s);app_result("temporary private credential restored",restored);
 int unchanged=ui_compare_original_stores();app_result("observed protected OC values unchanged",unchanged);
 output(U("Restoring exact original RAM targets...\r\n"));
 uint32_t result=platform_remove(s);if(result==TX_HOLD||result==TX_ENDED)app_hold(0xe3000000u|result);
 app_require_services();app_number("RemoveResult",result);
 if(result==TX_BUSY){s->failed=1;app_log("REMOVAL_BUSY_ALL_ALLOCATIONS_RETAINED\r\n");return;}
 s->failed|=!restored||!unchanged||result!=TX_ROLLED_BACK;s->finished=1;ui_active=0;
 app_log("RESIDENT_UNTIL_BMC_POWER_OFF=YES\r\nPUBLISHED_ALLOCATIONS_FREED=NO\r\nNATIVE_ASUS_GUI_ACCEPTANCE_IS_SEPARATE\r\n");
}
ES EA app_main(HANDLE image,ST *st){
 if(!st||!st->bs||!st->rt||!st->out||!st->in||!st->out->out||!st->out->clear||!st->out->attribute||!st->in->read||!st->bs->create_event||!st->bs->stall)return ERR(2);
 app_st=st;app_image=image;
 ES status=st->bs->create_event(0x201,16,ending,0,&exit_event);if(FAILED(status))return ERR(7);
 app_require_services();
 if(st->bs->create_event_ex){status=st->bs->create_event_ex(0x200,16,ending,0,&before_guid,&before_event);app_require_services();if(FAILED(status))app_hold(0xe0000010u);}
 if(st->bs->set_watchdog){status=st->bs->set_watchdog(0,0,0,0);app_require_services();app_number("WatchdogDisableStatus",status);}
 app_log("TOOL_SCOPE=TEMPORARY_RAM_NATIVE_TEST\r\nNO_FLASH_NO_RT_TABLE_CHANGE_NO_DISK_WRITES\r\nFOREIGN_PAGE_ATTRIBUTE_CHANGES=NO\r\n");
 inventory_ok=platform_inventory();app_require_services();app_result("complete initial original identity and boot context",inventory_ok);
 if(inventory_ok)credential_ready=ui_capture_initial();
 for(;;){
  show_menu();KEY key={0};
  for(;;){status=st->in->read(st->in,&key);app_require_services();if(!FAILED(status))break;status=st->bs->stall(10000);app_require_services();if(FAILED(status))app_hold(0xe0000011u);}
  C16 ch=key.ch;if(ch>='A'&&ch<='Z')ch=(C16)(ch+('a'-'A'));
  if(ch=='q'){show_log();continue;}
  if(log_overflow){if(ui_active&&ch=='r')finish_two();continue;}
  if(ch=='1'&&inventory_ok&&!ui_active&&!(used_modes&1)){mode_one();continue;}
  if(ch=='2'&&inventory_ok&&credential_ready&&!ui_active&&!(used_modes&2)){mode_two();continue;}
  if(ui_active&&ch=='r'){finish_two();continue;}
  if(ui_active&&!app_sessions[1].failed&&(ch=='m'||ch=='b')){
   next_action(2,ch=='m'?"PASSWORD_MANAGEMENT":"ORIGINAL_SETUP_BROWSE");
   int ok=ch=='m'?ui_open_management(&app_sessions[1]):ui_open_original_setup(&app_sessions[1]);
   app_require_services();if(!ok)app_sessions[1].failed=1;
  }
 }
}
