/* Resident display-only diagnostic controller. Standard volatile events/HII
 * publication and native SendForm are its explicit effects. No native writes,
 * provider, password operations, filesystem, network, flash or variable setter.
 */
#include "baseline.h"
extern ES kvm_present(ST *,const char *,size_t,unsigned);
ST *app_st;HANDLE app_image,app_setup_hii;void *app_browser;ENTRY_CAPTURE captured_entry;
volatile int app_ended;volatile uint32_t app_hold_reason;
static EVENT exit_event,before_event;
static GUID before_guid={0x8be0e274,0x3970,0x4b44,{0x80,0xc5,0x1a,0xb9,0x50,0x2f,0x3b,0xfc}};
static char journal[22016],snapshot[24576];static UN used,total;static unsigned overflow,warnings,ready,attempted,returned;
static uint64_t snapshot_id;
static void add(char *dest,UN *n,UN cap,const char *s){while(*s&&*n<cap)dest[(*n)++]=*s++;if(*s)overflow=1;dest[*n]=0;}
void app_log(const char *s){add(journal,&used,sizeof(journal)-1,s);}
static void hex(char *dest,UN *n,UN cap,uint64_t v){const char h[]="0123456789ABCDEF";for(int i=15;i>=0;i--){char x[]={h[(v>>(i*4))&15],0};add(dest,n,cap,x);}}
void app_number(const char *name,uint64_t v){app_log(name);app_log("=");hex(journal,&used,sizeof(journal)-1,v);app_log("\r\n");}
void app_result(const char *name,int ok){app_log(ok?"PASS ":"FAIL ");app_log(name);app_log("\r\n");if(!ok)warnings++;}
__attribute__((noreturn))void app_hold(uint32_t reason){app_hold_reason=reason;for(;;)__asm__ volatile("pause");}
void app_require_services(void){if(app_ended||app_hold_reason)app_hold(0xB606E001u);}
void baseline_tpl(void){app_require_services();if(!app_st->bs->raise_tpl||!app_st->bs->restore_tpl)app_hold(0xB606E002u);UN prior=app_st->bs->raise_tpl(31);app_require_services();if(prior!=4)app_hold(0xB606E003u);app_st->bs->restore_tpl(prior);app_require_services();}
static void EA ending(EVENT event,void *context){(void)event;(void)context;app_ended=1;}
static void print(C16 *s){app_require_services();ES e=app_st->out->out(app_st->out,s);app_require_services();if(FAILED(e))app_hold(0xB606E004u);}
static void menu(void){
 app_require_services();ES e=app_st->out->attribute(app_st->out,7);app_require_services();if(FAILED(e))app_hold(0xB606E005u);
 e=app_st->out->clear(app_st->out);app_require_services();if(FAILED(e))app_hold(0xB606E006u);
 print(U("SAGE N13 BROWSER BASELINE06\r\n\r\n"));
 if(ready&&!attempted&&!overflow)print(U("B  Open original ASUS browser once (all actions rejected)\r\n"));
 print(U("Q  Complete log as QR; T for text inside viewer\r\n\r\n"));
 if(!ready)print(U("Preflight refused. Native browser call is unavailable.\r\n"));
 if(attempted)print(returned?U("Native browser returned. Capture the result log.\r\n"):U("Attempt finished without an accepted return. Capture the log.\r\n"));
 print(U("No password operations or native guard installation.\r\nUse ESC inside the form. Do not save or reset firmware.\r\nAll published resources remain resident until BMC power off.\r\n"));
}
static void snum(const char *name,uint64_t v){add(snapshot,&total,sizeof(snapshot)-1,name);add(snapshot,&total,sizeof(snapshot)-1,"=");hex(snapshot,&total,sizeof(snapshot)-1,v);add(snapshot,&total,sizeof(snapshot)-1,"\r\n");}
static void log_view(void){
 if(snapshot_id==UINT64_MAX)app_hold(0xB606E007u);snapshot_id++;total=0;
 add(snapshot,&total,sizeof(snapshot)-1,"AITWK-P3-KVM\r\nSAGE_NATIVE13_BROWSER_BASELINE06\r\n");snum("SNAPSHOT_ID",snapshot_id);snum("BROWSER_ATTEMPTED",attempted);snum("BASELINE_RETURN_ACCEPTED",returned);
 add(snapshot,&total,sizeof(snapshot)-1,journal);add(snapshot,&total,sizeof(snapshot)-1,overflow?"LOG_OVERFLOW=YES\r\nLOG_COMPLETE=NO\r\n":"LOG_OVERFLOW=NO\r\nLOG_COMPLETE=YES\r\n");snum("Warnings",warnings);add(snapshot,&total,sizeof(snapshot)-1,"SAGE_NATIVE13_BROWSER_BASELINE06_END\r\n");
 app_require_services();ES e=kvm_present(app_st,snapshot,total,warnings);app_require_services();if(FAILED(e))app_hold(0xB606E008u);
}
ES EA app_main(HANDLE image,ST *st){
 if(!st||!st->bs||!st->rt||!st->out||!st->in||!st->out->out||!st->out->clear||!st->out->attribute||!st->in->read||!st->bs->create_event||!st->bs->stall||!st->bs->create_event_ex||!st->bs->set_watchdog)app_hold(0xB606E009u);
 app_st=st;app_image=image;baseline_tpl();
 ES e=st->bs->create_event(0x201,16,ending,0,&exit_event);app_require_services();if(FAILED(e)||!exit_event)app_hold(0xB606E00Au);
 e=st->bs->create_event_ex(0x200,16,ending,0,&before_guid,&before_event);app_require_services();if(FAILED(e)||!before_event)app_hold(0xB606E00Bu);
 e=st->bs->set_watchdog(0,0,0,0);app_require_services();app_number("WatchdogDisableStatus",e);if(FAILED(e))app_hold(0xB606E00Cu);
 app_log("TOOL_SCOPE=ORIGINAL_BROWSER_BASELINE_ONLY\r\nNO_DETOURS_NO_PROVIDER_NO_PASSWORD_OPERATIONS\r\nNO_DIRECT_VARIABLE_DISK_FLASH_OR_RT_TABLE_WRITES\r\nSTANDARD_VOLATILE_EVENT_HII_PROTOCOL_PUBLICATION\r\nOEM_INTERNAL_SEND_FORM_EFFECTS_NOT_ZERO\r\n");
 ready=baseline_inventory();app_result("complete initial original identity and boot context",ready);
 if(ready){ready=browser_capture();app_result("initial private absence and complete OC memory snapshots",ready);}
 if(ready){ready=browser_publish();app_result("static independent baseline HII publication",ready);}
 for(;;){
  menu();KEY key={0};
  for(;;){app_require_services();e=st->in->read(st->in,&key);app_require_services();if(!FAILED(e))break;e=st->bs->stall(10000);app_require_services();if(FAILED(e))app_hold(0xB606E00Du);}
  C16 ch=key.ch;if(ch>='A'&&ch<='Z')ch+=(C16)('a'-'A');
  if(ch=='q'){log_view();continue;}
  if(ch=='b'&&ready&&!attempted&&!overflow){attempted=1;app_log("ACTION=ORIGINAL_SEND_FORM_BASELINE\r\n");print(U("Opening original ASUS form. All actions are rejected.\r\nUse ESC to return; on an unresponsive display, power off via BMC.\r\n"));returned=(unsigned)browser_invoke();app_require_services();app_result("native browser returned and readonly checks passed",returned);}
 }
}
