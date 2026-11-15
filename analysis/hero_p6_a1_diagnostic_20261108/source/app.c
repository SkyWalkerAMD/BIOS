/* Application-only diagnostics. No resident callbacks, driver loading,
 * protocol installation, configuration writer, or firmware flash. */
#include "preflight.h"
#include "p5.h"
#include "kvm.h"
static GUID api_guid={0x1f771753,0xbb7b,0x4e4c,{0xb6,0x98,0xe7,0x1e,0x8d,0xb2,0x5e,0x7a}};
static PREFLIGHT initial,current;
static ES initial_status,entry_identity,watchdog_status;
static unsigned tried[4],okay[4],terminal;
static char snapshot[LOG_CAP];static UN snapshot_len;static unsigned snapshot_bad;
static const char *names[]={"B_BIND_NATIVE_HII","R_COLLECT_BMC_GETS","P_SINGLE_SAME_VALUE","P_FULL_PUBLISH"};
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static int upper(int c){return c>='a'&&c<='z'?c-32:c;}
static ES no_resident(void){void *p=0;ES e=gST->bs->locate_protocol(&api_guid,0,&p);return e==ERR(14)?0:e?e:ERR(20);}
static void add_n(const char *s,UN n){if(n>sizeof(snapshot)-1-snapshot_len){snapshot_bad=1;return;}memcpy(snapshot+snapshot_len,s,n);snapshot_len+=n;snapshot[snapshot_len]=0;}
static void add(const char *s){UN n=0;while(s[n])n++;add_n(s,n);}
static void hex(UN n,unsigned digits){char s[16];for(unsigned i=0;i<digits;i++)s[i]="0123456789ABCDEF"[(n>>((digits-i-1)*4))&15];add_n(s,digits);}
static ES capture(unsigned compact){
 snapshot_len=0;snapshot_bad=0;
 if(compact){
  add("HERO-P6-A1-COMPACT-SUMMARY\r\nFULL_TRACE_BYTES_HEX=");hex(audit_len,8);add(" CRC32=");hex(probe_crc32(audit,audit_len),8);add("\r\n");
  add(a1_trace_summary());
  /* Preserve every non-HII trace line, including all identity/variable gates,
   * stage outcomes, complete KCS requests/responses and PCI restoration. */
  for(UN at=0;at<audit_len;){UN end=at;while(end<audit_len&&audit[end]!='\n')end++;if(end<audit_len)end++;
   if(audit[at]!='>'&&audit[at]!='<')add_n(audit+at,end-at);at=end;}
  add("BEGIN CACHED DISPLAY VALUES\r\n");for(unsigned i=0;i<V_CONFIG_STATUS;i++){add("VALUE[");hex(i,2);add("]=");UN len=0;while(len<160&&values[i][len])len++;if(len==160){snapshot_bad=1;break;}add_n(values[i],len);add("\r\n");}add("CONFIG_STATUS: existing per-language HII value preserved, not evaluated\r\nEND CACHED DISPLAY VALUES\r\n");
 }else add_n(audit,audit_len);
 add(audit_bad?"SNAPSHOT_INCOMPLETE\r\n":"SNAPSHOT_END\r\n");
 return kvm_present(gST,snapshot,snapshot_len,snapshot_bad||audit_bad);
}
static ES gates(const char *label){
 if(terminal||watchdog_status||entry_identity||initial_status||audit_bad||audit_len>sizeof(audit)-524288)return ERR(15);
 ES e=identity_check();status("STAGE_IDENTITY",e);if(e)return e;
 e=no_resident();status("STAGE_NO_RESIDENT_P6",e);if(e)return e;
 e=preflight_read(&current,label);status("STAGE_PREFLIGHT",e);if(e)return e;
 if(!preflight_equal(&initial,&current)){status("STAGE_VARIABLES_CHANGED",ERR(15));return ERR(15);}
 return 0;
}
static void stage(unsigned n){
 if(n>3||tried[n]||terminal||(n&&!okay[0])||(n>=2&&!okay[1])||(n==3&&!okay[2])){say("Stage refused: prerequisite missing, already attempted, or terminal failure.\r\n");status("STAGE_ORDER_REFUSED",ERR(15));return;}
 logtext("CHECKPOINT_READY ");logtext(names[n]);logtext("\r\n");
 say("\r\nREADY ");say(names[n]);say(". Operation has NOT started.\r\n");
 say("M=summary; C=full trace; Enter=execute ONCE; Esc/Q=cancel.\r\n");
 for(;;){int k=upper(key());if(k=='C'||k=='M'){status("CHECKPOINT_QR_RETURN",capture(k=='M'));say("Enter=execute ONCE; Esc/Q=cancel.\r\n");continue;}if(k==13)break;if(k<0||k==27||k=='Q'){logtext("CHECKPOINT_CANCELLED\r\n");return;}}
 ES e=gates("BEFORE_STAGE_VARIABLES");status("STAGE_GATE",e);if(e){terminal=1;return;}
 tried[n]=1;
 status(names[n],0);say("ENTER STAGE: ");say(names[n]);say("\r\n");
 e=n==0?p5_bind():n==1?p1_collect():n==2?p5_probe_same_value():p5_publish();
 status("STAGE_RETURN",e);logtext("STAGE_RETURN_NAME ");logtext(names[n]);logtext("\r\n");
 if(e||audit_bad){terminal=1;say("Stage failed. Capture C; no stage will be retried.\r\n");return;}
 ES check=preflight_read(&current,"AFTER_STAGE_VARIABLES");status("POST_STAGE_PREFLIGHT",check);
 if(check||!preflight_equal(&initial,&current)){terminal=1;status("POST_STAGE_VARIABLE_CHANGE",ERR(15));return;}
 okay[n]=1;
 say("Stage completed. C captures its complete RAM log.\r\n");
 if(n==2)say("Same-value Set/Get passed. A second P separately confirms FULL publish.\r\n");
}
ES EA efi_main(HANDLE image,ST *system){
 (void)image;gST=system;
 if(!gST||!gST->bs||!gST->rt||!gST->rt->get_variable||!gST->bs->locate_protocol||!gST->bs->wait_for_event||!gST->in||!gST->in->read||!gST->out||!gST->out->out)return ERR(2);
 logtext("HERO-P6-A1-DIAGNOSTIC\r\nRUN=");uint32_t lo,hi;__asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));loghex(((uint64_t)hi<<32)|lo,16);logtext("\r\n");
 say("HERO P6 A1 DIAGNOSTIC - staged application, no resident callbacks\r\n");
 say("Only registered .71 HERO / BIOS 3107. No flash or configuration changes.\r\n");
 say("B binds existing forms; R queries BMC; P changes RAM display strings only.\r\n");
 say("R may temporarily enable PCI memory decoding; handled exits restore it.\r\n");
 say("Save C captures before exiting. RAM logs do not survive a reset.\r\n");
 watchdog_status=gST->bs->set_watchdog?gST->bs->set_watchdog(0,0,0,0):ERR(3);status("UEFI_APPLICATION_WATCHDOG_DISABLE",watchdog_status);
 entry_identity=identity_check();status("ENTRY_IDENTITY",entry_identity);
 initial_status=preflight_read(&initial,"ENTRY_PREFLIGHT");status("ENTRY_PREFLIGHT_RESULT",initial_status);
 ES resident=no_resident();status("ENTRY_NO_RESIDENT_P6",resident);if(resident)terminal=1;
 for(;;){
  say("\r\nB=bind; R=read BMC; P=single / full publish; M=summary; C=full log; Q then Q=exit\r\n");
  int k=upper(key());if(k<0)break;
  if(k=='B'){stage(0);continue;}if(k=='R'){stage(1);continue;}if(k=='P'){stage(okay[2]?3:2);continue;}
  if(k=='C'||k=='M'){status("QR_VIEWER_RETURN",capture(k=='M'));continue;}
  if(k=='Q'){say("Press Q again to return to BIOS. No callbacks remain.\r\n");k=upper(key());if(k=='Q')break;}
 }
 p5_release();logtext("A1_EXIT_NO_RESIDENT_CALLBACKS\r\n");say("A1 returning to firmware. RAM display strings may remain; no driver remains.\r\n");return 0;
}
