/* P6 RAM check: cached API reads only; the frozen driver owns its callbacks.
 * No SetVariable, SignalEvent, ConnectController, UnloadImage, manual writer
 * or manual refresh call exists in this launcher. */
#include "preflight.h"
#include "sha256.h"
#include "kvm.h"
#include "resident_image.h"
typedef struct {uint32_t version,size;const char *(EA *log)(UN *);const char *(EA *value)(unsigned);} P6_API;
_Static_assert(sizeof(P6_API)==24&&offsetof(P6_API,log)==8&&offsetof(P6_API,value)==16,"P6 API");
static GUID api_guid={0x1f771753,0xbb7b,0x4e4c,{0xb6,0x98,0xe7,0x1e,0x8d,0xb2,0x5e,0x7a}};
static P6_API *api;static ES api_status,watchdog_status,initial_status;static unsigned attempted;
static HANDLE current_image;
static PREFLIGHT initial,before,again;static char snapshot[LOG_CAP];static UN snapshot_len;
static unsigned snapshot_bad;
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static ES discover(void){
 api=0;void *found=0;ES e=gST->bs->locate_protocol(&api_guid,0,&found);
 if(e)return e;
 if(!found||!memory_refresh()||!memory_readable(found,sizeof(P6_API)))return ERR(33);
 P6_API *p=found;
 if(p->version!=6||p->size!=24||!p->log||!p->value||!memory_readable((void *)p->log,1)||!memory_readable((void *)p->value,1))return ERR(33);
 api=p;return 0;
}
static void take_driver(void){
 if(attempted){status("LOAD_REFUSED_ALREADY_ATTEMPTED",ERR(20));return;}
 attempted=1;
 /* Reserve the complete <128 KiB driver audit, 41 cached values and checks. */
 if(audit_bad||audit_len>sizeof(audit)-147456){say("LOAD REFUSED: insufficient space to retain the full preflight evidence.\r\n");return;}
 if(watchdog_status){status("LOAD_REFUSED_APPLICATION_WATCHDOG",watchdog_status);return;}
 api_status=discover();
 if(api_status!=ERR(14)){status("LOAD_REFUSED_EXISTING_OR_INVALID_P6_API",api_status?api_status:ERR(20));return;}
 ES e=identity_check();status("LOAD_IDENTITY",e);if(e)return;
 if(initial_status){status("LOAD_REFUSED_INITIAL_PREFLIGHT",initial_status);return;}
 e=preflight_read(&before,"L_PRECHECK_1");status("L_PRECHECK_1_RESULT",e);if(e)return;
 if(!preflight_equal(&initial,&before)){status("LOAD_REFUSED_CHANGED_SINCE_ENTRY",ERR(15));return;}
 uint8_t digest[32];ap_sha256(resident_image,sizeof(resident_image),digest);
 logtext("EMBEDDED_P6_SHA256=");logbytes(digest,32);
 if(!eq(digest,resident_sha256,32)){status("LOAD_REFUSED_DRIVER_SHA256",ERR(33));return;}
 e=preflight_read(&again,"L_PRECHECK_2_AFTER_SHA256");status("L_PRECHECK_2_RESULT",e);if(e)return;
 if(!preflight_equal(&before,&again)){status("LOAD_REFUSED_PREFLIGHT_CHANGED",ERR(15));return;}
 say(before.settings.status==ERR(14)?
  "P6 will create its missing 32-byte safe-default settings variable.\r\n":
  "Existing safe-default variables will be retained.\r\n");
 say("P6 refreshes inside real AfterBoot; early SetupEnter timer is unchanged.\r\n");
 HANDLE driver=0;e=gST->bs->load_image(0,current_image,0,(void *)resident_image,sizeof(resident_image),&driver);
 status("P6_LOAD_IMAGE",e);if(e||!driver){if(!e)status("P6_LOAD_NULL_HANDLE",ERR(33));return;}
 e=gST->bs->start_image(driver,0,0);status("P6_START_IMAGE",e);
 api_status=discover();status("P6_CACHED_API_AFTER_START",api_status);
 /* Neither a failed nor a successful StartImage is replayed or unloaded. */
 ES check=preflight_read(&again,"POST_START_VARIABLES");status("POST_START_PREFLIGHT",check);
 if(!check){
  unsigned expected=before.settings.status==ERR(14)?again.settings.status==0&&again.settings.bytes==32:preflight_equal(&before,&again);
  if(before.settings.status==ERR(14)&&!eq(&before.state,&again.state,sizeof(VAR_SNAPSHOT)))expected=0;
  status("POST_START_ONLY_EXPECTED_NV_CHANGE",expected?0:ERR(33));
 }
 say("C captures now. Q then Q returns to BIOS and permits AfterBoot refresh.\r\n");
}
static void add_n(const char *s,UN n){if(n>sizeof(snapshot)-1-snapshot_len){snapshot_bad=1;return;}memcpy(snapshot+snapshot_len,s,n);snapshot_len+=n;snapshot[snapshot_len]=0;}
static void add(const char *s){UN n=0;while(s[n])n++;add_n(s,n);}
static void hex(uint64_t v,unsigned n){char b[16];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-1-i)*4))&15];add_n(b,n);}
static ES capture(void){
 api_status=discover();status("CAPTURE_P6_API_STATUS",api_status);
 ES e=preflight_read(&again,"CAPTURE_CURRENT_VARIABLES");status("CAPTURE_PREFLIGHT",e);
 snapshot_len=0;snapshot_bad=0;add_n(audit,audit_len);
 add("BEGIN P6 CACHED AUDIT\r\n");
 if(api){
  UN n=0;const char *p=api->log(&n);
  if(!p||n>=131072||!memory_readable(p,n?n:1)){add("INVALID_P6_LOG_BOUNDS\r\n");snapshot_bad=1;}
  else add_n(p,n);
  add("\r\nEND P6 CACHED AUDIT\r\nBEGIN P6 CACHED VALUES\r\n");
  for(unsigned i=0;i<41;i++){
   p=api->value(i);add("P6_VALUE[");hex(i,2);add("]=");
   if(!p||!memory_readable(p,160)){add("INVALID_VALUE_POINTER\r\n");snapshot_bad=1;break;}
   UN len=0;while(len<160&&p[len])len++;
   if(len==160){add("UNTERMINATED_VALUE\r\n");snapshot_bad=1;break;}
   add_n(p,len);add("\r\n");
  }
 }else add("P6_API_UNAVAILABLE - no cached values\r\n");
 add("END P6 CACHED VALUES\r\n");
 if(snapshot_bad||audit_bad)add("SNAPSHOT_INCOMPLETE\r\n");else add("SNAPSHOT_END\r\n");
 return kvm_present(gST,snapshot,snapshot_len,snapshot_bad||audit_bad?1:0);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;current_image=image;
 if(!gST||!gST->bs||!gST->rt||!gST->rt->get_variable||!gST->in||!gST->in->read||!gST->out||!gST->out->out)return ERR(2);
 logtext("HERO-P6-RAMCHECK-4\r\nRUN=");uint32_t lo,hi;__asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));loghex(((uint64_t)hi<<32)|lo,16);logtext("\r\n");
 say("HERO P6 RAM CHECK 4 - native IPMI menu reads / S21S synchronous AfterBoot refresh\r\n");
 say("Only for the registered .71 HERO / BIOS 3107. No firmware flash.\r\n");
 say("No BMC configuration changes are requested. Missing settings may be seeded.\r\n");
 say("Exact safe defaults may occupy 21 or 32 bytes; existing width is preserved.\r\n");
 say("P6 may temporarily enable PCI memory decoding for reads, then restore it.\r\n");
 watchdog_status=gST->bs->set_watchdog?gST->bs->set_watchdog(0,0,0,0):ERR(3);status("UEFI_APPLICATION_WATCHDOG_DISABLE",watchdog_status);
 status("ENTRY_IDENTITY",identity_check());initial_status=preflight_read(&initial,"ENTRY_PREFLIGHT");status("ENTRY_PREFLIGHT_RESULT",initial_status);
 api_status=discover();status("ENTRY_P6_CACHED_API_STATUS",api_status);
 for(;;){
  say("\r\nL=load exact P6 once; C=full QR log; Q then Q=return to BIOS\r\n");
  say("Do not edit IPMI configuration during this test. Driver stays until reset.\r\n");
  int k=key();if(k<0)break;if(k>='a'&&k<='z')k-=32;
  if(k=='L'){take_driver();continue;}
  if(k=='C'){status("QR_VIEWER_RETURN",capture());continue;}
  if(k=='Q'){say("Press Q again to return to native BIOS. Resident P6 is retained.\r\n");k=key();if(k=='Q'||k=='q')break;}
 }
 say("P6 RAM check returning to firmware. No unload, reboot or flash requested.\r\n");return 0;
}
