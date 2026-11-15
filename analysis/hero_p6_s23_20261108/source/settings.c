/* P6 native-variable policy. F10 writes settings; this driver takes a boot-time
 * snapshot and applies it only on that boot's firmware notifications. No writes
 * are made through HII callbacks or through a public diagnostic protocol. */
#include "settings.h"
#include "p6_backend.h"

static GUID settings_guid=P6_CFG_GUID;
static C16 config_name[]=u"HeroIpmiSettings",state_name[]=u"HeroIpmiState";
typedef struct {
 uint32_t magic,version,size,crc,phase,blocked;
 P6_SETTINGS applied,request;
 P6_RESULT result;
} P6_STATE;
static P6_SETTINGS boot_config;
/* AMITSE may persist only the 21 bytes covered by questions. Keep the
 * original stored width: no migration, variable deletion or padded rewrite.
 * Missing variables retain the previous 32-byte seed policy. */
static UN settings_bytes=sizeof(P6_SETTINGS);
static P6_STATE state;
static unsigned loaded,available,applied_this_boot,prepared,started,settings_busy,failed_this_boot,recovery_attempted;
static const P6_IO io={0,p6_exchange,p6_delay};
static void defaults(P6_SETTINGS *c){memset(c,0,sizeof(*c));c->wdt_minutes=10;c->wdt_action=1;}
static uint32_t crc(const void *p,UN n){
 uint32_t v=~0U;const uint8_t *b=p;
 for(UN i=0;i<n;i++){v^=b[i];for(unsigned j=0;j<8;j++)v=(v>>1)^(0xedb88320U&-(v&1U));}return ~v;
}
static int valid(const P6_SETTINGS *c){
 if(c->source>2||c->channel>11||c->wdt_enabled>1||c->wdt_minutes<1||c->wdt_minutes>30||c->wdt_action>3||
    c->sel_logging>2||c->sel_erase>2||c->sel_full>2||c->retry>1)return 0;
 for(unsigned i=0;i<sizeof(c->reserved);i++)if(c->reserved[i])return 0;
 return c->source!=1||p6_validate_ipv4(c->ip,c->mask,c->gateway);
}
static ES read_var(C16 *name,void *p,UN size){
 UN n=size;uint32_t attrs=0;ES e=gST->rt->get_variable(name,&settings_guid,&attrs,&n,p);
 if(FAILED(e))return e;return n==size&&attrs==3?0:ERR(33);
}
static ES read_settings(P6_SETTINGS *p,UN *stored_bytes){
 memset(p,0,sizeof(*p));UN n=sizeof(*p);uint32_t attrs=0;
 ES e=gST->rt->get_variable(config_name,&settings_guid,&attrs,&n,p);
 if(e)return FAILED(e)?e:ERR(33);
 if((n!=21&&n!=sizeof(*p))||attrs!=3)return ERR(33);
 if(stored_bytes)*stored_bytes=n;
 return 0;
}
static ES write_checked(C16 *name,const void *p,UN n){
 uint8_t check[sizeof(P6_STATE)];if(n>sizeof(check))return ERR(2);
 if(name==config_name){
  if(n!=sizeof(P6_SETTINGS)||(settings_bytes!=21&&settings_bytes!=n)||!valid(p))return ERR(2);
  ES e=gST->rt->set_variable(name,&settings_guid,3,settings_bytes,(void *)p);if(e)return FAILED(e)?e:ERR(33);
  UN actual=0;e=read_settings((P6_SETTINGS *)check,&actual);
  return FAILED(e)?e:actual!=settings_bytes?ERR(33):eq(check,p,n)?0:ERR(7);
 }
 ES e=gST->rt->set_variable(name,&settings_guid,3,n,(void *)p);if(FAILED(e))return e;
 e=read_var(name,check,n);return FAILED(e)?e:eq(check,p,n)?0:ERR(7);
}
static ES save_state(void){
 state.magic=0x36504948;state.version=1;state.size=sizeof(state);state.crc=0;
 state.crc=crc(&state,sizeof(state));ES e=write_checked(state_name,&state,sizeof(state));
 if(FAILED(e)){failed_this_boot=1;logtext("P6_JOURNAL_WRITE_OR_READBACK_FAILED=");loghex(e,16);logtext("\r\n");}
 return e;
}
static void status_text(const char *s){value_text(V_CONFIG_STATUS,s);logtext("P6_CONFIG: ");logtext(s);logtext("\r\n");}
static void format_result(void){
 if(!available){status_text("Settings/journal invalid or unavailable; no configuration writes.");return;}
 if(state.blocked||state.phase){
  char s[128];unsigned p=0;const char *a="Blocked: phase 0x",*b=" status 0x",*c=". See P6 log; explicit Retry required.";
  while(*a)s[p++]=*a++;s[p++]="0123456789ABCDEF"[state.phase&15];
  while(*b)s[p++]=*b++;s[p++]="0123456789ABCDEF"[(state.result.status>>4)&15];s[p++]="0123456789ABCDEF"[state.result.status&15];
  while(*c)s[p++]=*c++;s[p]=0;status_text(s);return;
 }
 status_text("Saved settings checked. Changes apply at next boot; F10 saves.");
}
ES p6_seed_settings(void){
 if(loaded)return available?0:ERR(33);loaded=1;
 ES e=read_settings(&boot_config,&settings_bytes);
 if(e==ERR(14)){defaults(&boot_config);settings_bytes=sizeof(boot_config);e=write_checked(config_name,&boot_config,sizeof(boot_config));}
 if(FAILED(e)||!valid(&boot_config)){status_text("Invalid settings: check IPv4/ranges. No configuration writes.");return ERR(33);}
 logtext("P6_SETTINGS_STORAGE_BYTES=");loghex(settings_bytes,2);logtext(" NORMALIZED_BYTES=20\r\n");
 memset(&state,0,sizeof(state));e=read_var(state_name,&state,sizeof(state));
 if(e==ERR(14)){defaults(&state.applied);state.request=state.applied;state.phase=state.blocked=0;}
 else {
  uint32_t stored=state.crc;state.crc=0;
  int ok=!FAILED(e)&&state.magic==0x36504948&&state.version==1&&state.size==sizeof(state)&&
         stored==crc(&state,sizeof(state))&&state.phase<=P6_PHASE_WDT_STOP&&state.blocked<=1&&valid(&state.applied)&&valid(&state.request);
  state.crc=stored;if(!ok){status_text("Invalid journal; no configuration writes. Preserve P6 log.");return ERR(33);}
 }
 available=1;format_result();return 0;
}
void p6_load_saved_result(void){if(!loaded)p6_seed_settings();else format_result();}
unsigned p6_selected_lan(void){return loaded&&available?boot_config.channel:0;}
static void trace_result(void){
 logtext("P6_PHASE=");loghex(state.phase,2);logtext(" RESULT ");
 const uint32_t *r=(const uint32_t *)&state.result;
 for(unsigned i=0;i<sizeof(state.result)/4;i++){loghex(r[i],8);logtext(" ");}logtext("\r\n");
}
static int config_still_current(void){
 P6_SETTINGS c;UN actual=0;ES e=read_settings(&c,&actual);
 if(FAILED(e)||actual!=settings_bytes||!eq(&c,&boot_config,sizeof(c))){status_text("Settings changed during this boot; restart to apply saved values.");failed_this_boot=1;return 0;}
 return 1;
}
static int begin_operation(unsigned phase){
 state.phase=phase;state.blocked=1;state.request=boot_config;memset(&state.result,0,sizeof(state.result));
 /* Pending is persistent BEFORE even opening KCS, including after a power loss. */
 if(FAILED(save_state())){status_text("Cannot persist pending journal; no BMC write attempted.");return 0;}
 ES e=p6_transport_open();
 if(FAILED(e)){state.result.status=state.result.cause=P6_TRANSPORT;save_state();trace_result();failed_this_boot=1;format_result();return 0;}
 p6_write_armed=1;return 1;
}
static int end_operation(int rc){
 p6_write_armed=0;trace_result();unsigned phase=state.phase;
 if(rc!=P6_OK){
  ES e=p6_transport_close();if(FAILED(e)){state.result.status=P6_UNCERTAIN;state.result.cause=P6_TRANSPORT;}
  state.blocked=1;save_state();failed_this_boot=1;format_result();return 0;
 }
 if(phase==P6_PHASE_LAN){state.applied.source=boot_config.source;state.applied.channel=boot_config.channel;memcpy(state.applied.ip,boot_config.ip,12);}
 if(phase==P6_PHASE_LOGGING)state.applied.sel_logging=boot_config.sel_logging;
 if(phase==P6_PHASE_WDT_CONFIG){state.applied.wdt_enabled=boot_config.wdt_enabled;state.applied.wdt_minutes=boot_config.wdt_minutes;state.applied.wdt_action=boot_config.wdt_action;}
 state.phase=0;state.blocked=0;
 if(FAILED(save_state())){
  state.phase=phase;state.blocked=1;state.result.status=P6_UNCERTAIN;
  /* A known-successful timer start must not remain armed just because NVRAM
   * failed. Transport is still open and healthy here. No such compensation
   * is attempted after an ambiguous transport/protocol failure above. */
  if(phase==P6_PHASE_WDT_START){
   P6_RESULT stop;p6_write_armed=1;
   int s=p6_watchdog_configure(&io,0,boot_config.wdt_minutes,boot_config.wdt_action,&stop);
   p6_write_armed=0;logtext("P6_START_JOURNAL_FAILED_STOP_RESULT=");loghex(s,8);logtext("\r\n");
   state.result.recovery=s==P6_OK?P6_RECOVERY_STOPPED:P6_RECOVERY_UNCONFIRMED;
   state.result.recovery_cause=stop.status;prepared=started=0;
  }
  if(FAILED(p6_transport_close()))state.result.cause=P6_TRANSPORT;
  save_state();
  status_text("Final journal failed; automatic writes blocked. See P6 recovery log.");return 0;
 }
 ES e=p6_transport_close();
 if(FAILED(e)){
  state.phase=phase;state.blocked=1;state.result.status=P6_UNCERTAIN;state.result.cause=P6_TRANSPORT;
  save_state();failed_this_boot=1;format_result();return 0;
 }
 return 1;
}
static int run_operation(unsigned phase){
 if(!begin_operation(phase))return 0;int r=P6_ARGUMENT;
 if(phase==P6_PHASE_LAN){P6_LAN l={0};l.channel=boot_config.channel;l.source=boot_config.source;memcpy(l.address,boot_config.ip,12);r=p6_lan_apply(&io,&l,&state.result);}
 else if(phase==P6_PHASE_LOGGING)r=p6_sel_logging(&io,boot_config.sel_logging==2,&state.result);
 else if(phase==P6_PHASE_ERASE)r=p6_sel_clear(&io,&state.result);
 else if(phase==P6_PHASE_FULL){
  P6_SEL_INFO inf;r=p6_sel_get_info(&io,&inf,&state.result);
  /* Overflow is historical and may remain set after one deletion. Only
   * currently insufficient room for a 16-byte record triggers destruction. */
  if(r==P6_OK&&inf.free_bytes<16){
   if(boot_config.sel_full==1)r=p6_sel_clear(&io,&state.result);
   else r=p6_sel_delete_oldest(&io,&state.result);
  }
 }
 else if(phase==P6_PHASE_WDT_CONFIG)r=p6_watchdog_configure(&io,boot_config.wdt_enabled,boot_config.wdt_minutes,boot_config.wdt_action,&state.result);
 else if(phase==P6_PHASE_WDT_START)r=p6_watchdog_start(&io,boot_config.wdt_minutes,boot_config.wdt_action,&state.result);
 else if(phase==P6_PHASE_WDT_STOP)r=p6_watchdog_configure(&io,0,boot_config.wdt_minutes,boot_config.wdt_action,&state.result);
 return end_operation(r);
}
void p6_apply_settings(void){
 if(settings_busy||applied_this_boot||failed_this_boot)return;
 if(!loaded)p6_seed_settings();
 if(available&&state.phase==P6_PHASE_WDT_START&&!recovery_attempted)p6_stop_os_watchdog();
 if(failed_this_boot)return;settings_busy=1;applied_this_boot=1;
 if(!available||!config_still_current())goto out;
 if((state.blocked||state.phase)&&!boot_config.retry){format_result();goto out;}
 /* Explicit retry is consumed before any command and may not automatically
  * replay a one-shot erase that was already consumed on a previous boot. */
 unsigned retry=boot_config.retry,erase_once=boot_config.sel_erase==1;
 if(retry){
  P6_SETTINGS next=boot_config;next.retry=0;
  if(FAILED(write_checked(config_name,&next,sizeof(next)))){failed_this_boot=1;status_text("Cannot consume one-shot request; no BMC writes.");goto out;}
  boot_config=next;
 }
 if(retry){state.blocked=0;state.phase=0;if(FAILED(save_state()))goto out;}
 if(boot_config.source && (retry||boot_config.source!=state.applied.source||boot_config.channel!=state.applied.channel||!eq(boot_config.ip,state.applied.ip,12)))
  if(!run_operation(P6_PHASE_LAN))goto out;
 if(boot_config.sel_logging && (retry||boot_config.sel_logging!=state.applied.sel_logging))
  if(!run_operation(P6_PHASE_LOGGING))goto out;
 if(erase_once){
  P6_SETTINGS next=boot_config;next.sel_erase=0;
  if(FAILED(write_checked(config_name,&next,sizeof(next)))){failed_this_boot=1;status_text("Cannot consume erase request; no SEL erase attempted.");goto out;}
  boot_config=next;
 }
 if(erase_once||boot_config.sel_erase==2)if(!run_operation(P6_PHASE_ERASE))goto out;
 if(boot_config.sel_full)if(!run_operation(P6_PHASE_FULL))goto out;
 if(boot_config.wdt_enabled||state.applied.wdt_enabled){
  if(!run_operation(P6_PHASE_WDT_CONFIG))goto out;
  prepared=boot_config.wdt_enabled;
 }
 /* Returning a setting to Unchanged releases control, so reselecting the same
  * value later is a new request instead of being incorrectly treated as old. */
 if(!eq(&state.applied,&boot_config,sizeof(boot_config))){state.applied=boot_config;if(FAILED(save_state()))goto out;}
 status_text(prepared?"Configuration verified; OS watchdog prepared, not started yet.":"Configuration applied/unchanged. See status pages for current BMC values.");
out:settings_busy=0;
}
void p6_start_os_watchdog(void){
 if(!applied_this_boot)p6_apply_settings();
 if(settings_busy||failed_this_boot||!available||state.blocked||state.phase||!boot_config.wdt_enabled||started)return;
 settings_busy=1;
 if(!prepared){if(!run_operation(P6_PHASE_WDT_CONFIG)){settings_busy=0;return;}prepared=1;}
 started=1;
 if(run_operation(P6_PHASE_WDT_START))status_text("OS Load watchdog started at BeforeBoot. OS must service/stop it.");
 settings_busy=0;
}
void p6_stop_os_watchdog(void){
 if(settings_busy||failed_this_boot||!available)return;
 /* A host reset can interrupt START after the BMC accepted Reset Watchdog.
  * The validated pending record remains the authority for a stop-only repair;
  * it is not permission to replay any configuration operation. */
 if((state.blocked||state.phase)&&state.phase==P6_PHASE_WDT_START&&state.request.wdt_enabled){
  if(recovery_attempted)return;recovery_attempted=1;settings_busy=1;
  ES e=p6_transport_open();
  if(!FAILED(e)){
   P6_RESULT stop;p6_write_armed=1;
   int r=p6_watchdog_recover_stop(&io,state.request.wdt_minutes,state.request.wdt_action,&stop);
   p6_write_armed=0;e=p6_transport_close();
   state.result.recovery=r==P6_OK&&!FAILED(e)?P6_RECOVERY_STOPPED:P6_RECOVERY_UNCONFIRMED;
   state.result.recovery_cause=FAILED(e)?P6_TRANSPORT:stop.status;
   state.result.recovery_completion=stop.completion;
   state.blocked=1;save_state();trace_result();prepared=started=0;
   if(r!=P6_OK||FAILED(e))failed_this_boot=1;
   status_text(r==P6_OK&&!FAILED(e)?"Interrupted OS watchdog start recovered: timer stopped; configuration remains blocked.":"Watchdog recovery could not confirm a matching stopped timer; see P6 log.");
  }else{failed_this_boot=1;logtext("P6_PENDING_WDT_STOP_TRANSPORT_FAILED=");loghex(e,16);logtext("\r\n");}
  settings_busy=0;return;
 }
 if(state.blocked||state.phase||!state.applied.wdt_enabled)return;
 settings_busy=1;
 /* Only an OS Load timer is eligible; the backend refuses a running timer
  * owned by SMS/FRB/OEM. Keep desired enable state for the next OS launch. */
 if(run_operation(P6_PHASE_WDT_STOP)){
  prepared=started=0;
  status_text("OS Load watchdog stopped for Setup/Shell or returned boot image.");
 }
 settings_busy=0;
}
