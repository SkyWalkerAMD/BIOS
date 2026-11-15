/* Resident optional credential/session provider for static gate ABI v1.
 * No AMITSE/Setup pointer replacement and no RuntimeServices interposition.
 * The platform adapter binds Begin/End to reviewed native guard CALL sites.
 */
#include "provider.h"
AP_CORE password_core;
int boot_services_ended;
static PROVIDER_HOST host;
static uint64_t owned_token;
static uint32_t depth;
static int initialized,ready,call_busy;
GATE_PROVIDER native_provider={PROVIDER_MAGIC,1,sizeof(GATE_PROVIDER),provider_begin,provider_end,provider_query,provider_request,provider_manage};

static int valid(GATE_PROVIDER *p){return p==&native_provider;}
static void revoke(void){depth=0;owned_token=0;ap_session_end(&password_core);}
void provider_fault(void){revoke();ap_fault(&password_core);}
void provider_end_boot(void){
 boot_services_ended=1;ready=0;revoke();ap_secure_zero(password_core.record,sizeof(password_core.record));
}
AP_STATUS provider_initialize(const AP_ENV *env,const PROVIDER_HOST *hooks){
 if(initialized)return AP_BUSY;
 initialized=1;
 if(!hooks||!hooks->application_tpl||!hooks->owner_caller||!hooks->owner_active||!hooks->writable||!hooks->prompt){ap_fault(&password_core);return AP_BAD_ARGUMENT;}
 host=*hooks;
 AP_STATUS s=ap_init(&password_core,env);
 if(boot_services_ended){provider_end_boot();return AP_OUTSIDE_SESSION;}
 /* Malformed or inaccessible persistent state remains a published fault so
  * UI diagnostics can distinguish it; it never turns into DISABLED. */
 ready=1;return s;
}
static int state_owned(void){
 return ready&&!boot_services_ended&&depth&&depth<=PROVIDER_MAX_DEPTH&&owned_token&&
  password_core.active&&password_core.session_token==owned_token&&password_core.mode!=AP_MODE_FAULT;
}
int platform_session_owned(void){return state_owned()&&host.owner_active(owned_token,depth);}
int platform_can_enter(void){return platform_session_owned()&&ap_can_enter(&password_core);}
ES EA provider_begin(GATE_PROVIDER *p,uint64_t *token){
 void *caller=__builtin_return_address(0);
 if(!valid(p)||!ready||boot_services_ended||!token||!host.writable(token,sizeof(*token)))return ERR(15);
 *token=0;
 if(call_busy||password_core.busy||password_core.mode==AP_MODE_FAULT||!host.application_tpl()||!host.owner_caller(caller,depth?3:1,token,owned_token,depth)||boot_services_ended||!ready)return ERR(15);
 if(depth){
  if(!state_owned()||depth==PROVIDER_MAX_DEPTH){provider_fault();return ERR(15);}
  depth++;
 }else{
  if(password_core.active||owned_token){provider_fault();return ERR(15);}
  owned_token=ap_session_begin(&password_core);
  if(!owned_token||!password_core.active||password_core.mode==AP_MODE_FAULT){provider_fault();return ERR(15);}
  depth=1;
 }
 *token=owned_token;return 0;
}
ES EA provider_end(GATE_PROVIDER *p,uint64_t token){
 void *caller=__builtin_return_address(0);
 if(!valid(p)||!ready||boot_services_ended)return ERR(15);
 if(!host.application_tpl()||!host.owner_caller(caller,2,0,owned_token,depth))return ERR(15);
 if(!depth||!token||token!=owned_token||token!=password_core.session_token){provider_fault();return ERR(15);}
 /* End is allowed to revoke during a callback. The operation verifies its
  * saved token again on return and cannot grant after the owner exits. */
 if(--depth==0)revoke();return 0;
}
uint32_t EA provider_query(GATE_PROVIDER *p){
 if(!valid(p)||!initialized)return 0;
 if(boot_services_ended)return PROVIDER_ENDED;
 uint32_t s=ready?PROVIDER_READY:0;
 if(password_core.mode==AP_MODE_FAULT)return s|PROVIDER_FAULT;
 if(call_busy||password_core.busy)s|=PROVIDER_BUSY;
 if(platform_session_owned()){
  s|=PROVIDER_OWNED;
  if(ap_can_enter(&password_core))s|=PROVIDER_GRANTED;
 }
 /* Only the checksummed, explicitly cleared persistent record selects this.
  * Absence is UNCONFIGURED and exposes neither DISABLED nor GRANTED. */
 if(password_core.mode==AP_MODE_DISABLED)s|=PROVIDER_DISABLED;
 return s;
}
static ES interact(GATE_PROVIDER *p,int operation){
 if(!valid(p)||!ready||boot_services_ended||call_busy||password_core.busy||
    !platform_session_owned()||!host.application_tpl())return ERR(15);
 if(operation<0&&platform_can_enter())return 0;
 uint64_t token=owned_token;uint32_t entry_depth=depth;
 call_busy=1;int success=host.prompt(operation);call_busy=0;
 if(boot_services_ended){revoke();ap_secure_zero(password_core.record,sizeof(password_core.record));return ERR(15);}
 if(!platform_session_owned()||owned_token!=token||depth!=entry_depth){provider_fault();return ERR(15);}
 if(!success)return ERR(15);
 return operation<0&&!platform_can_enter()?ERR(15):0;
}
ES EA provider_request(GATE_PROVIDER *p){return interact(p,-1);}
ES EA provider_manage(GATE_PROVIDER *p,int clear){return clear==0||clear==1?interact(p,clear):ERR(2);}
