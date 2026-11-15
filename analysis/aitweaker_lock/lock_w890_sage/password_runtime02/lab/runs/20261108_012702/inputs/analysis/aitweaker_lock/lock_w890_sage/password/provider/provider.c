#include "provider.h"
AP_CORE w890_password_core;
static W890_HOST host;
static uint64_t owned_token;
static uint32_t depth;
static int initialized,ready,call_busy,ended;
W890_PROVIDER w890_provider={W890_PROVIDER_MAGIC,1,sizeof(W890_PROVIDER),w890_provider_begin,w890_provider_end,w890_provider_query,w890_provider_request,w890_provider_manage};
static int valid(W890_PROVIDER *p){return p==&w890_provider;}
static void revoke(void){depth=0;owned_token=0;ap_session_end(&w890_password_core);}
void w890_provider_fault(void){revoke();ap_fault(&w890_password_core);}
void w890_provider_end_boot(void){ended=1;ready=0;revoke();ap_secure_zero(w890_password_core.record,AP_RECORD_BYTES);}
static int bound(void){return ready&&!ended&&host.profile_bound()&&!ended;}
static int state_owned(void){return bound()&&depth&&depth<=W890_MAX_DEPTH&&owned_token&&w890_password_core.active&&
 w890_password_core.session_token==owned_token&&w890_password_core.mode!=AP_MODE_FAULT;}
int w890_session_owned(void){return state_owned()&&host.owner_active(owned_token,depth)&&!ended;}
int w890_session_can_enter(void){return !call_busy&&w890_session_owned()&&ap_can_enter(&w890_password_core);}
AP_STATUS w890_provider_initialize(const AP_ENV *env,const W890_HOST *hooks,const uint8_t setup[32],const uint8_t tse[32]){
 if(initialized)return AP_BUSY;
 initialized=1;
 if(ended||!env||!hooks||hooks->revision!=1||hooks->size!=sizeof(*hooks)||
    !hooks->profile_bound||!hooks->application_tpl||!hooks->owner_caller||!hooks->owner_active||
    !hooks->writable||!hooks->prompt||!hooks->authorize_operation||!w890_profile_matches(setup,tse)){
  w890_provider_fault();return AP_BAD_ARGUMENT;
 }
 host=*hooks;
 if(!host.profile_bound()||ended){w890_provider_fault();return AP_CREDENTIAL_ERROR;}
 AP_STATUS result=ap_init(&w890_password_core,env);
 if(ended){w890_provider_end_boot();return AP_OUTSIDE_SESSION;}
 if(!host.profile_bound()||ended){w890_provider_fault();return AP_CREDENTIAL_ERROR;}
 ready=1;return result;
}
ES EA w890_provider_begin(W890_PROVIDER *p,uint64_t *out){
 void *caller=__builtin_return_address(0);ES result=ERR(15);
 if(!valid(p)||!ready||ended||call_busy||!out||!host.writable(out,8)||ended)return result;
 *out=0;
 if(w890_password_core.busy||w890_password_core.mode==AP_MODE_FAULT)return result;
 call_busy=1;
 if(!bound()||!host.application_tpl()||ended||!host.owner_caller(caller,depth?3:1,out,owned_token,depth)||ended)goto done;
 if(depth){
  if(!state_owned()||depth==W890_MAX_DEPTH){w890_provider_fault();goto done;}
  depth++;
 }else{
  if(w890_password_core.active||owned_token){w890_provider_fault();goto done;}
  owned_token=ap_session_begin(&w890_password_core);
  if(!owned_token||!w890_password_core.active||w890_password_core.mode==AP_MODE_FAULT){w890_provider_fault();goto done;}
  depth=1;
 }
 if(!bound()||!host.writable(out,8)||ended){w890_provider_fault();goto done;}
 *out=owned_token;result=0;
done:call_busy=0;return result;
}
ES EA w890_provider_end(W890_PROVIDER *p,uint64_t token){
 void *caller=__builtin_return_address(0);
 if(!valid(p)||!ready||ended)return ERR(15);
 if(!bound()||!host.application_tpl()||ended||!host.owner_caller(caller,2,0,owned_token,depth)||ended)return ERR(15);
 if(!depth||!token||token!=owned_token||token!=w890_password_core.session_token){w890_provider_fault();return ERR(15);}
 if(--depth==0)revoke();return 0;
}
uint32_t EA w890_provider_query(W890_PROVIDER *p){
 if(!valid(p)||!initialized)return 0;
 if(ended)return W890_PROVIDER_ENDED;
 uint32_t flags=ready?W890_PROVIDER_READY:0;
 if(!ready||w890_password_core.mode==AP_MODE_FAULT)return flags|W890_PROVIDER_FAULT;
 if(!bound()){w890_provider_fault();return flags|W890_PROVIDER_FAULT;}
 if(call_busy||w890_password_core.busy)flags|=W890_PROVIDER_BUSY;
 if(w890_session_owned()){
  flags|=W890_PROVIDER_OWNED;
  if(!call_busy&&ap_can_enter(&w890_password_core))flags|=W890_PROVIDER_GRANTED;
 }
 if(ended)return W890_PROVIDER_ENDED;
 if(w890_password_core.mode==AP_MODE_DISABLED)flags|=W890_PROVIDER_DISABLED;
 return flags;
}
static ES interact(W890_PROVIDER *p,int operation,void *caller){
 if(!valid(p)||!ready||ended||call_busy||w890_password_core.busy||!w890_session_owned()||
    !host.application_tpl()||ended||!host.authorize_operation(caller,operation,owned_token,depth)||ended)return ERR(15);
 if(operation<0&&ap_can_enter(&w890_password_core))return 0;
 uint64_t token=owned_token;uint32_t saved_depth=depth;
 call_busy=1;int result=host.prompt(operation);call_busy=0;
 if(ended){revoke();ap_secure_zero(w890_password_core.record,AP_RECORD_BYTES);return ERR(15);}
 if(!w890_session_owned()||token!=owned_token||saved_depth!=depth){w890_provider_fault();return ERR(15);}
 if(!result)return ERR(15);
 return operation<0&&!ap_can_enter(&w890_password_core)?ERR(15):0;
}
ES EA w890_provider_request(W890_PROVIDER *p){return interact(p,-1,__builtin_return_address(0));}
ES EA w890_provider_manage(W890_PROVIDER *p,int operation){return operation==0||operation==1?interact(p,operation,__builtin_return_address(0)):ERR(2);}
static ES EA extract(void *this,void *input,void *progress,void *results){(void)this;(void)input;(void)progress;(void)results;return ended?ERR(15):ERR(3);}
static ES EA route(void *this,void *input,void *progress){(void)this;(void)input;(void)progress;return ended?ERR(15):ERR(3);}
W890_CONFIG w890_management_config={(void *)extract,(void *)route,w890_config_callback};
ES EA w890_config_callback(W890_CONFIG *this,uint64_t action,uint16_t id,uint8_t type,void *value,uint64_t *request){
 (void)type;(void)value;
 if(this!=&w890_management_config||!ready||ended)return ERR(15);
 if(request){if(!host.writable(request,8)||ended)return ERR(2);*request=0;}
 if(id<W890_SET_QID||id>W890_VERIFY_QID)return ERR(3);
 if(!w890_session_owned())return ERR(15);
 if(action==1)return 0;
 if(action!=0)return ERR(3);
 /* HII callbacks use their original caller in the operation check rather than
  * allowing the local forwarding callsite to masquerade as native ownership. */
 return interact(&w890_provider,id==W890_VERIFY_QID?-1:(id==W890_CLEAR_QID),__builtin_return_address(0));
}
