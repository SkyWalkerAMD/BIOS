/* Maintenance credential gate. This file does not replace production AP_ENV
 * read/persist. The frozen services.obj calls this instead of a raw SetVariable.
 * Only the named credential can reach the saved firmware function. No SPI I/O.
 */
#include "nv_guard.h"
static GETVAR firmware_get;
static SETVAR firmware_set;
static NV_STATUS state;
static uint8_t owned_record[AP_RECORD_BYTES];
static uint64_t generation(const uint8_t *r) {
 uint64_t n=0;for(unsigned i=0;i<8;i++)n|=(uint64_t)r[24+i]<<(8*i);return n;
}
static uint32_t enabled(const uint8_t *r) {
 return (uint32_t)r[12]|(uint32_t)r[13]<<8|(uint32_t)r[14]<<16|(uint32_t)r[15]<<24;
}
static int live(void) {return state.ready && state.armed && !state.retired && !state.fault && !boot_services_ended;}
static int authorized(void) {
 return live() && state.action && platform_session_owned() && password_core.busy &&
        password_core.mode!=AP_MODE_FAULT && state.action_token==password_core.session_token;
}
static ES read_current(uint8_t out[AP_RECORD_BYTES],uint32_t *attributes,UN *size) {
 *size=AP_RECORD_BYTES;*attributes=0;memset(out,0,AP_RECORD_BYTES);
 ES s=firmware_get(credential_name,&credential_guid,attributes,size,out);
 state.last_get_status=s;
 if(s==ERR(14)){*size=0;*attributes=0;}
 return s;
}
static int matches(ES s,uint32_t a,UN n,const uint8_t *r) {
 return state.present ? s==0 && a==3 && n==AP_RECORD_BYTES &&
        ap_constant_equal(r,owned_record,AP_RECORD_BYTES) : s==ERR(14) && n==0;
}
static void remember(const uint8_t r[AP_RECORD_BYTES]) {
 memcpy(owned_record,r,AP_RECORD_BYTES);state.present=state.owned=1;
 state.attributes=3;state.size=AP_RECORD_BYTES;state.generation=generation(r);
 ap_sha256(r,AP_RECORD_BYTES,state.hash);
}
static void uncertain(void) {
 state.fault=1;state.owned=0;state.action=0;ap_fault(&password_core);
}
int nv_prepare(GETVAR get,SETVAR set,uint32_t phase,const uint8_t expected[32]) {
 uint8_t r[AP_RECORD_BYTES],h[32];uint32_t a;UN n;ES s;int okay=0;
 if(state.initialized || boot_services_ended || !get || !set || set==nv_guard_set ||
    (phase!=1 && phase!=2) || (phase==2 && !expected))return 0;
 state.initialized=1;state.phase=phase;firmware_get=get;firmware_set=set;
 s=read_current(r,&a,&n);
 if(boot_services_ended)goto out;
 if(phase==1) {
  okay=s==ERR(14) && n==0 && password_core.mode==AP_MODE_UNCONFIGURED && !password_core.active;
 } else if(s==0 && a==3 && n==AP_RECORD_BYTES && ap_record_valid(r,n) && enabled(r)==1) {
  ap_sha256(r,n,h);
  okay=ap_constant_equal(h,expected,32) && password_core.mode==AP_MODE_ENABLED &&
       !password_core.active && ap_constant_equal(r,password_core.record,n);
  if(okay)remember(r);
 }
 state.ready=(uint32_t)okay;
out:
 ap_secure_zero(r,sizeof(r));ap_secure_zero(h,sizeof(h));return okay;
}
int nv_activate(void) {
 if(!state.ready || state.armed || state.retired || state.fault || boot_services_ended ||
    password_core.active || platform_session_owned())return 0;
 state.armed=1;return 1;
}
int nv_begin_action(uint32_t action) {
 if(!live() || state.action || state.gate_busy || password_core.busy ||
    !platform_session_owned() || (action!=NV_ACTION_SET && action!=NV_ACTION_CLEAR) ||
    state.sealed || (state.phase==1 && action!=NV_ACTION_SET) ||
    (state.phase==2 && (!state.owned || !state.present || enabled(owned_record)!=1)) ||
    password_core.mode==AP_MODE_FAULT)return 0;
 state.action=action;state.action_token=password_core.session_token;return 1;
}
void nv_end_action(void) {state.action=0;state.action_token=0;}
ES EA nv_guard_set(C16 *name,GUID *guid,uint32_t attributes,UN n,void *data) {
 uint8_t candidate[AP_RECORD_BYTES],before[AP_RECORD_BYTES],after[AP_RECORD_BYTES];
 uint32_t a=0;UN len=0;ES status=ERR(8),read_status;
 /* Canonical pointer identity is intentionally stricter than string equality:
  * production persist_record uses these exact exported name/GUID objects. */
 if(name!=credential_name || guid!=&credential_guid || attributes!=3 || n!=AP_RECORD_BYTES ||
    !data || state.gate_busy || !authorized() || state.sealed || state.attempts>=16) {
  state.blocked++;return ERR(8);
 }
 state.gate_busy=1;memcpy(candidate,data,sizeof(candidate));
 if(!ap_record_valid(candidate,sizeof(candidate)) || state.generation==UINT64_MAX ||
    generation(candidate)!=state.generation+1 ||
    enabled(candidate)!=(state.action==NV_ACTION_SET?1u:0u) ||
    (state.phase==1 && (state.present || state.owned || state.action!=NV_ACTION_SET)) ||
    (state.phase==2 && (!state.owned || !state.present || enabled(owned_record)!=1)) ||
    (state.present && !ap_constant_equal(password_core.record,owned_record,sizeof(owned_record))))goto done;
 read_status=read_current(before,&a,&len);
 if(!authorized())goto done;
 if(!matches(read_status,a,len,before)){uncertain();goto done;}
 /* Copy the desired record before calling a provider. A mutated caller buffer
  * cannot change the actual SetVariable body after authorization. */
 state.attempts++;status=firmware_set(credential_name,&credential_guid,3,sizeof(candidate),candidate);
 state.last_set_status=status;
 if(boot_services_ended || state.retired){uncertain();status=ERR(15);goto done;}
 read_status=read_current(after,&a,&len);
 if(boot_services_ended || state.retired){uncertain();status=ERR(15);goto done;}
 if(status==0 && read_status==0 && a==3 && len==sizeof(candidate) &&
    ap_constant_equal(after,candidate,sizeof(candidate))) {
  remember(candidate);state.commits++;if(state.phase==1)state.sealed=1;
 } else if(!FAILED(status) || !matches(read_status,a,len,after)) {
  uncertain();status=ERR(7);
 }
done:
 if(FAILED(status))state.blocked++;
 ap_secure_zero(candidate,sizeof(candidate));ap_secure_zero(before,sizeof(before));
 ap_secure_zero(after,sizeof(after));state.gate_busy=0;return status;
}
int nv_cleanup_tombstone(void) {
 uint8_t r[AP_RECORD_BYTES];uint32_t a;UN n;ES s;int okay=0;
 if(!live() || state.phase!=2 || !state.owned || !state.present || state.gate_busy ||
    state.action || state.cleanup_complete || state.delete_attempts || platform_session_owned() ||
    password_core.active || password_core.unlocked || password_core.busy ||
    password_core.mode!=AP_MODE_DISABLED || enabled(owned_record)!=0 ||
    !ap_record_valid(owned_record,sizeof(owned_record)) ||
    !ap_constant_equal(owned_record,password_core.record,sizeof(owned_record)))return 0;
 state.gate_busy=1;s=read_current(r,&a,&n);
 if(!live() || platform_session_owned() || password_core.active || password_core.busy)goto out;
 if(!matches(s,a,n,r)){uncertain();goto out;}
 /* This sole deletion path is unavailable to RT.SetVariable callers. It is
  * explicit, single-shot and only accepts our exact disabled tombstone. */
 state.delete_attempts++;s=firmware_set(credential_name,&credential_guid,0,0,0);
 state.last_set_status=s;
 if(boot_services_ended || state.retired){uncertain();goto out;}
 ES after=read_current(r,&a,&n);
 if(boot_services_ended || state.retired){uncertain();goto out;}
 if(s==0 && after==ERR(14) && !n) {
  state.cleanup_complete=1;state.owned=state.present=0;state.attributes=0;state.size=0;
  ap_secure_zero(owned_record,sizeof(owned_record));ap_secure_zero(state.hash,sizeof(state.hash));okay=1;
 } else uncertain();
out:
 ap_secure_zero(r,sizeof(r));state.gate_busy=0;return okay;
}
void nv_retire(void) {state.retired=1;state.armed=0;state.action=0;state.action_token=0;ap_secure_zero(owned_record,sizeof(owned_record));}
const NV_STATUS *nv_status(void) {return &state;}
