"""Create an isolated owner-gated candidate; never edits a baseline source."""
from pathlib import Path
import difflib, hashlib, json
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];D=CASE/'driver';EBS=HERE.parent/'ebs_candidate'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def replace(s,old,new):
    assert s.count(old)==1,(old,s.count(old))
    return s.replace(old,new)
sources={n:(EBS if n=='services.c' else D)/n for n in ['platform.c','hii.c','ui.c','services.c','lock.h']}
baseline={str(p.relative_to(CASE)):sha(p) for p in sources.values()}
for n,p in sources.items():
    s=p.read_text(encoding='utf8')
    if n=='lock.h':
        s=replace(s,'#include "../core/password_core.h"','#include "../../../core/password_core.h"')
        s=replace(s,'int ensure_unlocked(void);','int platform_session_owned(void);\nint platform_can_enter(void);\nint ensure_unlocked(void);')
    elif n=='platform.c':
        s=replace(s,'static int denied_this_turn;','''static int denied_this_turn;
/* A late stage-4 attach can occur inside an already-running OEM loop. Its
 * callbacks are guarded immediately, but only this wrapper owns a session.
 * Core.active/unlocked alone cannot prove that ownership. */
int platform_session_owned(void) {
 return loop_depth>0 && loop_depth<=16 && password_core.active && !boot_services_ended;
}
int platform_can_enter(void) {
 if(boot_services_ended || password_core.busy)return 0;
 if(password_core.mode==AP_MODE_DISABLED)return 1;
 return platform_session_owned() && ap_can_enter(&password_core);
}''')
        s=replace(s,' if(ap_can_enter(&password_core))return 1;',' if(platform_can_enter())return 1;')
        s=replace(s,' if(protected==1 && prompt && !denied_this_turn && ensure_unlocked())return 1;',' if(protected==1 && prompt && !denied_this_turn && platform_session_owned() &&\n    ensure_unlocked() && platform_can_enter())return 1;')
        s=replace(s,' if(!loop_depth || !tse_base || dword(tse_base+0x83468)!=5)return;',' if(boot_services_ended || !tse_base || dword(tse_base+0x83468)!=5)return;')
        s=replace(s,' gate(page_at(a,dword(a+0x28)),1);',' gate(page_at(a,dword(a+0x28)),platform_session_owned());')
        assert s.count('if(loop_depth && !gate(page,0))')==2
        s=s.replace('if(loop_depth && !gate(page,0))','if(!gate(page,0))')
        s=replace(s,' if(loop_depth && (!memory_present(a,0x60,0) || !gate(page_at(a,dword(a+0x28)),0)))return 0;',' if(!memory_present(a,0x60,0) || !gate(page_at(a,dword(a+0x28)),0))return 0;')
        s=replace(s,' if(loop_depth && !ap_can_enter(&password_core)) {',' if(!platform_can_enter()) {')
        s=replace(s,'  if(protected && (protected<0 || !ensure_unlocked())) {audit(46,(uint64_t)(int64_t)protected);return 0;}','  if(protected && (protected<0 || !platform_session_owned() ||\n     !ensure_unlocked() || !platform_can_enter())) {audit(46,(uint64_t)(int64_t)protected);return 0;}')
        s=replace(s,''' if(memory_present(new_guid,16,0) && memory_present(new_form,2,0) && !memcmp(new_guid,&setup_formset,16) && policy_form(*new_form)) {
  if(!ensure_unlocked()) {denied_this_turn=1;return ERR(15);}
 }''',''' if(!memory_present(new_guid,16,0) || !memory_present(new_form,2,0))
  return platform_can_enter()?status:ERR(15);
 if(!memcmp(new_guid,&setup_formset,16) && policy_form(*new_form)) {
  if(!platform_can_enter() && (!platform_session_owned() || !ensure_unlocked() ||
     !platform_can_enter())) {denied_this_turn=1;return ERR(15);}
 }''')
    elif n=='hii.c':
        s=replace(s,'  if(request)*request=0;','  if(request)*request=0;\n  if((action==0 || action==1) && !platform_session_owned())return ERR(15);')
        s=replace(s,' if((action==0 || action==1) && policy_question(q) && !ensure_unlocked())return ERR(15);',' if((action==0 || action==1) && policy_question(q) && !platform_can_enter() &&\n    (!platform_session_owned() || !ensure_unlocked() || !platform_can_enter()))return ERR(15);')
        s=replace(s,'route_is_protected(configuration) && !ap_can_enter(&password_core)','route_is_protected(configuration) && !platform_can_enter()')
    elif n=='ui.c':
        s=replace(s,' if(ap_can_enter(&password_core))return 1;',' if(platform_can_enter())return 1;')
        s=replace(s,' if(ui_busy || !password_core.active || boot_services_ended || !system_table->out || !system_table->in)return 0;',' if(ui_busy || password_core.busy || !platform_session_owned() || !system_table->out || !system_table->in)return 0;')
        s=replace(s,'print(U("Checking...\\r\\n"));s=ap_unlock(&password_core,token,p,n);','print(U("Checking...\\r\\n"));s=platform_session_owned()?ap_unlock(&password_core,token,p,n):AP_OUTSIDE_SESSION;')
        s=replace(s,' audit(10,(uint64_t)s);return ap_can_enter(&password_core);',' audit(10,(uint64_t)s);return platform_session_owned() && token==password_core.session_token && platform_can_enter();')
        s=replace(s,' if(ui_busy || !password_core.active || !system_table->out || !system_table->in)return 0;',' if(ui_busy || password_core.busy || !platform_session_owned() || !system_table->out || !system_table->in)return 0;')
        s=replace(s,'  s=ap_clear_password(&password_core,token,old,on);','  s=platform_session_owned()?ap_clear_password(&password_core,token,old,on):AP_OUTSIDE_SESSION;')
        s=replace(s,'s=ap_set_password(&password_core,token,old,on,fresh,nn);','s=platform_session_owned()?ap_set_password(&password_core,token,old,on,fresh,nn):AP_OUTSIDE_SESSION;')
        s=replace(s,'return s==AP_OK;','return s==AP_OK && platform_session_owned() && token==password_core.session_token;')
    elif n=='services.c':
        s=replace(s,' (void)v;uint8_t check[AP_RECORD_BYTES],before[AP_RECORD_BYTES];size_t before_n=0,after_n=0;',' (void)v;if(!platform_session_owned())return 1;\n uint8_t check[AP_RECORD_BYTES],before[AP_RECORD_BYTES];size_t before_n=0,after_n=0;')
        s=replace(s,' AP_READ_RESULT before_status=read_record(0,before,sizeof(before),&before_n);',' AP_READ_RESULT before_status=read_record(0,before,sizeof(before),&before_n);\n if(!platform_session_owned()) {ap_secure_zero(before,sizeof(before));return 1;}')
        s=replace(s,'!ap_can_enter(&password_core) && protected_change','!platform_can_enter() && protected_change')
        # EBS cleanup implementation remains byte-for-byte source equivalent.
        start='static int update_runtime_set(SETVAR fn) {'
        assert s[s.index(start):]==p.read_text(encoding='utf8')[p.read_text(encoding='utf8').index(start):]
    (HERE/n).write_text(s,encoding='utf8',newline='\n')
    diff=''.join(difflib.unified_diff(p.read_text(encoding='utf8').splitlines(True),s.splitlines(True),fromfile=str(p.relative_to(CASE)),tofile='late_attach_candidate/'+n))
    (HERE/(n+'.patch')).write_text(diff,encoding='utf8')
assert all(sha(CASE/name)==v for name,v in baseline.items())
(HERE/'source_manifest.json').write_text(json.dumps({'status':'ISOLATED_SOURCE_CANDIDATE','baseline_sources':baseline,'candidate_sources':{n:sha(HERE/n) for n in sources},'ebs_cleanup_source_unchanged':True,'hardware_acceptance_inherited':False},indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':'ISOLATED_SOURCE_CANDIDATE','candidate_sources':{n:sha(HERE/n) for n in sources}},indent=2))
