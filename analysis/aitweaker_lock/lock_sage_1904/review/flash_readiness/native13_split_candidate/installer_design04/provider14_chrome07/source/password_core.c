#include "password_core.h"

static const uint8_t magic[8]={'A','I','T','W','K','P','0','1'};
static void cp(void *vd,const void *vs,size_t n){uint8_t *d=vd;const uint8_t *s=vs;while(n--)*d++=*s++;}
static uint32_t le32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t le64(const uint8_t *p){return le32(p)|((uint64_t)le32(p+4)<<32);}
static void put32(uint8_t *p,uint32_t x){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(x>>(i*8));}
static void put64(uint8_t *p,uint64_t x){put32(p,(uint32_t)x);put32(p+4,(uint32_t)(x>>32));}
static int all_zero(const uint8_t *p,size_t n){uint8_t v=0;while(n--)v|=*p++;return v==0;}
static int uniform(const uint8_t *p,size_t n){uint8_t d=0;for(size_t i=1;i<n;i++)d|=p[i]^p[0];return d==0;}

AP_API int ap_record_valid(const uint8_t *r,size_t n){
    uint8_t sum[32];int ok;
    if(!r||n!=AP_RECORD_BYTES)return 0;
    if(!ap_constant_equal(r,magic,8)||r[8]!=1||r[9]!=0||r[10]!=128||r[11]!=0||le64(r+24)==0)return 0;
    if(le32(r+12)==1){
        if(le32(r+16)!=1||le32(r+20)<AP_ITERATIONS||le32(r+20)>AP_ITERATIONS_MAX||uniform(r+32,32)||all_zero(r+64,32))return 0;
    }else if(le32(r+12)==0){
        if(le32(r+16)||le32(r+20)||!all_zero(r+32,64))return 0;
    }else return 0;
    ap_sha256(r,96,sum);ok=ap_constant_equal(sum,r+96,32);ap_secure_zero(sum,32);return ok;
}
AP_API void ap_fault(AP_CORE *c){if(!c)return;c->mode=AP_MODE_FAULT;c->unlocked=0;c->active=0;ap_secure_zero(c->record,AP_RECORD_BYTES);}
AP_API AP_STATUS ap_init(AP_CORE *c,const AP_ENV *env){
    AP_ENV saved;size_t n=0;AP_READ_RESULT read_result;
    if(!c||!env)return AP_BAD_ARGUMENT;
    cp(&saved,env,sizeof(saved));ap_secure_zero(c,sizeof(*c));cp(&c->env,&saved,sizeof(saved));ap_secure_zero(&saved,sizeof(saved));
    c->mode=AP_MODE_FAULT;
    if(!c->env.read||!c->env.persist||!c->env.entropy||!c->env.now_ms)return AP_BAD_ARGUMENT;
    read_result=c->env.read(c->env.opaque,c->record,AP_RECORD_BYTES,&n);
    if(read_result==AP_READ_NOT_FOUND&&n==0){c->mode=AP_MODE_UNCONFIGURED;ap_secure_zero(c->record,AP_RECORD_BYTES);return AP_UNCONFIGURED;}
    if(read_result!=AP_READ_OK||!ap_record_valid(c->record,n)){ap_fault(c);return AP_CREDENTIAL_ERROR;}
    c->mode=le32(c->record+12)?AP_MODE_ENABLED:AP_MODE_DISABLED;return AP_OK;
}
AP_API uint64_t ap_session_begin(AP_CORE *c){
    if(!c)return 0;c->unlocked=0;c->active=0;
    if(c->session_token==UINT64_MAX){ap_fault(c);return 0;}
    c->session_token++;c->active=1;return c->session_token;
}
AP_API void ap_session_end(AP_CORE *c){if(c){c->active=0;c->unlocked=0;}}
AP_API int ap_can_enter(const AP_CORE *c){
    return c&&c->active&&!c->busy&&(c->mode==AP_MODE_DISABLED||(c->mode==AP_MODE_ENABLED&&c->unlocked));
}
static AP_STATUS session(AP_CORE *c,uint64_t token){
    if(!c)return AP_BAD_ARGUMENT;
    if(!c->active)return AP_OUTSIDE_SESSION;
    if(!token||token!=c->session_token)return AP_STALE_SESSION;
    if(c->mode==AP_MODE_FAULT)return AP_CREDENTIAL_ERROR;
    return AP_OK;
}
static AP_STATUS enter(AP_CORE *c,uint64_t token){AP_STATUS s=session(c,token);if(s)return s;if(c->busy)return AP_BUSY;c->busy=1;return AP_OK;}
static AP_STATUS clock_now(AP_CORE *c,uint64_t *now){
    if(c->env.now_ms(c->env.opaque,now)!=0||(c->clock_valid&&*now<c->last_now_ms))return AP_CLOCK_FAILED;
    c->last_now_ms=*now;c->clock_valid=1;return AP_OK;
}
static AP_STATUS authenticate(AP_CORE *c,uint64_t token,const uint8_t *pw,size_t len,int reset_rate){
    uint64_t now;uint8_t actual[32];AP_STATUS s;int match;
    if(!pw||len<AP_PASSWORD_MIN||len>AP_PASSWORD_MAX)return AP_BAD_ARGUMENT;
    s=clock_now(c,&now);if(s)return s;
    s=session(c,token);if(s)return s;
    if(c->retry_after_ms==UINT64_MAX||now<c->retry_after_ms)return AP_RATE_LIMITED;
    if(ap_pbkdf2_sha256(pw,len,c->record+32,32,le32(c->record+20),actual)!=0)return AP_CREDENTIAL_ERROR;
    match=ap_constant_equal(actual,c->record+64,32);ap_secure_zero(actual,32);
    s=session(c,token);if(s)return s;
    if(match){if(reset_rate){c->failed_attempts=0;c->retry_after_ms=0;}return AP_OK;}
    s=clock_now(c,&now);if(s)return s;
    s=session(c,token);if(s)return s;
    if(c->failed_attempts<UINT32_MAX)c->failed_attempts++;
    /* Delay every failed online authentication; an exit/re-entry cannot reset
     * this boot-local counter or deadline. No blocking sleep inside the core. */
    c->retry_after_ms=now>UINT64_MAX-AP_RETRY_DELAY_MS?UINT64_MAX:now+AP_RETRY_DELAY_MS;
    return AP_DENIED;
}
AP_API AP_STATUS ap_unlock(AP_CORE *c,uint64_t token,const uint8_t *pw,size_t len){
    AP_STATUS s=enter(c,token);if(s)return s;
    if(c->mode==AP_MODE_UNCONFIGURED)s=AP_UNCONFIGURED;
    else if(c->mode==AP_MODE_DISABLED||c->unlocked)s=AP_OK;
    else{s=authenticate(c,token,pw,len,1);if(s==AP_OK)c->unlocked=1;}
    c->busy=0;return s;
}
static AP_STATUS generation(AP_CORE *c,uint64_t *g){
    if(c->mode==AP_MODE_UNCONFIGURED){*g=1;return AP_OK;}
    *g=le64(c->record+24);if(*g==UINT64_MAX)return AP_COUNTER_EXHAUSTED;(*g)++;return AP_OK;
}
static void header(uint8_t r[128],uint64_t gen,int enabled){
    ap_secure_zero(r,128);cp(r,magic,8);r[8]=1;r[10]=128;put32(r+12,(uint32_t)enabled);put64(r+24,gen);
    if(enabled){put32(r+16,1);put32(r+20,AP_ITERATIONS);}
}
static AP_STATUS commit(AP_CORE *c,const uint8_t next[128]){
    if(c->env.persist(c->env.opaque,next,128)!=0)return AP_STORAGE_FAILED;
    /* Even if a session ended during a successful persistence callback, the
     * actual newly committed credential must become authoritative. */
    cp(c->record,next,128);c->mode=le32(next+12)?AP_MODE_ENABLED:AP_MODE_DISABLED;c->unlocked=0;
    c->failed_attempts=0;c->retry_after_ms=0;return AP_OK;
}
AP_API AP_STATUS ap_set_password(AP_CORE *c,uint64_t token,const uint8_t *old,size_t old_len,const uint8_t *pw,size_t len){
    AP_STATUS s;uint64_t gen;uint8_t next[128];
    if(!pw||len<AP_PASSWORD_MIN||len>AP_PASSWORD_MAX)return AP_BAD_ARGUMENT;
    s=enter(c,token);if(s)return s;
    if(c->mode==AP_MODE_ENABLED){s=authenticate(c,token,old,old_len,0);if(s)goto done;}
    else if(old_len!=0){s=AP_BAD_ARGUMENT;goto done;}
    s=generation(c,&gen);if(s)goto done;
    header(next,gen,1);
    if(c->env.entropy(c->env.opaque,next+32,32)!=0||uniform(next+32,32)||
       (c->mode==AP_MODE_ENABLED&&ap_constant_equal(next+32,c->record+32,32))){s=AP_ENTROPY_FAILED;goto wipe;}
    s=session(c,token);if(s)goto wipe;
    if(ap_pbkdf2_sha256(pw,len,next+32,32,AP_ITERATIONS,next+64)!=0){s=AP_CREDENTIAL_ERROR;goto wipe;}
    ap_sha256(next,96,next+96);
    s=session(c,token);if(s)goto wipe;
    s=commit(c,next);
wipe:ap_secure_zero(next,sizeof(next));
done:c->busy=0;return s;
}
AP_API AP_STATUS ap_clear_password(AP_CORE *c,uint64_t token,const uint8_t *old,size_t old_len){
    AP_STATUS s;uint64_t gen;uint8_t next[128];
    s=enter(c,token);if(s)return s;
    if(c->mode==AP_MODE_UNCONFIGURED){s=AP_UNCONFIGURED;goto done;}
    if(c->mode==AP_MODE_DISABLED){s=old_len?AP_BAD_ARGUMENT:AP_OK;goto done;}
    s=authenticate(c,token,old,old_len,0);if(s)goto done;
    s=generation(c,&gen);if(s)goto done;
    header(next,gen,0);ap_sha256(next,96,next+96);
    s=session(c,token);if(s==AP_OK)s=commit(c,next);
    ap_secure_zero(next,sizeof(next));
done:c->busy=0;return s;
}
AP_API AP_STATUS ap_cancel(AP_CORE *c,uint64_t token){AP_STATUS s=session(c,token);return s?s:AP_CANCELLED;}
AP_API uint64_t ap_retry_remaining_ms(AP_CORE *c){
    uint64_t now;if(!c||clock_now(c,&now)!=AP_OK)return UINT64_MAX;
    if(c->retry_after_ms==UINT64_MAX)return UINT64_MAX;
    return c->retry_after_ms>now?c->retry_after_ms-now:0;
}
