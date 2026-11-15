#include "r2.h"
ST *gST;
GUID config_guid=CFG_GUID_INIT,api_guid=API_GUID_INIT;
GUID r3_api_guid=R3_API_GUID_INIT;
R3_REPORT r3_report={.version=3,.size=sizeof(R3_REPORT),.sensor_status=ERR(6),.dashboard_status=ERR(6),.source_status=ERR(6)};
uint32_t config_source;
REPORT report;
char audit[131072]; UN audit_len;
void *memcpy(void *d,const void *s,size_t n) { uint8_t *a=d; const uint8_t *b=s; while(n--)*a++=*b++; return d; }
void *memset(void *d,int c,size_t n) { uint8_t *a=d; while(n--)*a++=(uint8_t)c; return d; }
int eq(const void *a,const void *b,size_t n) { const uint8_t *x=a,*y=b; while(n--)if(*x++!=*y++)return 0; return 1; }
int same(const char *a,const char *b) { while(*a && *a==*b){a++;b++;} return *a==*b; }
void strcopy(char *d,size_t cap,const char *s) { size_t i=0; if(!cap)return; while(i+1<cap && s[i]){d[i]=s[i];i++;}d[i]=0; }
void logtext(const char *s) { while(*s && audit_len<sizeof(audit)-1)audit[audit_len++]=*s++;audit[audit_len]=0; }
void loghex(uint64_t n,unsigned digits) { char b[17]; if(digits>16)digits=16;for(unsigned i=0;i<digits;i++)b[i]="0123456789ABCDEF"[(n>>((digits-1-i)*4))&15];b[digits]=0;logtext(b); }
void logbytes(const uint8_t *p,size_t n) { for(size_t i=0;i<n;i++){if(i)logtext(" ");loghex(p[i],2);}logtext("\r\n"); }
uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
uint32_t u32(const uint8_t *p){return u16(p)|((uint32_t)u16(p+2)<<16);}
uint64_t u64(const uint8_t *p){return u32(p)|((uint64_t)u32(p+4)<<32);}
void result(const char *s){strcopy(report.result,sizeof(report.result),s);logtext("RESULT: ");logtext(s);logtext("\r\n");}
static int valid_config(const CONFIG *c){return c->magic==CFG_MAGIC && c->version==1 && c->enabled<=1 && !c->reserved[0] && !c->reserved[1];}
ES config_read(CONFIG *c){
    CONFIG v={0};UN n=sizeof(v);uint32_t attrs=0;
    *c=(CONFIG){CFG_MAGIC,1,1,{0,0}}; config_source=2;
    ES e=gST->rt->get_variable(W("HeroIpmiCfg"),&config_guid,&attrs,&n,&v);
    if(e==ERR(14)){config_source=0;return 0;} /* R2 firmware default enabled; no implicit NVRAM write. */
    if(FAILED(e))return e;
    if(n!=sizeof(v) || attrs!=3 || !valid_config(&v))return ERR(33);
    *c=v;config_source=1;return 0;
}
ES config_write(const CONFIG *c){
    if(!valid_config(c))return ERR(2);
    CONFIG old;ES e=config_read(&old);
    if(!FAILED(e) && config_source==1 && eq(&old,c,sizeof(old)))return 0;
    e=gST->rt->set_variable(W("HeroIpmiCfg"),&config_guid,3,sizeof(*c),(void *)c);
    if(FAILED(e))return e;
    e=config_read(&old);return FAILED(e)?e:config_source==1 && eq(&old,c,sizeof(old))?0:ERR(7);
}
/* Any present/malformed/unreadable lock blocks OEM writes. Deletion is explicit
 * or follows a completely verified success. RAM attempted also blocks repeats. */
ES lock_read(void){
    uint32_t v[2]={0};UN n=sizeof(v);uint32_t attrs=0;
    ES e=gST->rt->get_variable(W("HeroIpmiAttempt"),&config_guid,&attrs,&n,v);
    report.locked=e!=ERR(14);return e==ERR(14)?0:ERR(15);
}
ES lock_write(int set){
    uint32_t v[2]={LOCK_MAGIC,1};
    ES e=gST->rt->set_variable(W("HeroIpmiAttempt"),&config_guid,set?3:0,set?sizeof(v):0,set?v:0);
    if(!set && e==ERR(14))e=0;
    if(FAILED(e)){lock_read();return e;}
    if(set){
        uint32_t verify[2]={0},attrs=0;UN n=sizeof(verify);
        e=gST->rt->get_variable(W("HeroIpmiAttempt"),&config_guid,&attrs,&n,verify);
        report.locked=1;
        if(FAILED(e)||n!=sizeof(v)||attrs!=3||!eq(v,verify,sizeof(v)))return ERR(7);
        return 0;
    }
    return lock_read();
}
/* Separate latch: sensor success/lock clearing can never authorize DMI writes. */
ES dmi_lock_read(void){
 uint32_t v[2]={0},attrs=0;UN n=sizeof(v);
 ES e=gST->rt->get_variable(W("HeroIpmiDmiAttempt"),&config_guid,&attrs,&n,v);
 r3_report.dmi_locked=e!=ERR(14);return e==ERR(14)?0:ERR(15);
}
ES dmi_lock_write(int set){
 uint32_t v[2]={DMI_LOCK_MAGIC,1};
 ES e=gST->rt->set_variable(W("HeroIpmiDmiAttempt"),&config_guid,set?3:0,set?sizeof(v):0,set?v:0);
 if(!set&&e==ERR(14))e=0;
 if(e){dmi_lock_read();return e;}
 if(set){uint32_t check[2]={0},attrs=0;UN n=sizeof(check);
  e=gST->rt->get_variable(W("HeroIpmiDmiAttempt"),&config_guid,&attrs,&n,check);r3_report.dmi_locked=1;
  return !e&&n==sizeof(v)&&attrs==3&&eq(check,v,sizeof(v))?0:ERR(7);
 }return dmi_lock_read();
}
