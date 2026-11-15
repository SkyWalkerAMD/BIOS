#include "r2.h"
ST *gST;
GUID config_guid=CFG_GUID_INIT,api_guid=API_GUID_INIT;
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
static void sm_string(const uint8_t *p,const uint8_t *end,uint8_t id,char *out,size_t cap){
    if(!id)return;
    for(unsigned i=1;p<end && *p;i++){
        const uint8_t *q=p;while(q<end && *q)q++;if(q==end)return;
        if(i==id){size_t n=q-p;if(n>=cap)n=cap-1;for(size_t j=0;j<n;j++)out[j]=p[j]>=32&&p[j]<127?(char)p[j]:'?';out[n]=0;return;}p=q+1;
    }
}
static int checksum(const uint8_t *p,size_t n){uint8_t s=0;while(n--)s+=*p++;return !s;}
void detect_board(void){
    static GUID s3={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
    static GUID s2={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}};
    const uint8_t *table=0;size_t length=0;report.board[0]=report.bios[0]=0;
    if(gST->table_count>1024)return;
    for(unsigned pass=0;pass<2&&!table;pass++)for(UN i=0;i<gST->table_count;i++){
        CT *t=&gST->tables[i];const uint8_t *p=t->table;if(!p)continue;
        if(!pass && eq(&t->guid,&s3,16) && eq(p,"_SM3_",5) && p[6]>=24 && p[6]<=64 && checksum(p,p[6])){table=(void *)(UN)u64(p+16);length=u32(p+12);break;}
        if(pass && eq(&t->guid,&s2,16) && eq(p,"_SM_",4) && p[5]>=31 && p[5]<=64 && checksum(p,p[5])){table=(void *)(UN)u32(p+24);length=u16(p+22);break;}
    }
    if(!table || length<6 || length>16*1024*1024 || (UN)table+length<(UN)table)return;
    const uint8_t *p=table,*end=table+length;
    while((size_t)(end-p)>=6){
        uint8_t type=p[0],size=p[1];if(size<4 || size>(size_t)(end-p)-2)break;
        const uint8_t *q=p+size;while(q+1<end && !(q[0]==0 && q[1]==0))q++;if(q+1>=end)break;
        if(type==0 && size>5 && !report.bios[0])sm_string(p+size,q+1,p[5],report.bios,sizeof(report.bios));
        if(type==2 && size>5 && !report.board[0])sm_string(p+size,q+1,p[5],report.board,sizeof(report.board));
        p=q+2;if(type==127)break;
    }
}
