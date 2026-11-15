#include "r2.h"
ST *gST;char audit[LOG_CAP];UN audit_len;unsigned audit_bad;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int same(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
void logn(const char *s,size_t n){if(n>sizeof(audit)-1-audit_len){audit_bad=1;return;}memcpy(audit+audit_len,s,n);audit_len+=n;audit[audit_len]=0;}
void logtext(const char *s){size_t n=0;while(s[n])n++;logn(s,n);}
void loghex(uint64_t n,unsigned digits){char b[16];if(digits>16)digits=16;for(unsigned i=0;i<digits;i++)b[i]="0123456789ABCDEF"[(n>>((digits-1-i)*4))&15];logn(b,digits);}
void logbytes(const uint8_t *p,size_t n){for(size_t i=0;i<n;i++)loghex(p[i],2);logtext("\r\n");}
uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
uint32_t u32(const uint8_t *p){return u16(p)|((uint32_t)u16(p+2)<<16);}
uint64_t u64(const uint8_t *p){return u32(p)|((uint64_t)u32(p+4)<<32);}
void say(const char *s){if(!gST||!gST->out||!gST->out->out)return;C16 b[160];while(*s){unsigned n=0;while(*s&&n<159)b[n++]=(uint8_t)*s++;b[n]=0;gST->out->out(gST->out,b);}}
void status(const char *s,ES e){logtext(s);logtext("=0x");loghex(e,16);logtext("\r\n");char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[16]=0;say(s);say("=0x");say(b);say("\r\n");}
