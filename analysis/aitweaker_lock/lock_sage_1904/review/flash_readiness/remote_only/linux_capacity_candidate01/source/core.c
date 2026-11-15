#include "core.h"
#include <stdio.h>
#include <string.h>
int lc_exact_line(const char *value,size_t n,const char *expected){
 if(!value||!expected)return 0;
 if(n&&value[n-1]=='\n')n--;
 return n==strlen(expected)&&!memcmp(value,expected,n);
}
int lc_identity(unsigned vid,unsigned pid,unsigned number,unsigned alt,unsigned eps,unsigned cls,unsigned sub,unsigned proto){
 return vid==LC_USB_VID&&pid==LC_USB_PID&&number==0&&alt==0&&eps==2&&cls==8&&sub==6&&proto==0x50;
}
int lc_response(int ret,unsigned st,unsigned mask,unsigned msg,unsigned host,unsigned driver,unsigned sense,int resid,unsigned info,int guards){
 return ret==0&&!st&&!mask&&!msg&&!host&&!driver&&!sense&&!resid&&!(info&1)&&guards;
}
int lc_retry_ua(int ret,unsigned st,unsigned mask,unsigned msg,unsigned host,unsigned driver,int resid,unsigned info,int guards,const uint8_t data[8],const uint8_t sense[32],unsigned n){
 static const uint8_t expected[32]={0x70,0,6,0,0,0,0,10,0,0,0,0,0x29,0,0,0,0,0};
 static const uint8_t zero[8]={0};
 return ret==0&&st==2&&mask==1&&!msg&&!host&&driver==8&&resid==8&&info==1&&guards==1&&n==18&&data&&sense&&!memcmp(data,zero,8)&&!memcmp(sense,expected,32);
}
int lc_capacity(const uint8_t d[8],uint32_t *last,uint32_t *block){
 if(!d||!last||!block)return 0;
 *last=((uint32_t)d[0]<<24)|((uint32_t)d[1]<<16)|((uint32_t)d[2]<<8)|d[3];
 *block=((uint32_t)d[4]<<24)|((uint32_t)d[5]<<16)|((uint32_t)d[6]<<8)|d[7];
 return *last!=0xffffffffU&&*block!=0;
}
uint32_t lc_crc32(const void *v,size_t n){const uint8_t *p=v;uint32_t c=~0U;while(n--){c^=*p++;for(unsigned i=0;i<8;i++)c=(c>>1)^(0xedb88320U&-(c&1));}return ~c;}
size_t lc_frame(const void *v,size_t n,void *out,size_t cap){
 if(!v||!out||!n||n>768)return 0;uint32_t crc=lc_crc32(v,n);char h[128];
 int k=snprintf(h,sizeof(h),"AITWK-P3-KVM\nT=%u;C=%08X;P=1/1;O=0;N=%u;D=%08X\n\n",(unsigned)n,crc,(unsigned)n,crc);
 if(k<0||(size_t)k>=sizeof(h)||(size_t)k+n>cap)return 0;memcpy(out,h,(size_t)k);memcpy((uint8_t *)out+k,v,n);return (size_t)k+n;
}
