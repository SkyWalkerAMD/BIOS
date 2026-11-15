#include "p1.h"
char values[V_COUNT][160];
ES last_refresh=ERR(6);
void value_text(unsigned i,const char *s){if(i<V_COUNT)strcopy(values[i],160,s);}
void value_hex(unsigned i,uint64_t n,unsigned width){
 char s[19]="0x";if(width>16)width=16;
 for(unsigned j=0;j<width;j++)s[j+2]="0123456789ABCDEF"[(n>>((width-1-j)*4))&15];s[width+2]=0;value_text(i,s);
}
void value_dec(unsigned i,uint32_t n){
 char s[11];unsigned j=10;s[j]=0;do{s[--j]=(char)('0'+n%10);n/=10;}while(n);value_text(i,s+j);
}
void value_ip(unsigned i,const uint8_t *p){
 char s[16];unsigned n=0;
 for(unsigned j=0;j<4;j++){
  if(j)s[n++]='.';unsigned v=p[j];if(v>=100)s[n++]=(char)('0'+v/100);
  if(v>=10)s[n++]=(char)('0'+v/10%10);s[n++]=(char)('0'+v%10);
 }s[n]=0;value_text(i,s);
}
