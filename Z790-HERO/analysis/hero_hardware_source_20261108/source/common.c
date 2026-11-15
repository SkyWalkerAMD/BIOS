#include "hhs_common.h"
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
uint32_t probe_crc32(const void *data,size_t n){
 const uint8_t *p=data;uint32_t crc=0xffffffffU;
 while(n--){crc^=*p++;for(unsigned k=0;k<8;k++)crc=(crc>>1)^(0xedb88320U&(0U-(crc&1)));}return ~crc;
}
