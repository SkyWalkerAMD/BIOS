#include "source/gzip.c"
#include "source/crc.c"
void *memcpy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *x=d;while(n--)*x++=(uint8_t)c;return d;}
uint16_t u16(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
uint32_t u32(const uint8_t *p){return u16(p)|(uint32_t)u16(p+2)<<16;}
