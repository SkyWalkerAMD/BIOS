#include "r2.h"
uint32_t probe_crc32(const void *data,size_t n){
 const uint8_t *p=data;uint32_t crc=0xffffffffU;
 while(n--){crc^=*p++;for(unsigned k=0;k<8;k++)crc=(crc>>1)^(0xedb88320U & (0U-(crc&1)));}
 return ~crc;
}
