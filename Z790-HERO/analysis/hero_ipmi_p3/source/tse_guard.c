#include "tse_audit.h"
/* EFI_MEMORY_DESCRIPTOR: Type + pad, PhysicalStart, VirtualStart,
 * NumberOfPages, Attribute. Only allocated firmware/loader memory is read. */
int tse_readable(const uint8_t *map,size_t bytes,size_t stride,uint64_t address,uint64_t length){
 if(!map||stride<40||stride>256||!bytes||bytes%stride||bytes/stride>16384||
    !address||!length||address>0x7fffffffffffULL||length>0x800000000000ULL-address)return 0;
 uint64_t end=address+length;size_t steps=0;
 while(address<end){
  uint64_t next=address;
  for(size_t p=0;p<bytes;p+=stride){
   const uint8_t *d=map+p;uint32_t type=u32(d);uint64_t start=u64(d+8),pages=u64(d+24);
   if(type<1||type>6||!pages||start&4095||pages>(UINT64_MAX-start)/4096)continue;
   uint64_t stop=start+pages*4096;
   if(address>=start&&address<stop){next=stop<end?stop:end;break;}
  }
  if(next==address||++steps>bytes/stride)return 0;
  address=next;
 }
 return 1;
}
