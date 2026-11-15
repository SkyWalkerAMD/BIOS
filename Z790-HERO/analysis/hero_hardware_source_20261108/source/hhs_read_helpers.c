#include "hhs_common.h"
#include "hhs_read_abi.h"
static void copy_volatile(void *dest,const void *src,size_t n){
 uint8_t *d=dest;const volatile uint8_t *s=src;for(size_t i=0;i<n;i++)d[i]=s[i];
}
static int map_shape(const I4_MAP *map){
 return map&&map->data&&map->descriptor_bytes>=sizeof(I4_MD)&&map->descriptor_bytes<=256&&
 !(map->descriptor_bytes&7)&&map->bytes&&map->bytes<=I4_MAP_CAP&&
 !(map->bytes%map->descriptor_bytes)&&map->bytes/map->descriptor_bytes<=I4_MAP_ENTRIES;
}
int hhs_range_readable(const I4_MAP *map,const void *ptr,size_t n){
 uint64_t pos=(uintptr_t)ptr,end;if(!ptr||!n||!map_shape(map)||n>UINT64_MAX-pos)return 0;end=pos+n;
 for(size_t step=0;step<=map->bytes/map->descriptor_bytes;step++){
  uint64_t next=pos;
  for(size_t off=0;off<map->bytes;off+=map->descriptor_bytes){
   I4_MD d;memcpy(&d,map->data+off,sizeof(d));
   if(d.type<1||d.type>6||(d.attributes&0x2000U)||!d.pages||d.pages>(UINT64_MAX-d.physical)/4096)continue;
   uint64_t top=d.physical+d.pages*4096;
   if(d.physical<=pos&&top>next)next=top;
  }
  if(next==pos)return 0;if(next>=end)return 1;pos=next;
 }
 return 0;
}
ES hhs_path_copy(const I4_MAP *map,const uint8_t *src,uint8_t *dest,size_t *length){
 if(!length)return ERR(2);*length=0;if(!src||!dest||(uintptr_t)src>UINT64_MAX-I4_PATH_CAP)return ERR(2);
 size_t used=0;
 for(unsigned node=0;node<128;node++){
  uint8_t h[4];if(used>I4_PATH_CAP-4||!hhs_range_readable(map,src+used,4))return ERR(2);
  copy_volatile(h,src+used,4);size_t n=(size_t)h[2]|((size_t)h[3]<<8);
  if(n<4||n>I4_PATH_CAP-used||!hhs_range_readable(map,src+used,n))return ERR(4);
  copy_volatile(dest+used,src+used,n);
  if(!eq(h,dest+used,4))return ERR(13);
  used+=n;*length=used;
  if(h[0]==0x7f){if(n!=4||(h[1]!=1&&h[1]!=0xff))return ERR(4);if(h[1]==0xff)return 0;}
 }
 return ERR(4);
}
size_t hhs_media_bytes(uint64_t rev){if(rev<0x10000)return 0;return rev>=0x2001f?48:(rev>=0x20001?44:32);}
int hhs_media_fields_equal(uint64_t rev,const uint8_t *a,const uint8_t *b){
 size_t n=hhs_media_bytes(rev);if(!n||!a||!b)return 0;
 return eq(a,b,9)&&eq(a+12,b+12,8)&&eq(a+24,b+24,n-24);
}
