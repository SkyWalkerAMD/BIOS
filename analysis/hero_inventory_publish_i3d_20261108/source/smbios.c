/* Bounded raw SMBIOS parsing only. No UEFI services or hardware access. */
#include "smbios_bounded.h"
static uint16_t r16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t r32(const uint8_t *p){return r16(p)|((uint32_t)r16(p+2)<<16);}
static uint64_t r64(const uint8_t *p){return r32(p)|((uint64_t)r32(p+4)<<32);}
static int sum0(const uint8_t *p,size_t n){uint8_t sum=0;while(n--)sum+=*p++;return !sum;}
int smbios_entry(const uint8_t *p,size_t n,unsigned kind,SM_ENTRY *e){
 if(!p||!e)return SM_ARGUMENT;memset(e,0,sizeof(*e));e->kind=kind;
 if(kind==3){
  if(n<24)return SM_LENGTH;
  if(!eq(p,"_SM3_",5))return SM_ANCHOR;
  if(p[6]<24||p[6]>64||p[6]>n)return SM_LENGTH;
  if(!sum0(p,p[6]))return SM_CHECKSUM;
  e->length=p[6];e->major=p[7];e->minor=p[8];e->docrev=p[9];
  e->bound=r32(p+12);e->address=r64(p+16);
 }else if(kind==2){
  if(n<31)return SM_LENGTH;
  if(!eq(p,"_SM_",4)||!eq(p+16,"_DMI_",5))return SM_ANCHOR;
  if(p[5]<31||p[5]>64||p[5]>n)return SM_LENGTH;
  if(!sum0(p,p[5])||!sum0(p+16,15))return SM_CHECKSUM;
  e->length=p[5];e->major=p[6];e->minor=p[7];
  e->bound=r16(p+22);e->address=r32(p+24);e->count=r16(p+28);
 }else return SM_ARGUMENT;
 if(!e->address||e->address+e->bound<e->address)return SM_ADDRESS;
 if(e->bound<6||e->bound>TABLE_CAP)return SM_TOO_LARGE;
 if(kind==2&&!e->count)return SM_COUNT;
 return SM_OK;
}
int smbios_table(const uint8_t *p,size_t n,unsigned expected,SM_TABLE *m){
 if(!p||!m||n<6||n>TABLE_CAP)return SM_ARGUMENT;
 memset(m,0,sizeof(*m));size_t at=0;
 while(at<n){
  if(n-at<6)return SM_HEADER;
  unsigned type=p[at],len=p[at+1];
  if(len<4||len>n-at-2)return SM_HEADER;
  size_t end=at+len;
  while(end+1<n&&(p[end]||p[end+1]))end++;
  if(end+1>=n)return SM_STRING_END;
  end+=2;m->count++;m->types[type]++;
  if(type==127){
   if(len!=4)return SM_HEADER;
   m->used=(uint32_t)end;m->end_offset=(uint32_t)at;
   if(expected&&m->count!=expected)return SM_COUNT;
   m->crc=probe_crc32(p,end);return SM_OK;
  }
  at=end;
 }
 return SM_MISSING_END;
}
