#include "internal.h"
static const uint8_t setup_guid[16]={0xd7,0x07,0x94,0x89,0xfe,0x99,0xd8,0x43,0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21};
static const uint8_t forms_sha[32]={0x01,0x11,0xab,0xd4,0xe9,0x91,0x4a,0x32,0xb8,0x65,0xfc,0x95,0xaf,0x15,0x99,0x06,0x87,0xa9,0xd0,0x5f,0x98,0x4d,0xf5,0x33,0xc3,0x0e,0x02,0x8e,0x38,0xcb,0xba,0x2f};
uint32_t mp_u32(const uint8_t*p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
void mp_put32(uint8_t*p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(8*i));}
static uint16_t u16(const uint8_t*p){return p[0]|((uint16_t)p[1]<<8);}
static int string_max(const uint8_t*p,UN n,uint16_t*out){
 if(n<48||mp_u32(p+4)<47||mp_u32(p+4)>n||mp_u32(p+8)!=mp_u32(p+4))return 0;
 UN pos=mp_u32(p+8);uint32_t token=1;
 while(pos<n){
  UN begin=pos;uint8_t block=p[pos++];
  if(!block){if(pos!=n||token>65536)return 0;*out=(uint16_t)(token-1);return 1;}
  if(block>=0x14&&block<=0x17){
   if(block==0x15||block==0x17){if(pos==n)return 0;pos++;}
   uint32_t count=1;if(block==0x16||block==0x17){if(n-pos<2)return 0;count=u16(p+pos);pos+=2;if(!count)return 0;}
   if(count>65536-token)return 0;
   for(uint32_t i=0;i<count;i++){for(;;){if(n-pos<2)return 0;uint16_t c=u16(p+pos);pos+=2;if(!c)break;}}
   token+=count;
  }else if(block==0x20){if(n-pos<2||!u16(p+pos)||u16(p+pos)>=token||token==65536)return 0;pos+=2;token++;}
  else if(block==0x21||block==0x22){unsigned width=block==0x21?2:1;if(n-pos<width)return 0;uint32_t count=width==2?u16(p+pos):p[pos];if(count>65536-token)return 0;token+=count;pos+=width;}
  else if(block==0x30||block==0x31||block==0x32){
   unsigned width=block==0x30?1:block==0x31?2:4;if(n-begin<2+width)return 0;
   uint32_t size=width==1?p[begin+2]:width==2?u16(p+begin+2):mp_u32(p+begin+2);
   if(size<2+width||size>n-begin)return 0;pos=begin+size;
  }else return 0; /* Unknown encodings do not receive compatibility treatment. */
 }return 0;
}
int mp_package(const uint8_t*p,UN n,const uint8_t**forms,UN*form_size,uint16_t*max_token){
 *forms=0;*form_size=0;*max_token=0;
 if(!p||n<24||n>MP_MAX_PACKAGE||memcmp(p,setup_guid,16)||mp_u32(p+16)!=n)return 0;
 unsigned strings=0;
 for(UN pos=20;pos<n;){
  if(n-pos<4)return 0;uint32_t h=mp_u32(p+pos),size=h&0xffffff;unsigned kind=h>>24;
  if(size<4||size>n-pos)return 0;
  if(kind==2){if(*forms)return 0;*forms=p+pos;*form_size=size;}
  if(kind==4){uint16_t maximum=0;if(!string_max(p+pos,size,&maximum))return 0;if(maximum>*max_token)*max_token=maximum;strings++;}
  if(kind==0xdf)return size==4&&pos+size==n&&*forms&&strings&&strings<=MP_MAX_LANGUAGES;
  pos+=size;
 }return 0;
}
int mp_original_forms(const uint8_t*p,UN n){uint8_t digest[32];ap_sha256(p,n,digest);int ok=ap_constant_equal(digest,forms_sha,32);ap_secure_zero(digest,32);return ok;}
int mp_nonform_equal(const uint8_t*a,UN an,const uint8_t*b,UN bn){
 UN ai=20,bi=20;
 for(;;){
  if(an-ai<4||bn-bi<4)return 0;uint32_t ah=mp_u32(a+ai),bh=mp_u32(b+bi),az=ah&0xffffff,bz=bh&0xffffff;
  if(az<4||az>an-ai||bz<4||bz>bn-bi)return 0;
  if((ah>>24)==2){ai+=az;continue;}if((bh>>24)==2){bi+=bz;continue;}
  if(az!=bz||memcmp(a+ai,b+bi,az))return 0;
  if((ah>>24)==0xdf)return ai+az==an&&bi+bz==bn;ai+=az;bi+=bz;
 }
}
int mp_string_growth_only(const uint8_t*a,UN an,const uint8_t*b,UN bn){
 UN ai=20,bi=20;
 for(;;){
  if(an-ai<4||bn-bi<4)return 0;uint32_t ah=mp_u32(a+ai),bh=mp_u32(b+bi),az=ah&0xffffff,bz=bh&0xffffff;
  if(az<4||az>an-ai||bz<4||bz>bn-bi||(ah>>24)!=(bh>>24))return 0;
  if((ah>>24)==4){if(az<48||bz<az||a[ai+az-1]||memcmp(a+ai+4,b+bi+4,az-5))return 0;}
  else if(az!=bz||memcmp(a+ai,b+bi,az))return 0;
  if((ah>>24)==0xdf)return ai+az==an&&bi+bz==bn;ai+=az;bi+=bz;
 }
}
