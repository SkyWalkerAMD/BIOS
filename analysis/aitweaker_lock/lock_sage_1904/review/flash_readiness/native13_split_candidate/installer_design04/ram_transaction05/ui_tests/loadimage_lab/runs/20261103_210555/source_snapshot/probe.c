/* TCG-only, LoadImage-only fixture. Never StartImage P13 and never deploy. */
#include "efi.h"
#include "password_core.h"
#include "provider_asset.h"
#include "canonical.h"
static uint8_t normalized[PROVIDER_IMAGE_BYTES];
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static void out(const char *s){while(*s)__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s++),"Nd"((uint16_t)0x402));}
static void number(const char *s,uint64_t n){out(s);out("=");const char hex[]="0123456789abcdef";for(int i=15;i>=0;i--){char c[2]={hex[(n>>(i*4))&15],0};out(c);}out("\n");}
static void hash(const char *s,const uint8_t *p,UN n){uint8_t h[32];ap_sha256(p,n,h);out(s);out("=");const char hex[]="0123456789abcdef";for(unsigned i=0;i<32;i++){char c[3]={hex[h[i]>>4],hex[h[i]&15],0};out(c);}out("\n");}
static void finish(unsigned n){__asm__ volatile("outl %0,%1"::"a"(n),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static uint64_t q(const uint8_t *p){uint64_t n;memcpy(&n,p,8);return n;}
static uint32_t d(const uint8_t *p){uint32_t n;memcpy(&n,p,4);return n;}
ES EA efi_main(HANDLE image,ST *st){
 uint32_t a,b,c,e;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(e):"a"(0x40000000),"c"(0));
 if(b!=0x54474354||c!=0x43544743||e!=0x47435447)return ERR(3);
 out("LOADIMAGE_IDENTITY_BEGIN\n");HANDLE driver=0;
 ES status=st->bs->load_image(0,image,0,(void *)provider_file,sizeof(provider_file),&driver);number("LoadImageStatus",status);
 if(status||!driver)finish(0x11);
 LOADED *li=0;status=st->bs->handle_protocol(driver,&loaded_guid,(void **)&li);number("HandleProtocolStatus",status);
 if(status||!li||li->image_size!=PROVIDER_IMAGE_BYTES)finish(0x11);
 uint8_t *p=li->image_base;uint32_t pe=d(p+0x3c);if(pe<0x40||pe>0x800)finish(0x11);
 number("LoadedBase",(uintptr_t)p);number("HeaderImageBase",q(p+pe+48));number("PreferredBase",PROVIDER_PREFERRED_BASE);number("SizeOfImage",li->image_size);
 hash("RawLoadedSha256",p,PROVIDER_IMAGE_BYTES);memcpy(normalized,p,PROVIDER_IMAGE_BYTES);
 uint64_t delta=(uintptr_t)p-PROVIDER_PREFERRED_BASE;
 for(UN i=0;i<sizeof(provider_relocs)/sizeof(*provider_relocs);i++){
  uint32_t at=provider_relocs[i];if(at>PROVIDER_IMAGE_BYTES-8)finish(0x11);
  uint64_t value=q(normalized+at)-delta;memcpy(normalized+at,&value,8);
 }
 number("Dir64Count",sizeof(provider_relocs)/sizeof(*provider_relocs));hash("InverseDir64Sha256",normalized,PROVIDER_IMAGE_BYTES);
 UN diff=0,outside=0;for(UN i=0;i<PROVIDER_IMAGE_BYTES;i++)if(normalized[i]!=canonical[i]){
  if(diff<32){number("DiffOffset",i);number("DiffActual",normalized[i]);number("DiffExpected",canonical[i]);}
  diff++;if(i<pe+48||i>=pe+56)outside++;
 }
 number("DifferentBytes",diff);number("DifferencesOutsideImageBase",outside);
 uint64_t preferred=PROVIDER_PREFERRED_BASE;memcpy(normalized+pe+48,&preferred,8);
 hash("InverseDir64AndImageBaseSha256",normalized,PROVIDER_IMAGE_BYTES);
 number("HeaderNormalizedMatches",ap_constant_equal(normalized,canonical,PROVIDER_IMAGE_BYTES));
 out("PROVIDER_START_IMAGE_CALLS=0\nLOADIMAGE_IDENTITY_COMPLETE\n");finish(0x10);return 0;
}
