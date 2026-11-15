/* TCG-only execution of the exact compiled TX08 validator after real LoadImage.
 * Neither imported EFI entrypoint is started. Negative mutations affect only
 * an owned, aligned, correctly rebased copy of the loaded provider image.
 */
#include "efi.h"
#include "password_core.h"
#include "payloads.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static unsigned checks;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static void out(const char *s){while(*s)__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s++),"Nd"((uint16_t)0x402));}
static void number(const char *s,uint64_t n){out(s);out("=");const char hex[]="0123456789abcdef";for(int i=15;i>=0;i--){char c[2]={hex[(n>>(i*4))&15],0};out(c);}out("\n");}
static void finish(unsigned n){__asm__ volatile("outl %0,%1"::"a"(n),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *s){checks++;out(ok?"PASS ":"FAIL ");out(s);out("\n");if(!ok)finish(0x11);}
static LOADED *load(ST *st,HANDLE image,const uint8_t *file,UN bytes){
 HANDLE handle=0;ES status=st->bs->load_image(0,image,0,(void *)file,bytes,&handle);
 check(!status&&handle,"standard OVMF LoadImage succeeds");LOADED *li=0;
 status=st->bs->handle_protocol(handle,&loaded_guid,(void **)&li);check(!status&&li,"real loaded image protocol");return li;
}
static uint64_t q(const uint8_t *p){uint64_t n;memcpy(&n,p,8);return n;}
ES EA efi_main(HANDLE image,ST *st){
 uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));
 if(b!=0x54474354||c!=0x43544743||d!=0x47435447)return ERR(3);
 out("ACTUAL_PLATFORM_VALIDATOR_BEGIN\n");
 LOADED *app=load(st,image,app_file,sizeof(app_file));LOADED *provider=load(st,image,provider_file,sizeof(provider_file));
 check(app->image_size==APP_IMAGE_BYTES&&provider->image_size==PROVIDER_IMAGE_BYTES,"both exact SizeOfImage values");
 uint8_t *app_base=app->image_base,*provider_base=provider->image_base;
 *(ST **)(app_base+RVA_APP_ST)=st;*(ST **)(app_base+RVA_SYSTEM_TABLE)=st;
 int(EA *read_env)(void *)=(void *)(app_base+RVA_READ_CPU_ENV);
 int(EA *refresh)(void)=(void *)(app_base+RVA_REFRESH_MAP);
 int(EA *validate)(LOADED *)=(void *)(app_base+RVA_PROVIDER_BEFORE_START);
 check(read_env(app_base+RVA_ENVIRONMENT),"actual app read_cpu_env on real OVMF CPU");
 check(refresh(),"actual app refresh_map on real OVMF map");
 check(validate(provider),"actual compiled validator accepts standard loaded P14");
 uint8_t before[32],after[32];ap_sha256(provider_base,PROVIDER_IMAGE_BYTES,before);
 uint64_t allocation=0;ES status=st->bs->allocate_pages(0,4,PROVIDER_IMAGE_BYTES/4096,&allocation);
 check(!status&&allocation&&!(allocation&4095),"owned aligned negative-test copy allocation");
 uint8_t *copy=(void *)(uintptr_t)allocation;memcpy(copy,provider_base,PROVIDER_IMAGE_BYTES);
 uint64_t delta=allocation-(uintptr_t)provider_base;
 for(UN i=0;i<sizeof(relocs)/sizeof(*relocs);i++){uint64_t value=q(copy+relocs[i])+delta;memcpy(copy+relocs[i],&value,8);}
 memcpy(copy+PROVIDER_IMAGEBASE_FIELD,&allocation,8);LOADED clone=*provider;clone.image_base=copy;
 check(refresh(),"actual app memory map refreshed for owned test copy");
 check(validate(&clone),"same validator accepts correctly rebased owned copy");
 uint64_t preferred=PROVIDER_PREFERRED_BASE;memcpy(copy+PROVIDER_IMAGEBASE_FIELD,&preferred,8);
 check(validate(&clone),"documented preferred header ImageBase accepted");
 uint64_t bad=preferred+4096;memcpy(copy+PROVIDER_IMAGEBASE_FIELD,&bad,8);
 check(!validate(&clone),"unexpected header ImageBase rejected");memcpy(copy+PROVIDER_IMAGEBASE_FIELD,&allocation,8);
 for(UN i=0;i<sizeof(active_offsets)/sizeof(*active_offsets);i++){
  uint32_t at=active_offsets[i];uint8_t old=copy[at];copy[at]^=1;number("ActiveMutationRva",at);
  check(!validate(&clone),"declared header section or BSS mutation rejected");copy[at]=old;
  check(validate(&clone),"declared content exact restoration accepted");
 }
 for(UN i=0;i<sizeof(relocs)/sizeof(*relocs);i++){
  uint32_t at=relocs[i];copy[at]^=1;number("Dir64MutationRva",at);
  check(!validate(&clone),"individual original DIR64 target mutation rejected");copy[at]^=1;
  check(validate(&clone),"DIR64 exact restoration accepted");
 }
 for(UN i=0;i<sizeof(padding_offsets)/sizeof(*padding_offsets);i++){
  uint32_t at=padding_offsets[i];uint8_t old=copy[at];copy[at]^=0x5a;number("PaddingMutationRva",at);
  check(validate(&clone),"undefined alignment or raw-tail padding ignored");copy[at]=old;
 }
 clone.image_size+=4096;check(!validate(&clone),"wrong loaded image size rejected");clone.image_size-=4096;
 clone.image_base=copy+1;check(!validate(&clone),"unaligned loaded base rejected");clone.image_base=copy;
 check(validate(provider),"original unmodified standard loaded P14 still accepted");
 ap_sha256(provider_base,PROVIDER_IMAGE_BYTES,after);check(ap_constant_equal(before,after,32),"entire originally loaded P14 image unchanged");
 number("Checks",checks);out("IMPORTED_APP_START_IMAGE_CALLS=0\nPROVIDER_START_IMAGE_CALLS=0\nACTUAL_PLATFORM_VALIDATOR_COMPLETE\n");finish(0x10);return 0;
}
