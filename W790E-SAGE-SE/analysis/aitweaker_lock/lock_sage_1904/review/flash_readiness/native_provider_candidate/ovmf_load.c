/* TCG-only loader fixture. Original OEM entry points are never started.
 * Read-only test disk; provider may read its missing OVMF variable but this
 * fixture never invokes enrollment, prompts or credential writes.
 */
#include "provider.h"
#include "ovmf_binding.h"
typedef struct FILEP FILEP;
struct FILEP{uint64_t revision;ES(EA *open)(FILEP *,FILEP **,C16 *,uint64_t,uint64_t);ES(EA *close)(FILEP *);void *del;ES(EA *read)(FILEP *,UN *,void *);};
typedef struct FS FS;
struct FS{uint64_t revision;ES(EA *open)(FS *,FILEP **);};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID provider_guid={0xf29d11ab,0xc12a,0x455a,{0x95,0xd3,0x9a,0x8e,0xcf,0x04,0x5c,0x04}};
static unsigned checks;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static void trace(const char *s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void hex(uint64_t n){const char h[]="0123456789abcdef";for(unsigned i=0;i<16;i++){char s[]={h[(n>>((15-i)*4))&15],0};trace(s);}}
static void finish(int ok){trace(ok?"NATIVE_PROVIDER_LOAD_OVMF_PASS\n":"NATIVE_PROVIDER_LOAD_OVMF_FAIL\n");__asm__ volatile("outl %0,%1"::"a"(ok?0x10u:0x11u),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *label){checks++;trace(ok?"PASS ":"FAIL ");trace(label);trace("\n");if(!ok)finish(0);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
static uint32_t crc32(const uint8_t *p,UN n){uint32_t c=~0u;while(n--){c^=*p++;for(unsigned i=0;i<8;i++)c=(c>>1)^(0xedb88320u&(0u-(c&1)));}return ~c;}
static int rt_valid(RT *rt){RT copy=*rt;uint32_t crc=copy.hdr.crc;copy.hdr.crc=0;return copy.hdr.size<=sizeof(copy)&&crc32((uint8_t *)&copy,copy.hdr.size)==crc;}
static void *read_file(ST *st,FILEP *root,C16 *name,UN expected,const uint8_t digest[32]){
 FILEP *f=0;void *p=0;check(!st->bs->allocate_pool(4,expected,&p)&&p,"allocate immutable input buffer");
 check(!root->open(root,&f,name,1,0)&&f,"open test image read-only");UN n=expected;check(!f->read(f,&n,p)&&n==expected,"read complete PE file");
 uint8_t extra;UN one=1;check(!f->read(f,&one,&extra)&&!one,"verify exact file EOF");check(!f->close(f),"close test image");
 uint8_t actual[32];ap_sha256(p,expected,actual);check(ap_constant_equal(actual,digest,32),"PE file SHA matches frozen candidate");return p;
}
static uint64_t attrs(void *p){
 uint64_t a=(uint64_t)(uintptr_t)p,cr3,cr4;__asm__ volatile("mov %%cr3,%0":"=r"(cr3));__asm__ volatile("mov %%cr4,%0":"=r"(cr4));
 uint64_t table=cr3&0x000ffffffffff000ULL;unsigned rw=1,nx=0;
 for(int level=(cr4&(1ULL<<12))?5:4;level;level--){
  uint64_t e=((uint64_t *)(uintptr_t)table)[(a>>(12+9*(level-1)))&511];if(!(e&1))return 0;
  rw&=(unsigned)((e>>1)&1);nx|=(unsigned)(e>>63);
  if(level==1||((level==2||level==3)&&(e&128)))return 1u|((uint64_t)rw<<1)|((uint64_t)nx<<2);
  table=e&0x000ffffffffff000ULL;
 }return 0;
}
ES EA efi_main(HANDLE image,ST *st){
 if(!tcg())return ERR(3);trace("NATIVE_PROVIDER_LOAD_OVMF_BEGIN\n");
 LOADED *self=0;FS *fs=0;FILEP *root=0;
 check(!st->bs->handle_protocol(image,&loaded_guid,(void **)&self)&&self,"find boot LoadedImage");
 check(!st->bs->handle_protocol(self->device,&fs_guid,(void **)&fs)&&fs,"find readonly filesystem");
 check(!fs->open(fs,&root)&&root,"open filesystem root");
 SETVAR original=st->rt->set_variable;uint32_t original_crc=st->rt->hdr.crc;check(rt_valid(st->rt),"original RuntimeServices CRC valid");
 HANDLE tse=0,setup=0,provider=0;void *buffer=read_file(st,root,U("\\TSE.EFI"),TSE_FILE_BYTES,tse_file_hash);
 ES status=st->bs->load_image(0,image,0,buffer,TSE_FILE_BYTES,&tse);trace("LOAD_TSE_STATUS=");hex(status);trace("\n");check(!status&&tse,"standard loader accepts modified AMITSE PE");st->bs->free_pool(buffer);
 buffer=read_file(st,root,U("\\SETUP.EFI"),SETUP_FILE_BYTES,setup_file_hash);
 status=st->bs->load_image(0,image,0,buffer,SETUP_FILE_BYTES,&setup);trace("LOAD_SETUP_STATUS=");hex(status);trace("\n");check(!status&&setup,"standard loader accepts modified Setup PE");st->bs->free_pool(buffer);
 LOADED *loaded=0;check(!st->bs->handle_protocol(tse,&loaded_guid,(void **)&loaded)&&loaded,"inspect relocated AMITSE image");
 uint8_t *base=loaded->image_base;check(loaded->image_size==TSE_IMAGE_BYTES,"AMITSE mapped image size matches");
 trace("TSE_GUARD_PAGE_ATTRS=");hex(attrs(base+TSE_GUARD_RVA));trace("\nTSE_CONTEXT_PAGE_ATTRS=");hex(attrs(base+TSE_CONTEXT_RVA));trace("\n");
 check(*(uint64_t *)(base+TSE_CONTEXT_RVA)==0,"new context head starts zero");
 /* Deliberately never StartImage(tse/setup); private OEM hardware/dependencies
  * are absent in OVMF. These are loader/relocation observations only. */
 buffer=read_file(st,root,U("\\PROVIDER.EFI"),PROVIDER_FILE_BYTES,provider_file_hash);
 check(!st->bs->load_image(0,image,0,buffer,PROVIDER_FILE_BYTES,&provider)&&provider,"standard loader accepts provider PE");st->bs->free_pool(buffer);
 check(!root->close(root),"close filesystem root");
 check(!st->bs->start_image(provider,0,0),"actual provider driver starts in OVMF");
 GATE_PROVIDER *p=0;check(!st->bs->locate_protocol(&provider_guid,0,(void **)&p)&&p,"provider protocol published");
 check(p->magic==PROVIDER_MAGIC&&p->revision==1&&p->size==56,"published ABI matches v1");
 check(p->query(p)==PROVIDER_READY,"missing credential remains unconfigured and locked");
 uint64_t token=0x1234;check(FAILED(p->begin(p,&token))&&!token,"foreign fixture caller cannot create browser owner");
 check(FAILED(p->request(p))&&FAILED(p->manage(p,0)),"out-of-session unlock and enrollment denied");
 check(st->rt->set_variable==original&&st->rt->hdr.crc==original_crc&&rt_valid(st->rt),"provider leaves RuntimeServices table unchanged");
 UN n=0,key=0,desc=0;uint32_t version=0;check(st->bs->memory_map(&n,0,&key,&desc,&version)==ERR(5),"size real memory map");
 n+=8192;UN capacity=n;void *map=0;check(!st->bs->allocate_pool(4,n,&map)&&map,"allocate map before EBS");
 ES(EA *exit_bs)(HANDLE,UN)=(void *)st->bs->exit_boot_services;
 for(unsigned attempt=0;attempt<3;attempt++){n=capacity;status=st->bs->memory_map(&n,map,&key,&desc,&version);if(FAILED(status))break;status=exit_bs(image,key);if(!status)break;}
 check(!status,"real ExitBootServices succeeds");
 /* No OS is launched or reclaims boot-service pages in this fixture. Only
  * this bounded local method is called after EBS; it must use no services. */
 check(p->query(p)==PROVIDER_ENDED,"real EBS notification revokes provider permanently");
 check(st->rt->set_variable==original&&st->rt->hdr.crc==original_crc&&rt_valid(st->rt),"RuntimeServices unchanged after handoff");
 trace("CHECKS=");hex(checks);trace("\n");finish(1);return 0;
}
