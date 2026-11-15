/* TCG-only P13 two-process persistence fixture. NOT the ASUS browser.
 * The provider PE and detached guards are pinned. OEM body bytes are unchanged;
 * an explicit #DB context fixture redirects execution to the body below.
 * GetVariable, SetVariable, HII database, FormBrowser2, console and GOP are real
 * OVMF services. The first enrollment is selected through the real HII form;
 * subsequent cases directly invoke that installed ConfigAccess callback.
 * The host supplies standard emulated-keyboard events through QMP.
 */
#include "split_owner.h"
#include "split_profile.h"
#include "management_package.h"
#include "binding.h"
typedef struct FILEP FILEP;
struct FILEP{uint64_t revision;ES(EA *open)(FILEP *,FILEP **,C16 *,uint64_t,uint64_t);ES(EA *close)(FILEP *);void *del;ES(EA *read)(FILEP *,UN *,void *);};
typedef struct FS FS;
struct FS{uint64_t revision;ES(EA *open)(FS *,FILEP **);};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID provider_guid={0x87e3c6fa,0x11fb,0x4e77,{0xaf,0x2d,0xea,0x50,0xb6,0x40,0xfa,0x13}};
static GUID credential_guid={0x750e9d9d,0xf2d8,0x4e14,{0x9b,0x53,0x89,0x23,0xa7,0x19,0x04,0x61}};
static GUID phase_guid={0x96bd3a18,0x453b,0x4e25,{0xb0,0x67,0x96,0x03,0x19,0x04,0x11,0x03}};
static GUID gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static C16 credential_name[]=L"AiTweakerPassword1904",phase_name[]=L"NativeProviderSimulationPhase";
typedef struct{uint8_t type,sub;uint16_t size;GUID guid;uint8_t end[4];}FVDP;
static FVDP tse_path={4,6,20,{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}},{0x7f,0xff,4,0}};
static FVDP setup_path={4,6,20,{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}},{0x7f,0xff,4,0}};
typedef struct{uint64_t magic;uint32_t phase,reserved;uint8_t digest[32];}PHASE;
static ST *st;
static GATE_PROVIDER *provider;
static unsigned checks,operation;
static const char *step_name;
static uint8_t *tse_base,*setup_base;
static SPLIT_CONTEXT split_context;
static SPLIT_STATE *split_state;
#include "fixture_extra.inc"
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static void trace(const char *s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void hex(uint64_t n){const char h[]="0123456789abcdef";for(unsigned i=0;i<16;i++){char s[]={h[(n>>((15-i)*4))&15],0};trace(s);}}
static void finish(int ok){trace(ok?"P13_UI_OVMF_PASS\n":"P13_UI_OVMF_FAIL\n");__asm__ volatile("outl %0,%1"::"a"(ok?0x10u:0x11u),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *label){checks++;trace(ok?"PASS ":"FAIL ");trace(label);trace("\n");if(!ok)finish(0);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
static uint32_t crc32(const uint8_t *p,UN n){uint32_t c=~0u;while(n--){c^=*p++;for(unsigned i=0;i<8;i++)c=(c>>1)^(0xedb88320u&(0u-(c&1)));}return ~c;}
static int rt_valid(RT *rt){RT copy=*rt;uint32_t crc=copy.hdr.crc;copy.hdr.crc=0;return copy.hdr.size<=sizeof(copy)&&crc32((uint8_t *)&copy,copy.hdr.size)==crc;}
static void *read_file(FILEP *root,C16 *name,UN expected,const uint8_t digest[32]){
 FILEP *f=0;void *p=0;check(!st->bs->allocate_pool(4,expected,&p)&&p,"allocate input buffer");
 check(!root->open(root,&f,name,1,0)&&f,"open immutable test image");UN n=expected;check(!f->read(f,&n,p)&&n==expected,"read complete PE file");
 uint8_t extra;UN one=1;check(!f->read(f,&one,&extra)&&!one,"exact file length");check(!f->close(f),"close test image");
 uint8_t actual[32];ap_sha256(p,expected,actual);check(ap_constant_equal(actual,digest,32),"PE SHA matches frozen input");return p;
}
static uint64_t attrs(void *p){
 uint64_t a=(uint64_t)(uintptr_t)p,cr3,cr4;__asm__ volatile("mov %%cr3,%0":"=r"(cr3));__asm__ volatile("mov %%cr4,%0":"=r"(cr4));
 uint64_t table=cr3&0x000ffffffffff000ULL;unsigned rw=1,nx=0;
 for(int level=(cr4&(1ULL<<12))?5:4;level;level--){uint64_t e=((uint64_t *)(uintptr_t)table)[(a>>(12+9*(level-1)))&511];if(!(e&1))return 0;rw&=(unsigned)((e>>1)&1);nx|=(unsigned)(e>>63);
  if(level==1||((level==2||level==3)&&(e&128)))return 1u|((uint64_t)rw<<1)|((uint64_t)nx<<2);table=e&0x000ffffffffff000ULL;
 }return 0;
}
static void record_check(uint64_t generation,int enabled,uint8_t digest[32]){
 uint8_t record[128],sum[32];UN n=sizeof(record);uint32_t a=0;
 check(!st->rt->get_variable(credential_name,&credential_guid,&a,&n,record)&&n==128&&a==3,"real NVRAM record length and NV-BS attributes");
 uint64_t gen=0;uint32_t flags=0;memcpy(&gen,record+24,8);memcpy(&flags,record+12,4);
 check(gen==generation&&flags==(uint32_t)enabled,"real record generation and enabled state");
 ap_sha256(record,96,sum);check(ap_constant_equal(sum,record+96,32),"real record checksum valid");ap_sha256(record,128,digest);ap_secure_zero(record,sizeof(record));
}
static void framebuffer_hash(GOP *gop,uint8_t digest[32]){
 check(gop&&gop->mode&&gop->mode->info&&gop->blt,"real GOP available for restoration check");
 UN w=gop->mode->info->width,h=gop->mode->info->height;check(w&&h&&w<=8192&&h<=4320,"bounded real framebuffer dimensions");
 void *pixels=0;UN bytes=w*h*4;check(!st->bs->allocate_pool(4,bytes,&pixels)&&pixels,"allocate framebuffer observation buffer");
 check(!gop->blt(gop,pixels,BLT_VIDEO_TO_BUFFER,0,0,0,0,w,h,0),"read actual GOP pixels");ap_sha256(pixels,bytes,digest);check(!st->bs->free_pool(pixels),"release observation buffer");
}
static uint64_t EA browser_body(void){
 uint32_t expected=operation==8?15:3;
 check(provider->query(provider)==expected,"real native wrapper owns expected locked session");
 int inspect=operation==5;GOP *gop=0;OUTMODE previous={0};uint8_t before_pixels[32],after_pixels[32];
 if(inspect){
  /* Observe the console as supplied, without requiring all ConSplitter
   * children to implement EnableCursor (the initial probe returned an error).
   * The exact pixel comparison below still fails if pixels are not restored. */
  previous=*st->out->mode;trace("CURSOR_VISIBLE_BEFORE=");hex(previous.cursor);trace("\n");
  check(!st->bs->locate_protocol(&gop_guid,0,(void **)&gop),"locate real GOP for restoration");framebuffer_hash(gop,before_pixels);
 }
 trace("STEP_BEGIN ");trace(step_name);trace("\n");
 ES result=0;
 if(operation==0){BROWSER_ACTION_REQUEST request=~0ULL;result=form_browser->send_form(form_browser,&management_hii,1,&management_formset,1,0,&request);trace("FORM_BROWSER_RETURN ");hex(result);trace(" ACTION ");hex(request);trace("\n");check(!result,"real HII management form exits successfully");}
 else if(operation!=8){BROWSER_ACTION_REQUEST request=~0ULL;uint16_t id=operation==3?0xffe0:operation==7?0xffe1:0xffe2;result=management_config->callback(management_config,0,id,0,0,&request);check(request==0,"actual independent HII callback sets request NONE");}
 trace("STEP_RETURN ");trace(step_name);trace(" ");hex(result);trace(" FLAGS ");hex(provider->query(provider));trace("\n");
 if(operation==1||operation==4||operation==6)check(FAILED(result)&&provider->query(provider)==3,"wrong password or cancel leaves session locked");
 else if(operation==0||operation==3)check(!result&&provider->query(provider)==3,"management return does not auto-unlock; record is checked after session");
 else if(operation==2||operation==5)check(!result&&provider->query(provider)==7,"correct password grants only current native session");
 else check(!result&&provider->query(provider)==15,"explicit clear selects disabled mode");
 if(inspect){
  OUTMODE *m=st->out->mode;check(m->mode==previous.mode&&m->attribute==previous.attribute&&m->column==previous.column&&m->row==previous.row&&m->cursor==previous.cursor,"console mode attributes cursor position and visibility restored");
  framebuffer_hash(gop,after_pixels);check(ap_constant_equal(before_pixels,after_pixels,32),"full real GOP framebuffer restored byte-for-byte");
  trace("RESTORE_CAPTURE_BEGIN ");trace(step_name);trace("\n");st->bs->stall(1000000);trace("RESTORE_CAPTURE_END\n");
 }
 return 0x190411;
}
static void run_step(unsigned op,const char *name){
 operation=op;step_name=name;uint64_t(EA *loop)(void)=(void *)(tse_base+0xe1b8);
 uint64_t hits=debug_hits;debug_arm();check(loop()==0x190411,"native wrapper preserves declared body-stub result");debug_disarm();check(debug_hits==hits+1,"exactly one TCG debug redirection per owned session");
 check(split_state->ui_head==0&&split_state->save_head==0,"real split guard popped both detached chains");
 check(provider->query(provider)==((op==7||op==8)?9u:1u),"outer end revokes owned session and grant");
 trace("STEP_DONE ");trace(name);trace("\n");
}
static void cooldown(void){trace("COOLDOWN_BEGIN\n");check(!st->bs->stall(6000000),"real firmware cooldown delay");trace("COOLDOWN_END\n");}
ES EA efi_main(HANDLE image,ST *table){
 if(!tcg())return ERR(3);st=table;trace("P13_UI_OVMF_BEGIN\n");
 PHASE phase={0};UN phase_bytes=sizeof(phase);uint32_t phase_attrs=0;ES prior=st->rt->get_variable(phase_name,&phase_guid,&phase_attrs,&phase_bytes,&phase);
 check(prior==ERR(14)||(!prior&&phase_bytes==sizeof(phase)&&phase_attrs==3&&phase.magic==0x1904114e56504d56ULL&&phase.phase==1),"fresh or first-boot completion marker");
 unsigned boot=prior==ERR(14)?1:2;trace("BOOT_PHASE ");hex(boot);trace("\n");
 if(boot==1){UN n=0;check(st->rt->get_variable(credential_name,&credential_guid,0,&n,0)==ERR(14),"first boot has no credential");}
 else{uint8_t digest[32];record_check(2,1,digest);check(ap_constant_equal(digest,phase.digest,32),"credential bytes persist identically across separate QEMU boots");}
 LOADED *self=0;FS *fs=0;FILEP *root=0;
 check(!st->bs->handle_protocol(image,&loaded_guid,(void **)&self)&&self,"boot LoadedImage available");
 check(!st->bs->handle_protocol(self->device,&fs_guid,(void **)&fs)&&fs,"readonly boot filesystem available");check(!fs->open(fs,&root)&&root,"open boot filesystem");
 GETVAR original_get=st->rt->get_variable;SETVAR original_set=st->rt->set_variable;uint32_t original_crc=st->rt->hdr.crc;check(rt_valid(st->rt),"real RuntimeServices table valid");
 HANDLE tse=0,setup=0,driver=0;void *buffer=read_file(root,U("\\TSE.EFI"),TSE_FILE_BYTES,tse_file_hash);
 check(!st->bs->load_image(0,image,&tse_path,buffer,TSE_FILE_BYTES,&tse)&&tse,"OVMF loads AMITSE with fixture FV identity path");st->bs->free_pool(buffer);
 buffer=read_file(root,U("\\SETUP.EFI"),SETUP_FILE_BYTES,setup_file_hash);check(!st->bs->load_image(0,image,&setup_path,buffer,SETUP_FILE_BYTES,&setup)&&setup,"OVMF loads Setup with fixture FV identity path");st->bs->free_pool(buffer);
 LOADED *li=0;check(!st->bs->handle_protocol(tse,&loaded_guid,(void **)&li)&&li&&li->image_size==TSE_IMAGE_BYTES,"relocated AMITSE size valid");tse_base=li->image_base;
 check(!st->bs->handle_protocol(setup,&loaded_guid,(void **)&li)&&li&&li->image_size==SETUP_IMAGE_BYTES,"relocated Setup original size valid");setup_base=li->image_base;
 prepare_split_fixture();install_debug_fixture();
 buffer=read_file(root,U("\\PROVIDER.EFI"),PROVIDER_FILE_BYTES,provider_file_hash);check(!st->bs->load_image(0,image,0,buffer,PROVIDER_FILE_BYTES,&driver)&&driver,"OVMF loads exact frozen provider");st->bs->free_pool(buffer);check(!root->close(root),"close readonly filesystem");
 check(!st->bs->handle_protocol(driver,&loaded_guid,(void **)&li)&&li,"provider LoadedImage available");li->options_size=sizeof(split_context);li->options=&split_context;check(!st->bs->start_image(driver,0,0),"actual provider entry starts");check(!st->bs->locate_protocol(&provider_guid,0,(void **)&provider)&&provider,"actual provider published");check(provider->query(provider)==1,"cold provider starts locked without owner");locate_management();check(management_config->callback(management_config,0,0xffe2,0,0,0)==ERR(15),"management callback rejects no-owner invocation");
 uint8_t digest[32];
 if(boot==1){
  run_step(0,"enroll_a");record_check(1,1,digest);
  run_step(1,"wrong_a");cooldown();run_step(2,"unlock_a");
  run_step(3,"change_to_b");record_check(2,1,digest);
  phase.magic=0x1904114e56504d56ULL;phase.phase=1;memcpy(phase.digest,digest,32);
 }else{
  run_step(4,"old_a_rejected");cooldown();run_step(5,"unlock_b");run_step(6,"cancel_b");
  run_step(7,"clear_b");record_check(3,0,digest);run_step(8,"disabled_next_session");phase.phase=2;
 }
 check(!st->rt->set_variable(phase_name,&phase_guid,3,sizeof(phase),&phase),"real NVRAM completion marker saved");
 check(st->rt->get_variable==original_get&&st->rt->set_variable==original_set&&st->rt->hdr.crc==original_crc&&rt_valid(st->rt),"GetVariable and SetVariable were never replaced");
 uninstall_debug_fixture();check(split_state->phase==1,"split state stays ARMED before actual EBS");
 UN n=0,key=0,desc=0;uint32_t version=0;check(st->bs->memory_map(&n,0,&key,&desc,&version)==ERR(5),"size memory map");n+=8192;UN capacity=n;void *map=0;check(!st->bs->allocate_pool(4,n,&map)&&map,"allocate final map");
 ES(EA *exit_bs)(HANDLE,UN)=(void *)st->bs->exit_boot_services;ES status=ERR(2);
 for(unsigned i=0;i<3;i++){n=capacity;status=st->bs->memory_map(&n,map,&key,&desc,&version);if(FAILED(status))break;status=exit_bs(image,key);if(!status)break;}
 check(!status,"real ExitBootServices succeeds");check(provider->query(provider)==64,"real EBS permanently revokes provider");check(split_state->phase==3,"actual EBS retires split state to ENDED");trace("CHECKS=");hex(checks);trace("\n");finish(1);return 0;
}
