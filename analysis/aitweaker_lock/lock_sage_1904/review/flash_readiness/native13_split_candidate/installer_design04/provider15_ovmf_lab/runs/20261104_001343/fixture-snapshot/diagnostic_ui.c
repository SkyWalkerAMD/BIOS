/* LOCAL QEMU TCG ONLY. Actual P15 diagnostics and real OVMF services; ASUS body is replaced by an explicit #DB fixture. No credential creation or hardware support. */
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
typedef struct{uint8_t type,sub;uint16_t size;GUID guid;uint8_t end[4];}FVDP;
static FVDP tse_path={4,6,20,{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}},{0x7f,0xff,4,0}};
static FVDP setup_path={4,6,20,{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}},{0x7f,0xff,4,0}};

static C16 credential_name[]=L"AiTweakerPassword1904";
static ST *st;static GATE_PROVIDER *provider;static unsigned checks,operation;
static const char *step_name;static uint8_t *tse_base,*setup_base;
static SPLIT_CONTEXT split_context;static SPLIT_STATE *split_state;
#include "diagnostic09.h"
#include "fixture_extra.inc"
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static void trace(const char *s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void hex(uint64_t n){const char h[]="0123456789abcdef";for(unsigned i=0;i<16;i++){char s[]={h[(n>>((15-i)*4))&15],0};trace(s);}}
static void finish(int ok){trace(ok?"P15_DIAGNOSTIC_OVMF_PASS\n":"P15_DIAGNOSTIC_OVMF_FAIL\n");__asm__ volatile("outl %0,%1"::"a"(ok?0x10u:0x11u),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
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

static uint64_t EA browser_body(void){
 check(provider->query(provider)==3,"real native wrapper owns locked session");
 trace("STEP_BEGIN ");trace(step_name);trace("\n");
 BROWSER_ACTION_REQUEST request=0;ES result;
 if(operation==0){
  result=form_browser->send_form(form_browser,&management_hii,1,&management_formset,1,0,&request);
  check(!result&&request==0,"real OVMF independent form returns NONE after Verify and ESC");
 }else{
  result=management_config->callback(management_config,0,0xffe2,0,0,&request);
  check(result==ERR(15)&&request==0,"actual independent Verify remains denied without credential");
 }
 check(provider->query(provider)==3,"unconfigured acknowledgement never grants session");
 trace("STEP_RETURN ");trace(step_name);trace(" ");hex(result);trace("\n");return 0x190411;
}
static void run_step(unsigned op,const char *name){
 operation=op;step_name=name;uint64_t(EA *loop)(void)=(void *)(tse_base+0xe1b8);
 uint64_t hits=debug_hits;debug_arm();check(loop()==0x190411,"native wrapper preserves declared body-stub result");debug_disarm();
 check(debug_hits==hits+1,"exactly one TCG body redirection per session");
 check(!split_state->ui_head&&!split_state->save_head,"real guard popped detached chains");
 check(provider->query(provider)==1,"outer end returns locked without owner");
 validate_text_identity();trace("STEP_DONE ");trace(name);trace("\n");
}
ES EA efi_main(HANDLE image,ST *table){
 if(!tcg())return ERR(3);st=table;trace("P15_DIAGNOSTIC_OVMF_BEGIN\n");
 UN initial=0;check(st->rt->get_variable(credential_name,&credential_guid,0,&initial,0)==ERR(14),"fresh real OVMF has no test credential");
 LOADED *self=0;FS *fs=0;FILEP *root=0;
 check(!st->bs->handle_protocol(image,&loaded_guid,(void **)&self)&&self,"boot LoadedImage available");
 check(!st->bs->handle_protocol(self->device,&fs_guid,(void **)&fs)&&fs,"readonly boot filesystem available");check(!fs->open(fs,&root)&&root,"open boot filesystem");
 GETVAR original_get=st->rt->get_variable;SETVAR original_set=st->rt->set_variable;uint32_t original_crc=st->rt->hdr.crc;check(rt_valid(st->rt),"real RuntimeServices table valid");
 HANDLE tse=0,setup=0,driver=0;void *buffer=read_file(root,U("\\TSE.EFI"),TSE_FILE_BYTES,tse_file_hash);
 check(!st->bs->load_image(0,image,&tse_path,buffer,TSE_FILE_BYTES,&tse)&&tse,"OVMF loads AMITSE with fixture FV identity path");st->bs->free_pool(buffer);
 buffer=read_file(root,U("\\SETUP.EFI"),SETUP_FILE_BYTES,setup_file_hash);check(!st->bs->load_image(0,image,&setup_path,buffer,SETUP_FILE_BYTES,&setup)&&setup,"OVMF loads Setup with fixture FV identity path");st->bs->free_pool(buffer);
 LOADED *li=0;check(!st->bs->handle_protocol(tse,&loaded_guid,(void **)&li)&&li&&li->image_size==TSE_IMAGE_BYTES,"relocated AMITSE size valid");tse_base=li->image_base;
 check(!st->bs->handle_protocol(setup,&loaded_guid,(void **)&li)&&li&&li->image_size==SETUP_IMAGE_BYTES,"relocated Setup original size valid");setup_base=li->image_base;
 prepare_split_fixture();
 DIAG09_REGION *diag=(void *)((uint8_t *)split_state+DIAG09_STATE_OFFSET);diag->magic=DIAG09_MAGIC;diag->revision=1;diag->bytes=sizeof(*diag);
 install_debug_fixture();
 buffer=read_file(root,U("\\PROVIDER.EFI"),PROVIDER_FILE_BYTES,provider_file_hash);check(!st->bs->load_image(0,image,0,buffer,PROVIDER_FILE_BYTES,&driver)&&driver,"OVMF loads exact frozen provider");st->bs->free_pool(buffer);check(!root->close(root),"close readonly filesystem");
 check(!st->bs->handle_protocol(driver,&loaded_guid,(void **)&li)&&li,"provider LoadedImage available");li->options_size=sizeof(split_context);li->options=&split_context;check(!st->bs->start_image(driver,0,0),"actual provider entry starts");check(!st->bs->locate_protocol(&provider_guid,0,(void **)&provider)&&provider,"actual provider published");check(provider->query(provider)==1,"cold provider starts locked without owner");locate_management();check(management_config->callback(management_config,0,0xffe2,0,0,0)==ERR(15),"management callback rejects no-owner invocation");

 run_step(0,"form_verify_one");
 trace("COUNTERS_AFTER_FIRST R=");hex(diag->request_count);trace(" P=");hex(diag->prompt_count);trace(" A=");hex(diag->ack_count);trace(" F=");hex(diag->flags);trace("\n");
 check(diag->request_count==1&&diag->prompt_count==1&&diag->ack_count==1&&!(diag->flags&DIAG09_FLAG_REQUEST_PENDING),"first real key acknowledgement and exact diagnostic counters");
 run_step(1,"direct_verify_two");
 check(diag->request_count==2&&diag->prompt_count==2&&diag->ack_count==2,"second request and ACK have distinct serial");
 /* Deliberate mutations of the private owned DIAGNOSTIC region only. They do
  * not alter grant/credential or OEM objects and never leave this local lab. */
 diag->flags|=DIAG09_FLAG_DROPPED_WRITER;
 run_step(2,"sticky_trace_unavailable");
 check(diag->request_count==3&&diag->prompt_count==3&&diag->ack_count==3,"sticky diagnostic loss preserves original denied UI and ACK");
 diag->magic^=1;
 run_step(3,"invalid_header_unavailable");
 check(diag->request_count==3&&diag->prompt_count==3&&diag->ack_count==3,"invalid diagnostic storage adds no counter write");
 diag->magic^=1;
 UN final_size=0;check(st->rt->get_variable(credential_name,&credential_guid,0,&final_size,0)==ERR(14),"credential remains absent after all diagnostic-only prompts");
 check(st->rt->get_variable==original_get&&st->rt->set_variable==original_set&&st->rt->hdr.crc==original_crc&&rt_valid(st->rt),"GetVariable and SetVariable were never replaced");
 uninstall_debug_fixture();check(split_state->phase==1,"split state stays ARMED before actual EBS");
 UN n=0,key=0,desc=0;uint32_t version=0;check(st->bs->memory_map(&n,0,&key,&desc,&version)==ERR(5),"size memory map");n+=8192;UN capacity=n;void *map=0;check(!st->bs->allocate_pool(4,n,&map)&&map,"allocate final map");
 ES(EA *exit_bs)(HANDLE,UN)=(void *)st->bs->exit_boot_services;ES status=ERR(2);
 for(unsigned i=0;i<3;i++){n=capacity;status=st->bs->memory_map(&n,map,&key,&desc,&version);if(FAILED(status))break;status=exit_bs(image,key);if(!status)break;}
 check(!status,"real ExitBootServices succeeds");check(provider->query(provider)==64,"real EBS permanently revokes provider");check(split_state->phase==3,"actual EBS retires split state to ENDED");trace("CHECKS=");hex(checks);trace("\n");finish(1);return 0;
}
