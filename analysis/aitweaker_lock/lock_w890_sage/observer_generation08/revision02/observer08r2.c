#include "F:/OpenAI/Codex/project/BIOS/analysis/aitweaker_lock/lock_w890_sage/observer_generation08/visit/restricted_profile.h"
#include "F:/OpenAI/Codex/project/BIOS/analysis/aitweaker_lock/lock_w890_sage/password/w890_policy.h"
#include "F:/OpenAI/Codex/project/BIOS/analysis/aitweaker_lock/lock_w890_sage/native_observer04/profile_windows.h"
#include "F:/OpenAI/Codex/project/BIOS/analysis/aitweaker_lock/lock_w890_sage/installer04/source/memory.h"
#define API __attribute__((noinline))
#define RETADDR ((uintptr_t)__builtin_return_address(0))
#define MAP_CAP (128u*1024u)
#define PKG_CAP (8u*1024u*1024u)
#define FORMS_CAP 199508u
#define TEXT_CAP 597466u
#define ST_SIG UINT64_C(0x5453595320494249)
#define BS_SIG UINT64_C(0x56524553544f4f42)
typedef ES(EA *HNOTIFY)(uint8_t,GUID *,void *,HANDLE,UN);
typedef ES(EA *HREGISTER)(HII *,uint8_t,GUID *,HNOTIFY,UN,HANDLE *);
typedef ES(EA *HUNREGISTER)(HII *,HANDLE);
typedef struct {uint32_t type,pad;uint64_t physical,virtual_address,pages,attributes;} MD;
typedef struct {HANDLE handle;LOADED *loaded;uintptr_t base;UN size;GUID ffs;} MODULE;
struct NO_TICKET {uint64_t magic,epoch,sequence,catalog_generation;uint32_t kind,depth;uintptr_t object,frame,caller,app,page,array;uint32_t index,count;uint8_t active,pad[7];};
typedef struct {uint64_t marker,epoch,token;uintptr_t stack,caller;uint32_t kind,depth;uint8_t begun,restricted;} FRAME;
typedef struct {
 ST *st;BS *bs;RT *rt;GETVAR getvar;BS bs_copy;HII hii_copy;MODULE tse,setup;HII *hii;CONFIG *config;HANDLE setup_hii,notify[3];EVENT end_event;I04_VM vm;
 uint8_t map[MAP_CAP];UN map_bytes,map_stride,map_key;uint32_t map_version;HANDLE hlist[512];
 uint8_t package[PKG_CAP],forms[FORMS_CAP],official[199463],scratch[TEXT_CAP];UN forms_bytes;
 NO_PATCH patches[NO_MAX_PATCHES];uint32_t patch_count;NO_CALL calls[NO_MAX_CALLS];uint32_t call_count;
 NO_INSTALL install;FRAME frames[NO_MAX_DEPTH];uint32_t depth,loops,sends,initialized,prepared,fault,ended,busy,changing;
 uint64_t epoch,sequence,provider_token,pubtoken,native_visit,visit_sequence,catalog_generation;NO_TICKET effect,lease,manage;
 uint16_t management_qid,tokens[6];uint8_t published,entering,pending_begin,pending_end;
 uintptr_t begin_caller,end_caller;uint32_t begin_depth;
} STATE;
static STATE s;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID hii_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID access_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID tse_guid={0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}};
static GUID setup_guid={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
static GUID formset_guid={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
static const uint8_t tse_sha[32]={0xe0,0xb8,0x09,0x4c,0x48,0x2a,0x64,0x7d,0x71,0x96,0xd1,0x3a,0xa3,0xb0,0x59,0x90,0xd4,0x85,0x6d,0xc3,0x5d,0xe8,0xae,0xe1,0x03,0xb9,0xf9,0x35,0xfe,0x35,0xd9,0x58};
static const uint8_t setup_sha[32]={0x49,0xad,0x95,0xff,0x56,0x45,0x19,0xfd,0xdf,0x96,0x62,0x71,0xe9,0x78,0x01,0x6a,0x5b,0xc5,0x18,0xa4,0x88,0xb3,0xb6,0x12,0xbd,0xc7,0x93,0xa0,0xc7,0x35,0xb1,0xd0};
static const uint8_t forms_sha[32]={0x01,0x11,0xab,0xd4,0xe9,0x91,0x4a,0x32,0xb8,0x65,0xfc,0x95,0xaf,0x15,0x99,0x06,0x87,0xa9,0xd0,0x5f,0x98,0x4d,0xf5,0x33,0xc3,0x0e,0x02,0x8e,0x38,0xcb,0xba,0x2f};
static void cp(void *d,const void *p,UN n){uint8_t *a=d;const uint8_t *b=p;while(n--)*a++=*b++;}
static void zero(void *d,UN n){uint8_t *a=d;while(n--)*a++=0;}
static int eq(const void *a,const void *b,UN n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint16_t u16(const void *p){const uint8_t *b=p;return (uint16_t)(b[0]|b[1]<<8);}
static uint32_t u32(const void *p){const uint8_t *b=p;return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static uint64_t u64(const void *p){uint64_t x=0;cp(&x,p,8);return x;}
static int digest(const void *p,UN n,const uint8_t expected[32]){uint8_t h[32];ap_sha256(p,n,h);return eq(h,expected,32);}
static void revoke(void){s.fault=1;s.epoch++;s.effect.active=s.lease.active=s.manage.active=0;}

/* Snapshot map is bounded, rejects any malformed/overlapping descriptor, and
 * only allows allocated loader/boot/runtime memory, never conventional/MMIO.
 * Cached page table walk additionally checks present/supervisor/RW/NX bits.
 * Page tables themselves are trusted CPU structures under UEFI identity map. */
int EA no_range(uintptr_t p,UN n,uint32_t access){
 if(s.ended||!n||p<4096||n>UINTPTR_MAX-p||!s.map_stride||!i04_vm_current(&s.vm)||!i04_access(&s.vm,p,n,!!(access&NO_WRITE),!!(access&NO_EXEC)))return 0;
 for(UN off=0;off<s.map_bytes;off+=s.map_stride){const MD *m=(const MD *)(s.map+off);
  if(m->type<1||m->type>6||m->attributes&0x2000)continue;
  if((access&NO_WRITE)&&(m->attributes&(0x1000|0x20000)))continue;
  if((access&NO_EXEC)&&(m->attributes&0x4000))continue;
  uint64_t size=m->pages<<12;if(p>=m->physical&&p-m->physical<size&&n<=size-(p-m->physical))return 1;
 }return 0;
}
static int refresh_map(void){
 if(!s.bs||s.ended)return 0;
 if(s.vm.valid&&(!i04_vm_current(&s.vm)||!i04_access(&s.vm,(uintptr_t)s.bs,sizeof(BS),0,0)||!eq(s.bs,&s.bs_copy,sizeof(BS))))return 0;
 if(!i04_capture(&s.vm,s.st))return 0;UN n=s.vm.bytes,key=s.vm.key,stride=s.vm.stride;uint32_t ver=1;
 if(n>sizeof(s.map)||n/stride>2048)return 0;cp(s.map,s.vm.map,n);
 for(UN off=0;off<n;off+=stride){const MD *a=(const MD *)(s.map+off);if(!a->pages||a->pages>UINT64_MAX/4096||a->physical>UINT64_MAX-(a->pages<<12))return 0;
  for(UN j=0;j<off;j+=stride){const MD *b=(const MD *)(s.map+j);if(a->physical<b->physical+(b->pages<<12)&&b->physical<a->physical+(a->pages<<12))return 0;}}
 s.map_bytes=n;s.map_stride=stride;s.map_key=key;s.map_version=ver;return 1;
}
static int tpl_application(void){
 if(!s.bs||s.ended)return 0;
 if(s.map_stride&&(!no_range((uintptr_t)s.bs,sizeof(BS),NO_READ)||!eq(s.bs,&s.bs_copy,sizeof(BS))))return 0;
 UN t=s.bs_copy.raise_tpl(31);s.bs_copy.restore_tpl(t);return t==4;
}
static int tables(void){return s.st&&no_range((uintptr_t)s.st,sizeof(ST),NO_READ)&&s.st->bs==s.bs&&s.st->rt==s.rt&&
 no_range((uintptr_t)s.bs,sizeof(BS),NO_READ)&&eq(s.bs,&s.bs_copy,sizeof(BS))&&no_range((uintptr_t)s.rt,sizeof(RT),NO_READ)&&s.rt->get_variable==s.getvar&&
 (!s.hii||(no_range((uintptr_t)s.hii,sizeof(HII),NO_READ)&&eq(s.hii,&s.hii_copy,sizeof(HII))));}
static int fv_path(void *path,const GUID *g){uintptr_t p=(uintptr_t)path;int found=0;
 for(unsigned i=0;i<32;i++){if(!no_range(p,4,NO_READ))return 0;uint16_t n=u16((void *)(p+2));if(n<4||n>256||!no_range(p,n,NO_READ))return 0;
  const uint8_t *b=(void *)p;if(b[0]==4&&b[1]==6){if(n!=20||!eq(b+4,g,16)||found)return 0;found=1;}
  if(b[0]==0x7f)return b[1]==0xff&&n==4&&found;p+=n;
 }return 0;}
static int pe_valid(MODULE *m,uint32_t text_bytes,uint32_t size){
 if(m->size!=size||!no_range(m->base,4096,NO_READ))return 0;const uint8_t *p=(void *)m->base;
 if(u16(p)!=0x5a4d)return 0;uint32_t e=u32(p+0x3c);if(e<0x40||e>0x800||u32(p+e)!=0x4550||u16(p+e+4)!=0x8664||u16(p+e+24)!=0x20b||u32(p+e+24+56)!=size)return 0;
 uint16_t sections=u16(p+e+6),opt=u16(p+e+20);if(!sections||sections>16||e+24u+opt+40u*sections>4096)return 0;
 unsigned found=0;for(unsigned i=0;i<sections;i++){const uint8_t *q=p+e+24+opt+i*40;if(eq(q,".text\0\0\0",8)){if(u32(q+8)!=text_bytes||u32(q+12)!=0x1000)return 0;found++;}}
 return found==1&&no_range(m->base+0x1000,text_bytes,NO_READ|NO_EXEC);
}
static int module_text(MODULE *m,unsigned which,int installed){
 uint32_t bytes=which?174073:597466,size=which?2154496:909312;
 if(!pe_valid(m,bytes,size)||!no_range((uintptr_t)m->loaded,sizeof(LOADED),NO_READ)||m->loaded->image_base!=(void *)m->base||m->loaded->image_size!=m->size||!fv_path(m->loaded->filepath,&m->ffs))return 0;
 cp(s.scratch,(void *)(m->base+0x1000),bytes);
 for(unsigned i=0;i<s.patch_count;i++){NO_PATCH *p=&s.patches[i];if(p->module!=which||p->rva<0x1000||p->rva>=0x1000+bytes)continue;
  if(p->length>bytes-(p->rva-0x1000)||!eq(s.scratch+p->rva-0x1000,installed?p->installed:p->original,p->length))return 0;
  cp(s.scratch+p->rva-0x1000,p->original,p->length);
 }return digest(s.scratch,bytes,which?setup_sha:tse_sha);
}
static int find_modules(void){
 UN count=0;HANDLE *handles=0;ES r=s.bs->locate_handles(2,&loaded_guid,0,&count,&handles);
 if(FAILED(r)||!count||count>4096||!refresh_map()||!no_range((uintptr_t)handles,count*8,NO_READ))return 0;
 unsigned a=0,b=0;for(UN i=0;i<count;i++){LOADED *l=0;if(FAILED(s.bs->handle_protocol(handles[i],&loaded_guid,(void **)&l))||!refresh_map()||!no_range((uintptr_t)l,sizeof(*l),NO_READ))continue;
  MODULE m={handles[i],l,(uintptr_t)l->image_base,l->image_size,{0}};
  if(m.size==909312&&fv_path(l->filepath,&tse_guid)){m.ffs=tse_guid;if(module_text(&m,0,0)){s.tse=m;a++;}}
  if(m.size==2154496&&fv_path(l->filepath,&setup_guid)){m.ffs=setup_guid;if(module_text(&m,1,0)){s.setup=m;b++;}}
 }if(FAILED(s.bs->free_pool(handles)))return 0;return refresh_map()&&a==1&&b==1;
}
static int export_forms(HANDLE handle,uint8_t *out,UN *written){
 UN n=sizeof(s.package);if(FAILED(s.hii->export_list(s.hii,handle,&n,s.package))||n<24||n>sizeof(s.package)||u32(s.package+16)!=n||!eq(s.package,&setup_guid,16))return 0;
 UN at=20,found=0;while(at<n){if(n-at<4)return 0;uint32_t h=u32(s.package+at),len=h&0xffffff;uint8_t type=h>>24;if(len<4||len>n-at)return 0;
  if(type==2){if(++found!=1||len>FORMS_CAP)return 0;cp(out,s.package+at,len);*written=len;}
  if(type==0xdf&&(len!=4||at+4!=n))return 0;at+=len;
 }return at==n&&found==1;
}
static int config_identity(int installed){
 HANDLE driver=0;CONFIG *config=0;LOADED *image=0;
 if(FAILED(s.hii_copy.get_driver(s.hii,s.setup_hii,&driver))||driver!=s.setup.handle||FAILED(s.bs_copy.handle_protocol(driver,&loaded_guid,(void **)&image))||image!=s.setup.loaded||FAILED(s.bs_copy.handle_protocol(driver,&access_guid,(void **)&config)))return 0;
 if(config!=s.config||!refresh_map()||!no_range((uintptr_t)config,sizeof(CONFIG),NO_READ))return 0;
 return config->extract==(void *)(s.setup.base+0x2240)&&config->route==(ROUTE)(s.setup.base+0x2248)&&config->callback==(installed&&s.install.management_bridge?s.install.management_bridge:(CALLBACK)(s.setup.base+0x2250));
}
static int find_hii(void){
 if(FAILED(s.bs->locate_protocol(&hii_guid,0,(void **)&s.hii))||!refresh_map()||!no_range((uintptr_t)s.hii,sizeof(HII),NO_READ)||!s.hii->list||!s.hii->export_list||!s.hii->get_driver||!s.hii->register_notify||!s.hii->unregister_notify)return 0;
 cp(&s.hii_copy,s.hii,sizeof(HII));
 HANDLE *list=s.hlist;UN n=sizeof(s.hlist);if(FAILED(s.hii->list(s.hii,2,0,&n,list))||n>sizeof(s.hlist)||n%8)return 0;unsigned found=0;
 for(UN i=0;i<n/8;i++){HANDLE driver=0;CONFIG *config=0;if(FAILED(s.hii->get_driver(s.hii,list[i],&driver))||driver!=s.setup.handle)continue;
  if(FAILED(s.bs->handle_protocol(driver,&access_guid,(void **)&config))||!refresh_map()||!no_range((uintptr_t)config,sizeof(CONFIG),NO_READ))continue;
  UN bytes=0;if(export_forms(list[i],s.forms,&bytes)&&bytes==199463&&digest(s.forms,bytes,forms_sha)){
   s.setup_hii=list[i];s.config=config;s.forms_bytes=bytes;if(!config_identity(0))return 0;cp(s.official,s.forms,bytes);found++;
  }}return found==1;
}
static ES EA changed(uint8_t type,GUID *guid,void *package,HANDLE handle,UN kind){
 (void)guid;(void)package;if(type==2&&(kind&11)){
  if(!handle||s.catalog_generation==UINT64_MAX){revoke();return 0;}
  s.catalog_generation++;
  if(handle!=s.setup_hii){
   /* A foreign catalog change invalidates proofs, not the native visit.
    * Keep an existing ticket occupied until its original owner leaves:
    * otherwise reentry could reuse the same private ticket pointer. */
   return 0;
  }
  s.epoch++;s.effect.active=s.lease.active=s.manage.active=0;
  if(handle==s.setup_hii&&s.changing&&s.pubtoken&&s.depth==1&&s.frames[0].kind==NO_COLD&&(kind==2||kind==8)&&!s.loops&&!s.sends)s.frames[0].epoch=s.epoch;
  else revoke();
 }return 0;
}
void EA no_end_boot(EVENT e,void *c){(void)e;(void)c;s.ended=1;s.vm.ended=1;revoke();}
ES EA no_initialize(ST *st){
 if(s.initialized||!st||s.ended)return ERR(20);
 /* EFI entry supplies ST; do not accept a discovered arbitrary pointer. */
 if(st->hdr.sig!=ST_SIG||!st->bs||st->bs->hdr.sig!=BS_SIG||!st->rt)return NO_DENIED;
 s.st=st;s.bs=st->bs;s.rt=st->rt;s.getvar=st->rt->get_variable;s.epoch=1;s.catalog_generation=1;cp(&s.bs_copy,s.bs,sizeof(BS));
 if(!s.bs->memory_map||!s.bs->raise_tpl||!s.bs->restore_tpl||!s.bs->locate_handles||!s.bs->handle_protocol||!s.bs->free_pool||!s.bs->locate_protocol||!s.bs->create_event||!s.bs->close_event||!s.getvar||!tpl_application()||!refresh_map()||!find_modules()||!find_hii())goto denied;
 const UN kinds[3]={1,2,8};
 for(unsigned i=0;i<3;i++)if(FAILED(((HREGISTER)s.hii->register_notify)(s.hii,2,0,changed,kinds[i],&s.notify[i]))||!s.notify[i])goto denied;
 if(FAILED(s.bs->create_event(0x201,16,no_end_boot,0,&s.end_event))||!s.end_event)goto denied;
 if(!refresh_map())goto denied;s.initialized=1;return 0;
denied:revoke();return NO_DENIED;
}
static int trampoline(uintptr_t p,uint32_t rva,const uint8_t *bytes,UN n){
 if(!no_range(p,n+14,NO_READ|NO_EXEC)||!eq((void *)p,bytes,n))return 0;
 static const uint8_t j[6]={0xff,0x25,0,0,0,0};return eq((void *)(p+n),j,6)&&u64((void *)(p+n+6))==s.tse.base+rva+n;
}
static int has_detour(uint32_t rva,UN size,void *target){
 for(unsigned i=0;i<s.patch_count;i++){NO_PATCH *p=&s.patches[i];if(p->module==0&&p->rva==rva&&p->length==size){
  static const uint8_t op[6]={0xff,0x25,0,0,0,0};if(!eq(p->installed,op,6)||u64(p->installed+6)!=(uintptr_t)target)return 0;
  for(UN j=14;j<size;j++)if(p->installed[j]!=0x90)return 0;return 1;
 }}return 0;
}
ES EA no_prepare(const NO_INSTALL *i){
 if(!s.initialized||s.prepared||s.fault||s.ended||!tpl_application()||!refresh_map()||!no_range((uintptr_t)i,sizeof(*i),NO_READ)||i->revision!=NO_REVISION||i->size!=sizeof(*i)||i->patch_count>NO_MAX_PATCHES||i->call_count>NO_MAX_CALLS||!i->provider||!no_range((uintptr_t)i->provider,sizeof(W890_PROVIDER),NO_READ))return NO_DENIED;
 if(!no_range((uintptr_t)i->patches,i->patch_count*sizeof(NO_PATCH),NO_READ)||(i->call_count&&!no_range((uintptr_t)i->calls,i->call_count*sizeof(NO_CALL),NO_READ)))return NO_DENIED;
 s.install=*i;s.patch_count=i->patch_count;s.call_count=i->call_count;cp(s.patches,i->patches,s.patch_count*sizeof(NO_PATCH));cp(s.calls,i->calls,s.call_count*sizeof(NO_CALL));
 for(unsigned k=0;k<s.patch_count;k++){NO_PATCH *p=&s.patches[k];MODULE *m=p->module==0?&s.tse:&s.setup;
  if(p->module>1||!p->length||p->length>32||p->rva>=m->size||p->length>m->size-p->rva||!no_range(m->base+p->rva,p->length,NO_READ)||!eq((void *)(m->base+p->rva),p->original,p->length))goto failed;
  for(unsigned j=0;j<k;j++){NO_PATCH *q=&s.patches[j];if(q->module==p->module&&q->rva<p->rva+p->length&&p->rva<q->rva+q->length)goto failed;}}
 if(!module_text(&s.tse,0,0)||!module_text(&s.setup,1,0)||!has_detour(0x190f4,18,(void *)no_native_loop)||!has_detour(0x36da4,15,(void *)no_native_send_form)||!has_detour(0x6480,16,(void *)no_native_entry)||
 !trampoline((uintptr_t)i->loop_trampoline,0x190f4,original_browser_loop,sizeof(original_browser_loop))||!trampoline((uintptr_t)i->send_trampoline,0x36da4,original_send_form,sizeof(original_send_form))||!trampoline((uintptr_t)i->entry_trampoline,0x6480,original_cold_entry,sizeof(original_cold_entry)))goto failed;
 for(unsigned k=0;k<s.call_count;k++)if(s.calls[k].address<16||!no_range(s.calls[k].address-16,32,NO_READ|NO_EXEC)||!eq((void *)(s.calls[k].address-16),s.calls[k].window,32))goto failed;
 s.prepared=1;return 0;
failed:revoke();return NO_DENIED;
}
static int patches_live(void){for(unsigned k=0;k<s.patch_count;k++){NO_PATCH *p=&s.patches[k];MODULE *m=p->module?&s.setup:&s.tse;if(!no_range(m->base+p->rva,p->length,NO_READ)||!eq((void *)(m->base+p->rva),p->installed,p->length))return 0;}return 1;}
static int identity_live(int full){
 if(!s.prepared||s.fault||s.ended)return 0;
 if(!tpl_application()||!refresh_map()||!tables()||!patches_live()||!no_range(s.tse.base+0xafb00,0x600,NO_READ)||!no_range(s.tse.base+0xbaa00,0x200,NO_READ))goto failed;
 if(full&&(!module_text(&s.tse,0,1)||!module_text(&s.setup,1,1)))goto failed;
 LOADED *current=0;if(FAILED(s.bs->handle_protocol(s.tse.handle,&loaded_guid,(void **)&current))||current!=s.tse.loaded)goto failed;
 if(!config_identity(1)||!s.install.provider||!no_range((uintptr_t)s.install.provider,sizeof(W890_PROVIDER),NO_READ)||s.install.provider->magic!=W890_PROVIDER_MAGIC||s.install.provider->revision!=1)goto failed;
 return !s.fault&&!s.ended;
failed:revoke();return 0;
}
int EA no_identity(NO_IDENTITY *out){if(!out||!s.initialized||!refresh_map()||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE))return 0;
 NO_IDENTITY v={s.st,s.hii,s.setup_hii,s.setup.handle,s.tse.handle,s.config,s.setup.base,s.tse.base,s.setup.size,s.tse.size,s.epoch,s.loops,s.sends,s.fault,s.ended};*out=v;return 1;}
static FRAME *top(void){return s.depth?&s.frames[s.depth-1]:0;}
static int frame_active(void){FRAME *f=top();return f&&f->marker==UINT64_C(0x3430464f393857)&&f->epoch==s.epoch&&f->kind!=NO_COLD&&!s.fault&&!s.ended&&s.loops&&f->depth==s.depth&&no_range(f->stack,8,NO_READ);}
static int callsite(uintptr_t p,unsigned kind){for(unsigned i=0;i<s.call_count;i++){NO_CALL *c=&s.calls[i];if(c->address==p&&c->kind==kind&&no_range(p-16,32,NO_READ|NO_EXEC)&&eq((void *)(p-16),c->window,32))return 1;}return 0;}
static uint64_t readg(uint32_t rva){return u64((void *)(s.tse.base+rva));}
static int app_read(uintptr_t *app,uint32_t *index,uintptr_t *page){
 if(!no_range(s.tse.base+0xafbc0,0x260,NO_READ)||readg(0xafbc0)!=(uintptr_t)s.st||readg(0xafbc8)!=(uintptr_t)s.bs||readg(0xafbd8)!=(uintptr_t)s.rt)return 0;uintptr_t a=readg(0xafdd0);if(!no_range(a,0x60,NO_READ))return 0;
 uint32_t count=u32((void *)(a+0x2c)),i=u32((void *)(a+0x28));uintptr_t pages=u64((void *)(a+0x30));
 if(!count||count>4096||i>=count||!no_range(pages,8u*count,NO_READ))return 0;uintptr_t p=u64((void *)(pages+8u*i));
 if(!no_range(p,0x68,NO_READ)||u16((void *)(p+0x30))!=i)return 0;*app=a;*index=i;*page=p;return 1;
}
static int page_identity(uintptr_t p,uint32_t index){
 if(!no_range(p,0x68,NO_READ)||u64((void *)(p+0x20))!=(uintptr_t)s.setup_hii||u16((void *)(p+0x30))!=index||w890_classify_form((uint8_t *)&formset_guid,u16((void *)(p+0x2a)))==W890_UNKNOWN)return 0;
 /* Raw descriptor cross-check: page offsets + shared descriptor blob. */
 uintptr_t table=readg(0xbaaf0),blob=readg(0xbabc0);if(!no_range(table,4,NO_READ))return 0;uint32_t n=u32((void *)table);
 if(n>4096||index>=n||!no_range(table,4+4u*n,NO_READ))return 0;uint32_t offset=u32((void *)(table+4+4u*index));if(offset>16u*1024u*1024u||blob>UINTPTR_MAX-offset)return 0;uintptr_t d=blob+offset;
 return no_range(d,0x20,NO_READ)&&u64((void *)d)==(uintptr_t)s.setup_hii&&u16((void *)(d+0x0a))==u16((void *)(p+0x2a));
}
static int form_opcode(uint16_t wanted,const uint8_t *opcode,UN length){
 uint16_t form=0,stack[128];unsigned depth=0;int fs=0;for(UN at=4;at<s.forms_bytes;){if(s.forms_bytes-at<2)return 0;const uint8_t *p=s.forms+at;unsigned n=p[1]&127,scope=p[1]>>7;if(n<2||n>s.forms_bytes-at)return 0;
  if(p[0]==0x0e){if(n<23||!eq(p+2,&formset_guid,16))return 0;fs=1;}
  if(p[0]==0x01){if(n!=6||!scope)return 0;form=u16(p+2);}
  if(fs&&form==wanted&&n==length&&eq(p,opcode,n))return 1;
  if(p[0]==0x29){if(n!=2||scope||!depth)return 0;form=stack[--depth];}
  else if(scope){if(depth>=128)return 0;stack[depth++]=(p[0]==1)?0:form;}
  at+=n;
 }return 0;
}
static int control_identity(uintptr_t page,uintptr_t control,uint8_t out[127],uint32_t *length){
 uint32_t frames=u32((void *)(page+0x4c));uintptr_t array=u64((void *)(page+0x50));if(!frames||frames>64||!no_range(array,frames*8,NO_READ))return 0;unsigned found=0;
 for(uint32_t i=0;i<frames;i++){uintptr_t f=u64((void *)(array+i*8));if(!no_range(f,0x50,NO_READ))return 0;uint32_t n=u32((void *)(f+0x3c));uintptr_t ca=u64((void *)(f+0x48));if(n>4096||(n&&!no_range(ca,n*8,NO_READ)))return 0;
  for(uint32_t j=0;j<n;j++)if(u64((void *)(ca+j*8))==control)found++;}
 if(found!=1||!no_range(control,0x60,NO_READ)||u64((void *)(control+0x20))!=(uintptr_t)s.setup_hii)return 0;
 uint16_t type=u16((void *)(control+0x34));uintptr_t vtable=u64((void *)control);unsigned registered=0;
 static const uint32_t types[15][2]={{14,0x95680},{1,0xa5520},{2,0xa51f0},{3,0xa5250},{19,0xa5190},{4,0xa5380},{5,0xa5440},{6,0x93f90},{10,0x93f90},{8,0x93ff0},{11,0xa52c0},{15,0xa53e0},{13,0xa54c0},{27,0x95620},{28,0xa5320}};
 for(unsigned i=0;i<15;i++)if(type==types[i][0]&&vtable==s.tse.base+types[i][1])registered++;
 if(registered!=1)return 0;
 uintptr_t opcode=u64((void *)(control+0x48));if(!no_range(opcode,2,NO_READ))return 0;uint32_t n=((uint8_t *)opcode)[1]&127;
 if(n<2||!no_range(opcode,n,NO_READ)||!form_opcode(u16((void *)(page+0x2a)),(void *)opcode,n))return 0;
 /* The canonical opcode must also originate in this raw native page's
  * descriptor list; frame membership alone cannot authorize a forged copy. */
 uint32_t pi=u16((void *)(page+0x30));uintptr_t pt=readg(0xbaaf0),blob=readg(0xbabc0),cb=readg(0xbab08);
 if(!no_range(pt,8+4u*pi,NO_READ))return 0;uint32_t po=u32((void *)(pt+4+4u*pi));if(blob>UINTPTR_MAX-po)return 0;uintptr_t pd=blob+po;
 if(!no_range(pd,0x20,NO_READ))return 0;uint32_t nc=u32((void *)(pd+0x1c));if(nc>4096||!no_range(pd,0x20+4u*nc,NO_READ))return 0;unsigned origins=0;
 for(uint32_t i=0;i<nc;i++){uint32_t co=u32((void *)(pd+0x20+4u*i));if(co>16u*1024u*1024u||cb>UINTPTR_MAX-co)return 0;uintptr_t d=cb+co;if(!no_range(d,0x40,NO_READ))return 0;
  if(u64((void *)d)==(uintptr_t)s.setup_hii&&u16((void *)(d+0x14))==type&&u64((void *)(d+0x28))==opcode)origins++;}
 if(origins!=1)return 0;
 cp(out,(void *)opcode,n);*length=n;return 1;
}
int EA no_observe(void *unused,uint32_t point,uintptr_t page,uintptr_t control,WG_SNAPSHOT *out){
 (void)unused;if(!out||!frame_active()||!identity_live(0)||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE))return 0;
 uintptr_t app,current;uint32_t index;if(!app_read(&app,&index,&current))return 0;
 if(point==WG_FIRST){if(page&&page!=app)return 0;page=current;control=0;}
 else if(point==WG_CONTROL_INPUT){control=page;page=current;}
 else if(point==WG_MENU){
  uintptr_t menu=page,cookie=control;if(!no_range(menu,0x98,NO_READ)||u64((void *)menu)!=s.tse.base+0x95680||u64((void *)(menu+0x18))!=cookie||cookie!=s.tse.base+0x94758||!no_range(cookie,12,NO_READ)||u32((void *)cookie)!=8)return 0;
  uintptr_t frame=u64((void *)(menu+0x10));if(!no_range(frame,0x50,NO_READ)||u32((void *)(frame+0x20))!=4)return 0;
  uint32_t nf=u32((void *)(current+0x4c)),nc=u32((void *)(frame+0x3c));uintptr_t fa=u64((void *)(current+0x50)),ca=u64((void *)(frame+0x48));if(nf>64||nc>4096||!no_range(fa,nf*8,NO_READ)||!no_range(ca,nc*8,NO_READ))return 0;
  unsigned fm=0,cm=0;for(uint32_t i=0;i<nf;i++)if(u64((void *)(fa+8u*i))==frame)fm++;for(uint32_t i=0;i<nc;i++)if(u64((void *)(ca+8u*i))==menu)cm++;if(fm!=1||cm!=1)return 0;
  uint32_t target=u16((void *)(cookie+8)),count=u32((void *)(app+0x2c));uintptr_t array=u64((void *)(app+0x30));if(target>=count)return 0;page=u64((void *)(array+target*8));control=0;
 }else if(point!=WG_RENDER&&point!=WG_PAGE_INPUT)return 0;
 if(!page)page=current;else{uint32_t count=u32((void *)(app+0x2c));uintptr_t array=u64((void *)(app+0x30));unsigned matches=0;for(uint32_t i=0;i<count;i++)if(u64((void *)(array+8u*i))==page){index=i;matches++;}if(matches!=1)return 0;}
 if(!page_identity(page,index))return 0;WG_SNAPSHOT q;zero(&q,sizeof(q));q.session=s.native_visit;q.native_base=s.tse.base;q.application=app;q.page=page;q.hii=(uintptr_t)s.setup_hii;q.page_index=index;q.application_index=u32((void *)(app+0x28));q.form=u16((void *)(page+0x2a));q.owner=WG_OWNER_SETUP;
 q.proof=WG_IDENTITY|WG_SESSION|WG_EXTENTS|WG_PAGE|WG_HII;cp(q.formset,&formset_guid,16);q.history=readg(0xafde8);q.history_count=u32((void *)(s.tse.base+0xafe00));q.history_root=u32((void *)(s.tse.base+0xafddc));
 if(point==WG_CONTROL_INPUT){if(!control||!control_identity(page,control,q.ifr,&q.ifr_size))return 0;q.control=control;q.proof|=WG_CONTROL;}
 if(!frame_active()||readg(0xafdd0)!=app)return 0;cp(out,&q,sizeof(q));return 1;
}
static int cold(void){FRAME *f=top();return f&&f->kind==NO_COLD&&f->epoch==s.epoch&&!s.loops&&!s.sends&&!s.fault&&!s.ended&&no_range(s.tse.base+0xafb00,0x600,NO_READ)&&no_range(s.tse.base+0xbaa00,0x200,NO_READ)&&readg(0xafdd0)==0&&readg(0xbabc0)==0&&readg(0xbaa68)==0&&readg(0xbaa78)==0;}
int EA no_publication_validate(void *unused,uint64_t ticket){(void)unused;return ticket&&ticket==s.pubtoken&&cold()&&identity_live(0)&&ticket==s.pubtoken&&cold();}
int EA no_publication_finished(void *unused,uint64_t ticket,const uint16_t tokens[6],const uint8_t hash[32]){
 (void)unused;if(!no_publication_validate(0,ticket)||!no_range((uintptr_t)tokens,12,NO_READ)||!no_range((uintptr_t)hash,32,NO_READ))return 0;
 UN bytes=0;size_t expected=0;if(!w890_security_insert(s.official,sizeof(s.official),tokens,s.forms,sizeof(s.forms),&expected)||!digest(s.forms,expected,hash))return 0;
 cp(s.scratch,s.forms,expected);if(!export_forms(s.setup_hii,s.forms,&bytes)||bytes!=expected||!eq(s.forms,s.scratch,bytes)||!no_publication_validate(0,ticket))return 0;
 s.forms_bytes=bytes;cp(s.tokens,tokens,12);s.published=1;return 1;
}
int EA no_restoration_finished(void *unused,uint64_t ticket){
 (void)unused;if(!no_publication_validate(0,ticket))return 0;UN n=0;
 if(!export_forms(s.setup_hii,s.forms,&n)||n!=sizeof(s.official)||!eq(s.forms,s.official,n)||!no_publication_validate(0,ticket))return 0;
 s.forms_bytes=n;s.published=0;zero(s.tokens,sizeof(s.tokens));s.manage.active=0;return 1;
}
static int ticket_valid(NO_TICKET *t){return t&&(t==&s.effect||t==&s.lease||t==&s.manage)&&t->active&&t->epoch==s.epoch&&t->catalog_generation==s.catalog_generation&&t->depth==s.depth&&t->frame==(uintptr_t)top()&&!s.fault&&!s.ended;}
static void mint(NO_TICKET *t,uint32_t kind,uintptr_t object,uintptr_t caller){zero(t,sizeof(*t));t->magic=UINT64_C(0x3430544b393857);t->epoch=s.epoch;t->catalog_generation=s.catalog_generation;t->sequence=++s.sequence;t->kind=kind;t->depth=s.depth;t->frame=(uintptr_t)top();t->object=object;t->caller=caller;t->active=1;}
API int EA no_scope_enter(uint32_t kind,uintptr_t object,NO_TICKET **out){
 uintptr_t caller=RETADDR;if(kind!=NO_EFFECT||s.effect.active||!out||!frame_active()||!callsite(caller,NO_CALL_EFFECT)||!identity_live(1)||!frame_active()||s.effect.active||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE))return 0;
 uintptr_t app,page;uint32_t index;if(!app_read(&app,&index,&page)||!page_identity(page,index))return 0;mint(&s.effect,kind,object,caller);
 s.effect.app=app;s.effect.page=page;s.effect.array=u64((void *)(app+0x30));s.effect.index=index;s.effect.count=u32((void *)(app+0x2c));*out=&s.effect;return 1;
}
int EA no_scope_validate_cached(NO_TICKET *t){
 if(t!=&s.effect||!ticket_valid(t)||!i04_vm_current(&s.vm)||!frame_active()||!tables()||!patches_live()||!callsite(t->caller,NO_CALL_EFFECT))return 0;
 uintptr_t app,page;uint32_t index;if(!app_read(&app,&index,&page)||app!=t->app||page!=t->page||index!=t->index||u32((void *)(app+0x2c))!=t->count||u64((void *)(app+0x30))!=t->array)return 0;
 return page_identity(page,index);
}
int EA no_scope_validate(NO_TICKET *t){return ticket_valid(t)&&frame_active()&&identity_live(0)&&no_scope_validate_cached(t);}
void EA no_scope_leave(NO_TICKET *t){if(t==&s.effect)t->active=0;}
int EA no_copy(NO_TICKET *t,uintptr_t address,void *out,UN n){if(!no_scope_validate(t)||!n||n>1024*1024||!no_range(address,n,NO_READ)||!no_range((uintptr_t)out,n,NO_WRITE))return 0;cp(out,(void *)address,n);return no_scope_validate(t);}
ES EA no_read_variable(NO_TICKET *t,C16 *name,GUID *guid,uint32_t *attrs,UN *size,void *out){
 if(!no_scope_validate(t)||!no_range((uintptr_t)guid,16,NO_READ)||!no_range((uintptr_t)attrs,4,NO_WRITE)||!no_range((uintptr_t)size,8,NO_WRITE))return NO_DENIED;
 UN count=0;for(;count<128;count++){if(!no_range((uintptr_t)(name+count),2,NO_READ))return NO_DENIED;if(!name[count])break;}if(!count||count==128||*size>1024*1024||(*size&&!no_range((uintptr_t)out,*size,NO_WRITE)))return NO_DENIED;
 ES r=s.getvar(name,guid,attrs,size,out);return no_scope_validate(t)?r:NO_DENIED;
}
int EA no_lease_begin(NO_TICKET **out){if(!out||s.lease.active||!cold()||!identity_live(1)||s.lease.active||!cold()||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE))return 0;mint(&s.lease,NO_COLD,0,0);*out=&s.lease;return 1;}
int EA no_lease_validate_cached(NO_TICKET *t){return t==&s.lease&&ticket_valid(t)&&i04_vm_current(&s.vm)&&cold()&&tables()&&patches_live();}
void EA no_lease_end(NO_TICKET *t){if(t==&s.lease)t->active=0;}
/* W890 original 3B96C creates ACTION(0x0C) as native type 27, whose
 * 68AE8 constructor installs 95620. EFI callback Type remains 0x0A.
 * A different native class with a copied opcode is not a management button. */
static int management_control(uintptr_t page,uintptr_t control,uint16_t qid){
 uint8_t op[127];uint32_t length=0;
 return control_identity(page,control,op,&length)&&u16((void *)(control+0x34))==27&&u64((void *)control)==s.tse.base+0x95620&&length==15&&op[0]==0x0c&&u16(op+6)==qid;
}
int EA no_management_enter(void *unused,void *caller,CONFIG *config,UN action,uint16_t qid,uint8_t type,void *value,UN *request,uint64_t *ticket){
 (void)unused;if(!s.published||s.manage.active||config!=s.config||action>1||type!=10||qid<0xffd0||qid>0xffd2||(uintptr_t)caller!=s.tse.base+0x3e4f0||!frame_active()||!identity_live(0)||!frame_active()||s.manage.active||!no_range((uintptr_t)value,2,NO_READ)||!no_range((uintptr_t)request,8,NO_WRITE)||!no_range((uintptr_t)ticket,8,NO_WRITE))return 0;
 if(readg(0xafeb8)!=action||!*((uint8_t *)(s.tse.base+0xafd88))||!*((uint8_t *)(s.tse.base+0xafff8)))return 0;
 uintptr_t app,page;uint32_t index;if(!app_read(&app,&index,&page)||!page_identity(page,index)||u16((void *)(page+0x2a))!=0x271d)return 0;
 /* Require the selected real control, not a caller-supplied question ID. */
 uint32_t nf=u32((void *)(page+0x4c));uintptr_t fa=u64((void *)(page+0x50));unsigned found=0;uintptr_t chosen=0;
 if(nf>64||!no_range(fa,8u*nf,NO_READ))return 0;
 for(uint32_t i=0;i<nf;i++){uintptr_t f=u64((void *)(fa+8u*i));if(!no_range(f,0x50,NO_READ))return 0;uint32_t n=u32((void *)(f+0x3c)),sel=u32((void *)(f+0x44));uintptr_t ca=u64((void *)(f+0x48));if(n>4096||sel>=n)continue;if(!no_range(ca,8u*n,NO_READ))return 0;uintptr_t c=u64((void *)(ca+8u*sel));
  if(management_control(page,c,qid)){found++;chosen=c;}}
 if(found!=1)return 0;mint(&s.manage,NO_MANAGE,chosen,(uintptr_t)caller);s.management_qid=qid;*ticket=s.manage.sequence;return 1;
}
int EA no_management_valid(void *unused,uint64_t ticket){(void)unused;if(!ticket||ticket!=s.manage.sequence||!ticket_valid(&s.manage)||!frame_active()||!identity_live(0))return 0;
 uintptr_t app,page;uint32_t index;return app_read(&app,&index,&page)&&page_identity(page,index)&&u16((void *)(page+0x2a))==0x271d&&management_control(page,s.manage.object,s.management_qid)&&ticket_valid(&s.manage)&&frame_active();
}
void EA no_management_leave(void *unused,uint64_t ticket){(void)unused;if(ticket==s.manage.sequence)s.manage.active=0;}
static int EA host_profile(void){return s.initialized&&s.prepared&&!s.fault&&!s.ended;}
static int EA host_tpl(void){return tpl_application();}
static int EA host_writable(void *p,size_t n){return no_range((uintptr_t)p,n,NO_WRITE);}
static int EA host_owner(void *caller,unsigned operation,uint64_t *out,uint64_t token,uint32_t depth){
 if(!top()||s.fault||s.ended||!s.loops)return 0;
 if(operation==1||operation==3)return s.pending_begin&&(uintptr_t)caller==s.begin_caller&&out==&top()->token&&depth==s.begin_depth;
 return operation==2&&s.pending_end&&(uintptr_t)caller==s.end_caller&&token==top()->token&&depth==s.begin_depth;
}
static int EA host_active(uint64_t token,uint32_t depth){return token&&token==s.provider_token&&depth==s.loops&&frame_active()&&identity_live(0);}
static int EA host_authorize(void *caller,int operation,uint64_t token,uint32_t depth){
 if(!host_active(token,depth))return 0;if(operation==-1&&callsite((uintptr_t)caller,NO_CALL_REQUEST))return 1;
 return no_management_valid(0,s.manage.sequence)&&callsite((uintptr_t)caller,NO_CALL_SCOPE)&&((operation==0&&s.management_qid==0xffd0)||(operation==1&&s.management_qid==0xffd1)||(operation==-1&&s.management_qid==0xffd2));
}
W890_HOST EA no_host(void){W890_HOST h={1,sizeof(W890_HOST),host_profile,host_tpl,host_owner,host_active,host_writable,0,host_authorize};return h;}
/* Assembly thunks expose precise call return labels instead of accepting any
 * caller in this component. The native wrappers alone set pending_begin/end. */
extern ES EA no_provider_begin_call(W890_PROVIDER *,uint64_t *);
extern ES EA no_provider_end_call(W890_PROVIDER *,uint64_t);
extern uint8_t no_provider_begin_return[],no_provider_end_return[];
#include "F:/OpenAI/Codex/project/BIOS/analysis/aitweaker_lock/lock_w890_sage/observer_generation08/visit/restricted_check.inc"
static FRAME *push(uint32_t kind,uintptr_t caller,uintptr_t stack){
 if(s.depth>=NO_MAX_DEPTH||!identity_live(1))return 0;FRAME *f=&s.frames[s.depth++];zero(f,sizeof(*f));f->marker=UINT64_C(0x3430464f393857);f->epoch=s.epoch;f->kind=kind;f->caller=caller;f->stack=stack;f->depth=s.depth;
 if(kind==NO_LOOP){if(!s.loops){if(s.visit_sequence==UINT64_MAX){s.depth--;zero(f,sizeof(*f));return 0;}s.native_visit=++s.visit_sequence;}s.loops++;s.pending_begin=1;s.begin_caller=(uintptr_t)no_provider_begin_return;s.begin_depth=s.loops-1;
  ES r=no_provider_begin_call(s.install.provider,&f->token);s.pending_begin=0;
  if(r!=0){
   uint32_t flags=s.install.provider->query(s.install.provider);
   if(flags==(W890_PROVIDER_READY|W890_PROVIDER_FAULT)&&!w890_password_core.busy&&restricted_profile_live()){
    /* A real private native visit, with no credential token and no grant.
     * Every protected effect continues to consult the faulted provider. */
    f->restricted=1;f->token=0;
   }else{s.loops--;if(!s.loops)s.native_visit=0;s.depth--;zero(f,sizeof(*f));return 0;}
  }else{f->begun=1;if(s.loops==1)s.provider_token=f->token;}
 }else if(kind==NO_SEND)s.sends++;return f;
}
static void pop(FRAME *f){if(f!=top()){revoke();return;}if(f->kind==NO_LOOP){if(f->begun){s.pending_end=1;s.end_caller=(uintptr_t)no_provider_end_return;s.begin_depth=s.loops;ES r=no_provider_end_call(s.install.provider,f->token);s.pending_end=0;if(FAILED(r))revoke();}if(s.loops)s.loops--;if(!s.loops){s.provider_token=0;s.native_visit=0;}}else if(f->kind==NO_SEND&&s.sends)s.sends--;s.depth--;zero(f,sizeof(*f));s.effect.active=s.manage.active=s.lease.active=0;}
API ES EA no_native_loop(void){
 uintptr_t caller=RETADDR,stack=(uintptr_t)__builtin_frame_address(0);int allowed=0;for(unsigned i=0;i<sizeof(loop_callers)/sizeof(loop_callers[0]);i++)if(caller==s.tse.base+loop_callers[i])allowed=1;
 if(!allowed)return NO_DENIED;FRAME *f=push(NO_LOOP,caller,stack);if(!f)return NO_DENIED;
 ES r=((ES(EA *)(void))s.install.loop_trampoline)();pop(f);return r;
}
API ES EA no_native_send_form(void *this,HANDLE *handles,UN count,GUID *guid,uint16_t form,void *dimensions,UN *request){
 uintptr_t caller=RETADDR,stack=(uintptr_t)__builtin_frame_address(0);
 if(this!=(void *)(s.tse.base+0x943a8)||count!=1||!identity_live(1)||!no_range((uintptr_t)handles,8,NO_READ)||handles[0]!=s.setup_hii||(guid&&(!no_range((uintptr_t)guid,16,NO_READ)||!eq(guid,&formset_guid,16)))||(form&&w890_classify_form((uint8_t *)&formset_guid,form)==W890_UNKNOWN)||(request&&!no_range((uintptr_t)request,8,NO_WRITE)))return NO_DENIED;
 FRAME *f=push(NO_SEND,caller,stack);if(!f)return NO_DENIED;ES r=((ES(EA *)(void *,HANDLE *,UN,GUID *,uint16_t,void *,UN *))s.install.send_trampoline)(this,handles,count,guid,form,dimensions,request);pop(f);return r;
}
API ES EA no_native_entry(HANDLE image,ST *st){
 uintptr_t caller=RETADDR,stack=(uintptr_t)__builtin_frame_address(0);if(st!=s.st||image!=s.tse.handle||s.depth||s.entering)return NO_DENIED;s.entering=1;FRAME *f=push(NO_COLD,caller,stack);if(!f)return NO_DENIED;
 if(!cold()){pop(f);return NO_DENIED;}s.pubtoken=++s.sequence;s.changing=1;ES r=NO_UNSUPPORTED;
 if(s.install.publish)r=s.install.publish(s.install.publisher,s.pubtoken);
 s.changing=0;s.pubtoken=0;if(r!=0||!s.published){revoke();pop(f);return NO_DENIED;}
 f->epoch=s.epoch;r=((ES(EA *)(HANDLE,ST *))s.install.entry_trampoline)(image,st);pop(f);return r;
}
ES EA no_shutdown(void){if(s.depth||s.effect.active||s.manage.active||s.lease.active)return ERR(20);if(s.ended)return NO_DENIED;
 /* Detours and ConfigAccess must be restored before callbacks can be retired.
  * A failed/partial rollback keeps this code resident, even without a loop. */
 if(s.prepared){if(!tpl_application()||!refresh_map())return NO_DENIED;
  for(unsigned i=0;i<s.patch_count;i++){NO_PATCH *p=&s.patches[i];uintptr_t b=p->module?s.setup.base:s.tse.base;
   if(!no_range(b+p->rva,p->length,NO_READ)||!eq((void *)(b+p->rva),p->original,p->length))return ERR(20);}}
 for(unsigned i=0;i<3;i++){if(s.notify[i]&&FAILED(((HUNREGISTER)s.hii->unregister_notify)(s.hii,s.notify[i])))return ERR(7);s.notify[i]=0;}
 if(s.end_event&&FAILED(s.bs->close_event(s.end_event)))return ERR(7);s.end_event=0;s.ended=1;s.initialized=0;return 0;
}

int EA no_native_visit_identity(uint64_t *visit,uint32_t *restricted){
 if(!frame_active()||!s.native_visit||!identity_live(0)||!frame_active()||!s.native_visit||!no_range((uintptr_t)visit,8,NO_WRITE)||!no_range((uintptr_t)restricted,4,NO_WRITE))return 0;
 uint32_t limited=0;for(unsigned i=0;i<s.depth;i++)if(s.frames[i].kind==NO_LOOP&&s.frames[i].restricted)limited=1;
 *visit=s.native_visit;*restricted=limited;return 1;
}
#include "F:/OpenAI/Codex/project/BIOS/analysis/aitweaker_lock/lock_w890_sage/observer_generation08/visit/form_descriptor.inc"

/* Read-only stamp. A private active native visit is still required; this
 * cannot create a ticket or authorize a page, callback or variable write. */
API int EA no_catalog_generation(uint64_t *out){
 if(!out||!frame_active()||!identity_live(0)||!frame_active()||!no_range((uintptr_t)out,8,NO_WRITE))return 0;
 *out=s.catalog_generation;return s.catalog_generation!=0;
}
