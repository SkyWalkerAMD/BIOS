/* Isolated SAGE1904 selective native guard. Not a deployed firmware module.
 * Every entry remains default-deny when the optional provider is missing.
 * Original UI/ConfigAccess calls are reached only after bounded classification.
 * No SetVariable, ResetSystem, SPI/PCI/MMIO write, runtime patch or event APIs.
 */
#include "gate.h"
#include "policy_data.h"
#include "native_chrome_data.h"
#include "diagnostic_store.h"
__attribute__((section(".rdata"),used))
const volatile GATE_BINDING gate_binding={.magic=GATE_BINDING_MAGIC,.revision=1};
static const GUID provider_guid={0x87e3c6fa,0x11fb,0x4e77,{0xaf,0x2d,0xea,0x50,0xb6,0x40,0xfa,0x13}};
static const GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static const GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static const GUID routing_guid={0x587e72d7,0xcc50,0x4f79,{0x82,0x09,0xca,0x29,0x1f,0xc1,0xa1,0x0f}};
static const GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static const GUID setup_formset={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
static const GUID oc_guid={0xa3a3b874,0x7636,0x4182,{0xba,0x1e,0xf5,0x2c,0x58,0x44,0x94,0xe3}};
static const GUID memory_guid={0x98cf19ed,0x4109,0x4681,{0xb7,0x9d,0x91,0x96,0x75,0x7c,0x78,0x24}};
static const C16 oc_name[]=L"VARSTORE_OCMR_SETTINGS_NAME",memory_name[]=L"SocketMemoryConfig";
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
static uint16_t w(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t d(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static uint64_t q(const void *p){uint64_t x;memcpy(&x,p,8);return x;}
static void *ptr(const void *p){return (void *)(uintptr_t)q(p);}
static void *add(const void *p,UN n){uintptr_t x=(uintptr_t)p;return n>UINTPTR_MAX-x?0:(void *)(x+n);}
uint8_t *gate_base(void){
 uintptr_t own=(uintptr_t)&gate_binding;uint32_t offset=gate_binding.self_offset;
 uint64_t original=gate_binding.original_base,size=gate_binding.original_size;
 if(gate_binding.magic!=GATE_BINDING_MAGIC||gate_binding.revision!=1||
    (gate_binding.kind!=1&&gate_binding.kind!=2)||offset>own||offset>=gate_binding.payload_size||
    gate_binding.payload_size>65536||gate_binding.payload_size-offset<sizeof(gate_binding)||
    gate_binding.guard_base!=own-offset||(gate_binding.guard_base&4095)||
    original<4096||(original&4095)||original>=(1ULL<<47)||size>(1ULL<<47)-original||
    size!=(gate_binding.kind==1?0xa1f40u:0x1a5ca0u))return 0;
 return (uint8_t *)(uintptr_t)original;
}
/* x64 UEFI identity mapping; no permission changes. Page-table physical pages
 * must be identity-mapped readable RAM in this firmware execution environment;
 * checking the leaf does not establish that premise. No arbitrary-map claim. */
int gate_memory(const void *p,UN n,int write){
 uint64_t a=(uint64_t)(uintptr_t)p,cr3,cr4;
 if(!n || a<4096)return 0;
 __asm__ volatile("mov %%cr3,%0":"=r"(cr3));__asm__ volatile("mov %%cr4,%0":"=r"(cr4));
 uint64_t limit=(cr4&(1ULL<<12))?(1ULL<<56):(1ULL<<47);
 if(a>=limit || n>limit-a)return 0;uint64_t end=a+n-1;
 for(a&=~4095ULL;a<=end;a+=4096){
  uint64_t table=cr3&0x000ffffffffff000ULL;int levels=(cr4&(1ULL<<12))?5:4;
  if(table<4096 || table>=limit)return 0;
  for(int level=levels;level>=1;level--){
   uint64_t e=((volatile uint64_t *)(uintptr_t)table)[(a>>(12+9*(level-1)))&511];
   if(!(e&1) || (write && !(e&2)))return 0;
   if(level==1 || ((level==2 || level==3)&&(e&128)))break;
   table=e&0x000ffffffffff000ULL;if(table<4096 || table>=limit)return 0;
  }
 }
 return 1;
}
static SPLIT_STATE *split_state(void){
 if(!gate_base()||gate_binding.state_size!=4096||gate_binding.state_base<4096||(gate_binding.state_base&4095))return 0;
 SPLIT_STATE *s=(void *)(uintptr_t)gate_binding.state_base;
 if(!gate_memory(s,sizeof(*s),1)||s->magic!=SPLIT_STATE_MAGIC||s->reserved||
    (s->phase!=SPLIT_ARMED&&s->phase!=SPLIT_RETIRED&&s->phase!=SPLIT_ENDED))return 0;
 return s;
}
static int split_live(void){SPLIT_STATE *s=split_state();return s&&s->phase!=SPLIT_ENDED;}
static int split_armed(void){SPLIT_STATE *s=split_state();return s&&s->phase==SPLIT_ARMED;}
static DIAG09_REGION *diagnostic_region(void){
 SPLIT_STATE *s=split_state();if(!s||s->phase!=SPLIT_ARMED)return 0;
 DIAG09_REGION *r=(void *)((uint8_t *)s+DIAG09_STATE_OFFSET);
 return gate_memory(r,sizeof(*r),1)&&d09_header(r)?r:0;
}
static void trace_init(DIAG09_RECORD *r,uint32_t hook){memset(r,0,sizeof(*r));r->hook=hook;r->classification=-1;r->redirect_result=-2;}
static int trace_fail(DIAG09_RECORD *r,uint32_t reason,uint32_t detail){if(r&&!r->reason){r->reason=reason;r->detail=detail;r->classification=-1;}return -1;}
static int trace_no(DIAG09_RECORD *r,uint32_t reason,uint32_t detail){trace_fail(r,reason,detail);return 0;}
static int trace_return(DIAG09_RECORD *out,const DIAG09_RECORD *local,int result){if(out&&local)*out=*local;return result;}
static void trace_first(DIAG09_RECORD *r,int result){if(r&&result){r->classification=result;d09_first(diagnostic_region(),r);}}
static void trace_app(DIAG09_RECORD *r,uint32_t index,uint32_t count){if(r){r->app_index=index;r->app_count=count;r->valid|=D09_V_APP;}}
static uint32_t trace_rva(uint8_t *base,const void *p){uintptr_t at=(uintptr_t)p,b=(uintptr_t)base;return at>=b&&at-b<gate_binding.original_size?(uint32_t)(at-b):UINT32_MAX;}
static GATE_FRAME **ui_head(void){SPLIT_STATE *s=split_state();return s?(GATE_FRAME **)&s->ui_head:0;}
static BS *bs(void){
 uint8_t *b=gate_base();UN r=gate_binding.kind==1?0x83308:0x43610;
 if(!b || !gate_memory(add(b,r),8,0))return 0;
 BS *x=ptr(add(b,r));return gate_memory(x,sizeof(*x),0)?x:0;
}
static RT *rt(void){
 uint8_t *b=gate_base();UN r=gate_binding.kind==1?0x83318:0x43620;
 if(!b || !gate_memory(add(b,r),8,0))return 0;
 RT *x=ptr(add(b,r));return gate_memory(x,sizeof(*x),0)?x:0;
}
static int code(void *p){return p && gate_memory(p,1,0);}
/* Private state immediately after the public UI-frame head. No grant or
 * initialization exception is represented by this scope: it only reports a
 * denied local commit back to the exact original save caller. */
#define SAVE_MAGIC 0x3231534556415347ULL
typedef struct SAVE_FRAME SAVE_FRAME;
struct SAVE_FRAME {uint64_t magic;uint32_t revision,size;SAVE_FRAME *previous;uint32_t depth,failed;};
static SAVE_FRAME **save_head(void){
 SPLIT_STATE *s=split_state();return s&&gate_binding.kind==1?(SAVE_FRAME **)&s->save_head:0;
}
static int save_chain(SAVE_FRAME *p){
 uint32_t expected=0;unsigned seen=0;
 while(p){
  if(++seen>16||!gate_memory(p,sizeof(*p),1)||p->magic!=SAVE_MAGIC||p->revision!=1||p->size!=sizeof(*p)||
     !p->depth||p->depth>16||p->failed>1||(expected&&p->depth!=expected))return 0;
  expected=p->depth-1;p=p->previous;
  if(!expected)return !p;
 }
 return !seen;
}
static void save_denied(void){SAVE_FRAME **head=save_head();if(head&&*head&&save_chain(*head))(*head)->failed=1;}
uint64_t EA gate_save(void *question){if(!split_live())return 0;
 SAVE_FRAME **head=save_head();if(!head||!save_chain(*head)||(*head&&(*head)->depth==16))return 0;
 SAVE_FRAME frame={SAVE_MAGIC,1,sizeof(frame),*head,*head?(*head)->depth+1:1,0};
 *head=&frame;
 uint64_t result=((uint64_t(EA *)(void *))((uint8_t *)(uintptr_t)gate_binding.original_save))(question);
 int valid=*head==&frame&&save_chain(&frame);
 int failed=!valid||frame.failed;
 *head=valid?frame.previous:0;
 if(failed&&*head&&save_chain(*head))(*head)->failed=1;
 memset(&frame,0,sizeof(frame));
 /* Original1425C has completed its existing cleanup/post-event path. Callers
  * use AL to decide native exit/reset flags; preserve the full normal result
  * unless this bounded save observed EFI_ACCESS_DENIED or a broken scope. */
 return failed?0:result;
}
static GATE_PROVIDER *provider(void){
 if(!split_armed())return 0;BS *b=bs();GATE_PROVIDER *p=0;
 if(!b || !code((void *)b->locate_protocol) || FAILED(b->locate_protocol((GUID *)&provider_guid,0,(void **)&p)) ||
    !split_armed() ||
    !gate_memory(p,sizeof(*p),0) || p->magic!=PROVIDER_MAGIC || p->revision!=1 || p->size!=sizeof(*p) ||
    !code((void *)p->begin) || !code((void *)p->end) || !code((void *)p->query) ||
    !code((void *)p->request) || !code((void *)p->manage))return 0;
 return p;
}
static uint32_t state(GATE_PROVIDER *p){
 if(!p||!split_armed())return 0;uint32_t s=p->query(p);if(!split_armed())return 0;
 if(s&~127u || !(s&PROVIDER_READY) || s&(PROVIDER_BUSY|PROVIDER_FAULT|PROVIDER_ENDED))return 0;
 return s;
}
static int granted(uint32_t s){return !!((s&PROVIDER_DISABLED) || ((s&(PROVIDER_OWNED|PROVIDER_GRANTED))==(PROVIDER_OWNED|PROVIDER_GRANTED)));}
static int allow_trace(int prompt,DIAG09_RECORD *diagnostic){
 GATE_PROVIDER *p=provider();uint32_t s=state(p);
 if(granted(s))return 1;
 if(!prompt || !(s&PROVIDER_OWNED) || !split_armed())return 0;
 uint64_t serial=0;
 if(diagnostic){diagnostic->provider_flags=s;diagnostic->valid|=D09_V_PROVIDER;trace_first(diagnostic,diagnostic->classification);serial=d09_request(diagnostic_region(),diagnostic);}
 ES result=p->request(p);
 if(diagnostic)d09_complete(diagnostic_region(),serial);
 if(FAILED(result))return 0;
 return granted(state(p));
}
static int allow(int prompt){return allow_trace(prompt,0);}
static uint32_t crc32(const uint8_t *p,UN n){uint32_t c=~0u;while(n--){c^=*p++;for(unsigned i=0;i<8;i++)c=(c>>1)^(0xedb88320u&(0u-(c&1)));}return ~c;}
/* HII identity: no allocation/export. For the final static Setup module both
 * ConfigAccess entries must identify the paired generated guard RVAs. Original
 * Setup RVAs are supported only in the unpatched native test baseline. */
typedef struct {uint32_t reason,status_valid,canonical_count,target_seen;ES status;} OWNER_OBSERVATION;
static int owner_failure(OWNER_OBSERVATION *o,uint32_t reason,ES status,int valid){if(o){o->reason=reason;o->status=status;o->status_valid=(uint32_t)valid;}return -1;}
static void owner_trace(DIAG09_RECORD *r,const OWNER_OBSERVATION *o,uint32_t domain){
 if(!r||!o)return;r->owner_reason=(domain<<24)|o->reason;r->canonical_count=o->canonical_count;r->target_seen=o->target_seen;
 if(o->status_valid){r->owner_status=o->status;r->valid|=D09_V_OWNER_DETAIL;}
}
static int setup_handle(BS *b,HII *db,HANDLE hii,uint8_t **out,OWNER_OBSERVATION *o){
 HANDLE h=0;CONFIG *cfg=0;
 if(!split_live())return owner_failure(o,1,0,0);
 ES status=db->get_driver(db,hii,&h);
 if(FAILED(status)||!split_live()||!h)return owner_failure(o,2,status,1);
 status=b->handle_protocol(h,(GUID *)&config_guid,(void **)&cfg);
 if(FAILED(status)||!split_live()||!gate_memory(cfg,sizeof(*cfg),0)||!code((void *)cfg->callback)||!code((void *)cfg->route))return owner_failure(o,3,status,1);
 uintptr_t callback=(uintptr_t)cfg->callback;UN cb=gate_binding.setup_callback,route=gate_binding.setup_route;
 if(!cb||!route||!gate_binding.setup_base)return -1;
 if(callback!=cb||(uintptr_t)cfg->route!=route)return 0;
 uint8_t *image=(uint8_t *)(uintptr_t)gate_binding.setup_base;
 /* A valid foreign ConfigAccess implementation is unrelated, never infer its
 * variable IDs as Setup IDs. Malformed matching candidates remain unknown. */
 if((uintptr_t)image&4095 || !gate_memory(image,0x200,0) || w(image)!=0x5a4d)return 0;
 if(gate_binding.setup_size!=0x1a5ca0)return -1;
 uint32_t pe=d(image+0x3c);if(pe<0x40 || pe>0x1000 || !gate_memory(add(image,pe),0x110,0))return -1;
 uint8_t *nt=add(image,pe);
 if(d(nt)!=0x4550 || w(nt+4)!=0x8664 || w(nt+24)!=0x20b || d(nt+40)!=0x590)return 0;
 uint32_t size=d(nt+80);if(size!=gate_binding.setup_size||!gate_memory(image,size,0))return -1;
 if(crc32(image+0x2c0,0x2793f)!=0xe94c541a)return -1;
 uint8_t *guard=(void *)(uintptr_t)gate_binding.setup_guard;UN gn=gate_binding.setup_guard_size;
 if(!guard||((uintptr_t)guard&4095)||!gn||gn>65536||!gate_memory(guard,gn,0)||crc32(guard,gn)!=gate_binding.setup_guard_crc)return -1;
 if(out)*out=image;return 1;
}
static int gate_owner_observed(HANDLE hii,uint8_t **out,OWNER_OBSERVATION *o){
 if(o)memset(o,0,sizeof(*o));
 if(out)*out=0;if(!hii||!split_live())return owner_failure(o,4,0,0);BS *b=bs();HII *db=0;
 if(!b || !code((void *)b->locate_protocol) || !code((void *)b->handle_protocol) ||
    FAILED(b->locate_protocol((GUID *)&database_guid,0,(void **)&db)) || !split_live() || !gate_memory(db,sizeof(*db),0) || !code((void *)db->get_driver))return -1;
 int direct=setup_handle(b,db,hii,out,o);if(direct)return direct;
 /* A non-matching method pointer alone is not proof of a foreign package.
  * Resolve exactly one genuine Setup handle using a fixed caller-owned list.
  * This bounded slow path uses no AllocatePool/ExportPackageLists call. */
 HANDLE handles[1024];UN n=sizeof(handles);HANDLE canonical=0;int target_seen=0;
 if(!split_live()||!code((void *)db->list) || FAILED(db->list(db,0,0,&n,handles)) || !split_live() || !n || n>sizeof(handles) || n%8)return -1;
 for(UN i=0;i<n/8;i++){
  if(handles[i]==hii)target_seen=1;
  if(setup_handle(b,db,handles[i],0,0)==1){
   if(o)o->canonical_count++;
   if(canonical&&canonical!=handles[i])return owner_failure(o,5,0,0);canonical=handles[i];
  }
 }
 if(o)o->target_seen=(uint32_t)target_seen;
 return canonical&&canonical!=hii&&target_seen?0:owner_failure(o,6,0,0);
}
int gate_owner(HANDLE hii,uint8_t **out){return gate_owner_observed(hii,out,0);}
static int form(uint16_t f){for(UN i=0;i<sizeof(protected_forms)/sizeof(*protected_forms);i++)if(protected_forms[i]==f)return 1;return 0;}
static int question_id(uint16_t f){for(UN i=0;i<sizeof(protected_questions)/sizeof(*protected_questions);i++)if(protected_questions[i]==f)return 1;return 0;}
static int inert(uint8_t *p,UN n){if(n!=17)return 0;for(UN i=0;i<sizeof(inert_exit_questions)/17;i++)if(!memcmp(p,inert_exit_questions[i],17))return 1;return 0;}
static uint8_t *app(void){uint8_t *b=gate_base();return b&&gate_memory(b+0x83588,8,0)?ptr(b+0x83588):0;}
static uint8_t *page_at_trace(uint8_t *a,uint32_t index,DIAG09_RECORD *r){
 if(!gate_memory(a,0x60,0))return 0;UN n=d(a+0x2c);uint8_t *array=ptr(a+0x30);
 trace_app(r,index,(uint32_t)n);
 if(!n || n>8192 || index>=n || !gate_memory(array,n*8,0))return 0;
 uint8_t *p=ptr(array+index*8);return gate_memory(p,0x58,0)?p:0;
}
static uint8_t *page_at(uint8_t *a,uint32_t index){return page_at_trace(a,index,0);}
static int page_form_trace(uint8_t *p,uint16_t *f,DIAG09_RECORD *r){
 uint8_t *b=gate_base();if(!b || !gate_memory(p,0x58,0) || !gate_memory(b+0x930b0,8,0) || !gate_memory(b+0x93948,8,0))return trace_no(r,D09_PAGE_FORM_GLOBALS,0);
 uint16_t i=w(p+0x30);uint8_t *table=ptr(b+0x930b0),*records=ptr(b+0x93948);
 if(r){r->page_index=i;r->valid|=D09_V_PAGE;}
 if(!gate_memory(table,4,0))return trace_no(r,D09_PAGE_FORM_TABLE,1);UN n=d(table);
 if(!n || n>8192 || i>=n || !gate_memory(add(table,4+(UN)i*4),4,0))return trace_no(r,D09_PAGE_FORM_INDEX,i>=n?1:2);
 UN off=d(add(table,4+(UN)i*4));uint8_t *record=add(records,off);
 if(off>16*1024*1024 || !gate_memory(record,12,0))return trace_no(r,D09_PAGE_FORM_RECORD,off>16*1024*1024?1:2);
 *f=w(record+10);if(r){r->form_id=*f;r->valid|=D09_V_FORM;}return 1;
}
static int page_form(uint8_t *p,uint16_t *f){return page_form_trace(p,f,0);}
static int question_op(uint8_t x){return x==5||x==6||x==7||x==8||x==12||x==15||x==0x1a||x==0x1b||x==0x1c||x==0x23;}
/* Original16354/33634 create static SUBTITLE chrome before PageRender171D4
 * assigns its source HII. Its -1 source is an intentional string-package
 * sentinel, not a missing Question owner. Keep this exact class separate from
 * general foreign/unknown controls. No protected form/store rule changes.
 */
static int chrome_identity(uint8_t *b,DIAG09_RECORD *r){
 if(gate_binding.kind!=1||!gate_memory(b,0x200,0)||w(b)!=0x5a4d||d(b+0x3c)!=CHROME_PE_OFFSET)return trace_no(r,D09_CHROME_IMAGE,1);
 uint8_t *nt=b+CHROME_PE_OFFSET;
 if(d(nt)!=0x4550||w(nt+4)!=0x8664||w(nt+24)!=0x20b||d(nt+40)!=CHROME_ENTRY_RVA||d(nt+80)!=0xa1f40)return trace_no(r,D09_CHROME_IMAGE,2);
 if(!gate_memory(b+0x6bb20,sizeof(chrome_methods)/sizeof(chrome_methods[0])*8,0))return trace_no(r,D09_CHROME_METHOD,1);
 for(UN i=0;i<sizeof(chrome_methods)/sizeof(chrome_methods[0]);i++)if(q(b+0x6bb20+i*8)!=(uintptr_t)b+chrome_methods[i]){if(r)r->method_slot=(uint32_t)i;return trace_no(r,D09_CHROME_METHOD,2);}
 if(!gate_memory(b+0x6b8b8,sizeof(chrome_frame_methods)/sizeof(chrome_frame_methods[0])*8,0))return trace_no(r,D09_CHROME_METHOD,3);
 for(UN i=0;i<sizeof(chrome_frame_methods)/sizeof(chrome_frame_methods[0]);i++)if(q(b+0x6b8b8+i*8)!=(uintptr_t)b+chrome_frame_methods[i]){if(r)r->method_slot=(uint32_t)i;return trace_no(r,D09_CHROME_METHOD,4);}
 if(!gate_memory(b+0x15320,15,0)||b[0x15320]!=0xe9||
    (uintptr_t)(b+0x15325)+(intptr_t)(int32_t)d(b+0x15321)!=(uintptr_t)&gate_frame_input)return trace_no(r,D09_CHROME_DETOUR,1);
 for(UN i=5;i<15;i++)if(b[0x15320+i]!=0x90)return trace_no(r,D09_CHROME_DETOUR,2);
 for(UN i=0;i<sizeof(chrome_ranges)/sizeof(chrome_ranges[0]);i++){
  const uint8_t *p=b+chrome_ranges[i].rva;UN n=chrome_ranges[i].size;
  if(!gate_memory(p,n,0)||crc32(p,n)!=chrome_ranges[i].crc){if(r)r->code_range_index=(uint32_t)i;return trace_no(r,D09_CHROME_CRC,0);}
 }
 return 1;
}
static int chrome_hii(uint8_t *b,HANDLE h){
 if((uintptr_t)h==UINTPTR_MAX)return 1;
 if(!h)return 0;
 if(gate_owner(h,0)>=0)return 1;
 /* After original171D4 some chrome uses AMITSE's own string package, which
  * need not publish ConfigAccess. Pin both its exact runtime slot and its
  * HII driver LoadedImage, rather than treating every ConfigAccess failure
  * or arbitrary foreign package as safe. Unknown association stays denied.
  */
 if(!gate_memory(b+0x93970,8,0)||ptr(b+0x93970)!=h)return 0;
 BS *s=bs();HII *db=0;HANDLE driver=0;LOADED *li=0;
 if(!s||!code((void *)s->locate_protocol)||!code((void *)s->handle_protocol)||
    !split_live()||FAILED(s->locate_protocol((GUID *)&database_guid,0,(void **)&db))||!split_live()||
    !gate_memory(db,sizeof(*db),0)||!code((void *)db->get_driver)||
    FAILED(db->get_driver(db,h,&driver))||!split_live()||!driver||
    FAILED(s->handle_protocol(driver,(GUID *)&loaded_guid,(void **)&li))||!split_live()||
    !gate_memory(li,sizeof(*li),0)||li->image_base!=b||li->image_size!=0xa1f40)return 0;
 return 1;
}
static int chrome_kind(uint32_t kind){return kind==1||kind==2||kind==3||kind==5;}
/* 0 ordinary frame; 1 exact native chrome; -1 claimed chrome with a failed
 * invariant. In particular, post-render valid HII must not turn a failed
 * static-class validation into a generic non-Question fallback exemption. */
static int native_chrome_trace(uint8_t *frame,DIAG09_RECORD *r){
 uint8_t *b=gate_base();if(!b||!gate_memory(frame,0x50,0))return trace_fail(r,D09_FRAME_MEMORY,0);
 uint32_t kind=d(frame+0x20);uint8_t *array=ptr(frame+0x48),*c=0;
 uint32_t count=d(frame+0x3c);if(r){r->frame_kind=kind;r->frame_count=count;r->valid|=D09_V_FRAME;}
 if(count==1&&gate_memory(array,8,0))c=ptr(array);
 int claimed=chrome_kind(kind);
 if(!claimed&&gate_memory(c,0x70,0)){
  void *vtable=ptr(c);if(r){r->control_vtable_rva=trace_rva(b,vtable);r->valid|=D09_V_CONTROL_VTABLE;}
  if(vtable==b+0x6bb20&&chrome_kind(d(c+0x6c)))claimed=1;
 }
 if(!claimed)return 0;
 if(!chrome_kind(kind)||!gate_memory(frame,0x78,1)||ptr(frame)!=b+0x6b8b8||d(frame+0x3c)!=1)return trace_fail(r,D09_CHROME_FRAME,0);
 if(r){r->frame_vtable_rva=0x6b8b8;r->valid|=D09_V_FRAME_VTABLE;}
 if(!gate_memory(array,8,0)||!gate_memory(c,0x88,1)||ptr(c)!=b+0x6bb20||d(c+0x6c)!=kind)return trace_fail(r,D09_CHROME_CONTROL,0);
 if(r){r->control_vtable_rva=0x6bb20;r->valid|=D09_V_CONTROL_VTABLE;}
 /* Generic object callback/context fields, Question metadata and expression
  * pointer are all zero in the original constructed class. Pin the complete
  * descriptor except source HII and the separately validated IFR pointer.
  */
 if(q(c+8)||q(c+16)||q(c+24))return trace_fail(r,D09_CHROME_OBJECT_FIELDS,0);
 if(r){r->callback_bits=0;r->valid|=D09_V_CALLBACK;}
 for(UN i=8;i<64;i++){
  if(i>=40&&i<48)continue;
  uint8_t expected=i==20?8:i==28?1:0;
  if(c[0x20+i]!=expected){if(r)r->descriptor_byte=(uint32_t)i;return trace_fail(r,D09_CHROME_DESCRIPTOR,(uint32_t)i);}
 }
 if(r){r->control_type=8;r->descriptor_flags=1;r->valid|=D09_V_CONTROL_TYPE;}
 uint8_t *ifr=ptr(c+0x48);if(!gate_memory(ifr,7,1)||ifr[0]!=2||ifr[1]!=7||w(ifr+4)||ifr[6])return trace_fail(r,D09_CHROME_IFR,0);
 if(r){r->opcode=2;r->opcode_length=7;r->valid|=D09_V_IFR;}
 if(kind==5){if(w(ifr+2)!=3)return trace_fail(r,D09_CHROME_LOCATION,1);}
 else if(ifr!=b+(kind==1?0x6bc98:kind==2?0x6be48:0x6be50))return trace_fail(r,D09_CHROME_LOCATION,2);
 if(!chrome_identity(b,r))return -1;
 HANDLE source=ptr(c+0x20);if(r){r->control_hii=(uintptr_t)source;r->valid|=D09_V_CONTROL;}
 if(!chrome_hii(b,source))return trace_fail(r,D09_CHROME_HII,0);
 return split_live()?1:-1;
}
static int frame_protected_trace(uint8_t *frame,DIAG09_RECORD *r){
 int chrome=native_chrome_trace(frame,r);if(r){r->chrome_result=chrome;r->valid|=D09_V_CHROME_RESULT;}if(chrome)return chrome>0?0:-1;
 if(!gate_memory(frame,0x50,0))return trace_fail(r,D09_FRAME_MEMORY,1);UN n=d(frame+0x3c);uint8_t *array=ptr(frame+0x48);
 if(n>8192 || (n&&!gate_memory(array,n*8,0)))return trace_fail(r,D09_FRAME_ARRAY,0);
 DIAG09_RECORD baseline;DIAG09_RECORD *out=r;if(r)baseline=*r;
 for(UN i=0;i<n;i++){
  DIAG09_RECORD local;if(out){local=baseline;r=&local;}
  uint8_t *c=ptr(array+i*8);if(r)r->control_index=(uint32_t)i;if(!gate_memory(c,0x50,0))return trace_return(out,r,trace_fail(r,D09_CONTROL_MEMORY,0));
  HANDLE source=ptr(c+0x20);OWNER_OBSERVATION obs;int owner=gate_owner_observed(source,0,r?&obs:0);
  if(r){r->control_hii=(uintptr_t)source;r->control_owner=owner;r->hii_class=!source?1:(uintptr_t)source==UINTPTR_MAX?2:owner==1?3:owner==0?4:5;r->valid|=D09_V_CONTROL|D09_V_CONTROL_OWNER;if(owner<0)owner_trace(r,&obs,2);}
  if(owner<0)return trace_return(out,r,trace_fail(r,D09_CONTROL_OWNER,0));if(!owner)continue;
  uint8_t *ifr=ptr(c+0x48);if(!ifr)continue;if(!gate_memory(ifr,2,0))return trace_return(out,r,trace_fail(r,D09_IFR_MEMORY,0));uint8_t opcode=*ifr;if(!question_op(opcode))continue;
  UN size=ifr[1]&127;if(r){r->opcode=opcode;r->opcode_length=(uint32_t)size;r->valid|=D09_V_IFR;}
  if(size<13 || !gate_memory(ifr,size,0))return trace_return(out,r,trace_fail(r,D09_IFR_LENGTH,0));if(inert(ifr,size))continue;
  uint16_t store=w(ifr+8),off=w(ifr+10);
  if(r){r->varstore_id=store;r->varstore_offset=off;}
  if(store==29 || (store==33 && (off==0x10 || off==0xbd || off==0xbe))){if(r){r->reason=D09_PROTECTED_QUESTION;r->classification=1;}return trace_return(out,r,1);}
 }
 return 0;
}
static int frame_protected(uint8_t *frame){return frame_protected_trace(frame,0);}
static int page_protected_trace(uint8_t *p,DIAG09_RECORD *r){
 uint16_t f=0;if(!page_form_trace(p,&f,r))return -1;HANDLE source=ptr(p+0x20);OWNER_OBSERVATION obs;int owner=gate_owner_observed(source,0,r?&obs:0);
 if(r){r->page_hii=(uintptr_t)source;r->page_owner=owner;r->valid|=D09_V_PAGE_OWNER;if(owner<0)owner_trace(r,&obs,1);}
 if(owner<0)return trace_fail(r,D09_PAGE_OWNER,0);if(owner && form(f)){if(r){r->reason=D09_PROTECTED_FORM;r->classification=1;}return 1;}
 UN n=d(p+0x4c);uint8_t *array=ptr(p+0x50);if(n>64 || (n&&!gate_memory(array,n*8,0)))return trace_fail(r,D09_PAGE_FRAMES,0);
 for(UN i=0;i<n;i++){
  DIAG09_RECORD local;if(r){local=*r;local.frame_index=(uint32_t)i;}
  uint8_t *frame=ptr(array+i*8);int x=r?frame_protected_trace(frame,&local):frame_protected(frame);if(x){if(r)*r=local;return x;}
 }return 0;
}
static int page_protected(uint8_t *p){return page_protected_trace(p,0);}
static int overlap(const void *a,UN n,const void *b,UN m){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<=y?y-x<n:x-y<m;}
int gate_redirect(void){
 if(!split_live())return 0;uint8_t *b=gate_base(),*a=app();if(!b || !gate_memory(a,0x60,0))return 0;
 UN count=d(a+0x2c);if(!count || count>8192)return 0;
 for(unsigned pass=0;pass<2;pass++)for(uint32_t i=0;i<count;i++){
  uint8_t *p=page_at(a,i);uint16_t f=0;
  if(!p || !page_form(p,&f) || (pass==0&&f!=0x2713) || !ptr(p+0x20) || (p[0x34]&1) || w(p+0x32) || w(p+0x30)!=i || page_protected(p)!=0)continue;
  if(!gate_memory(b+0x83594,0x28,0))return 0;
  UN start=d(b+0x83594),cap=d(b+0x83598),used=d(b+0x835b8);uint8_t *history=ptr(b+0x835a0),*setup=0;
  if(start>=count || !cap || cap>8212 || !used || used>cap || !history || ((uintptr_t)history&7))return 0;
  UN bytes=cap*32;int owner=gate_owner(ptr(p+0x20),&setup);
  if(!split_live() || owner<0 || overlap(history,bytes,b,gate_binding.original_size) || (setup&&overlap(history,bytes,setup,4*1024*1024)) ||
     overlap(history,bytes,a,0x60) || overlap(history,bytes,p,0x58) || overlap(history,bytes,ptr(a+0x30),count*8) ||
     !gate_memory(history,bytes,1) || !gate_memory(b+0x83594,4,1) || !gate_memory(b+0x835b8,4,1) || !gate_memory(a+0x28,4,1) || !gate_memory(a+0x58,1,1))return 0;
  HANDLE h=ptr(p+0x20);uint32_t id=w(p+0x2a),one=1;
  memset(history,0,bytes);memcpy(history,&h,8);memcpy(history+8,&id,4);memcpy(b+0x83594,&i,4);memcpy(b+0x835b8,&one,4);
  memcpy(a+0x28,&i,4);a[0x58]=1;return 1;
 }
 /* Intentionally no app+5a mutation here until the native cleanup/reset proof
  * is complete. This missing-safe-page branch is NOT acceptance-complete. */
 return 0;
}
ES EA gate_render(void *p){if(!split_live())return 0;DIAG09_RECORD r;trace_init(&r,D09_RENDER);int x=page_protected_trace(p,&r);if(x!=0&&!allow(0)){trace_first(&r,x);gate_redirect();return 0;}if(!split_live())return 0;return ((ES(EA *)(void *))(gate_base()+0x16a90))(p);}
ES EA gate_page_input(void *p,void *key){if(!split_live())return 0;DIAG09_RECORD r;trace_init(&r,D09_PAGE_INPUT);int x=page_protected_trace(p,&r);if(x!=0&&!allow(0)){trace_first(&r,x);gate_redirect();return 0;}if(!split_live())return 0;return ((ES(EA *)(void *,void *))(gate_base()+0x16c20))(p,key);}
ES EA gate_app_input(void *a,void *key){if(!split_live())return 0;
 DIAG09_RECORD r;trace_init(&r,D09_APP_INPUT);
 if(!gate_memory(a,0x60,0)){trace_fail(&r,D09_PAGE_MEMORY,1);trace_first(&r,-1);gate_redirect();return 0;}
 int x=page_protected_trace(page_at_trace(a,d((uint8_t *)a+0x28),&r),&r);
 if(x!=0&&!allow(0)){trace_first(&r,x);gate_redirect();return 0;}
 /* Native F5 scan0x0f reaches330e0 ->5abc(defaults hook0xffff001d), including
  * OEM callbacks that can change OC cached state from unrelated visible pages.
  * Its native handler is inert at application index0; preserve that behavior. */
 if(!gate_memory(key,0x10,0))return 0;
 if(d((uint8_t *)a+0x28)!=0 && w((uint8_t *)key+8)==1 && w((uint8_t *)key+12)==0x0f){
  trace_init(&r,D09_APP_INPUT);r.reason=D09_F5;r.classification=1;r.event_arg=0x0f;r.event_action=1;r.valid|=D09_V_EVENT;
  if(!allow_trace(1,&r))return 0;
 }
 if(!split_live())return 0;return ((ES(EA *)(void *,void *))(gate_base()+0x12168))(a,key);
}
ES EA gate_frame_input(void *frame,void *key){if(!split_live())return 0;DIAG09_RECORD r;trace_init(&r,D09_FRAME_INPUT);int x=frame_protected_trace(frame,&r);if(x!=0&&!allow(0)){trace_first(&r,x);return 0;}if(!split_live())return 0;return ((ES(EA *)(void *,void *))((uint8_t *)(uintptr_t)gate_binding.original_frame))(frame,key);}
/* All three registered defaults callbacks must be gated before the generic
 * dispatcher, not just its default13b9c implementation. Exit action5, F5 and
 * the native menu shortcut all reach this event. The installed vendor method
 *5f688 also initializes defaults outside E1B8; retain only its exact call site
 * when the static UI frame head is empty. This does not by itself prove that
 * later protected commits in its save path remain initialization-compatible. */
uint64_t EA gate_defaults(uint64_t event,void *fallback,void *arg1,void *arg2){if(!split_live())return ERR(15);
 uint8_t *base=gate_base();if(!base)return ERR(15);
 if(event==0xffff001dULL){
  GATE_FRAME **head=ui_head();
  if(!head||!gate_memory(head,8,0))return ERR(15);
  int initialization=!*head&&__builtin_return_address(0)==base+0x5f6c7;
  if(!initialization){DIAG09_RECORD r;trace_init(&r,D09_DEFAULTS);r.reason=D09_DEFAULTS_EVENT;r.classification=1;r.event_arg=(uint32_t)event;r.valid|=D09_V_EVENT;if(!allow_trace(1,&r))return ERR(15);}
 }
 if(!split_live())return ERR(15);return ((uint64_t(EA *)(uint64_t,void *,void *,void *))((uint8_t *)(uintptr_t)gate_binding.original_defaults))(event,fallback,arg1,arg2);
}
ES EA gate_navigation(GUID *old,uint16_t *of,GUID *next,uint16_t *nf){if(!split_live())return ERR(15);
 if(!gate_memory(old,16,0)||!gate_memory(of,2,0)||!gate_memory(next,16,0)||!gate_memory(nf,2,0))return ERR(15);
 if(!memcmp(next,&setup_formset,16)){
  uint16_t destination=*nf;if(form(destination)){DIAG09_RECORD r;trace_init(&r,D09_NAVIGATION);r.reason=D09_NAVIGATION_FORM;r.classification=1;r.form_id=destination;r.valid|=D09_V_FORM;if(!allow_trace(1,&r))return ERR(15);}
 }
 if(!split_live())return ERR(15);return ((ES(EA *)(GUID *,uint16_t *,GUID *,uint16_t *))(gate_base()+0x11fbc))(old,of,next,nf);
}
void EA gate_poll(void){if(!split_live())return;
 uint8_t *b=gate_base(),*a=app();
 if(b&&gate_memory(b+0x83468,8,0)){
  uint64_t stage=q(b+0x83468);if(stage==5){
   DIAG09_RECORD r;trace_init(&r,D09_POLL);r.stage=stage;r.valid|=D09_V_STAGE;
   if(!gate_memory(a,0x60,0)){trace_fail(&r,D09_PAGE_MEMORY,1);trace_first(&r,-1);if(!gate_redirect())return;}
   else{int x=page_protected_trace(page_at_trace(a,d(a+0x28),&r),&r);if(x!=0&&!allow_trace(1,&r)){trace_first(&r,x);if(!gate_redirect())return;}}
  }
 }
 if(split_live())((void(EA *)(void))(gate_base()+0x34b2c))();
}
uint64_t EA gate_loop(void){if(!split_live())return ERR(15);
 /* This native frame exists even when no provider is installed. A provider
  * arriving during a nested SendForm therefore sees previous!=NULL and must
  * not claim a new outer session. Its Query also verifies this active chain. */
 GATE_FRAME **head=ui_head();
 GATE_FRAME frame={GATE_FRAME_MAGIC,1,sizeof(frame),0,0,0,1,GATE_FRAME_OPEN};
 int linked=head&&gate_memory(head,8,1);
 if(linked){
  frame.previous=*head;
  if(frame.previous){
   if(!gate_memory(frame.previous,sizeof(frame),0)||frame.previous->magic!=GATE_FRAME_MAGIC||frame.previous->revision!=1||
      frame.previous->size!=sizeof(frame)||frame.previous->flags!=GATE_FRAME_OPEN||!frame.previous->depth||frame.previous->depth>=64)linked=0;
   else frame.depth=frame.previous->depth+1;
  }
 }
 GATE_PROVIDER *p=linked?provider():0;frame.provider=p;
 if(linked)*head=&frame;
 int begun=p&&split_armed()&&!FAILED(p->begin(p,&frame.token))&&frame.token;
 uint64_t result=ERR(15);
 if(split_live())result=((uint64_t(EA *)(void))((uint8_t *)(uintptr_t)gate_binding.original_loop))();
 if(begun&&split_armed())p->end(p,frame.token);
 if(linked){if(*head==&frame)*head=frame.previous;else *head=0;}
 memset(&frame,0,sizeof(frame));return result;
}
ES EA gate_callback(CONFIG *this,UN action,uint16_t id,uint8_t type,void *value,BROWSER_ACTION_REQUEST *request){if(!split_live())return ERR(15);
 if(id==0xffe0 || id==0xffe1){
  if(request){if(!gate_memory(request,sizeof(*request),1))return ERR(2);*request=0;}
  GATE_PROVIDER *p=provider();if(!(state(p)&PROVIDER_OWNED))return ERR(15);
  if(!split_armed())return ERR(15);if(action==0)return p->manage(p,id==0xffe1);return action==1?0:ERR(3);
 }
 if((action==0||action==1)&&question_id(id)){
  DIAG09_RECORD r;trace_init(&r,D09_SETUP_CALLBACK);r.reason=D09_CALLBACK_QUESTION;r.classification=1;r.event_arg=id;r.event_action=(uint32_t)action;r.valid|=D09_V_EVENT;if(!allow_trace(1,&r))return ERR(15);
 }
 if(!split_live())return ERR(15);return ((CALLBACK)(gate_base()+0x1534))(this,action,id,type,value,request);
}
static int variable_name(const C16 *s,const C16 *name){
 for(UN i=0;i<40;i++){if(s[i]!=name[i])return 0;if(!name[i])return 1;}return 0;
}
/* AMITSE's own generic commit bypasses ConfigAccess for native variable records
 * carrying0x1000. The shipped SocketMemoryConfig record really has this flag.
 * Guard this local function, never replace RuntimeServices.SetVariable. */
static ES EA commit_checked(uint32_t index,void *data,UN size){
 uint8_t *base=gate_base();if(!base||!gate_memory(base+0x930b8,8,0))return ERR(15);
 uint8_t *table=ptr(base+0x930b8);if(!gate_memory(table,4,0))return ERR(15);
 UN count=d(table);if(!count||count>8192||index>=count||!gate_memory(add(table,4+(UN)index*4),4,0))return ERR(15);
 UN off=d(add(table,4+(UN)index*4));uint8_t *record=add(table,off);
 if(off<4+count*4||off>16*1024*1024||!gate_memory(record,0x6c,0))return ERR(15);
 int kind=!memcmp(record,&oc_guid,16)&&variable_name((C16 *)(record+16),oc_name)?1:
          !memcmp(record,&memory_guid,16)&&variable_name((C16 *)(record+16),memory_name)?2:0;
 if(kind&&!allow(0)){
  UN expected=kind==1?26681:1392;BS *b=bs();RT *r=rt();uint8_t *old=0;int same=0;
  if(size!=expected||!gate_memory(data,size,0)||!b||!r||!code((void *)r->get_variable)||
     !code((void *)b->allocate_pool)||!code((void *)b->free_pool)||!split_live()||FAILED(b->allocate_pool(4,size,(void **)&old))||!split_live())return ERR(15);
  if(!gate_memory(old,size,1)){if(old&&split_live())b->free_pool(old);return ERR(15);}
  UN got=size;uint32_t attrs=0;
  if(!FAILED(r->get_variable((C16 *)(record+16),(GUID *)record,&attrs,&got,old))&&split_live()&&got==size&&attrs==d(record+0x60)){
   uint8_t *fresh=data;same=kind==1?!memcmp(old,fresh,size):old[0x10]==fresh[0x10]&&old[0xbd]==fresh[0xbd]&&old[0xbe]==fresh[0xbe];
  }
  if(!split_live())return ERR(15);memset(old,0,size);b->free_pool(old);if(!split_live()||!same)return ERR(15);
 }
 if(!split_live())return ERR(15);return ((ES(EA *)(uint32_t,void *,UN))((uint8_t *)(uintptr_t)gate_binding.original_commit))(index,data,size);
}
ES EA gate_variable_commit(uint32_t index,void *data,UN size){if(!split_live())return ERR(15);
 ES result=commit_checked(index,data,size);
 if(result==ERR(15))save_denied();
 return result;
}
typedef struct ROUTING ROUTING;
struct ROUTING {void *extract,*export,*route,*block_to_config;ES(EA *config_to_block)(ROUTING *,C16 *,uint8_t *,UN *,C16 **);void *alt;};
OFF(ROUTING,config_to_block,0x20);
static int nibble(C16 x){return x>='0'&&x<='9'?x-'0':x>='a'&&x<='f'?x-'a'+10:x>='A'&&x<='F'?x-'A'+10:-1;}
static int equal(const C16 *s,UN n,const char *v){UN i=0;for(;v[i];i++)if(i>=n||s[i]!=(uint8_t)v[i])return 0;return i==n;}
static int string_length(C16 *s,UN *out){
 if(!s || ((uintptr_t)s&1))return 0;UN checked=0;
 for(UN i=0;i<65536;i++){
  if(i>=checked){void *p=add(s,i*2);UN bytes=4096-((uintptr_t)p&4095);if(!gate_memory(p,bytes,0))return 0;checked=i+bytes/2;}
  if(!s[i]){*out=i;return 1;}
 }
 return 0;
}
static int name_matches(const C16 *p,UN n,const C16 *name){
 UN chars=0;while(name[chars])chars++;if(n%4)return -1;int same=n==chars*4;
 /* Validate all code units before treating a different name as unrelated.
  * An early length/character mismatch must not hide malformed hex later. */
 for(UN i=0;i<n/4;i++){
  unsigned x=0;for(unsigned j=0;j<4;j++){int z=nibble(p[i*4+j]);if(z<0)return -1;x=(x<<4)|(unsigned)z;}
  if(!x)return -1;if(i>=chars || x!=name[i])same=0;
 }
 return same;
}
/* 0 unrelated, 1OC,2memory,-1 malformed protected/ambiguous header. */
static int route_kind(C16 *s,UN n){
 if(n<37 || !equal(s,5,"GUID="))return -1;uint8_t guid[16];
 for(unsigned i=0;i<16;i++){int a=nibble(s[5+i*2]),b=nibble(s[6+i*2]);if(a<0||b<0)return -1;guid[i]=(uint8_t)((a<<4)|b);}
 /* ConfigAccess receives one header. Never pass an ambiguous multi-header
  * buffer to an original parser merely because its first GUID is foreign. */
 for(UN i=37;i+6<=n;i++)if(equal(s+i,6,"&GUID="))return -1;
 int kind=!memcmp(guid,&oc_guid,16)?1:!memcmp(guid,&memory_guid,16)?2:0;if(!kind)return 0;
 if(n<43||s[37]!='&'||!equal(s+38,5,"NAME="))return -1;UN e=43;while(e<n&&s[e]!='&')e++;
 int match=name_matches(s+43,e-43,kind==1?oc_name:memory_name);if(match<0)return -1;if(!match)return 0;
 if(e+6>=n || !equal(s+e,6,"&PATH="))return -1;
 /* Reject multi-header ambiguity before invoking the standard block mapper. */
 for(UN i=e+6;i+6<=n;i++)if(equal(s+i,6,"&GUID="))return -1;
 return kind;
}
ES EA gate_route(CONFIG *this,C16 *configuration,C16 **progress){if(!split_live())return ERR(15);
 if(!progress||!gate_memory(progress,8,1))return ERR(2);UN n=0;
 if(!string_length(configuration,&n)){*progress=configuration;return ERR(15);}
 int kind=route_kind(configuration,n);
 if(kind<0){*progress=configuration;return ERR(15);}
 if(!kind||allow(0)){if(!split_live())return ERR(15);return ((ROUTE)(gate_base()+0x152c))(this,configuration,progress);}
 BS *b=bs();RT *r=rt();ROUTING *routing=0;UN size=kind==1?26681:1392;uint8_t *buf=0;ES result=ERR(15);
 if(!b||!r||!code((void *)r->get_variable)||!code((void *)b->allocate_pool)||!code((void *)b->free_pool)||
    !split_live()||FAILED(b->locate_protocol((GUID *)&routing_guid,0,(void **)&routing))||!split_live()||!gate_memory(routing,sizeof(*routing),0)||!code((void *)routing->config_to_block))goto deny;
 if(FAILED(b->allocate_pool(4,size*2,(void **)&buf))||!split_live())goto deny;
 if(!gate_memory(buf,size*2,1)){if(buf&&split_live())b->free_pool(buf);goto deny;}
 UN got=size;uint32_t attrs=0;
 if(FAILED(r->get_variable((C16 *)(kind==1?oc_name:memory_name),(GUID *)(kind==1?&oc_guid:&memory_guid),&attrs,&got,buf))||!split_live()||got!=size)goto done;
 memcpy(buf+size,buf,size);C16 *parsed=configuration;UN mapped=size;
 if(FAILED(routing->config_to_block(routing,configuration,buf+size,&mapped,&parsed)) || !split_live() || mapped>size || parsed!=configuration+n)goto done;
 int same=kind==1?!memcmp(buf,buf+size,size):(buf[0x10]==buf[size+0x10]&&buf[0xbd]==buf[size+0xbd]&&buf[0xbe]==buf[size+0xbe]);
 if(same)result=0;
done:
 if(!split_live())goto deny;memset(buf,0,size*2);b->free_pool(buf);
 if(!FAILED(result)&&split_live())return ((ROUTE)(gate_base()+0x152c))(this,configuration,progress);
deny:
 *progress=configuration;return ERR(15);
}
