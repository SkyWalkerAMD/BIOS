/* Exact detached guard binding, never a late UI hook that invents ownership.
 * All compared code is local expected code. Same-privilege malicious UEFI code
 * remains outside this application's security boundary, as for frozen P12. */
#include "split_owner.h"
#include "split_profile.h"
#include "diagnostic_provider.h"
typedef struct FRAME FRAME;
struct FRAME{uint64_t magic;uint32_t revision,size;FRAME *previous;GATE_PROVIDER *provider;uint64_t token;uint32_t depth,flags;};
_Static_assert(sizeof(FRAME)==48,"native frame v1");
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID module_guids[2]={{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}},
 {0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}}};
static SPLIT_CONTEXT bound_context;
static uint8_t text_hashes[2][32],guard_hashes[2][32];
static FRAME *owned_frames[PROVIDER_MAX_DEPTH];
static int bound,verifying;
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t u32(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static uint64_t u64(const void *p){uint64_t x;memcpy(&x,p,8);return x;}
static int extent(uint64_t a,uint64_t n){return a>=4096&&!(a&4095)&&n&&a<(1ULL<<47)&&n<=(1ULL<<47)-a;}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return a<=b?b-a<n:a-b<m;}
static int hash_matches(const void *p,UN n,const uint8_t expected[32]){
 uint8_t actual[32];ap_sha256(p,n,actual);int ok=!boot_services_ended&&ap_constant_equal(actual,expected,32);ap_secure_zero(actual,sizeof(actual));return ok;
}
static uint32_t crc32(const uint8_t *p,UN n){uint32_t c=~0u;while(n--){c^=*p++;for(unsigned i=0;i<8;i++)c=(c>>1)^(0xedb88320u&(0u-(c&1)));}return ~c;}
static int header(const SPLIT_CONTEXT *c,unsigned i){
 uint8_t *p=(void *)(uintptr_t)c->module_base[i];UN n=c->module_size[i];
 if(n!=(i?SETUP_IMAGE_BYTES:AMITSE_IMAGE_BYTES)||!memory_present(p,n,0)||u16(p)!=0x5a4d)return 0;
 uint32_t pe=u32(p+0x3c);if(pe<0x40||pe>0x800||u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664||u16(p+pe+24)!=0x20b||
    u32(p+pe+80)!=n||u32(p+pe+40)!=(i?SETUP_ENTRY_RVA:AMITSE_ENTRY_RVA))return 0;
 return 1;
}
static int patches(const SPLIT_CONTEXT *c){
 for(UN i=0;i<sizeof(split_patches)/sizeof(*split_patches);i++){
  const ID_PATCH *p=&split_patches[i];uint64_t base=c->module_base[p->module],target=c->guard_base[p->module]+p->target;
  if(p->rva>c->module_size[p->module]||p->length>c->module_size[p->module]-p->rva)return 0;
  uint8_t *at=(void *)(uintptr_t)(base+p->rva);
  if(p->kind==0){if(p->length!=8||u64(at)!=target)return 0;}
  else{
   int64_t delta=(int64_t)target-(int64_t)(base+p->rva+5);
   if(delta<(-2147483647LL-1)||delta>2147483647LL||p->length<5||at[0]!=(p->kind==1?0xe9:0xe8)||(int32_t)u32(at+1)!=delta)return 0;
   for(UN j=5;j<p->length;j++)if(at[j]!=0x90)return 0;
  }
 }return 1;
}
static int template_binding(const SPLIT_CONTEXT *c,unsigned i){
 uint8_t *g=(void *)(uintptr_t)c->guard_base[i];UN n=c->guard_size[i];
 if(n!=(i?SETUP_GUARD_BYTES:AMITSE_GUARD_BYTES)||!memory_present(g,n,0)||
    memcmp(g,split_template,SPLIT_BINDING_OFFSET)||
    memcmp(g+SPLIT_BINDING_OFFSET+160,split_template+SPLIT_BINDING_OFFSET+160,SPLIT_TEMPLATE_BYTES-SPLIT_BINDING_OFFSET-160))return 0;
 const SPLIT_BINDING *b=(const void *)(g+SPLIT_BINDING_OFFSET);
 if(b->magic!=SPLIT_BINDING_MAGIC||b->revision!=1||b->kind!=i+1||b->self_offset!=SPLIT_BINDING_OFFSET||b->payload_size!=n||b->reserved||
    b->original_base!=c->module_base[i]||b->original_size!=c->module_size[i]||b->guard_base!=c->guard_base[i]||
    b->state_base!=c->state_base||b->state_size!=c->state_size||b->setup_base!=c->module_base[1]||b->setup_size!=c->module_size[1]||
    b->setup_guard!=c->guard_base[1]||b->setup_guard_size!=c->guard_size[1]||
    b->setup_callback!=c->guard_base[1]+SPLIT_CALLBACK_OFFSET||b->setup_route!=c->guard_base[1]+SPLIT_ROUTE_OFFSET)return 0;
 const uint64_t values[5]={b->original_loop,b->original_frame,b->original_commit,b->original_defaults,b->original_save};
 if(i){for(unsigned k=0;k<5;k++)if(values[k])return 0;return b->setup_guard_crc==0&&n==SPLIT_TEMPLATE_BYTES;}
 UN end=SPLIT_TEMPLATE_BYTES;
 for(UN k=0;k<sizeof(split_trampolines)/sizeof(*split_trampolines);k++){
  const ID_TRAMP *t=&split_trampolines[k];
  if(t->offset<end||t->offset>n||t->length+14>n-t->offset||values[k]!=c->guard_base[i]+t->offset)return 0;
  while(end<t->offset)if(g[end++]!=0x90)return 0;
  uint8_t *at=g+t->offset;
  static const uint8_t jump[6]={0xff,0x25,0,0,0,0};
  if(memcmp(at,t->original,t->length)||memcmp(at+t->length,jump,6)||u64(at+t->length+6)!=c->module_base[i]+t->rva+t->length)return 0;
  end=t->offset+t->length+14;
 }
 return end==n&&b->setup_guard_crc==crc32((void *)(uintptr_t)c->guard_base[1],c->guard_size[1]);
}
static int original_text(const SPLIT_CONTEXT *c,unsigned i){
 const ID_SEGMENT *segments=i?setup_segments:amitse_segments;UN count=i?sizeof(setup_segments)/sizeof(*setup_segments):sizeof(amitse_segments)/sizeof(*amitse_segments);
 const ID_RELOC *relocs=i?setup_relocs:amitse_relocs;UN nr=i?SETUP_RELOC_COUNT:AMITSE_RELOC_COUNT;
 uint8_t *p=(void *)(uintptr_t)c->module_base[i];uint64_t preferred=i?SETUP_IMAGE_BASE:AMITSE_IMAGE_BASE;
 for(UN j=0;j<count;j++)if(!hash_matches(p+segments[j].rva,segments[j].size,segments[j].hash))return 0;
 for(UN j=0;j<nr;j++)if(u64(p+relocs[j].rva)!=relocs[j].original+c->module_base[i]-preferred)return 0;
 return 1;
}
static int path_guid(void *path,GUID *out){
 uint8_t *p=path;if(!p)return 0;
 for(UN off=0;off<65536;){
  if(!memory_present(p+off,4,0))return 0;UN n=u16(p+off+2);
  if(n<4||n>65536-off||!memory_present(p+off,n,0))return 0;
  if(p[off]==4&&p[off+1]==6&&n==20){memcpy(out,p+off+4,16);return 1;}
  if(p[off]==0x7f)return 0;off+=n;
 }return 0;
}
static int loaded_identity(const SPLIT_CONTEXT *c){
 BS *bs=system_table->bs;HANDLE *handles=0;UN n=0;unsigned seen[2]={0,0};int ok=1;
 if(!bs->locate_handles||!bs->handle_protocol||!bs->free_pool)return 0;
 ES status=bs->locate_handles(2,&loaded_guid,0,&n,&handles);
 if(boot_services_ended)return 0;
 if(FAILED(status)||!handles||!n||n>4096||!memory_present(handles,n*8,0))return 0;
 /* LocateHandleBuffer transfers a pool allocation. Never FreePool a suspicious
  * response pointing into one of the modules/code/state known to this owner. */
 for(unsigned j=0;j<2;j++)if(overlap((uintptr_t)handles,n*8,c->module_base[j],c->module_size[j])||overlap((uintptr_t)handles,n*8,c->guard_base[j],c->guard_size[j]))return 0;
 if(overlap((uintptr_t)handles,n*8,c->state_base,c->state_size))return 0;
 for(UN j=0;j<n;j++){
  LOADED *li=0;GUID id;status=bs->handle_protocol(handles[j],&loaded_guid,(void **)&li);
  if(boot_services_ended)return 0;
  if(FAILED(status)||!memory_present(li,sizeof(*li),0)||!path_guid(li->filepath,&id))continue;
  for(unsigned k=0;k<2;k++)if(!memcmp(&id,&module_guids[k],16)){
   if(++seen[k]!=1||(uintptr_t)li->image_base!=c->module_base[k]||li->image_size!=c->module_size[k])ok=0;
  }
 }
 status=bs->free_pool(handles);return !boot_services_ended&&!FAILED(status)&&ok&&seen[0]==1&&seen[1]==1;
}
static int context_ranges(const SPLIT_CONTEXT *c,uint8_t *self,UN own_size){
 uint64_t bases[5]={c->module_base[0],c->module_base[1],c->guard_base[0],c->guard_base[1],c->state_base};
 uint64_t sizes[5]={c->module_size[0],c->module_size[1],(c->guard_size[0]+4095)&~4095ULL,(c->guard_size[1]+4095)&~4095ULL,c->state_size};
 if(c->guard_size[0]>65536||c->guard_size[1]>65536||c->state_size!=4096||!extent((uintptr_t)self,own_size))return 0;
 for(unsigned i=0;i<5;i++){
  if(!extent(bases[i],sizes[i])||overlap(bases[i],sizes[i],(uintptr_t)self,own_size)||
     overlap(bases[i],sizes[i],(uintptr_t)system_table,sizeof(*system_table))||
     overlap(bases[i],sizes[i],(uintptr_t)system_table->bs,sizeof(*system_table->bs))||
     overlap(bases[i],sizes[i],(uintptr_t)system_table->rt,sizeof(*system_table->rt)))return 0;
  for(unsigned j=0;j<i;j++)if(overlap(bases[i],sizes[i],bases[j],sizes[j]))return 0;
 }return 1;
}
static int state_ok(const SPLIT_CONTEXT *c,int idle){
 SPLIT_STATE *s=(void *)(uintptr_t)c->state_base;
 return !boot_services_ended&&memory_present(s,sizeof(*s),1)&&s->magic==SPLIT_STATE_MAGIC&&s->phase==1&&!s->reserved&&(!idle||(!s->ui_head&&!s->save_head));
}
int split_owner_bind(const SPLIT_CONTEXT *input,uint8_t *self,UN own_size){
 if(boot_services_ended||bound||verifying||!system_table||!system_table->bs||!system_table->rt||!memory_present(input,sizeof(*input),0))return 0;
 SPLIT_CONTEXT c;memcpy(&c,input,sizeof(c));
 if(c.magic!=SPLIT_CONTEXT_MAGIC||c.revision!=1||c.size!=sizeof(c)||!context_ranges(&c,self,own_size))return 0;
 verifying=1;int ok=0;
 if(!header(&c,0)||!header(&c,1)||!patches(&c)||!template_binding(&c,1)||!template_binding(&c,0)||
    !state_ok(&c,1)||!loaded_identity(&c)||!original_text(&c,0)||!original_text(&c,1)||!state_ok(&c,1))goto done;
 for(unsigned i=0;i<2;i++){
  ap_sha256((void *)(uintptr_t)(c.module_base[i]+(i?SETUP_TEXT_RVA:AMITSE_TEXT_RVA)),i?SETUP_TEXT_BYTES:AMITSE_TEXT_BYTES,text_hashes[i]);
  ap_sha256((void *)(uintptr_t)c.guard_base[i],c.guard_size[i],guard_hashes[i]);
 }
 if(boot_services_ended)goto done;
 memcpy(&bound_context,&c,sizeof(c));bound=ok=1;
done:verifying=0;return ok;
}
int split_owner_ready(void){
 if(!bound||verifying||boot_services_ended)return 0;verifying=1;int ok=0;
 const SPLIT_CONTEXT *c=&bound_context;
 if(!state_ok(c,0)||!header(c,0)||!header(c,1)||!patches(c))goto done;
 for(unsigned i=0;i<2;i++)if(!memory_present((void *)(uintptr_t)c->guard_base[i],c->guard_size[i],0)||
    !hash_matches((void *)(uintptr_t)c->guard_base[i],c->guard_size[i],guard_hashes[i])||
    !hash_matches((void *)(uintptr_t)(c->module_base[i]+(i?SETUP_TEXT_RVA:AMITSE_TEXT_RVA)),i?SETUP_TEXT_BYTES:AMITSE_TEXT_BYTES,text_hashes[i]))goto done;
 ok=state_ok(c,0);
done:verifying=0;return ok;
}
void split_owner_end(void){
 /* Set only the previously validated owned state. No BootServices call, page
  * permission change, protocol uninstall or foreign code write is made here. */
 if(bound)((SPLIT_STATE *)(uintptr_t)bound_context.state_base)->phase=3;
}
DIAG09_REGION *split_diagnostic_region(void){
 /* This private extension is never an authorization input. The immutable
  * bound context already proved exclusive state ownership and4096B extent. */
 if(!bound||boot_services_ended||bound_context.state_size!=4096||!state_ok(&bound_context,0))return 0;
 DIAG09_REGION *r=(void *)(uintptr_t)(bound_context.state_base+DIAG09_STATE_OFFSET);
 return memory_present(r,sizeof(*r),1)?r:0;
}
int locate_bound_setup(uint8_t **out,UN *size){
 if(!out||!size||!split_owner_ready())return 0;*out=(void *)(uintptr_t)bound_context.module_base[1];*size=bound_context.module_size[1];return 1;
}
static int read_head(FRAME **out){
 if(!split_owner_ready())return 0;*out=((SPLIT_STATE *)(uintptr_t)bound_context.state_base)->ui_head;return 1;
}
int native_browser_state(void){FRAME *f=0;return read_head(&f)?(f?0:1):-1;}
static FRAME *head(void){FRAME *f=0;return read_head(&f)?f:0;}
static int valid_frame(FRAME *f,uint32_t depth){
 return f&&memory_present(f,sizeof(*f),0)&&f->magic==0x343039314d524647ULL&&f->revision==1&&f->size==sizeof(*f)&&
   f->depth==depth&&f->flags==1&&f->provider==&native_provider;
}
static int chain(FRAME *f,uint64_t token,uint32_t depth){
 if(!token||!depth||depth>PROVIDER_MAX_DEPTH)return 0;
 for(uint32_t i=depth;i;i--){if(f!=owned_frames[i-1]||!valid_frame(f,i)||f->token!=token)return 0;f=f->previous;}
 return f==0;
}
int verify_owner_active(uint64_t token,uint32_t depth){return chain(head(),token,depth);}
int verify_owner_caller(void *caller,unsigned operation,uint64_t *token_out,uint64_t token,uint32_t depth){
 FRAME *f=head();if(!f)return 0;
 if(operation==2)return (uintptr_t)caller==bound_context.guard_base[0]+SPLIT_END_RETURN_OFFSET&&chain(f,token,depth);
 if(operation!=1&&operation!=3)return 0;
 if((uintptr_t)caller!=bound_context.guard_base[0]+SPLIT_BEGIN_RETURN_OFFSET||depth>=PROVIDER_MAX_DEPTH||
    !valid_frame(f,depth+1)||token_out!=&f->token||!memory_present(token_out,8,1)||f->token)return 0;
 if(operation==1){if(depth||token||f->previous)return 0;}
 else if(!depth||!chain(f->previous,token,depth))return 0;
 owned_frames[depth]=f;return 1;
}
