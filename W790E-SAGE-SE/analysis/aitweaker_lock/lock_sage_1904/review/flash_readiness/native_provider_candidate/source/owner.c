/* Bind ownership to the exact static wrapper and its explicit stack chain.
 * This is not protection against malicious code at the same UEFI privilege.
 */
#include "provider.h"
#include "guard_binding.h"
typedef struct FRAME FRAME;
struct FRAME{uint64_t magic;uint32_t revision,size;FRAME *previous;GATE_PROVIDER *provider;uint64_t token;uint32_t depth,flags;};
OFF(FRAME,previous,16);OFF(FRAME,provider,24);OFF(FRAME,token,32);OFF(FRAME,depth,40);
_Static_assert(sizeof(FRAME)==48,"Frozen native frame v1");
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID tse_guid={0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}};
static GUID setup_guid={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
static uint8_t *tse_base,*setup_base;
static FRAME *owned_frames[PROVIDER_MAX_DEPTH];
static int identifying;
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t u32(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static int image_path_guid(void *path,GUID *out){
 uint8_t *p=path;if(!p)return 0;
 for(UN off=0;off<65536;){
  if(!memory_present(p+off,4,0))return 0;UN n=u16(p+off+2);
  if(n<4||n>65536-off||!memory_present(p+off,n,0))return 0;
  if(p[off]==4&&p[off+1]==6&&n==20){memcpy(out,p+off+4,16);return 1;}
  if(p[off]==0x7f)return 0;off+=n;
 }return 0;
}
static int identity(uint8_t *base,UN size,UN rva,UN bytes,const uint8_t hash[32]){
 if(!base||((uintptr_t)base&4095)||size<rva||bytes>size-rva||!memory_present(base,0x1000,0)||u16(base)!=0x5a4d)return 0;
 uint32_t pe=u32(base+0x3c);if(pe<0x40||pe>0x800||u32(base+pe)!=0x4550||u16(base+pe+4)!=0x8664||u16(base+pe+24)!=0x20b||u32(base+pe+80)!=size)return 0;
 if(!memory_present(base+rva,bytes,0))return 0;
 uint8_t actual[32];ap_sha256(base+rva,bytes,actual);int ok=ap_constant_equal(actual,hash,32);ap_secure_zero(actual,sizeof(actual));return ok;
}
static int discover(void){
 if(boot_services_ended||identifying||!system_table||!system_table->bs||!system_table->bs->locate_handles||!system_table->bs->handle_protocol||!system_table->bs->free_pool)return 0;
 identifying=1;HANDLE *handles=0;UN count=0;uint8_t *tse=0,*setup=0;int uncertain=0;
 ES s=system_table->bs->locate_handles(2,&loaded_guid,0,&count,&handles);
 if(boot_services_ended){identifying=0;return 0;}
 if(FAILED(s)||!handles||!count||count>4096||!memory_present(handles,count*sizeof(*handles),0)){if(handles)system_table->bs->free_pool(handles);identifying=0;return 0;}
 for(UN i=0;i<count;i++){
  LOADED *li=0;GUID id;
  ES found=system_table->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li);
  if(boot_services_ended){identifying=0;return 0;}
  if(FAILED(found)||!memory_present(li,sizeof(*li),0)||!image_path_guid(li->filepath,&id))continue;
  if(!memcmp(&id,&tse_guid,16)){
   if(tse||li->image_size!=AMITSE_IMAGE_BYTES||!identity(li->image_base,AMITSE_IMAGE_BYTES,AMITSE_PAYLOAD_RVA,AMITSE_PAYLOAD_BYTES,amitse_payload_hash)){uncertain=1;break;}tse=li->image_base;
  }else if(!memcmp(&id,&setup_guid,16)){
   if(setup||li->image_size!=SETUP_IMAGE_BYTES||!identity(li->image_base,SETUP_IMAGE_BYTES,SETUP_PAYLOAD_RVA,SETUP_PAYLOAD_BYTES,setup_payload_hash)){uncertain=1;break;}setup=li->image_base;
  }
 }
 s=system_table->bs->free_pool(handles);identifying=0;
 if(boot_services_ended||uncertain||FAILED(s)||!tse||!setup)return 0;
 tse_base=tse;setup_base=setup;return 1;
}
int locate_bound_setup(uint8_t **out,UN *size){
 if(boot_services_ended||!out||!size)return 0;
 if((!setup_base||!tse_base)&&!discover())return 0;
 if(!identity(setup_base,SETUP_IMAGE_BYTES,SETUP_PAYLOAD_RVA,SETUP_PAYLOAD_BYTES,setup_payload_hash))return 0;
 *out=setup_base;*size=SETUP_IMAGE_BYTES;return 1;
}
static int read_head(FRAME **out){
 if(boot_services_ended)return 0;
 if(!tse_base&&!discover())return 0;
 if(!identity(tse_base,AMITSE_IMAGE_BYTES,AMITSE_PAYLOAD_RVA,AMITSE_PAYLOAD_BYTES,amitse_payload_hash)||
    BOUND_CONTEXT_HEAD_RVA>AMITSE_IMAGE_BYTES-8||!memory_present(tse_base+BOUND_CONTEXT_HEAD_RVA,8,0))return 0;
 memcpy(out,tse_base+BOUND_CONTEXT_HEAD_RVA,8);return 1;
}
/* 1 = verified idle, 0 = active (including an ownerless wrapper), -1 = unknown.
 * A missing/invalid module must never be conflated with a NULL head slot. */
int native_browser_state(void){FRAME *f=0;return read_head(&f)?(f?0:1):-1;}
static FRAME *head(void){FRAME *f=0;return read_head(&f)?f:0;}
static int valid_frame(FRAME *f,uint32_t depth){
 return f&&memory_present(f,sizeof(*f),0)&&f->magic==0x343039314d524647ULL&&f->revision==1&&f->size==sizeof(*f)&&
   f->depth==depth&&f->flags==1&&f->provider==&native_provider;
}
static int chain(FRAME *f,uint64_t token,uint32_t depth){
 if(!token||!depth||depth>PROVIDER_MAX_DEPTH)return 0;
 for(uint32_t i=depth;i;i--){
  if(f!=owned_frames[i-1]||!valid_frame(f,i)||f->token!=token)return 0;f=f->previous;
 }
 return f==0;
}
int verify_owner_active(uint64_t token,uint32_t depth){return chain(head(),token,depth);}
int verify_owner_caller(void *caller,unsigned operation,uint64_t *token_out,uint64_t token,uint32_t depth){
 FRAME *f=head();if(!f||!tse_base)return 0;
 if(operation==2)return (uint8_t *)caller==tse_base+BOUND_END_RETURN_RVA&&chain(f,token,depth);
 if(operation!=1&&operation!=3)return 0;
 if((uint8_t *)caller!=tse_base+BOUND_BEGIN_RETURN_RVA||depth>=PROVIDER_MAX_DEPTH||
    !valid_frame(f,depth+1)||token_out!=&f->token||!memory_present(token_out,8,1)||f->token)return 0;
 if(operation==1){if(depth||token||f->previous)return 0;}
 else if(!depth||!chain(f->previous,token,depth))return 0;
 owned_frames[depth]=f;return 1;
}
