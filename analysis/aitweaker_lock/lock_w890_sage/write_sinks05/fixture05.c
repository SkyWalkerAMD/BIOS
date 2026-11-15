/* EXPLICIT TEST MODEL. Not linked into the real-observer product. This model
 * exercises the exact gate/thunk machine bytes and vendor Save bytes; it is
 * not evidence of native owner, HII identity or physical firmware services. */
#include "save_guard05.h"
static NO_IDENTITY id;static uint64_t ticket;static uintptr_t old[3];
static uint32_t flags,mode,reads,requests;W890_PROVIDER w890_provider;
#define p w890_provider
extern void ws05_fixture_profile_return(void);
int EA no_range(uintptr_t a,UN n,uint32_t rights){(void)rights;return a>=0x10000000&&a+n>=a&&a+n<0x70000000;}
int EA no_identity(NO_IDENTITY *out){*out=id;return 1;}
int EA no_scope_enter(uint32_t kind,uintptr_t obj,NO_TICKET **out){(void)obj;if(kind!=NO_EFFECT||mode==1)return 0;*out=(NO_TICKET *)&ticket;return 1;}
int EA no_scope_validate(NO_TICKET *t){return t==(NO_TICKET *)&ticket&&mode!=1;}
int EA no_scope_validate_cached(NO_TICKET *t){return no_scope_validate(t);}
void EA no_scope_leave(NO_TICKET *t){(void)t;}
int EA no_copy(NO_TICKET *t,uintptr_t a,void *out,UN n){if(!no_scope_validate(t)||!no_range(a,n,NO_READ))return 0;uint8_t *d=out,*s=(void *)a;while(n--)*d++=*s++;return 1;}
ES EA no_read_variable(NO_TICKET *t,C16 *name,GUID *g,uint32_t *attrs,UN *size,void *out){
 (void)g;if(!no_scope_validate(t))return UINT64_C(0x800000000000000f);
 uint32_t k=name[0]=='V'?0:name[0]=='S'?1:2;uint32_t want=k==0?22955:k==1?1219:2283;
 reads++;
 if(mode==6||mode==62||(mode==7&&reads<=3)||(mode==8&&reads>3))return UINT64_C(0x800000000000000e);
 if(mode==9)return UINT64_C(0x8000000000000007);
 if(*size!=want)return UINT64_C(0x8000000000000005);*attrs=mode==5?3:7;*size=want;
 uint8_t *d=out,*s=(void *)old[k];for(uint32_t i=0;i<want;i++)d[i]=s[i];
 if(mode==4&&reads>3)d[0]^=1;return 0;
}
static uint32_t EA query(W890_PROVIDER *self){return self==&p?flags:32;}
static ES EA request(W890_PROVIDER *self){requests++;if(self!=&p||mode==2||mode==62)return UINT64_C(0x800000000000000f);flags|=4;return 0;}
ES EA ws05_fixture_init(uintptr_t tse,uintptr_t replay,UN replaybytes,uintptr_t old_array,uint32_t provider_flags){
 id=(NO_IDENTITY){0};id.tse_base=tse;id.tse_size=0xde000;id.setup_base=0x60000000;id.config=(CONFIG *)0x30012340;id.epoch=7;
 for(uint32_t i=0;i<3;i++)old[i]=((uintptr_t *)old_array)[i];
 p=(W890_PROVIDER){0};p.magic=W890_PROVIDER_MAGIC;p.revision=1;p.size=sizeof p;p.query=query;p.request=request;flags=provider_flags;
 WS05_BINDING b={5,sizeof b,&p,(void *)replay,(uint32_t)replaybytes,0,{(void *)(tse+0xfd6c),32,0},{(void *)(tse+0x1f4ac),32,0},{(void *)(tse+0x851a4),32,0},{(void *)(id.setup_base+0x1457c),32,0},{(void *)(id.setup_base+0x143ac),32,0},(void *)ws05_fixture_profile_return};return ws05_prepare(&b);
}
void EA ws05_fixture_mode(uint32_t value){mode=value;}
uint32_t EA ws05_fixture_requests(void){return requests;}
