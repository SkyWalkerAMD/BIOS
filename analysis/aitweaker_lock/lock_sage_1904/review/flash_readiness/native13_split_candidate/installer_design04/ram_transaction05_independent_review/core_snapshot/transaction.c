/* Exact 12-site transaction; this file has no UEFI allocation, permission,
 * variable, HII, filesystem, flash or RuntimeServices interface. Host.validate
 * MUST be a bounded read-only validator with no BootServices call. Only the
 * RaiseTPL and successful RestoreTPL callbacks are allowed around the copy.
 * TPL does not quiesce APs or SMM; the documented BSP execution premise applies.
 */
#include "transaction.h"
#include "transaction_plan.h"
typedef struct {uint64_t ui_head,save_head,magic;volatile uint32_t phase;uint32_t reserved;} OWN_STATE;
static int same(const void *a,const void *b,size_t n){const volatile uint8_t *x=a;const uint8_t *y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static void copy(void *a,const void *b,size_t n){volatile uint8_t *x=a;const uint8_t *y=b;while(n--)*x++=*y++;}
static void zero(void *a,size_t n){volatile uint8_t *x=a;while(n--)*x++=0;}
static int span(uint64_t a,uint64_t n){return a>=4096&&!(a&4095)&&n&&a<(1ULL<<47)&&n<=(1ULL<<47)-a;}
static int overlaps(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return a<=b?b-a<n:a-b<m;}
static OWN_STATE *state(TX_CONTEXT *c){return (void *)(uintptr_t)c->plan.state_base;}
static int plan_valid(const TX_PLAN *p){
 if(p->module_size[0]!=TX_AMITSE_SIZE||p->module_size[1]!=TX_SETUP_SIZE||p->guard_size[0]!=TX_AMITSE_GUARD_SIZE||p->guard_size[1]!=TX_SETUP_GUARD_SIZE||p->state_size!=4096)return 0;
 uint64_t a[5]={p->module_base[0],p->module_base[1],p->guard_base[0],p->guard_base[1],p->state_base};
 uint64_t n[5]={p->module_size[0],p->module_size[1],(p->guard_size[0]+4095)&~4095ULL,(p->guard_size[1]+4095)&~4095ULL,p->state_size};
 for(unsigned i=0;i<5;i++){
  if(!span(a[i],n[i]))return 0;
  for(unsigned j=0;j<i;j++)if(overlaps(a[i],n[i],a[j],n[j]))return 0;
 }
 return 1;
}
static int context_valid(TX_CONTEXT *c){return c&&c->magic==TX_MAGIC&&plan_valid(&c->plan)&&c->host.raise_tpl&&c->host.restore_tpl&&c->host.validate;}
static int state_valid(TX_CONTEXT *c,int idle){
 OWN_STATE *s=state(c);return s->magic==0x3331535441544547ULL&&!s->reserved&&(s->phase==1||s->phase==2)&&(!idle||(!s->ui_head&&!s->save_head));
}
static void serialize(void){uint32_t a,b,c,d;__asm__ volatile("mfence":::"memory");__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0),"c"(0):"memory");}
static int all_sites(TX_CONTEXT *c,int replaced){
 for(unsigned i=0;i<12;i++){const TX_SITE *s=&tx_sites[i];if(!same((void *)(uintptr_t)(c->plan.module_base[s->module]+s->rva),replaced?c->replacement[i]:c->original[i],s->length))return 0;}return 1;
}
static void write_site(TX_CONTEXT *c,unsigned i,int replacement){
 const TX_SITE *s=&tx_sites[i];void *address=(void *)(uintptr_t)(c->plan.module_base[s->module]+s->rva);
 const uint8_t *bytes=replacement?c->replacement[i]:c->original[i];
 if(!s->kind){uint64_t value=0;copy(&value,bytes,8);*(volatile uint64_t *)address=value;}
 else copy(address,bytes,s->length);
}
void EA tx_end(TX_CONTEXT *c){
 if(c&&c->magic==TX_MAGIC){c->ended=1;if(c->owned_state_valid)state(c)->phase=3;}
}
uint32_t EA tx_prepare(TX_CONTEXT *c,const TX_PLAN *p,const TX_HOST *h){
 if(!c||!p||!h||c->magic==TX_MAGIC||!plan_valid(p)||!h->raise_tpl||!h->restore_tpl||!h->validate)return TX_REFUSED;
 zero(c,sizeof(*c));c->magic=TX_MAGIC;c->busy=1;copy(&c->plan,p,sizeof(*p));copy(&c->host,h,sizeof(*h));
 if(!c->host.validate(c,TX_ORIGINAL)||c->ended||!state_valid(c,1)||state(c)->phase!=1)goto refused;
 c->owned_state_valid=1;
 for(unsigned i=0;i<12;i++){
  const TX_SITE *s=&tx_sites[i];uint64_t address=p->module_base[s->module]+s->rva,target=p->guard_base[s->module]+s->target;
  if(s->rva>p->module_size[s->module]||s->length>p->module_size[s->module]-s->rva||s->target>=p->guard_size[s->module])goto refused;
  if(!s->kind){
   if(s->length!=8||(address&7))goto refused;uint64_t original=p->module_base[s->module]+s->original_rva;
   copy(c->original[i],&original,8);copy(c->replacement[i],&target,8);
  }else{
   int64_t delta=(int64_t)target-(int64_t)(address+5);if(s->length<5||s->length>24||delta<(-2147483647LL-1)||delta>2147483647LL)goto refused;
   copy(c->original[i],s->original,s->length);c->replacement[i][0]=s->kind==1?0xe9:0xe8;int32_t relative=(int32_t)delta;copy(c->replacement[i]+1,&relative,4);
   for(unsigned j=5;j<s->length;j++)c->replacement[i][j]=0x90;
  }
  if(!same((void *)(uintptr_t)address,c->original[i],s->length))goto refused;
 }
 c->phase=TX_PREPARED;c->busy=0;return TX_OK;
refused:c->busy=0;return c->ended?TX_ENDED:TX_REFUSED;
}
static uint32_t hold(TX_CONTEXT *c){
 c->held=1;c->phase=TX_HELD;
 if(c->owned_state_valid)state(c)->phase=c->ended?3:2;
 c->busy=0;return c->ended?TX_ENDED:TX_HOLD;
}
static uint32_t release_tpl(TX_CONTEXT *c,uint32_t result){
 /* Restoring TPL can synchronously deliver a pending EBS notification. Check
  * immediately after that boundary and make no subsequent firmware call. */
 c->host.restore_tpl(c->saved_tpl);c->busy=0;
 if(c->ended){c->held=1;return TX_ENDED;}return result;
}
static uint32_t rollback(TX_CONTEXT *c){
 if(c->ended)return hold(c);
 state(c)->phase=2;
 if(!c->host.validate(c,TX_PERMISSIONS)||c->ended)return hold(c);
 int unknown=0;
 for(unsigned i=12;i;i--){unsigned at=i-1;const TX_SITE *s=&tx_sites[at];
  if(!(c->attempted&(1u<<at)))continue;
  void *p=(void *)(uintptr_t)(c->plan.module_base[s->module]+s->rva);
  if(same(p,c->replacement[at],s->length))write_site(c,at,0);
  else if(!same(p,c->original[at],s->length))unknown=1;
 }
 serialize();
 if(unknown||!all_sites(c,0)||!c->host.validate(c,TX_ORIGINAL)||c->ended)return hold(c);
 c->phase=TX_RETIRED;return release_tpl(c,TX_ROLLED_BACK);
}
uint32_t EA tx_install(TX_CONTEXT *c){
 if(!context_valid(c))return TX_REFUSED;if(c->busy)return TX_BUSY;if(c->ended)return TX_ENDED;if(c->phase!=TX_PREPARED||c->held)return TX_REFUSED;
 c->busy=1;c->saved_tpl=c->host.raise_tpl(31);
 if(c->ended)return hold(c);
 if(c->saved_tpl!=4)return release_tpl(c,TX_REFUSED);
 if(!c->host.validate(c,TX_ORIGINAL)||c->ended||!state_valid(c,1)||state(c)->phase!=1||!all_sites(c,0)){
  if(c->ended)return hold(c);return release_tpl(c,TX_REFUSED);
 }
 for(unsigned i=0;i<12;i++){
  c->attempted|=1u<<i;write_site(c,i,1);
  const TX_SITE *s=&tx_sites[i];if(!same((void *)(uintptr_t)(c->plan.module_base[s->module]+s->rva),c->replacement[i],s->length))return rollback(c);
 }
 serialize();
 if(!all_sites(c,1)||!c->host.validate(c,TX_PATCHED)||c->ended)return rollback(c);
 c->phase=TX_INSTALLED;return release_tpl(c,TX_OK);
}
uint32_t EA tx_remove(TX_CONTEXT *c){
 if(!context_valid(c))return TX_REFUSED;if(c->busy)return TX_BUSY;if(c->ended)return TX_ENDED;if(c->phase!=TX_INSTALLED||c->held)return TX_REFUSED;
 c->busy=1;c->saved_tpl=c->host.raise_tpl(31);
 if(c->ended)return hold(c);
 if(c->saved_tpl!=4)return release_tpl(c,TX_REFUSED);
 if(!c->host.validate(c,TX_PATCHED)||c->ended){if(c->ended)return hold(c);return hold(c);}
 if(!state_valid(c,1))return release_tpl(c,TX_BUSY);
 return rollback(c);
}
