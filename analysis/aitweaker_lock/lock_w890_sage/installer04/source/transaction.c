#include "transaction.h"
#include "../../password/core/password_core.h"
#include "profile.h"
static int same(const void *a,const void *b,size_t n){const volatile uint8_t *x=a;const uint8_t *y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static void write_bytes(void *a,const void *b,size_t n){volatile uint8_t *x=a;const uint8_t *y=b;while(n--)*x++=*y++;}
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t u32(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return n&&m&&(a<=b?b-a<n:a-b<m);}
static int digest(const void *p,UN n,const uint8_t wanted[32]){uint8_t h[32];ap_sha256(p,n,h);return ap_constant_equal(h,wanted,32);}
static void jump(uint8_t *p,uint64_t to){p[0]=0xff;p[1]=0x25;memset(p+2,0,4);memcpy(p+6,&to,8);}
int i04_trampolines(uint8_t page[4096],uint64_t base){
 if(!page||base<4096||base>=(1ULL<<47)-909312)return 0;
 memset(page,0xcc,4096);
 for(unsigned i=0;i<3;i++){const I04_SITE *s=&i04_sites[i];
  memcpy(page+i*64,s->bytes,s->length);jump(page+i*64+s->length,base+s->rva+s->length);}
 return 1;
}
static int loaded_identity(I04_TX *c,unsigned i){
 LOADED *l=i?c->plan.setup:c->plan.tse;const I04_MODULE *m=&i04_modules[i];
 if(!i04_access(c->vm,(uintptr_t)l,sizeof(*l),0,0)||memcmp(l,&c->original_loaded[i],sizeof(*l)))return 0;
 uint8_t *p=c->module_base[i];
 if(l->revision!=0x1000||l->image_base!=p||l->image_size!=m->size||((uintptr_t)p&4095)||!i04_access(c->vm,(uintptr_t)p,4096,0,0)||memcmp(p,c->header[i],4096))return 0;
 uint32_t pe=u32(p+0x3c);if(pe<0x40||pe>0x800||u16(p)!=0x5a4d||u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664||u16(p+pe+24)!=0x20b||u32(p+pe+40)!=m->entry||u32(p+pe+80)!=m->size)return 0;
 if(!i04_access(c->vm,(uintptr_t)p+m->text_rva,m->text_size,0,1))return 0;
 for(unsigned j=0;j<I04_SEGMENT_COUNT;j++){const I04_SEGMENT *s=&i04_segments[j];if(s->module==i&&!digest(p+s->rva,s->length,s->hash))return 0;}
 return 1;
}
static int lease(I04_TX *c){return c->plan.lease.valid&&c->plan.lease.ticket&&c->plan.lease.valid(c->plan.lease.context,c->plan.lease.ticket)&&!c->ended&&!c->vm->ended;}
static int readonly_code(I04_TX *c,uint64_t a,UN n){
 if(!i04_access(c->vm,a,n,0,1))return 0;
 for(uint64_t p=a&~4095ULL;p<a+n;p+=4096){I04_PAGE v;if(!i04_walk(c->vm,p,&v)||v.rw||v.nx||v.user)return 0;}return 1;
}
static int service_tables(I04_VM *v){
 return i04_access(v,(uintptr_t)v->st,sizeof(ST),0,0)&&i04_access(v,(uintptr_t)v->bs,sizeof(BS),0,0)&&v->st->bs==v->bs&&
  i04_access(v,(uintptr_t)v->bs->raise_tpl,1,0,1)&&i04_access(v,(uintptr_t)v->bs->restore_tpl,1,0,1);
}
int i04_validate(I04_TX *c,uint32_t mask){
 if(!c||c->magic!=I04_MAGIC||c->ended||mask>15||!i04_vm_current(c->vm)||!digest(&c->plan,sizeof(c->plan),c->plan_sha)||!lease(c))return 0;
 if(!service_tables(c->vm)||c->vm->bs->raise_tpl!=c->raise||c->vm->bs->restore_tpl!=c->restore)return 0;
 if(!loaded_identity(c,0)||!loaded_identity(c,1))return 0;
 if(!readonly_code(c,c->plan.guard_base,c->plan.guard_size)||!digest((void *)(uintptr_t)c->plan.guard_base,c->plan.guard_size,c->guard_sha)||
    !readonly_code(c,c->plan.tramp_base,4096)||!digest((void *)(uintptr_t)c->plan.tramp_base,4096,c->tramp_sha))return 0;
 if(!i04_access(c->vm,(uintptr_t)c->plan.config,sizeof(CONFIG),0,0)||c->plan.config->extract!=c->original_config.extract||c->plan.config->route!=c->original_config.route)return 0;
 for(unsigned i=0;i<4;i++){
  if(!i04_access(c->vm,c->site[i],c->length[i],1,i<3)||!same((void *)(uintptr_t)c->site[i],mask&(1u<<i)?c->replacement[i]:c->original[i],c->length[i]))return 0;
 }
 return lease(c);
}
I04_RESULT i04_prepare(I04_TX *c,I04_VM *v,const I04_PLAN *p){
 if(!c||!v||!p||c->magic==I04_MAGIC||v->ended||!i04_vm_current(v)||!service_tables(v)||!p->tse||!p->setup||!p->config||!p->lease.valid||!p->lease.ticket)return I04_REFUSED;
 memset(c,0,sizeof(*c));c->magic=I04_MAGIC;c->vm=v;c->plan=*p;c->busy=1;
 if(!i04_access(v,(uintptr_t)p->tse,sizeof(LOADED),0,0)||!i04_access(v,(uintptr_t)p->setup,sizeof(LOADED),0,0)||!i04_access(v,(uintptr_t)p->config,sizeof(CONFIG),0,0))goto refused;
 c->original_loaded[0]=*p->tse;c->original_loaded[1]=*p->setup;c->original_config=*p->config;
 c->module_base[0]=p->tse->image_base;c->module_base[1]=p->setup->image_base;
 if(overlap((uintptr_t)c->module_base[0],i04_modules[0].size,(uintptr_t)c->module_base[1],i04_modules[1].size))goto refused;
 for(unsigned i=0;i<2;i++){
  uint64_t b=(uintptr_t)c->module_base[i];
  if(!i04_access(v,b,4096,0,0)||overlap(b,i04_modules[i].size,p->guard_base,p->guard_size)||overlap(b,i04_modules[i].size,p->tramp_base,4096))goto refused;
  memcpy(c->header[i],(void *)(uintptr_t)b,4096);
 }
 if(!p->guard_size||p->guard_size>4*1024*1024||!readonly_code(c,p->guard_base,p->guard_size)||
    (p->tramp_base&4095)||!readonly_code(c,p->tramp_base,4096)||overlap(p->tramp_base,4096,p->guard_base,p->guard_size))goto refused;
 uint8_t wanted[4096];if(!i04_trampolines(wanted,(uintptr_t)c->module_base[0])||memcmp(wanted,(void *)(uintptr_t)p->tramp_base,4096))goto refused;
 if(c->original_config.extract!=c->module_base[1]+0x2240||(void *)c->original_config.route!=c->module_base[1]+0x2248||(void *)c->original_config.callback!=c->module_base[1]+0x2250)goto refused;
 for(unsigned i=0;i<4;i++){
  if(p->targets[i]<p->guard_base||p->targets[i]-p->guard_base>=p->guard_size)goto refused;
  if(i<3){const I04_SITE *s=&i04_sites[i];c->site[i]=(uintptr_t)c->module_base[0]+s->rva;c->length[i]=s->length;memcpy(c->original[i],s->bytes,s->length);memset(c->replacement[i],0x90,s->length);jump(c->replacement[i],p->targets[i]);}
  else{c->site[i]=(uintptr_t)&p->config->callback;c->length[i]=8;if(c->site[i]&7)goto refused;memcpy(c->original[i],&c->original_config.callback,8);memcpy(c->replacement[i],&p->targets[i],8);}
  for(unsigned j=0;j<i;j++)if(overlap(c->site[i],c->length[i],c->site[j],c->length[j]))goto refused;
 }
 if(!service_tables(v))goto refused;c->raise=v->bs->raise_tpl;c->restore=v->bs->restore_tpl;
 ap_sha256((const void *)&c->plan,sizeof(c->plan),c->plan_sha);ap_sha256((void *)(uintptr_t)p->guard_base,p->guard_size,c->guard_sha);ap_sha256((void *)(uintptr_t)p->tramp_base,4096,c->tramp_sha);
 if(!i04_validate(c,0))goto refused;
 c->phase=I04_PREPARED;c->busy=0;return I04_OK;
refused:c->busy=0;return c->ended?I04_ENDED:I04_REFUSED;
}
static void serialize(void){uint32_t a,b,c,d;__asm__ volatile("mfence":::"memory");__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0),"c"(0):"memory");}
static I04_RESULT held(I04_TX *c){c->phase=I04_HELD;c->busy=0;return c->ended?I04_ENDED:I04_HOLD;}
static I04_RESULT finish(I04_TX *c,I04_RESULT result){
 if(c->ended||c->vm->ended||!i04_vm_current(c->vm)||!service_tables(c->vm)||
    c->vm->bs->restore_tpl!=c->restore||!i04_access(c->vm,(uintptr_t)c->restore,1,0,1))return held(c);
 c->restore(c->old_tpl);c->busy=0;if(c->ended||c->vm->ended)return held(c);return result;
}
static int site_write(I04_TX *c,unsigned i,int patched){
 void *p=(void *)(uintptr_t)c->site[i];const uint8_t *wanted=patched?c->replacement[i]:c->original[i],*before=patched?c->original[i]:c->replacement[i];
 if(i==3){uint64_t expected,value;memcpy(&expected,before,8);memcpy(&value,wanted,8);if(!__atomic_compare_exchange_n((uint64_t *)p,&expected,value,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST))return 0;}
 else write_bytes(p,wanted,c->length[i]);
 return same(p,wanted,c->length[i]);
}
static I04_RESULT rollback(I04_TX *c){
 /* Never overwrite unknown bytes or resume after loss of execution context.
  * In HOLD, caller must stay resident; unloading would strand native jumps. */
 if(c->ended||!i04_validate(c,c->attempted))return held(c);
 for(unsigned i=4;i;i--){unsigned at=i-1;if(!(c->attempted&(1u<<at)))continue;
  c->touched|=1u<<at;if(!site_write(c,at,0)){c->unknown_site=at+1;return held(c);}c->attempted&=~(1u<<at);}
 serialize();if(!i04_validate(c,0))return held(c);c->phase=I04_RETIRED;return finish(c,I04_ROLLED_BACK);
}
I04_RESULT i04_install(I04_TX *c){
 if(!c||c->magic!=I04_MAGIC)return I04_REFUSED;if(c->ended)return I04_ENDED;if(c->busy)return I04_BUSY;if(c->phase!=I04_PREPARED)return I04_REFUSED;
 if(!i04_validate(c,0))return I04_REFUSED;c->busy=1;c->old_tpl=c->raise(16);
 if(c->ended||c->vm->ended)return held(c);if(c->old_tpl!=4)return finish(c,I04_REFUSED);
 if(!i04_validate(c,0))return finish(c,I04_REFUSED);
 for(unsigned i=0;i<4;i++){
  c->touched|=1u<<i;if(!site_write(c,i,1)){c->unknown_site=i+1;return held(c);}c->attempted|=1u<<i;
  if(!i04_validate(c,c->attempted))return rollback(c);
 }
 serialize();c->phase=I04_INSTALLED;return finish(c,I04_OK);
}
I04_RESULT i04_remove(I04_TX *c){
 if(!c||c->magic!=I04_MAGIC)return I04_REFUSED;if(c->ended)return I04_ENDED;if(c->busy)return I04_BUSY;if(c->phase!=I04_INSTALLED)return I04_REFUSED;
 if(!i04_validate(c,15))return I04_REFUSED;c->busy=1;c->old_tpl=c->raise(16);
 if(c->ended||c->vm->ended)return held(c);if(c->old_tpl!=4)return finish(c,I04_REFUSED);return rollback(c);
}
void i04_end(I04_TX *c){if(c&&c->magic==I04_MAGIC){c->ended=1;if(c->vm)c->vm->ended=1;}}
