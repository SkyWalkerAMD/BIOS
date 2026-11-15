#include "provider.h"
ST *system_table;
static GUID credential_guid={0x750e9d9d,0xf2d8,0x4e14,{0x9b,0x53,0x89,0x23,0xa7,0x19,0x04,0x61}};
static C16 credential_name[]=L"AiTweakerPassword1904";
static GUID rng_guid={0x3152bca5,0xeade,0x433d,{0x86,0x2e,0xc0,0x1c,0xdc,0x29,0x1f,0x44}};
static GUID cpu_guid={0x26baccb1,0x6f42,0x11d4,{0xbc,0xe7,0,0x80,0xc7,0x3c,0x88,0x81}};
static SETVAR persist_variable;
static CPU *clock_cpu;
static uint64_t clock_origin,clock_period,clock_ticks_per_ms;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
size_t c16len(const C16 *s){size_t n=0;while(s&&s[n]&&n<1048576)n++;return n;}
void *alloc(UN n){void *p=0;if(!boot_services_ended&&n&&n<=32*1024*1024&&!FAILED(system_table->bs->allocate_pool(4,n,&p))&&!boot_services_ended)return p;return 0;}
void release(void *p){if(p&&!boot_services_ended)system_table->bs->free_pool(p);}
/* Only numeric operation/status diagnostics; no credential, salt or verifier. */
static struct{uint32_t count,reserved;struct{uint32_t code,reserved;uint64_t value;}item[32];}audit_ring;
void audit(uint32_t code,uint64_t value){unsigned n=audit_ring.count++%32;audit_ring.item[n].code=code;audit_ring.item[n].value=value;}
int memory_present(const void *p,UN n,int write){
 uint64_t a=(uint64_t)(uintptr_t)p,cr3,cr4;
 if(boot_services_ended||!n||a<4096)return 0;
 __asm__ volatile("mov %%cr3,%0":"=r"(cr3));__asm__ volatile("mov %%cr4,%0":"=r"(cr4));
 uint64_t limit=(cr4&(1ULL<<12))?(1ULL<<56):(1ULL<<47);
 if(a>=limit||n>limit-a)return 0;uint64_t end=a+n-1;
 for(a&=~4095ULL;a<=end;a+=4096){
  uint64_t table=cr3&0x000ffffffffff000ULL;int levels=(cr4&(1ULL<<12))?5:4;
  if(!table)return 0;
  for(int level=levels;level>=1;level--){
   uint64_t e=((volatile uint64_t *)(uintptr_t)table)[(a>>(12+9*(level-1)))&511];
   if(!(e&1)||(write&&!(e&2)))return 0;
   if(level==1||((level==2||level==3)&&(e&128)))break;
   table=e&0x000ffffffffff000ULL;if(!table)return 0;
  }
 }return 1;
}
static AP_READ_RESULT read_record(void *v,uint8_t *out,size_t capacity,size_t *length){
 (void)v;if(boot_services_ended){*length=0;return AP_READ_ERROR;}
 UN n=capacity;uint32_t attributes=0;ES s=system_table->rt->get_variable(credential_name,&credential_guid,&attributes,&n,out);
 if(boot_services_ended){ap_secure_zero(out,capacity);*length=0;return AP_READ_ERROR;}*length=n;
 if(s==ERR(14)){*length=0;return AP_READ_NOT_FOUND;}
 if(FAILED(s)||attributes!=3)return AP_READ_ERROR;return AP_READ_OK;
}
static int persist_record(void *v,const uint8_t *record,size_t n){
 (void)v;if(n!=AP_RECORD_BYTES||!record||!ap_record_valid(record,n)||!platform_session_owned())return 1;
 uint8_t before[AP_RECORD_BYTES],after[AP_RECORD_BYTES];size_t bn=0,an=0;
 AP_READ_RESULT bs=read_record(0,before,sizeof(before),&bn);
 int expected=(password_core.mode==AP_MODE_UNCONFIGURED)?bs==AP_READ_NOT_FOUND&&bn==0:
  bs==AP_READ_OK&&bn==AP_RECORD_BYTES&&ap_constant_equal(before,password_core.record,AP_RECORD_BYTES);
 if(!expected||!platform_session_owned()){
  provider_fault();ap_secure_zero(before,sizeof(before));return 1;
 }
 ES s=persist_variable(credential_name,&credential_guid,3,n,(void *)record);
 if(boot_services_ended){provider_fault();ap_secure_zero(before,sizeof(before));ap_secure_zero(after,sizeof(after));return 1;}
 AP_READ_RESULT as=read_record(0,after,sizeof(after),&an);
 int success=!FAILED(s)&&as==AP_READ_OK&&an==n&&ap_constant_equal(after,record,n);
 if(!success){
  int unchanged=bs==as&&bn==an&&(bs==AP_READ_NOT_FOUND||(bs==AP_READ_OK&&bn<=sizeof(before)&&ap_constant_equal(before,after,bn)));
  if(!unchanged||!FAILED(s))provider_fault();
 }
 ap_secure_zero(before,sizeof(before));ap_secure_zero(after,sizeof(after));audit(20,s);return success?0:1;
}
static int entropy(void *v,uint8_t *out,size_t n){
 (void)v;if(boot_services_ended||!platform_session_owned()){ap_secure_zero(out,n);return 1;}
 RNG *rng=0;ES s=system_table->bs->locate_protocol(&rng_guid,0,(void **)&rng);
 if(boot_services_ended)goto failure;
 if(s==ERR(14)){int result=cpu_entropy(out,n);if(boot_services_ended||result)goto failure;return 0;}
 if(FAILED(s)||!rng||!rng->get)goto failure;
 s=rng->get(rng,0,n,out);if(boot_services_ended||FAILED(s))goto failure;return 0;
failure:ap_secure_zero(out,n);return 1;
}
static int now_ms(void *v,uint64_t *value){
 (void)v;if(boot_services_ended)return 1;uint64_t ticks=0,period=0;
 if(!clock_cpu){ES s=system_table->bs->locate_protocol(&cpu_guid,0,(void **)&clock_cpu);if(boot_services_ended||FAILED(s)||!clock_cpu)return 1;}
 if(!clock_cpu->timer_count||!clock_cpu->timer)return 1;
 ES s=clock_cpu->timer(clock_cpu,0,&ticks,&period);if(boot_services_ended||FAILED(s)||!period||period>1000000000000ULL)return 1;
 if(!clock_period){
  uint64_t best=UINT64_MAX;
  for(unsigned i=0;i<3;i++){
   uint64_t first=0,last=0;
   s=clock_cpu->timer(clock_cpu,0,&first,0);if(boot_services_ended||FAILED(s))return 1;
   s=system_table->bs->stall(100000);if(boot_services_ended||FAILED(s))return 1;
   s=clock_cpu->timer(clock_cpu,0,&last,0);if(boot_services_ended||FAILED(s)||last<=first)return 1;
   if(last-first<best)best=last-first;
  }
  if(best>UINT64_MAX-99)return 1;clock_ticks_per_ms=(best+99)/100;
  if(!clock_ticks_per_ms)return 1;s=clock_cpu->timer(clock_cpu,0,&ticks,0);if(boot_services_ended||FAILED(s))return 1;clock_origin=ticks;clock_period=period;
 }
 if(period!=clock_period||ticks<clock_origin)return 1;*value=(ticks-clock_origin)/clock_ticks_per_ms;return 0;
}
static int EA application_tpl(void){
 if(boot_services_ended||!system_table||!system_table->bs||!system_table->bs->raise_tpl||!system_table->bs->restore_tpl)return 0;
 UN prior=system_table->bs->raise_tpl(31);if(boot_services_ended)return 0;system_table->bs->restore_tpl(prior);return !boot_services_ended&&prior==4;
}
static int EA writable(void *p,UN n){return memory_present(p,n,1);}
static int EA prompt(int operation){
 TEXTOUT *o=system_table->out;INPUT *i=system_table->in;
 if(boot_services_ended||!o||!i||!i->read||!o->out||!o->attribute||!o->clear||!o->enable_cursor||!o->cursor)return 0;
 return operation<0?ensure_unlocked():manage_password(operation);
}
int initialize_native_services(ST *st){
 if(!st||!st->bs||!st->rt||!st->rt->get_variable||!st->rt->set_variable||!st->bs->raise_tpl||!st->bs->restore_tpl||!st->bs->allocate_pool||!st->bs->free_pool||!st->bs->locate_protocol||!st->bs->stall)return 0;
 system_table=st;persist_variable=st->rt->set_variable;
 AP_ENV env={0,read_record,persist_record,entropy,now_ms};PROVIDER_HOST hooks={application_tpl,verify_owner_caller,verify_owner_active,writable,prompt};
 AP_STATUS s=provider_initialize(&env,&hooks);audit(1,(uint64_t)s);return !boot_services_ended&&(s==AP_OK||s==AP_UNCONFIGURED||s==AP_CREDENTIAL_ERROR);
}
