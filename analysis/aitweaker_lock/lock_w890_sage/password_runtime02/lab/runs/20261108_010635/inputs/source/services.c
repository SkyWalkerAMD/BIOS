#include "runtime.h"
ST *w890_system_table;
int w890_runtime_ended;
GUID w890_credential_guid={0x7aa1505b,0xef11,0x4c41,{0x90,0x02,0x42,0x7f,0x82,0x69,0x03,0xe6}};
C16 w890_credential_name[]=L"AiTweakerPasswordW890V1";
static GUID rng_guid={0x3152bca5,0xeade,0x433d,{0x86,0x2e,0xc0,0x1c,0xdc,0x29,0x1f,0x44}};
static GUID cpu_guid={0x26baccb1,0x6f42,0x11d4,{0xbc,0xe7,0,0x80,0xc7,0x3c,0x88,0x81}};
static GETVAR original_get;
static SETVAR original_set;
static CPU *clock_cpu;
static uint64_t clock_origin,clock_period,ticks_per_ms;
static EVENT end_event;
static int bound;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
int w890_runtime_alive(void){return w890_system_table&&!w890_runtime_ended&&!(w890_provider_query(&w890_provider)&W890_PROVIDER_ENDED);}
int w890_runtime_active(void){return w890_runtime_alive()&&w890_session_owned();}
void w890_runtime_end_boot(void){w890_runtime_ended=1;w890_provider_end_boot();}
static void EA on_end(EVENT event,void *context){(void)event;(void)context;w890_runtime_end_boot();}
void *w890_alloc(UN n){void *p=0;if(w890_runtime_alive()&&n&&n<=32*1024*1024&&!FAILED(w890_system_table->bs->allocate_pool(4,n,&p))&&w890_runtime_alive())return p;return 0;}
void w890_release(void *p){if(p&&w890_runtime_alive())w890_system_table->bs->free_pool(p);}
int w890_memory_present(const void *p,UN n,int write){
 uint64_t a=(uint64_t)(uintptr_t)p,cr3,cr4;
 if(w890_runtime_ended||!n||a<4096)return 0;
 __asm__ volatile("mov %%cr3,%0":"=r"(cr3));__asm__ volatile("mov %%cr4,%0":"=r"(cr4));
 uint64_t limit=(cr4&(1ULL<<12))?(1ULL<<56):(1ULL<<47);
 if(a>=limit||n>limit-a)return 0;uint64_t end=a+n-1;
 for(a&=~4095ULL;a<=end;a+=4096){
  uint64_t table=cr3&0x000ffffffffff000ULL;int levels=(cr4&(1ULL<<12))?5:4;if(!table)return 0;
  for(int level=levels;level>=1;level--){
   uint64_t e=((volatile uint64_t *)(uintptr_t)table)[(a>>(12+9*(level-1)))&511];
   if(!(e&1)||(write&&!(e&2)))return 0;
   if(level==1||((level==2||level==3)&&(e&128)))break;
   table=e&0x000ffffffffff000ULL;if(!table)return 0;
  }
 }return 1;
}
AP_READ_RESULT w890_read_record(void *unused,uint8_t *out,size_t cap,size_t *length){
 (void)unused;if(!length)return AP_READ_ERROR;*length=0;
 if(!out||cap!=AP_RECORD_BYTES||!original_get||!w890_runtime_alive())return AP_READ_ERROR;
 UN n=cap;uint32_t attributes=0;ES s=original_get(w890_credential_name,&w890_credential_guid,&attributes,&n,out);
 if(!w890_runtime_alive()){ap_secure_zero(out,cap);return AP_READ_ERROR;}
 if(s==ERR(14)){ap_secure_zero(out,cap);return AP_READ_NOT_FOUND;}
 *length=n;
 if(FAILED(s)||n!=AP_RECORD_BYTES||attributes!=3){ap_secure_zero(out,cap);return AP_READ_ERROR;}
 return AP_READ_OK;
}
int w890_persist_record(void *unused,const uint8_t *record,size_t n){
 (void)unused;if(!record||n!=AP_RECORD_BYTES||!ap_record_valid(record,n)||!w890_runtime_active())return 1;
 uint8_t before[AP_RECORD_BYTES],after[AP_RECORD_BYTES];size_t bn=0,an=0;int success=0;
 AP_READ_RESULT bs=w890_read_record(0,before,sizeof(before),&bn);
 int expected=w890_password_core.mode==AP_MODE_UNCONFIGURED?bs==AP_READ_NOT_FOUND&&bn==0:
  bs==AP_READ_OK&&bn==AP_RECORD_BYTES&&ap_constant_equal(before,w890_password_core.record,AP_RECORD_BYTES);
 if(!expected||!w890_runtime_active()){w890_provider_fault();goto done;}
 ES status=original_set(w890_credential_name,&w890_credential_guid,3,n,(void *)record);
 if(!w890_runtime_alive()){w890_provider_fault();goto done;}
 AP_READ_RESULT as=w890_read_record(0,after,sizeof(after),&an);
 success=!FAILED(status)&&as==AP_READ_OK&&an==n&&ap_constant_equal(after,record,n);
 if(!success){
  int unchanged=bs==as&&bn==an&&(bs==AP_READ_NOT_FOUND||(bs==AP_READ_OK&&bn==AP_RECORD_BYTES&&ap_constant_equal(before,after,bn)));
  if(!unchanged||!FAILED(status))w890_provider_fault();
 }
done:ap_secure_zero(before,sizeof(before));ap_secure_zero(after,sizeof(after));return success?0:1;
}
int w890_entropy(void *unused,uint8_t *out,size_t n){
 (void)unused;if(!out||!n||n>256)return 1;ap_secure_zero(out,n);
 if(!w890_runtime_active())return 1;
 RNG *rng=0;ES s=w890_system_table->bs->locate_protocol(&rng_guid,0,(void **)&rng);
 if(!w890_runtime_active())goto failed;
 if(s==ERR(14)){int r=cpu_entropy(out,n);if(r||!w890_runtime_active())goto failed;return 0;}
 if(FAILED(s)||!w890_memory_present(rng,sizeof(*rng),0)||!rng->get)goto failed;
 s=rng->get(rng,0,n,out);if(FAILED(s)||!w890_runtime_active())goto failed;return 0;
failed:ap_secure_zero(out,n);return 1;
}
int w890_now_ms(void *unused,uint64_t *value){
 (void)unused;if(!value||!w890_runtime_active())return 1;uint64_t ticks=0,period=0;
 if(!clock_cpu){ES s=w890_system_table->bs->locate_protocol(&cpu_guid,0,(void **)&clock_cpu);if(!w890_runtime_active()||FAILED(s)||!w890_memory_present(clock_cpu,sizeof(*clock_cpu),0))return 1;}
 if(!clock_cpu->timer_count||!clock_cpu->timer)return 1;
 ES s=clock_cpu->timer(clock_cpu,0,&ticks,&period);if(!w890_runtime_active()||FAILED(s)||!period||period>1000000000000ULL)return 1;
 if(!clock_period){
  uint64_t best=UINT64_MAX;
  for(unsigned i=0;i<3;i++){
   uint64_t first=0,last=0;s=clock_cpu->timer(clock_cpu,0,&first,0);if(!w890_runtime_active()||FAILED(s))return 1;
   s=w890_system_table->bs->stall(100000);if(!w890_runtime_active()||FAILED(s))return 1;
   s=clock_cpu->timer(clock_cpu,0,&last,0);if(!w890_runtime_active()||FAILED(s)||last<=first)return 1;
   if(last-first<best)best=last-first;
  }
  if(best>UINT64_MAX-99)return 1;ticks_per_ms=(best+99)/100;if(!ticks_per_ms)return 1;
  s=clock_cpu->timer(clock_cpu,0,&ticks,0);if(!w890_runtime_active()||FAILED(s))return 1;clock_origin=ticks;clock_period=period;
 }
 if(period!=clock_period||ticks<clock_origin)return 1;*value=(ticks-clock_origin)/ticks_per_ms;return 0;
}
AP_STATUS w890_runtime_bind(ST *st,const W890_HOST *owner,const uint8_t setup[32],const uint8_t tse[32]){
 if(bound||w890_runtime_ended)return AP_BUSY;
 if(!st||!owner||!st->bs||!st->rt||!st->rt->get_variable||!st->rt->set_variable||
    !st->bs->create_event||!st->bs->allocate_pool||!st->bs->free_pool||!st->bs->locate_protocol||!st->bs->stall)return AP_BAD_ARGUMENT;
 bound=1;w890_system_table=st;original_get=st->rt->get_variable;original_set=st->rt->set_variable;
 ES s=st->bs->create_event(0x201,8,on_end,0,&end_event);
 if(w890_runtime_ended||FAILED(s)||!end_event){w890_provider_fault();return AP_BAD_ARGUMENT;}
 AP_ENV env={0,w890_read_record,w890_persist_record,w890_entropy,w890_now_ms};W890_HOST host=*owner;host.prompt=w890_console_prompt;
 return w890_provider_initialize(&env,&host,setup,tse);
}
