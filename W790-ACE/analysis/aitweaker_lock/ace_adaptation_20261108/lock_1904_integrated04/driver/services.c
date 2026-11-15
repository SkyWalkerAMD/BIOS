#include "lock.h"
#include "probe_core.h"
#include "save_feedback.h"
ST *system_table;
AP_CORE password_core;
int platform_ready,boot_services_ended;
SETVAR original_set_variable;
GUID credential_guid={0x750e9d9d,0xf2d8,0x4e14,{0x9b,0x53,0x89,0x23,0xa7,0x19,0x04,0x61}};
GUID oc_guid={0xa3a3b874,0x7636,0x4182,{0xba,0x1e,0xf5,0x2c,0x58,0x44,0x94,0xe3}};
GUID memory_guid={0x98cf19ed,0x4109,0x4681,{0xb7,0x9d,0x91,0x96,0x75,0x7c,0x78,0x24}};
C16 credential_name[]=L"AiTweakerPassword1904";
static C16 oc_name[]=L"VARSTORE_OCMR_SETTINGS_NAME",memory_name[]=L"SocketMemoryConfig";
static GUID rng_guid={0x3152bca5,0xeade,0x433d,{0x86,0x2e,0xc0,0x1c,0xdc,0x29,0x1f,0x44}};
static GUID attr_guid={0xf4560cf6,0x40ec,0x4b4a,{0xa1,0x92,0xbf,0x1d,0x57,0xd0,0xb1,0x89}};
static GUID cpu_guid={0x26baccb1,0x6f42,0x11d4,{0xbc,0xe7,0,0x80,0xc7,0x3c,0x88,0x81}};
static CPU *clock_cpu;
static uint64_t clock_origin,clock_period,clock_ticks_per_ms;
static EVENT exit_event,before_exit_event;
static GUID before_exit_guid=BEFORE_EXIT_BOOT_SERVICES_GUID;
static int guard_may_be_published,before_exit_seen,services_initialized;
static uint32_t handoff_error;
static uint8_t old_variable[26681];
static int write_guard_busy;
typedef struct {uint32_t code,reserved;uint64_t value;} AUDIT_ITEM;
static struct {uint32_t version,count;AUDIT_ITEM items[128];} audit_log={1,0,{{0,0,0}}};
void *memcpy(void *d,const void *s,size_t n) {uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n) {uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n) {const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
size_t c16len(const C16 *s) {size_t n=0;while(s && s[n] && n<1048576)n++;return n;}
int c16equal(const C16 *a,const C16 *b) {if(!a||!b)return 0;for(size_t i=0;i<128;i++){if(a[i]!=b[i])return 0;if(!a[i])return 1;}return 0;}
void *alloc(UN n) {void *p=0;if(n && n<=32*1024*1024 && !FAILED(system_table->bs->allocate_pool(4,n,&p)))return p;return 0;}
void release(void *p) {if(p)system_table->bs->free_pool(p);}
void audit(uint32_t code,uint64_t value) {uint32_t n=audit_log.count++;audit_log.items[n%128]=(AUDIT_ITEM){code,0,value};}
static AP_READ_RESULT read_record(void *v,uint8_t *out,size_t capacity,size_t *length) {
 (void)v;UN n=capacity;uint32_t attributes=0;
 ES s=system_table->rt->get_variable(credential_name,&credential_guid,&attributes,&n,out);
 *length=n;
 if(s==ERR(14)){*length=0;return AP_READ_NOT_FOUND;}
 if(FAILED(s) || attributes!=3)return AP_READ_ERROR;
 return AP_READ_OK;
}
static int persist_record(void *v,const uint8_t *record,size_t n) {
 (void)v;
 if(!platform_session_owned())return 1;
 uint8_t check[AP_RECORD_BYTES],before[AP_RECORD_BYTES];size_t before_n=0,after_n=0;
 AP_READ_RESULT before_status=read_record(0,before,sizeof(before),&before_n);
 /* GetVariable can call firmware code; revalidate the owning browser lifetime
  * before allowing the private persistence adapter to commit a credential. */
 if(!platform_session_owned()) {
  ap_secure_zero(before,sizeof(before));ap_secure_zero(check,sizeof(check));return 1;
 }
 ES s=original_set_variable(credential_name,&credential_guid,3,n,(void *)record);
 AP_READ_RESULT after_status=read_record(0,check,sizeof(check),&after_n);
 int success=!FAILED(s) && after_status==AP_READ_OK && after_n==n && ap_constant_equal(record,check,n);
 if(!success) {
  int unchanged=before_status==after_status && before_n==after_n &&
   ((before_status==AP_READ_NOT_FOUND) || (before_status==AP_READ_OK && before_n<=sizeof(before) && ap_constant_equal(before,check,before_n)));
  if(!unchanged || !FAILED(s))ap_fault(&password_core);
 }
 ap_secure_zero(before,sizeof(before));ap_secure_zero(check,sizeof(check));audit(20,s);return success?0:1;
}
static int entropy(void *v,uint8_t *out,size_t n) {
 (void)v;RNG *rng=0;
 ES located=system_table->bs->locate_protocol(&rng_guid,0,(void **)&rng);
 if(located==ERR(14))return cpu_entropy(out,n);
 if(FAILED(located) || !rng || !rng->get) {ap_secure_zero(out,n);return 1;}
 if(FAILED(rng->get(rng,0,n,out))) {ap_secure_zero(out,n);return 1;}
 return 0;
}
static int now_ms(void *v,uint64_t *value) {
 (void)v;uint64_t ticks=0,period=0;
 if(!clock_cpu && (FAILED(system_table->bs->locate_protocol(&cpu_guid,0,(void **)&clock_cpu)) || !clock_cpu))return 1;
 if(!clock_cpu->timer_count || FAILED(clock_cpu->timer(clock_cpu,0,&ticks,&period)) || !period || period>1000000000000ULL)return 1;
 if(!clock_period) {
  /* Some firmware calibrates the advertised CPU timer period over only 100 us.
   * That was measurably inaccurate in TCG. Calibrate the counter over three
   * standard 100-ms Stall intervals and retain the least interrupted sample.
   * Stall guarantees a minimum delay; rounding upward is conservative. */
  uint64_t best=UINT64_MAX;
  for(unsigned i=0;i<3;i++) {
   uint64_t first=0,last=0;
   if(FAILED(clock_cpu->timer(clock_cpu,0,&first,0)) || FAILED(system_table->bs->stall(100000)) ||
      FAILED(clock_cpu->timer(clock_cpu,0,&last,0)) || last<=first)return 1;
   if(last-first<best)best=last-first;
  }
  if(best>UINT64_MAX-99)return 1;
  clock_ticks_per_ms=(best+99)/100;
  if(!clock_ticks_per_ms || FAILED(clock_cpu->timer(clock_cpu,0,&ticks,0)))return 1;
  clock_origin=ticks;clock_period=period;
 }
 if(period!=clock_period || ticks<clock_origin)return 1;
 /* Round ticks/ms upward so conversion never shortens the retry interval.
  * Count hardware ticks: EFI timer notification callbacks can be coalesced. */
 *value=(ticks-clock_origin)/clock_ticks_per_ms;return 0;
}
int protection_for_variable(C16 *name,GUID *guid) {
 if(!name || !guid)return 0;
 if(!memcmp(guid,&credential_guid,16) && c16equal(name,credential_name))return 3;
 if(!memcmp(guid,&oc_guid,16) && c16equal(name,oc_name))return 1;
 if(!memcmp(guid,&memory_guid,16) && c16equal(name,memory_name))return 2;
 return 0;
}
int protected_change(int kind,uint32_t attributes,UN size,const void *value) {
 UN old_size=sizeof(old_variable);uint32_t old_attributes=0;UN required=kind==1?26681:1392;
 if(!value || size!=required || (attributes&0x40) || write_guard_busy)return 1;
 write_guard_busy=1;
 ES s=system_table->rt->get_variable(kind==1?oc_name:memory_name,kind==1?&oc_guid:&memory_guid,&old_attributes,&old_size,old_variable);
 int changed=FAILED(s) || old_size!=required || attributes!=old_attributes;
 if(!changed) {
  if(kind==1)changed=memcmp(old_variable,value,(size_t)size)!=0;
  else {const uint8_t *p=value;changed=old_variable[0x10]!=p[0x10] || old_variable[0xbd]!=p[0xbd] || old_variable[0xbe]!=p[0xbe];}
 }
 ap_secure_zero(old_variable,sizeof(old_variable));write_guard_busy=0;return changed;
}
static ES EA guarded_set(C16 *name,GUID *guid,uint32_t attributes,UN size,void *value) {
 int kind=protection_for_variable(name,guid);
 /* Only the private persistence adapter can update the credential. */
 if(kind==3){save_feedback_note_denial(ERR(15));audit(21,ERR(15));return ERR(15);}
 if(kind && password_core.mode!=AP_MODE_DISABLED && !platform_can_enter() && protected_change(kind,attributes,size,value)) {
  save_feedback_note_denial(ERR(15));audit(22,(uint64_t)kind);return ERR(15);
 }
 return original_set_variable(name,guid,attributes,size,value);
}
/* Check actual page-table write bits before a fallback write. Never disable CR0.WP.
 * Boot Services x64 identity mapping is required; after ExitBootServices forbidden. */
int memory_present(const void *p,UN n,int write) {
 uint64_t a=(uint64_t)(uintptr_t)p,end,cr3,cr4;
 if(!n || a<4096 || a>0x0000ffffffffffffULL || n>0x0001000000000000ULL-a)return 0;
 end=a+n-1;
 __asm__ volatile("mov %%cr3,%0":"=r"(cr3));__asm__ volatile("mov %%cr4,%0":"=r"(cr4));
 for(a&=~4095ULL;a<=end;a+=4096) {
  uint64_t table=cr3&0x000ffffffffff000ULL;int levels=(cr4&(1ULL<<12))?5:4;
  for(int level=levels;level>=1;level--) {
   uint64_t entry=((volatile uint64_t *)(uintptr_t)table)[(a>>(12+9*(level-1)))&511];
   if(!(entry&1) || (write && !(entry&2)))return 0;
   if(level==1 || ((level==2 || level==3) && (entry&128)))break;
   table=entry&0x000ffffffffff000ULL;if(!table)return 0;
  }
 }
 return 1;
}
int patch_memory(void *target,const void *bytes,UN n) {
 MEMATTR *ma=0;uint64_t base=(uint64_t)(uintptr_t)target&~4095ULL;
 uint64_t end=((uint64_t)(uintptr_t)target+n+4095)&~4095ULL,attrs[4]={0};
 if(boot_services_ended || !n || end<base || end-base>sizeof(attrs)/sizeof(attrs[0])*4096)return 0;
 if(!FAILED(system_table->bs->locate_protocol(&attr_guid,0,(void **)&ma)) && ma) {
  UN count=(end-base)/4096,cleared=0;
  for(UN i=0;i<count;i++) {
   if(FAILED(ma->get(ma,base+i*4096,4096,&attrs[i])))goto fail;
   if((attrs[i]&0x20000) && FAILED(ma->clear(ma,base+i*4096,4096,0x20000)))goto fail;
   cleared++;
  }
  if(!memory_present(target,n,1))goto fail;
  {UN old=system_table->bs->raise_tpl(16);memcpy(target,bytes,(size_t)n);system_table->bs->restore_tpl(old);}
  for(UN i=0;i<count;i++)if((attrs[i]&0x20000) && FAILED(ma->set(ma,base+i*4096,4096,0x20000))) {audit(90,base);ap_fault(&password_core);return 0;}
  return memcmp(target,bytes,(size_t)n)==0;
fail:
  for(UN i=0;i<cleared;i++)if(attrs[i]&0x20000)ma->set(ma,base+i*4096,4096,0x20000);
  return 0;
 }
 if(!memory_present(target,n,1))return 0;
 UN old=system_table->bs->raise_tpl(16);memcpy(target,bytes,(size_t)n);system_table->bs->restore_tpl(old);
 return memcmp(target,bytes,(size_t)n)==0;
}
static int update_runtime_set(SETVAR fn) {
 RT copy=*system_table->rt;
 if(copy.hdr.size<offsetof(RT,set_variable)+8 || copy.hdr.size>sizeof(copy))return 0;
 copy.set_variable=fn;copy.hdr.crc=0;
 if(FAILED(system_table->bs->crc32(&copy,copy.hdr.size,&copy.hdr.crc)))return 0;
 return patch_memory(system_table->rt,&copy,copy.hdr.size);
}
static int local_runtime_crc_valid(void) {
 /* Deliberately independent of Boot Services and protocol providers. */
 RT copy=*system_table->rt;uint32_t expected=copy.hdr.crc;
 if(copy.hdr.sig!=EFI_RUNTIME_SERVICES_SIGNATURE || copy.hdr.reserved ||
    copy.hdr.size<offsetof(RT,set_variable)+8 || copy.hdr.size>sizeof(copy))return 0;
 copy.hdr.crc=0;return probe_crc32(&copy,copy.hdr.size)==expected;
}
static void stop_browser_context(void) {
 /* end_platform must remain a local-state-only operation at final EBS. */
 end_platform();ap_session_end(&password_core);
 ap_secure_zero(password_core.record,sizeof(password_core.record));boot_services_ended=1;
}
static __attribute__((noreturn)) void fatal_handoff(uint32_t reason) {
 /* Do not return a Boot Services code pointer to an OS which can reclaim it.
  * This exceptional path uses no reset, variable, protocol or boot service.
  * It intentionally stops boot and requires external recovery; it has only
  * been tested in emulation, never asserted safe for unattended deployment. */
 handoff_error=reason;audit(93,reason);stop_browser_context();
 for(;;)__asm__ volatile("cli; hlt");
}
static void EA before_exiting(EVENT e,void *v) {
 (void)e;(void)v;
 /* The first EBS attempt may signal twice and may later reject MapKey.
  * Retire permanently on its first BeforeExit notification. */
 if(before_exit_seen)return;
 before_exit_seen=1;
 end_platform();ap_session_end(&password_core);
 if(guard_may_be_published) {
  if(!local_runtime_crc_valid())handoff_error=1;
  else if(system_table->rt->set_variable==guarded_set) {
   int restored=0;
   for(unsigned attempt=0;attempt<2;attempt++) {
    if(update_runtime_set(original_set_variable)){restored=1;break;}
    /* A partial write, bad CRC or another owner is not a safe retry state. */
    if(system_table->rt->set_variable!=guarded_set || !local_runtime_crc_valid())break;
   }
   if(!restored)handoff_error=2;
  } else if(system_table->rt->set_variable!=original_set_variable)handoff_error=3;
  if(!handoff_error && (system_table->rt->set_variable!=original_set_variable ||
     !local_runtime_crc_valid()))handoff_error=4;
 }
 audit(92,handoff_error);stop_browser_context();
}
static void EA exiting(EVENT e,void *v) {
 (void)e;(void)v;
 /* A provider may already have handled its own Exit notification. No calls
  * to Boot Services or protocol methods are permitted in this callback. */
 if(guard_may_be_published) {
  if(handoff_error)fatal_handoff(handoff_error);
  if(!before_exit_seen || system_table->rt->set_variable!=original_set_variable)fatal_handoff(5);
  if(!local_runtime_crc_valid())fatal_handoff(6);
 }
 stop_browser_context();
}
int initialize_services(void) {
 if(services_initialized)return !before_exit_seen && !boot_services_ended;
 if(before_exit_seen || boot_services_ended || !system_table || !system_table->bs ||
    !system_table->rt || !system_table->rt->set_variable || !local_runtime_crc_valid())return 0;
 original_set_variable=system_table->rt->set_variable;
 AP_ENV env={0,read_record,persist_record,entropy,now_ms};ap_init(&password_core,&env);
 if(FAILED(system_table->bs->create_event(EVT_SIGNAL_EXIT_BOOT_SERVICES,TPL_NOTIFY,exiting,0,&exit_event)))return 0;
 if(!system_table->bs->create_event_ex || FAILED(system_table->bs->create_event_ex(EVT_NOTIFY_SIGNAL,TPL_NOTIFY,before_exiting,0,&before_exit_guid,&before_exit_event))) {
  /* Returning loader failure is safe only after removing our callback. */
  if(FAILED(system_table->bs->close_event(exit_event)))fatal_handoff(7);
  exit_event=0;return 0;
 }
 services_initialized=1;return 1;
}
int install_variable_guard(void) {
 if(!services_initialized || before_exit_seen || boot_services_ended)return 0;
 if(system_table->rt->set_variable!=original_set_variable || !local_runtime_crc_valid())return 0;
 /* Track any attempted publication, including a partially failed write. */
 guard_may_be_published=1;
 return update_runtime_set(guarded_set);
}
