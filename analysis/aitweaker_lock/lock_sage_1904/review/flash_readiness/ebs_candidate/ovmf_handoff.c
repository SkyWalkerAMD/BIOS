/* QEMU TCG-only, no OEM navigation and no intentional variable writes. */
#include "lock.h"
#include "probe_core.h"
static unsigned checks,before_notifications,exit_notifications;
static EVENT before_observer,exit_observer;
static GUID before_guid={0x8be0e274,0x3970,0x4b44,{0x80,0xc5,0x1a,0xb9,0x50,0x2f,0x3b,0xfc}};
static void trace(const char *s) {while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void hex(uint64_t n) {const char h[]="0123456789abcdef";for(unsigned i=0;i<16;i++){char s[]={h[(n>>((15-i)*4))&15],0};trace(s);}}
static void finish(int ok) {trace(ok?"EBS_CANDIDATE_OVMF_PASS\n":"EBS_CANDIDATE_OVMF_FAIL\n");__asm__ volatile("outl %0,%1"::"a"(ok?0x10u:0x11u),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *label) {checks++;trace(ok?"PASS ":"FAIL ");trace(label);trace("\n");if(!ok)finish(0);}
static int tcg(void) {uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354 && c==0x43544743 && d==0x47435447;}
void end_platform(void) {} /* Navigation is absent from this EBS-only fixture. */
static void EA before_seen(EVENT e,void *p) {(void)e;(void)p;before_notifications++;trace("OBSERVE_BEFORE_EXIT\n");}
static void EA exit_seen(EVENT e,void *p) {(void)e;(void)p;exit_notifications++;trace("OBSERVE_EXIT\n");}
static int crc_valid(void) {RT copy=*system_table->rt;uint32_t expected=copy.hdr.crc;copy.hdr.crc=0;return copy.hdr.size<=sizeof(copy) && probe_crc32(&copy,copy.hdr.size)==expected;}
ES EA efi_main(HANDLE image,ST *st) {
 if(!tcg())return ERR(3);system_table=st;
 trace("EBS_CANDIDATE_OVMF_BEGIN\n");
 check(initialize_services(),"candidate registers real BeforeExit and Exit callbacks");
 check(!st->bs->create_event_ex(0x200,16,before_seen,0,&before_guid,&before_observer),"register BeforeExit observation");
 check(!st->bs->create_event(0x201,16,exit_seen,0,&exit_observer),"register final observation");
 check(install_variable_guard(),"actual RT guard installed through actual page permission path");
 check(st->rt->set_variable!=original_set_variable && crc_valid(),"guarded RT pointer and CRC valid");
 ap_session_begin(&password_core);memset(password_core.record,0xa5,sizeof(password_core.record));
 UN n=0,key=0,desc=0;uint32_t version=0;
 check(st->bs->memory_map(&n,0,&key,&desc,&version)==ERR(5),"get real memory map size");
 n+=8192;UN capacity=n;void *map=alloc(capacity);check(map!=0,"allocate map before EBS attempt");
 check(!st->bs->memory_map(&n,map,&key,&desc,&version),"get real memory map");
 ES (EA *exit_bs)(HANDLE,UN)=(void *)st->bs->exit_boot_services;
 ES status=exit_bs(image,key+1);trace("WRONG_MAP_KEY_STATUS=");hex(status);trace("\n");
 check(status==ERR(2),"intentional stale MapKey returns INVALID_PARAMETER");
 trace("BEFORE_COUNT_AFTER_FAILED_EBS=");hex(before_notifications);trace("\n");
 if(boot_services_ended)check(st->rt->set_variable==original_set_variable && crc_valid(),"failed first EBS already leaves RT restored");
 for(unsigned attempt=0;attempt<3;attempt++) {
  n=capacity;status=st->bs->memory_map(&n,map,&key,&desc,&version);if(FAILED(status))break;
  status=exit_bs(image,key);if(!status)break;
 }
 check(!status,"real ExitBootServices succeeds after retry");
 check(before_notifications && exit_notifications,"real BeforeExit and final events delivered");
 check(boot_services_ended,"candidate handoff state committed");
 check(st->rt->set_variable==original_set_variable,"actual RuntimeServices pointer restored");
 check(crc_valid(),"restored RuntimeServices CRC valid without BootServices call");
 check(!password_core.active && !password_core.unlocked,"browser authorization removed");
 uint8_t zeros[128]={0};check(!memcmp(password_core.record,zeros,sizeof(zeros)),"credential verifier wiped");
 check(!install_variable_guard(),"guard cannot rearm after EBS failure/success sequence");
 trace("CHECKS=");hex(checks);trace("\n");finish(1);return 0;
}
