/* Runs only under QEMU TCG, before any firmware service access. */
#include "source/transaction.h"
#include "fixtures.h"
#include "../password/core/password_core.h"
static ST *st;static I04_VM vm;static I04_TX tx,prepare_probe;static LOADED loaded[2];static CONFIG config;
static uint32_t checks,lease_open,fail_once_mask,end_during_commit;static uint64_t owned[4];
static GUID cpu_guid={0x26baccb1,0x6f42,0x11d4,{0xbc,0xe7,0,0x80,0xc7,0x3c,0x88,0x81}};
typedef ES(EA *CPU_ATTR)(CPU *,uint64_t,uint64_t,uint64_t);
static CPU *cpu;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int x,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)x;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
static void trace(const char *s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void stop(unsigned c){__asm__ volatile("outl %0,%1"::"a"(c),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *label){checks++;trace(ok?"PASS ":"FAIL ");trace(label);trace("\n");if(!ok)stop(0x11);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
/* Lab lease covers only these four exclusively owned, unstarted allocations.
 * It is NOT a native ASUS browser/loader lifetime or security authority. */
static int EA lab_lease(void *context,uint64_t ticket){
 if(end_during_commit&&tx.busy&&!tx.attempted){end_during_commit=0;i04_end(&tx);return 0;}
 if(fail_once_mask&&tx.busy&&tx.attempted==fail_once_mask){fail_once_mask=0;return 0;}
 return context==&owned&&ticket==0x5443474c41423034ULL&&lease_open;
}
static void EA ended(EVENT e,void *ctx){(void)e;i04_end(ctx);}
static uint64_t pages(UN bytes){uint64_t p=0;check(!st->bs->allocate_pages(0,3,(bytes+4095)/4096,&p)&&p&&!(p&4095),"allocate exclusively owned lab code pages");return p;}
static void attrs(uint64_t p,UN n,uint64_t attr){check(!((CPU_ATTR)cpu->set_attributes)(cpu,p,(n+4095)&~4095ULL,attr),"real CPU architecture owned-page attribute change");}
static void fresh(void){check(i04_capture(&vm,st),"fresh real memory map and CPU page-table state");}
static I04_PLAN plan(void){I04_PLAN p={0};p.tse=&loaded[0];p.setup=&loaded[1];p.config=&config;
 p.guard_base=owned[2];p.guard_size=4096;p.tramp_base=owned[3];
 for(unsigned i=0;i<4;i++)p.targets[i]=owned[2]+16*i;
 p.lease=(I04_LEASE){&owned,0x5443474c41423034ULL,lab_lease};return p;}
static void reset(void){memset(&tx,0,sizeof(tx));fresh();}
ES EA efi_main(HANDLE image,ST *system){
 if(!tcg())return ERR(3);st=system;trace("W890_INSTALLER04_BEGIN\n");
 check(!st->bs->locate_protocol(&cpu_guid,0,(void **)&cpu)&&cpu&&cpu->set_attributes,"locate real CPU architecture protocol");
 const uint8_t *fixtures[2]={fixture_amitse,fixture_setup};UN sizes[2]={sizeof(fixture_amitse),sizeof(fixture_setup)};
 for(unsigned i=0;i<2;i++){owned[i]=pages(sizes[i]);attrs(owned[i],sizes[i],0x4000);memcpy((void *)(uintptr_t)owned[i],fixtures[i],sizes[i]);attrs(owned[i],sizes[i],0);
  loaded[i].revision=0x1000;loaded[i].image_base=(void *)(uintptr_t)owned[i];loaded[i].image_size=sizes[i];}
 owned[2]=pages(4096);attrs(owned[2],4096,0x4000);memset((void *)(uintptr_t)owned[2],0xcc,4096);
 for(unsigned i=0;i<4;i++){uint8_t code[]={0xb8,0x40,0x30,0x20,0x10,0xc3};code[1]+=(uint8_t)i;memcpy((void *)(uintptr_t)(owned[2]+i*16),code,sizeof(code));}
 attrs(owned[2],4096,0x20000);
 owned[3]=pages(4096);attrs(owned[3],4096,0x4000);check(i04_trampolines((void *)(uintptr_t)owned[3],owned[0]),"emit exact original trampolines into private NX memory");attrs(owned[3],4096,0x20000);
 config.extract=(void *)(uintptr_t)(owned[1]+0x2240);config.route=(ROUTE)(uintptr_t)(owned[1]+0x2248);config.callback=(CALLBACK)(uintptr_t)(owned[1]+0x2250);
 fresh();lease_open=1;I04_PLAN p=plan();
 check(i04_prepare(&tx,&vm,&p)==I04_OK,"exact W890 bytes permissions and trampoline preflight");
 check(i04_install(&tx)==I04_OK&&tx.phase==I04_INSTALLED,"publish three lifecycle detours and callback in one transaction");
 typedef uint64_t(EA *PROBE)(void);
 check(((PROBE)(uintptr_t)(owned[0]+0x6480))()==0x10203040,"actual patched cold entry reaches private code");
 check(((PROBE)(uintptr_t)(owned[0]+0x190f4))()==0x10203041,"actual patched BrowserLoop reaches private code");
 check(((PROBE)(uintptr_t)(owned[0]+0x36da4))()==0x10203042,"actual patched SendForm reaches private code");
 check(config.callback(&config,0,0,0,0,0)==0x10203043,"actual callback pointer reaches private code");
 check(i04_validate(&tx,15),"installed overlay verifies all untouched original text");
 check(i04_remove(&tx)==I04_ROLLED_BACK,"remove entire transaction");
 for(unsigned i=0;i<2;i++)check(!memcmp((void *)(uintptr_t)owned[i],fixtures[i],sizes[i]),"entire original mapped image unchanged after rollback");
 check((uintptr_t)config.callback==owned[1]+0x2250,"original Setup callback restored");
 reset();p=plan();p.targets[0]=owned[2]+4096;check(i04_prepare(&tx,&vm,&p)==I04_REFUSED,"target outside immutable wrapper image refused");
 reset();p=plan();lease_open=0;check(i04_prepare(&tx,&vm,&p)==I04_REFUSED,"no lifetime lease refuses before patch");lease_open=1;
 reset();p=plan();uint8_t *wrong=(void *)(uintptr_t)(owned[0]+0x6480);uint8_t saved=*wrong;*wrong^=1;
 check(i04_prepare(&tx,&vm,&p)==I04_REFUSED,"one changed hook byte refuses");*wrong=saved;
 reset();p=plan();wrong=(void *)(uintptr_t)(owned[0]+0x7000);saved=*wrong;*wrong^=1;
 check(i04_prepare(&tx,&vm,&p)==I04_REFUSED,"one unlisted text modification refuses");*wrong=saved;
 attrs(owned[0],sizes[0],0x20000);reset();p=plan();check(i04_prepare(&tx,&vm,&p)==I04_REFUSED,"read-only original code refused without changing its permissions");attrs(owned[0],sizes[0],0);
 attrs(owned[2],4096,0);reset();p=plan();check(i04_prepare(&tx,&vm,&p)==I04_REFUSED,"writable wrapper code refused");attrs(owned[2],4096,0x20000);
 reset();p=plan();check(i04_prepare(&tx,&vm,&p)==I04_OK,"prepare fresh transaction after refusal cases");
 lease_open=0;check(i04_install(&tx)==I04_REFUSED,"lease revoked between prepare and commit prevents writes");lease_open=1;
 check(!memcmp((void *)(uintptr_t)owned[0],fixture_amitse,sizeof(fixture_amitse)),"all refusal cases left original image exact");
 check(i04_install(&tx)==I04_OK,"revalidated pending transaction installs");
 wrong=(void *)(uintptr_t)(owned[0]+0x7000);saved=*wrong;*wrong^=1;
 check(i04_remove(&tx)==I04_REFUSED&&tx.phase==I04_INSTALLED,"changed foreign bytes prevent unsafe removal");*wrong=saved;
 check(i04_remove(&tx)==I04_ROLLED_BACK,"removal succeeds only after complete revalidation");
 for(unsigned mask=1;mask<=15;mask=(mask<<1)|1){
  reset();p=plan();check(i04_prepare(&tx,&vm,&p)==I04_OK,"prepare interrupted multi-site transaction");fail_once_mask=mask;
  check(i04_install(&tx)==I04_ROLLED_BACK&&tx.phase==I04_RETIRED&&!tx.attempted,"mid-commit rejection revalidates then rolls back every published site");
  check(!memcmp((void *)(uintptr_t)owned[0],fixture_amitse,sizeof(fixture_amitse))&&(uintptr_t)config.callback==owned[1]+0x2250,"interrupted transaction returns image and callback byte exact");
 }
 reset();p=plan();check(i04_prepare(&tx,&vm,&p)==I04_OK,"prepare terminal notification injection during second commit validation");end_during_commit=1;
 check(i04_install(&tx)==I04_ENDED&&!tx.touched,"terminal notification during raised-TPL validation refuses before mutation");
 UN remained=st->bs->raise_tpl(16);check(remained==16,"terminal transaction did not call RestoreTPL after revocation");st->bs->restore_tpl(4);
 /* The preceding notification is modeled, so the lab itself still owns live
  * firmware services. The final test below uses actual ExitBootServices. */
 memset(&vm,0,sizeof(vm));reset();
 uint64_t table_copy=pages(8192);attrs(table_copy,8192,0x4000);
 ST *copied_st=(void *)(uintptr_t)table_copy;BS *copied_bs=(void *)(uintptr_t)(table_copy+4096);memcpy(copied_st,st,sizeof(ST));memcpy(copied_bs,st->bs,sizeof(BS));copied_st->bs=copied_bs;
 for(unsigned which=0;which<2;which++){
  memset(&vm,0,sizeof(vm));memset(&tx,0,sizeof(tx));check(i04_capture(&vm,copied_st),"capture mapped private table copies");p=plan();check(i04_prepare(&tx,&vm,&p)==I04_OK,"prepare against exact mapped table copies");
  attrs(table_copy+4096*which,4096,0x2000);
  memset(&prepare_probe,0,sizeof(prepare_probe));check(i04_prepare(&prepare_probe,&vm,&p)==I04_REFUSED,"prepare refuses unreadable cached ST or BS before capturing methods");
  check(!i04_validate(&tx,0),"unmapped ST or BS refused before any stale-pointer dereference");
  check(!i04_capture(&vm,copied_st),"resnapshot refuses unreadable cached table before calling a service");
  attrs(table_copy+4096*which,4096,0x4000);
 }
 memset(&vm,0,sizeof(vm));
 reset();p=plan();check(i04_prepare(&tx,&vm,&p)==I04_OK,"prepare boot-service lifetime boundary");i04_end(&tx);
 check(i04_install(&tx)==I04_ENDED,"ExitBootServices invalidates pending transaction");
 check(!memcmp((void *)(uintptr_t)owned[0],fixture_amitse,sizeof(fixture_amitse)),"boot-service end did not mutate original image");
 /* A final real ExitBootServices exercise. After this point only local code
  * and TCG diagnostic ports execute; no UEFI call, free, restore or unload. */
 memset(&vm,0,sizeof(vm));reset();p=plan();check(i04_prepare(&tx,&vm,&p)==I04_OK&&i04_install(&tx)==I04_OK,"install final lab-owned transaction for real EBS boundary");
 EVENT event=0;check(!st->bs->create_event(0x201,8,ended,&tx,&event)&&event,"real ExitBootServices notification registration");fresh();
 typedef ES(EA *EXIT_BOOT)(HANDLE,UN);ES exit_status=((EXIT_BOOT)st->bs->exit_boot_services)(image,vm.key);
 check(!exit_status&&tx.ended&&vm.ended,"real ExitBootServices invokes terminal callback");
 check(i04_remove(&tx)==I04_ENDED,"no removal or firmware call after real ExitBootServices");
 trace("W890_INSTALLER04_PASS\n");stop(0x10);return 0;
}
