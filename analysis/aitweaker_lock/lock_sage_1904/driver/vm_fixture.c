/* QEMU TCG ONLY. Exercises the actual services/UI/core objects against OVMF.
 * The OEM navigation adapter is not linked into this fixture. */
#include "lock.h"
#include "probe_core.h"
#include "status.h"
#include "vm_hii_data.h"
static const char *script;
static GUID fixture_guid={0x7e68a67f,0xb340,0x4be7,{0x80,0x11,0x19,0x04,0x16,0x01,0x20,0x26}};
static ST shadow;
static uint8_t oc[26681],memory[1392];
static unsigned checks;
static CONFIG fixture_config;
static C16 oc_route[]=L"GUID=74b8a3a336768241ba1ef52c584494e3&NAME=VM_ONLY";
static void trace(const char *s) {while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void hex(uint64_t n) {const char h[]="0123456789abcdef";for(unsigned i=0;i<16;i++){char s[]={h[(n>>((15-i)*4))&15],0};trace(s);}}
static void finish(int ok) {trace(ok?"INTEGRATION_PASS\n":"INTEGRATION_FAIL\n");__asm__ volatile("outl %0,%1"::"a"(ok?0x10u:0x11u),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *label) {checks++;trace(ok?"PASS ":"FAIL ");trace(label);trace("\n");if(!ok)finish(0);}
static int tcg(void) {uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354 && c==0x43544743 && d==0x47435447;}
static ES EA fake_read(INPUT *self,KEY *k) {(void)self;if(!script || !*script)return ERR(6);k->ch=(uint8_t)*script++;k->scan=k->ch==27?0x17:0;return 0;}
static INPUT input={0,fake_read,0};
static void queue(const char *s) {script=s;}
static ES(EA *real_locate)(GUID *,void *,void **);
static unsigned rng_case;
static ES EA failed_rng(RNG *self,GUID *algorithm,UN n,uint8_t *out) {
 (void)self;(void)algorithm;memset(out,0xcc,n);return ERR(7);
}
static RNG bad_rng={0,failed_rng};
static ES EA entropy_locate(GUID *guid,void *registration,void **out) {
 static GUID rng={0x3152bca5,0xeade,0x433d,{0x86,0x2e,0xc0,0x1c,0xdc,0x29,0x1f,0x44}};
 if(!memcmp(guid,&rng,16)) {
  *out=rng_case==2?&bad_rng:0;
  return rng_case==1?ERR(14):rng_case==2?0:ERR(7);
 }
 return real_locate(guid,registration,out);
}
static void test_entropy(void) {
 uint8_t a[32],b[32],zero[32]={0};
 check(cpu_entropy_supported(),"TCG exposes RDSEED feature for missing-protocol test");
 check(!cpu_entropy(a,sizeof(a)) && !cpu_entropy(b,sizeof(b)),"actual RDSEED provider fills two salt buffers");
 check(!ap_constant_equal(a,b,sizeof(a)),"separate seed calls do not repeat the sample");
 BS copy=*system_table->bs;BS *saved=system_table->bs;real_locate=copy.locate_protocol;
 copy.locate_protocol=entropy_locate;system_table->bs=&copy;rng_case=1;
 check(!password_core.env.entropy(0,a,sizeof(a)),"missing EFI RNG protocol selects CPU seed provider");
 rng_case=2;memset(a,0xaa,sizeof(a));
 check(password_core.env.entropy(0,a,sizeof(a)) && ap_constant_equal(a,zero,sizeof(a)),"existing RNG failure stays an error and wipes partial bytes");
 rng_case=3;memset(a,0xaa,sizeof(a));
 check(password_core.env.entropy(0,a,sizeof(a)) && ap_constant_equal(a,zero,sizeof(a)),"protocol lookup error does not silently choose another provider");
 system_table->bs=saved;ap_secure_zero(a,sizeof(a));ap_secure_zero(b,sizeof(b));
}
static void wait_retry(void) {
 trace("RETRY_BEFORE=");hex(ap_retry_remaining_ms(&password_core));trace("\n");
 for(unsigned i=0;i<100 && ap_retry_remaining_ms(&password_core);i++)system_table->bs->stall(100000);
 trace("RETRY_AFTER=");hex(ap_retry_remaining_ms(&password_core));trace("\n");
 check(!ap_retry_remaining_ms(&password_core),"retry deadline expires within bounded 10-second wait");
}
void end_platform(void) {}
static ES EA fixture_callback(CONFIG *c,UN action,uint16_t q,uint8_t type,void *value,BROWSER_ACTION_REQUEST *request) {
 (void)c;(void)action;(void)q;(void)type;(void)value;if(request)*request=0;return ERR(3);
}
static ES EA fixture_route(CONFIG *c,C16 *s,C16 **p) {(void)c;if(p)*p=s;return ERR(3);}
static void relative_jump(uint8_t *where,void *target) {
 int64_t distance=(int64_t)(uintptr_t)target-(int64_t)(uintptr_t)(where+5);
 check(distance>=INT32_MIN && distance<=INT32_MAX,"VM callback relative jump range");int32_t rel=(int32_t)distance;where[0]=0xe9;memcpy(where+1,&rel,4);
}
static void test_hii(void) {
 GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
 GUID ca_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
 HII *db=0;check(!system_table->bs->locate_protocol(&db_guid,0,(void **)&db) && db,"real HII database available");
 uint64_t image=0;check(!system_table->bs->allocate_pages(0,3,2,&image) && image,"VM ConfigAccess shim allocation");
 uint8_t *base=(uint8_t *)(uintptr_t)image;
 relative_jump(base+0x152c,(void *)fixture_route);relative_jump(base+0x1534,(void *)fixture_callback);
 fixture_config=(CONFIG){0,(ROUTE)(void *)(base+0x152c),(CALLBACK)(void *)(base+0x1534)};
 HANDLE owner=0,hii=0;check(!system_table->bs->install_protocol(&owner,&ca_guid,0,&fixture_config),"register VM ConfigAccess owner");
 ES (EA *new_list)(HII *,void *,HANDLE,HANDLE *)=db->new_list;
 check(!new_list(db,(void *)vm_hii_data,owner,&hii) && hii,"register original 1904 forms and English strings in actual HII");
 check(install_hii_management(base,8192),"actual management installer updates Security HII");
 check(setup_hii==hii && fixture_config.callback!=(CALLBACK)(void *)(base+0x1534),"HII owner verified and callback interposed");
 check(install_hii_management(base,8192),"management installation idempotent");
 struct {UN before;BROWSER_ACTION_REQUEST value;UN after;} request={0x1234567890abcdefULL,UINT64_MAX,0xfedcba0987654321ULL};
 check(!fixture_config.callback(&fixture_config,1,LOCK_QID,0,0,&request.value) && request.value==0,"CHANGED clears the complete UINTN request without duplicate UI");
 request.value=UINT64_MAX;
 check(!fixture_config.callback(&fixture_config,1,LOCK_CLEAR_QID,0,0,&request.value) && request.value==0,"clear ACTION resets all 64 output bits");
 request.value=UINT64_MAX;
 check(fixture_config.callback(&fixture_config,2,LOCK_QID,0,0,&request.value)==ERR(3) && request.value==0,"unsupported management action returns full-width NONE");
 request.value=UINT64_MAX;
 check(fixture_config.callback(&fixture_config,2,0x7fff,0,0,&request.value)==ERR(3) && request.value==0,"unrelated callback chains to original UINTN ABI");
 check(request.before==0x1234567890abcdefULL && request.after==0xfedcba0987654321ULL,"callback output preserves adjacent caller storage");
 C16 *progress=0;
 check(fixture_config.route(&fixture_config,oc_route,&progress)==ERR(15) && progress==oc_route,"locked HII OC route denied before original handler");
 check(fixture_config.route(&fixture_config,U("GUID=00000000000000000000000000000000"),&progress)==ERR(3),"unrelated HII route chains to original handler");
}
static void test_screen(uint64_t phase) {
 GUID guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};GOP *gop=0;
 check(!system_table->bs->locate_protocol(&guid,0,(void **)&gop) && gop && gop->mode && gop->mode->info,"real GOP screen available");
 UN width=gop->mode->info->width,height=gop->mode->info->height,bytes=width*height*sizeof(PIXEL);
 check(width && height && width<=4096 && height<=2160,"screen size bounded");
 PIXEL *buffer=alloc(bytes);check(buffer!=0,"screen snapshot buffer");
 system_table->out->enable_cursor(system_table->out,0);
 PIXEL background={0x21,0x35,0x48,0},marker={0x82,0x42,0x12,0};
 check(!gop->blt(gop,&background,0,0,0,0,0,width,height,0) && !gop->blt(gop,&marker,0,0,0,10,10,20,30,0),"paint distinctive VM background");
 uint32_t before=0,after=0;
 check(!gop->blt(gop,buffer,1,0,0,0,0,width,height,0) && !system_table->bs->crc32(buffer,bytes,&before),"capture background before modal UI");
 queue(phase?"\x1b":"!");check(!ensure_unlocked(),"cancel or unconfigured UI remains locked during screen test");
 check(!gop->blt(gop,buffer,1,0,0,0,0,width,height,0) && !system_table->bs->crc32(buffer,bytes,&after),"capture background after modal UI");
 check(before==after,"complete GOP framebuffer restored byte for byte");release(buffer);
}
ES EA efi_main(HANDLE image,ST *st) {
 (void)image;if(!tcg())return ERR(3);shadow=*st;shadow.in=&input;system_table=&shadow;
 GUID status_guid=STATUS_GUID;LOCK_STATUS_PROTOCOL *production=0;LOCK_STATUS status;
 check(!st->bs->locate_protocol(&status_guid,0,(void **)&production) && production && production->signature==STATUS_SIGNATURE,"actual driver auto-dispatched from FV before app");
 check(!production->query(&status) && status.version==1 && status.build==1904 && !status.board_matches && !status.hooks_installed,"actual driver refuses OEM hooks on OVMF board");
 trace("ACTUAL_SERVICES_UI_CORE_BEGIN\n");check(initialize_services(),"initialize real UEFI storage, RNG lookup, timer");
 test_entropy();
 uint64_t phase=0;UN size=8;uint32_t attr=0;
 ES s=st->rt->get_variable(U("Phase"),&fixture_guid,&attr,&size,&phase);
 check(s==ERR(14) || (!s && size==8 && attr==3),"phase read");
 trace("PHASE=");hex(phase);trace("\n");check(phase<3,"phase range");
 if(!phase) {
  check(password_core.mode==AP_MODE_UNCONFIGURED,"missing credential locked");
  check(!original_set_variable(U("VARSTORE_OCMR_SETTINGS_NAME"),&oc_guid,7,sizeof(oc),oc),"create VM OC variable");
  check(!original_set_variable(U("SocketMemoryConfig"),&memory_guid,7,sizeof(memory),memory),"create VM memory variable");
 } else check(password_core.mode==AP_MODE_ENABLED,"credential survives cold boot");
 check(!ap_can_enter(&password_core),"fresh boot starts locked");
 check(memory_present(st->rt,sizeof(*st->rt),0),"page table presence checks");
 check(install_variable_guard(),"install actual runtime write guard and CRC");
 uint32_t crc=st->rt->hdr.crc;RT copy=*st->rt;copy.hdr.crc=0;
 check(probe_crc32(&copy,copy.hdr.size)==crc,"runtime service CRC correct");
 uint64_t token=ap_session_begin(&password_core);check(token!=0,"start actual session");
 test_hii();
 test_screen(phase);
 if(!phase) {
  queue("!");check(!ensure_unlocked(),"unconfigured UI denies entry");
  queue("VmOnly-1904-A\rDifferent-1904\r!");check(!manage_password(0),"UI confirmation mismatch does not enroll");
  check(password_core.mode==AP_MODE_UNCONFIGURED,"mismatch keeps missing credential");
  BROWSER_ACTION_REQUEST request=UINT64_MAX;queue("VmOnly-1904-A\rVmOnly-1904-A\r!");check(!fixture_config.callback(&fixture_config,0,LOCK_QID,0,0,&request) && request==0,"Security ACTION callback enrolls through actual UI RNG and NVRAM");
  check(!ap_can_enter(&password_core),"enrollment remains locked");
  oc[4]=1;check(st->rt->set_variable(U("VARSTORE_OCMR_SETTINGS_NAME"),&oc_guid,7,sizeof(oc),oc)==ERR(15),"locked OC modification rejected");
  queue("Wrong-1904\r!");check(!ensure_unlocked(),"wrong password rejected through actual UI");
  check(ap_retry_remaining_ms(&password_core)>0,"real CPU timer retry delay");
  wait_retry();queue("\x1b");check(!ensure_unlocked(),"ESC keeps lock");
  queue("VmOnly-1904-A\r");check(ensure_unlocked(),"correct UI password unlocks");
  check(!st->rt->set_variable(U("VARSTORE_OCMR_SETTINGS_NAME"),&oc_guid,7,sizeof(oc),oc),"authorized OC write succeeds");
  check(st->rt->set_variable(credential_name,&credential_guid,0,0,0)==ERR(15),"outside credential deletion rejected");
 } else if(phase==1) {
  queue("VmOnly-1904-A\r");check(ensure_unlocked(),"old credential unlock after cold boot");
  queue("VmOnly-1904-A\rVmOnly-1904-B\rVmOnly-1904-B\r!");check(manage_password(0),"authenticated UI password change");
  check(!ap_can_enter(&password_core),"changed credential requires unlock");
  queue("VmOnly-1904-A\r!");check(!ensure_unlocked(),"previous password no longer works");
  wait_retry();queue("VmOnly-1904-B\r");check(ensure_unlocked(),"replacement password unlocks");
  ap_session_end(&password_core);
  size=sizeof(memory);check(!st->rt->get_variable(U("SocketMemoryConfig"),&memory_guid,&attr,&size,memory),"memory snapshot");
  memory[0x11]=1;check(!st->rt->set_variable(U("SocketMemoryConfig"),&memory_guid,7,sizeof(memory),memory),"unprotected memory byte remains writable");
  static const UN protected_bytes[]={0x10,0xbd,0xbe};
  for(unsigned i=0;i<3;i++) {
   UN offset=protected_bytes[i];uint8_t before=memory[offset];memory[offset]^=1;
   check(st->rt->set_variable(U("SocketMemoryConfig"),&memory_guid,7,sizeof(memory),memory)==ERR(15),"protected memory byte denied outside session");memory[offset]=before;
  }
 } else {
  queue("VmOnly-1904-B\r");check(ensure_unlocked(),"changed credential survives cold boot");
  queue("Wrong-1904\ry!");check(!manage_password(1),"wrong password cannot clear lock");
  wait_retry();queue("VmOnly-1904-B\ry!");check(manage_password(1),"authenticated explicit clear");
  check(password_core.mode==AP_MODE_DISABLED,"clear stores explicit disabled record");
  ap_session_end(&password_core);C16 *progress=0;
  check(fixture_config.route(&fixture_config,oc_route,&progress)==ERR(3),"explicitly disabled protection permits OC route outside browser session");
  ap_session_end(&password_core);ap_session_begin(&password_core);check(ap_can_enter(&password_core),"explicit disabled mode survives next session");
  queue("VmOnly-1904-A\rVmOnly-1904-A\r!");check(manage_password(0),"re-enroll from explicit disabled mode");
 }
 ap_session_end(&password_core);check(!ap_can_enter(&password_core),"session exit relocks");
 ap_session_begin(&password_core);check(!ap_can_enter(&password_core),"re-entry stays locked");ap_session_end(&password_core);
 phase++;check(!original_set_variable(U("Phase"),&fixture_guid,3,8,&phase),"commit VM phase");
 /* Validate the actual ExitBootServices notification removes the temporary
  * Runtime Services interposition. No Boot Services calls after success. */
 UN map_size=0,key=0,descriptor_size=0;uint32_t descriptor_version=0;
 check(st->bs->memory_map(&map_size,0,&key,&descriptor_size,&descriptor_version)==ERR(5),"get memory map size");
 map_size+=4096;UN capacity=map_size;void *map=alloc(capacity);check(map!=0,"map allocation");
 ES (EA *exit_bs)(HANDLE,UN)=(void *)st->bs->exit_boot_services;
 for(unsigned attempt=0;attempt<3;attempt++) {
  map_size=capacity;s=st->bs->memory_map(&map_size,map,&key,&descriptor_size,&descriptor_version);if(FAILED(s))break;
  s=exit_bs(image,key);if(!s)break;
 }
 check(!s,"ExitBootServices succeeds");check(boot_services_ended,"exit notification ran");
 check(st->rt->set_variable==original_set_variable,"runtime pointer restored before boot code release");
 copy=*st->rt;crc=copy.hdr.crc;copy.hdr.crc=0;check(probe_crc32(&copy,copy.hdr.size)==crc,"restored runtime CRC correct");
 trace("CHECKS=");hex(checks);trace("\n");finish(1);return 0;
}
