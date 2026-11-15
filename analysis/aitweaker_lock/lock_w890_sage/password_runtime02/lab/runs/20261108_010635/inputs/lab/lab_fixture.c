/* QEMU TCG ONLY. Scripted input and interruption injection exist only here.
 * The source/runtime objects linked below are the unmodified component objects.
 * This carrier never belongs in a firmware release or hardware tool package. */
#include "runtime.h"
#include "profile_fixture.h"
static ST shadow;static RT shadow_rt;static BS shadow_bs;static TEXTOUT shadow_out;
static ST *real_st;static const char *script;static uint32_t checks,target_sets,interrupt_mode,rng_mode;
static char transcript[8192];static size_t transcript_size;
static GUID fixture_guid={0x70d12762,0x9f98,0x409c,{0xbc,0x70,0x1a,0x0f,0x90,0xaa,0x21,0x9f}};
static const char pw_a[]="Vm-W890-Password-A",pw_b[]="Vm-W890-Password-B";
static uint64_t canary=0x527b901ba40ee16fULL;
static void trace(const char *s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void finish(unsigned code){__asm__ volatile("outl %0,%1"::"a"(code),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *label){checks++;trace(ok?"PASS ":"FAIL ");trace(label);trace("\n");if(!ok)finish(0x11);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
static int equal_name(const C16 *a,const C16 *b){for(unsigned i=0;i<128;i++){if(a[i]!=b[i])return 0;if(!a[i])return 1;}return 0;}
static int target(C16 *name,GUID *guid){return !memcmp(guid,&w890_credential_guid,16)&&equal_name(name,w890_credential_name);}
static ES EA read_key(INPUT *self,KEY *key){(void)self;if(!script||!*script)return ERR(6);key->ch=(uint8_t)*script++;key->scan=key->ch==27?23:0;return 0;}
static INPUT input={0,read_key,0};
static void queue(const char *s){script=s;transcript_size=0;memset(transcript,0,sizeof(transcript));}
static ES EA output(TEXTOUT *self,C16 *text){(void)self;for(unsigned i=0;text[i]&&i<4096;i++)if(transcript_size+1<sizeof(transcript))transcript[transcript_size++]=(char)text[i];return real_st->out->out(real_st->out,text);}
static ES EA attribute(TEXTOUT *s,UN n){(void)s;return real_st->out->attribute(real_st->out,n);}
static ES EA clear(TEXTOUT *s){(void)s;return real_st->out->clear(real_st->out);}
static ES EA cursor(TEXTOUT *s,UN x,UN y){(void)s;return real_st->out->cursor(real_st->out,x,y);}
static ES EA enable(TEXTOUT *s,uint8_t on){(void)s;return real_st->out->enable_cursor(real_st->out,on);}
static int contains(const char *s,const char *needle){for(size_t i=0;s[i];i++){size_t j=0;while(needle[j]&&s[i+j]==needle[j])j++;if(!needle[j])return 1;}return 0;}
static ES EA set_variable(C16 *name,GUID *guid,uint32_t attrs,UN n,void *data){
 if(!target(name,guid))return real_st->rt->set_variable(name,guid,attrs,n,data);
 target_sets++;
 if(interrupt_mode==1){trace("INTERRUPT_BEFORE_COMMIT\n");finish(0x12);}
 ES status=real_st->rt->set_variable(name,guid,attrs,n,data);
 if(interrupt_mode==2){check(!status,"real SetVariable completed before interruption");trace("INTERRUPT_AFTER_COMMIT_BEFORE_READBACK\n");finish(0x13);}
 return status;
}
static ES EA broken_rng(RNG *r,GUID *g,UN n,uint8_t *out){(void)r;(void)g;memset(out,0xaa,n);return ERR(7);}
static RNG failed_rng={0,broken_rng};
static ES EA locate(GUID *guid,void *registration,void **out){
 static GUID rng={0x3152bca5,0xeade,0x433d,{0x86,0x2e,0xc0,0x1c,0xdc,0x29,0x1f,0x44}};
 if(rng_mode&&!memcmp(guid,&rng,16)){*out=rng_mode==2?&failed_rng:0;return rng_mode==1?ERR(14):rng_mode==2?0:ERR(7);}
 return real_st->bs->locate_protocol(guid,registration,out);
}
static int EA yes(void){return 1;}
static int EA owner(void *caller,unsigned op,uint64_t *token,uint64_t value,uint32_t depth){(void)caller;(void)op;(void)token;(void)value;(void)depth;return 1;}
static int EA active(uint64_t token,uint32_t depth){return token&&depth;}
static int EA writable(void *p,size_t n){return w890_memory_present(p,n,1);}
static int EA prompt_unused(int op){(void)op;return 0;}
static int EA authorize(void *caller,int op,uint64_t token,uint32_t depth){(void)caller;(void)op;return token&&depth;}
static W890_HOST owner_model={1,sizeof(W890_HOST),yes,yes,owner,active,writable,prompt_unused,authorize};
static void configure(ST *st){
 real_st=st;shadow=*st;shadow_rt=*st->rt;shadow_bs=*st->bs;shadow_out=*st->out;
 shadow_rt.set_variable=set_variable;shadow_bs.locate_protocol=locate;
 shadow_out.out=output;shadow_out.attribute=attribute;shadow_out.clear=clear;shadow_out.cursor=cursor;shadow_out.enable_cursor=enable;
 shadow.in=&input;shadow.out=&shadow_out;shadow.rt=&shadow_rt;shadow.bs=&shadow_bs;
}
static ES raw_set(C16 *name,GUID *guid,uint32_t attrs,UN n,void *data){return real_st->rt->set_variable(name,guid,attrs,n,data);}
static void canaries(int create){
 C16 *names[]={U("OtherPrivate"),w890_credential_name};GUID *guids[]={&w890_credential_guid,&fixture_guid};
 for(unsigned i=0;i<2;i++){
  if(create)check(!raw_set(names[i],guids[i],3,8,&canary),"create unrelated namespace canary");
  uint64_t value=0;UN n=8;uint32_t attrs=0;
  check(!real_st->rt->get_variable(names[i],guids[i],&attrs,&n,&value)&&n==8&&attrs==3&&value==canary,"unrelated variable unchanged");
 }
}
static void phase_write(uint64_t phase){check(!raw_set(U("Phase"),&fixture_guid,3,8,&phase),"commit lab reboot stage");}
static void begin(void){uint64_t token=0;check(!w890_provider.begin(&w890_provider,&token)&&token,"modeled native session begins through actual provider");}
static void end(void){check(!w890_provider.end(&w890_provider,w890_password_core.session_token),"outer session ends through actual provider");}
static uint32_t screen_crc(void){
 GUID guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};GOP *gop=0;
 check(!real_st->bs->locate_protocol(&guid,0,(void **)&gop)&&gop&&gop->mode&&gop->mode->info,"real OVMF GOP available");
 UN width=gop->mode->info->width,height=gop->mode->info->height,n=width*height*sizeof(PIXEL);
 PIXEL *data=w890_alloc(n);check(data!=0,"allocate framebuffer comparison buffer");uint32_t crc=0;
 check(!gop->blt(gop,data,1,0,0,0,0,width,height,0)&&!real_st->bs->crc32(data,n,&crc),"capture actual framebuffer");w890_release(data);return crc;
}
static void screen_test(void){
 real_st->out->enable_cursor(real_st->out,0);real_st->out->out(real_st->out,U("W890 original screen restoration marker\r\n"));
 uint32_t before=screen_crc();queue("!");check(w890_provider.request(&w890_provider)==ERR(15),"unconfigured prompt remains locked");
 check(screen_crc()==before,"unconfigured dialog restores full original framebuffer");
}
static void mask_test(void){check(!contains(transcript,pw_a)&&!contains(transcript,pw_b),"no plaintext credential reaches ConsoleOut");check(contains(transcript,"********"),"password input emits masks");}
static void enroll(void){
 queue("Vm-W890-Password-A\rVm-W890-Password-A\r!");check(!w890_provider.manage(&w890_provider,0),"actual UI enrolls through actual RNG and NVRAM");mask_test();
 check(!(w890_provider.query(&w890_provider)&W890_PROVIDER_GRANTED),"enrollment does not grant current session");
}
static void wait_retry(void){for(unsigned i=0;i<100&&ap_retry_remaining_ms(&w890_password_core);i++)real_st->bs->stall(100000);check(!ap_retry_remaining_ms(&w890_password_core),"actual monotonic retry expires within ten seconds");}
static void entropy_tests(void){
 uint8_t a[32],b[32],zero[32]={0};
 check(!w890_entropy(0,a,32)&&!w890_entropy(0,b,32)&&!ap_constant_equal(a,b,32),"actual EFI RNG produces independent samples");
 rng_mode=1;check(!w890_entropy(0,a,32),"missing RNG protocol uses checked RDSEED fallback");
 rng_mode=2;check(w890_entropy(0,a,32)&&ap_constant_equal(a,zero,32),"existing RNG failure wipes partial output");
 rng_mode=3;check(w890_entropy(0,a,32)&&ap_constant_equal(a,zero,32),"RNG lookup error does not fallback silently");rng_mode=0;
 ap_secure_zero(a,32);ap_secure_zero(b,32);
}
static void recovery(unsigned phase){
 uint8_t before[128],after[128];UN n=128;uint32_t attrs=0;
 check(!real_st->rt->get_variable(w890_credential_name,&w890_credential_guid,&attrs,&n,before)&&n==128&&attrs==3,"interrupted credential survives cold boot with exact shape");
 const char *right=phase==1?pw_a:pw_b,*wrong=phase==1?pw_b:pw_a;
 check(w890_recover_known_record(&shadow,(const uint8_t *)wrong,18)==W890_RECOVERY_DENIED,"wrong pre/post-commit password cannot recover");
 n=128;attrs=0;check(!real_st->rt->get_variable(w890_credential_name,&w890_credential_guid,&attrs,&n,after)&&n==128&&attrs==3&&ap_constant_equal(before,after,128),"denied recovery preserves exact credential");
 check(w890_recover_known_record(&shadow,(const uint8_t *)right,18)==W890_RECOVERY_OK,"known committed credential recovered after interruption");
 n=128;check(real_st->rt->get_variable(w890_credential_name,&w890_credential_guid,&attrs,&n,after)==ERR(14),"recovery verified private variable absent");
 ap_secure_zero(before,128);ap_secure_zero(after,128);canaries(0);
}
ES EA efi_main(HANDLE image,ST *st){
 if(!tcg())return ERR(3);configure(st);trace("W890_RUNTIME02_LAB_BEGIN\n");
 uint64_t phase=0;UN n=8;uint32_t attrs=0;ES s=st->rt->get_variable(U("Phase"),&fixture_guid,&attrs,&n,&phase);
 check(s==ERR(14)||(!s&&n==8&&attrs==3),"read lab stage");check(phase<=2,"lab stage bounded");
 if(!phase){trace("PHASE0\n");canaries(1);}else{trace(phase==1?"PHASE1\n":"PHASE2\n");recovery((unsigned)phase);}
 check(w890_runtime_bind(&shadow,&owner_model,fixture_setup_sha,fixture_tse_sha)==AP_UNCONFIGURED,"real services bind to absent credential using modeled native owner");
 begin();
 if(!phase){
  screen_test();entropy_tests();
  queue("Mismatch-Password\rDifferent-Password\r!");uint32_t before=target_sets;
  check(w890_provider.manage(&w890_provider,0)==ERR(15)&&target_sets==before,"confirmation mismatch performs no SetVariable");
  enroll();queue("Wrong-Password\r!");check(w890_provider.request(&w890_provider)==ERR(15),"wrong password denied through real UI");
  check(ap_retry_remaining_ms(&w890_password_core)>0,"wrong password starts real retry delay");wait_retry();
  uint32_t screen=screen_crc();queue("\x1b");check(w890_provider.request(&w890_provider)==ERR(15),"Escape cancels without grant");check(screen_crc()==screen,"cancel restores original framebuffer");
  queue("Vm-W890-Password-A\r");check(!w890_provider.request(&w890_provider),"correct real input unlocks");mask_test();
  end();begin();check(!(w890_provider.query(&w890_provider)&4),"new BIOS session relocks");
  phase_write(1);interrupt_mode=1;queue("Vm-W890-Password-A\rVm-W890-Password-B\rVm-W890-Password-B\r!");
  w890_provider.manage(&w890_provider,0);check(0,"before-commit interruption must exit carrier");
 }else if(phase==1){
  enroll();phase_write(2);interrupt_mode=2;queue("Vm-W890-Password-A\rVm-W890-Password-B\rVm-W890-Password-B\r!");
  w890_provider.manage(&w890_provider,0);check(0,"after-commit interruption must exit carrier");
 }else{
  enroll();uint8_t enabled[128],readback[129],zero[128]={0};memcpy(enabled,w890_password_core.record,128);
  queue("Vm-W890-Password-A\ry!");check(!w890_provider.manage(&w890_provider,1),"real authenticated clear writes disabled record");end();
  check(w890_recover_known_record(&shadow,(const uint8_t *)pw_a,18)==W890_RECOVERY_DENIED,"disabled record is not claimed by old password");
  check(!raw_set(w890_credential_name,&w890_credential_guid,3,128,enabled),"test carrier restores its own enabled record solely for recovery-negative cases");
  check(!raw_set(w890_credential_name,&w890_credential_guid,7,128,enabled),"test carrier creates wrong-attribute record");size_t length=0;
  memset(readback,0xaa,128);check(w890_read_record(0,readback,128,&length)==AP_READ_ERROR&&ap_constant_equal(readback,zero,128),"real read adapter rejects attributes and wipes buffer");
  check(w890_recover_known_record(&shadow,(const uint8_t *)pw_a,18)==W890_RECOVERY_INVALID,"recovery preserves wrong attributes");
  memcpy(readback,enabled,128);readback[128]=0xaa;check(!raw_set(w890_credential_name,&w890_credential_guid,3,129,readback),"test carrier creates oversized record");
  check(w890_recover_known_record(&shadow,(const uint8_t *)pw_a,18)==W890_RECOVERY_INVALID,"recovery preserves oversized record");
  check(!raw_set(w890_credential_name,&w890_credential_guid,3,128,enabled),"test carrier restores known enabled record");
  check(w890_recover_known_record(&shadow,(const uint8_t *)pw_a,18)==W890_RECOVERY_OK,"final known-record cleanup succeeds");
  ap_secure_zero(enabled,128);ap_secure_zero(readback,129);canaries(0);
  UN map_size=0,key=0,descriptor_size=0;uint32_t version=0;
  check(st->bs->memory_map(&map_size,0,&key,&descriptor_size,&version)==ERR(5),"ExitBootServices map size");map_size+=4096;UN capacity=map_size;void *map=w890_alloc(capacity);check(map!=0,"ExitBootServices map allocation");
  ES(EA *exit_bs)(HANDLE,UN)=(void *)st->bs->exit_boot_services;
  for(unsigned attempt=0;attempt<3;attempt++){map_size=capacity;s=st->bs->memory_map(&map_size,map,&key,&descriptor_size,&version);if(FAILED(s))break;s=exit_bs(image,key);if(!s)break;}
  check(!s&&w890_runtime_ended&&w890_provider.query(&w890_provider)==64,"actual ExitBootServices revokes runtime and provider");
  check(ap_constant_equal(w890_password_core.record,zero,128),"credential RAM copy cleared at boot-services exit");
  trace("W890_RUNTIME02_LAB_PASS\n");finish(0x10);
 }
 return ERR(3);
}
