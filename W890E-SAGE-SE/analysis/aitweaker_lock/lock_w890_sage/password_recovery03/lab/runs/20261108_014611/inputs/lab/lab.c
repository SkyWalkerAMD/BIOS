/* QEMU TCG test carrier only. Supplies explicit identity fixtures and models
 * writer exclusion; no fixture/proof/input override is in the actual carrier. */
#include "recovery.h"
#include "module_data.inc"
#include "credential_data.inc"
static ST *real;static ST shadow;static RT rt;static BS bs;static TEXTOUT output;
static INPUT input;static const char *script;static int injected,proof_allowed,target_sets;static unsigned checks;
static LOADED loaded[2];static uint8_t paths[2][24];static CT table;static uint8_t sm_entry[24],smbios[256];static UN table_bytes;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fixture_guid={0x1783c653,0x3dc1,0x4ce6,{0xb3,0xb0,0x39,0x77,0xc1,0x7c,0x39,0x59}};
static int prompt_masks;static int change_on_confirm;static uint32_t saved_identity_byte;
static void trace(const char*s){while(*s)__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s++),"Nd"((uint16_t)0x402));}
static void finish(unsigned n){__asm__ volatile("outl %0,%1"::"a"(n),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char*s){checks++;trace(ok?"PASS ":"FAIL ");trace(s);trace("\n");if(!ok)finish(0x11);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
static int EA proof(void*c,uint64_t epoch){return c==&proof_allowed&&epoch==0x8900603&&proof_allowed&&tcg();}
static ES EA read_key(INPUT*self,KEY*k){(void)self;if(!script||!*script)return ERR(6);k->ch=(uint8_t)*script++;k->scan=k->ch==27?23:0;return 0;}
static ES EA text(TEXTOUT*self,C16*s){(void)self;for(unsigned i=0;s[i]&&i<1024;i++)if(s[i]=='*')prompt_masks++;return real->out->out(real->out,s);}
static ES EA attr(TEXTOUT*self,UN n){(void)self;return real->out->attribute(real->out,n);}
static ES EA clear(TEXTOUT*self){(void)self;return real->out->clear(real->out);}
static ES EA cursor(TEXTOUT*self,UN x,UN y){(void)self;return real->out->cursor(real->out,x,y);}
static ES EA enable(TEXTOUT*self,uint8_t n){(void)self;return real->out->enable_cursor(real->out,n);}
static int same_name(const C16*a,const C16*b){for(unsigned i=0;i<64;i++){if(a[i]!=b[i])return 0;if(!a[i])return 1;}return 0;}
static ES EA set(C16*n,GUID*g,uint32_t a,UN z,void*d){
 if(memcmp(g,&rc_guid,16)||!same_name(n,rc_name)||a||z||d){check(0,"recovery writer attempted non-deletion or unrelated variable");return ERR(15);}
 target_sets++;return real->rt->set_variable(n,g,a,z,d);
}
static ES EA locate(uint32_t mode,GUID*g,void*k,UN*n,HANDLE**out){
 if(!injected||memcmp(g,&loaded_guid,16))return real->bs->locate_handles(mode,g,k,n,out);
 *n=2;ES s=real->bs->allocate_pool(4,16,(void**)out);if(!FAILED(s)){(*out)[0]=&loaded[0];(*out)[1]=&loaded[1];}return s;
}
static ES EA handle(HANDLE h,GUID*g,void**out){
 if(injected&&!memcmp(g,&loaded_guid,16)&&(h==&loaded[0]||h==&loaded[1])){*out=h;return 0;}
 return real->bs->handle_protocol(h,g,out);
}
static void make_identity(void){
 GUID guids[2]={{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}},
 {0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}}};
 const uint8_t *headers[]={fixture_header_0,fixture_header_1},*texts[]={fixture_text_0,fixture_text_1};UN sizes[]={2154496,909312},text_sizes[]={174073,597466};
 for(unsigned i=0;i<2;i++){
  loaded[i].revision=0x1000;loaded[i].image_size=sizes[i];check(!real->bs->allocate_pool(4,sizes[i],&loaded[i].image_base),"allocate inert original-module fixture");
  memset(loaded[i].image_base,0,sizes[i]);memcpy(loaded[i].image_base,headers[i],4096);memcpy((uint8_t*)loaded[i].image_base+4096,texts[i],text_sizes[i]);
  paths[i][0]=4;paths[i][1]=6;paths[i][2]=20;memcpy(paths[i]+4,&guids[i],16);paths[i][20]=0x7f;paths[i][21]=0xff;paths[i][22]=4;loaded[i].filepath=paths[i];
 }
 uint8_t b0[18]={0,18,0,0,0,1};memcpy(smbios,b0,18);memcpy(smbios+18,"0603\0\0",6);UN pos=24;
 uint8_t b2[8]={2,8,1,0,1,2};memcpy(smbios+pos,b2,8);pos+=8;
 const char strings[]="ASUSTeK COMPUTER INC.\0Pro WS W890E-SAGE SE\0";UN length=sizeof(strings);memcpy(smbios+pos,strings,length);pos+=length;
 const uint8_t end[6]={127,4,2,0,0,0};memcpy(smbios+pos,end,6);table_bytes=pos+6;
 memcpy(sm_entry,"_SM3_",5);sm_entry[6]=24;sm_entry[7]=3;sm_entry[8]=2;uint32_t maximum=(uint32_t)table_bytes;memcpy(sm_entry+12,&maximum,4);uint64_t address=(uint64_t)(uintptr_t)smbios;memcpy(sm_entry+16,&address,8);
 uint8_t sum=0;for(unsigned i=0;i<24;i++)sum+=sm_entry[i];sm_entry[5]=(uint8_t)(0-sum);
 table.guid=(GUID){0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};table.table=sm_entry;
}
static uint32_t screen_crc(void){
 GUID g={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};GOP*p=0;check(!real->bs->locate_protocol(&g,0,(void**)&p),"locate real GOP");
 UN width=p->mode->info->width,height=p->mode->info->height;PIXEL*image=rc_alloc(width*height*4);check(image!=0,"allocate real screenshot");uint32_t crc=0;
 check(!p->blt(p,image,1,0,0,0,0,width,height,0)&&!real->bs->crc32(image,width*height*4,&crc),"capture real screen");rc_release(image);return crc;
}
ES EA efi_main(HANDLE image,ST*st){
 (void)image;(void)change_on_confirm;(void)saved_identity_byte;if(!tcg())return ERR(3);real=st;shadow=*st;rt=*st->rt;bs=*st->bs;output=*st->out;
 rt.set_variable=set;bs.locate_handles=locate;bs.handle_protocol=handle;output.out=text;output.attribute=attr;output.clear=clear;output.cursor=cursor;output.enable_cursor=enable;
 input=(INPUT){0,read_key,0};shadow.rt=&rt;shadow.bs=&bs;shadow.out=&output;shadow.in=&input;
 trace("RECOVERY03_LAB_BEGIN\n");check(rc_initialize(&shadow,proof,&proof_allowed,0x8900603),"initialize actual recovery services");
 check(rc_identity()!=3&&!rc_authorized(),"actual OVMF identity cannot authorize ASUS recovery");
 make_identity();injected=1;shadow.tables=&table;shadow.table_count=1;
 check(rc_identity()==3,"actual parser and SHA accept isolated exact original-module and board fixtures");
 check(!rc_authorized(),"matching identity is insufficient without writer-exclusion proof");
 script="!";check(rc_ui_attempt()==RC_READ_ONLY&&target_sets==0,"actual read-only UI asks for no password and writes nothing");
 proof_allowed=1;check(rc_authorized(),"explicit lab-only writer exclusion enables test recovery");
 check(!real->rt->set_variable(rc_name,&rc_guid,3,128,(void*)fixture_record),"create owned isolated test record through real OVMF NV");
 uint64_t canary=0x4277bbac5906e119ULL;check(!real->rt->set_variable(U("Unrelated"),&fixture_guid,3,8,&canary),"create unrelated NV canary");
 real->out->enable_cursor(real->out,0);real->out->out(real->out,U("Original recovery screen marker\r\n"));uint32_t before=screen_crc();
 script="\x1b";check(rc_ui_attempt()==RC_CANCELLED&&target_sets==0,"first masked-input cancellation preserves credential");check(screen_crc()==before,"cancel restores original full framebuffer");
 script="\x1b";check(rc_ui_attempt()==RC_CANCELLED&&target_sets==0,"repeated cancellation remains usable");
 script="Wrong-Password\ry!";check(rc_ui_attempt()==RC_DENIED&&target_sets==0,"wrong real UI input does not delete");
 uint8_t record[128];check(rc_read(record)==RC_OK&&ap_constant_equal(record,fixture_record,128),"wrong input preserves exact owned record");ap_secure_zero(record,128);
 shadow.in=real->in;trace("READY_FOR_DPAPI_HANDOFF\n");RC_RESULT result=rc_ui_attempt();
 check(result==RC_OK&&target_sets==1,"real keyboard DPAPI handoff authenticates and deletes only exact record");
 check(prompt_masks>=8,"real console displays password masks");check(rc_read(record)==RC_ABSENT,"real NV confirms credential absent after recovery");
 UN n=8;uint32_t a=0;uint64_t value=0;check(!real->rt->get_variable(U("Unrelated"),&fixture_guid,&a,&n,&value)&&a==3&&n==8&&value==canary,"unrelated variable remains unchanged");
 shadow.in=&input;script="!";check(rc_ui_attempt()==RC_ABSENT&&target_sets==1,"repeat recovery reports absence without writing");
 check(rc_shutdown(),"event closure verified before carrier may return to loader");check(!rc_alive()&&rc_delete_known((const uint8_t*)"Wrong-Password",14)==RC_READ_ONLY,"closed carrier cannot write");
 trace("RECOVERY03_LAB_PASS\n");finish(0x10);return 0;
}
