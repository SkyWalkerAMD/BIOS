/* QEMU TCG ONLY. Exercises real HII services; never a hardware carrier. */
#include "../password_runtime02/source/efi.h"
#include "../password/w890_policy.h"
#include "../password/management_package.h"
#include "fixtures.h"
static ST *st;
static unsigned checks;
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID strings_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
typedef ES(EA *NEW_LIST)(HII *,const void *,HANDLE,HANDLE *);
typedef ES(EA *REMOVE_LIST)(HII *,HANDLE);
typedef ES(EA *GET_STRING)(STRINGS *,const char *,HANDLE,uint16_t,C16 *,UN *,void **);
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
static void trace(const char *s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void finish(unsigned code){__asm__ volatile("outl %0,%1"::"a"(code),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char *s){checks++;trace(ok?"PASS ":"FAIL ");trace(s);trace("\n");if(!ok)finish(0x11);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
static uint32_t u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(8*i));}
static uint8_t *alloc(UN n){void *p=0;check(n&&n<8*1024*1024&&!st->bs->allocate_pool(4,n,&p)&&p,"allocate bounded private buffer");return p;}
static void release(void *p){if(p)check(!st->bs->free_pool(p),"free private buffer");}
static uint8_t *export_pack(HII *db,HANDLE h,UN *n){
 *n=0;check(db->export_list(db,h,n,0)==ERR(5)&&*n>=24&&*n<8*1024*1024,"export size query");
 UN cap=*n;uint8_t *p=alloc(cap);check(!db->export_list(db,h,n,p)&&*n<=cap&&u32(p+16)==*n,"export complete package");return p;
}
static const uint8_t *form(const uint8_t *p,UN n,UN *size){
 const uint8_t *found=0;*size=0;if(n<24||u32(p+16)!=n)return 0;
 for(UN at=20;at<n;){if(n-at<4)return 0;uint32_t h=u32(p+at),z=h&0xffffff;uint8_t kind=(uint8_t)(h>>24);
  if(z<4||z>n-at)return 0;if(kind==2){if(found)return 0;found=p+at;*size=z;}
  if(kind==0xdf)return z==4&&at+4==n?found:0;at+=z;
 }return 0;
}
static int other_packages_equal(const uint8_t *a,UN an,const uint8_t *b,UN bn){
 UN ai=20,bi=20;
 for(;;){
  if(an-ai<4||bn-bi<4)return 0;uint32_t ah=u32(a+ai),bh=u32(b+bi),az=ah&0xffffff,bz=bh&0xffffff;
  if(az<4||az>an-ai||bz<4||bz>bn-bi)return 0;
  if((ah>>24)==2){ai+=az;continue;}if((bh>>24)==2){bi+=bz;continue;}
  if(az!=bz||memcmp(a+ai,b+bi,az))return 0;
  if((ah>>24)==0xdf)return ai+az==an&&bi+bz==bn;ai+=az;bi+=bz;
 }
}
static int string_equals(STRINGS *s,HANDLE h,uint16_t id,C16 *want){
 C16 value[256];UN n=sizeof(value);memset(value,0xff,sizeof(value));
 if(((GET_STRING)s->get_string)(s,"en-US",h,id,value,&n,0)||n<2||n>sizeof(value)||n%2)return 0;
 UN chars=n/2;if(value[chars-1])return 0;
 for(UN i=0;i<chars;i++)if(value[i]!=want[i])return 0;return 1;
}
ES EA efi_main(HANDLE image,ST *system){
 if(!tcg())return ERR(3);st=system;trace("W890_HII_LAB01_BEGIN\n");
 HII *db=0;STRINGS *strings=0;HANDLE h=0,driver=0;
 check(!st->bs->locate_protocol(&db_guid,0,(void **)&db)&&db,"real HII Database locate");
 check(!st->bs->locate_protocol(&strings_guid,0,(void **)&strings)&&strings,"real HII String locate");
 check(!((NEW_LIST)db->new_list)(db,w890_management_package,image,&h)&&h,"management NewPackageList");
 check(!db->get_driver(db,h,&driver)&&driver==image,"management driver association");
 check(string_equals(strings,h,4,U("Set or change password")),"management action prompt resolves");
 UN n=0,fn=0;uint8_t *pack=export_pack(db,h,&n);const uint8_t *f=form(pack,n,&fn);
 check(f&&fn==90&&!memcmp(f,w890_management_package+20,fn),"management forms round trip unchanged");release(pack);
 check(!((REMOVE_LIST)db->remove_list)(db,h),"management remove");
 n=0;check(db->export_list(db,h,&n,0)==ERR(14),"management no longer in HII database");
 h=0;check(!((NEW_LIST)db->new_list)(db,original_package,image,&h)&&h,"original W890 forms and English strings publish in isolated lab package");
 pack=export_pack(db,h,&n);f=form(pack,n,&fn);check(f&&fn==sizeof(original_forms)&&!memcmp(f,original_forms,fn),"original forms exact before changes");release(pack);
 C16 *texts[]={U("Ai Tweaker Password"),U("Set or change the independent password."),U("Clear Ai Tweaker Password"),U("Current password is required to clear protection."),U("Verify Ai Tweaker Password"),U("Unlock for this BIOS visit.")};
 uint16_t tokens[6]={0};
 for(unsigned i=0;i<6;i++){
  check(!strings->new_string(strings,h,&tokens[i],"en-US",0,texts[i],0)&&tokens[i]>ORIGINAL_MAX_STRING,"real new string gets a noncolliding token");
  check(string_equals(strings,h,tokens[i],texts[i]),"new string readback matches");
  for(unsigned j=0;j<i;j++)check(tokens[i]!=tokens[j],"new tokens unique");
 }
 UN before_n=0;uint8_t *before=export_pack(db,h,&before_n);f=form(before,before_n,&fn);
 uint8_t *changed=alloc(fn+45);size_t written=0;
 check(f&&w890_security_insert(f,fn,tokens,changed,fn+45,&written)&&written==fn+45,"actual Security inserter consumes real allocated tokens");
 uint8_t *update=alloc(written+24);memcpy(update,original_package,16);put32(update+16,(uint32_t)written+24);memcpy(update+20,changed,written);put32(update+20+written,0xdf000004);
 check(!db->update_list(db,h,update),"real UpdatePackageList accepts changed forms");
 pack=export_pack(db,h,&n);f=form(pack,n,&fn);check(f&&fn==written&&!memcmp(f,changed,fn),"updated forms exported byte exact");
 check(other_packages_equal(before,before_n,pack,n),"all nonform packages preserved by update");
 for(unsigned i=0;i<6;i++)check(string_equals(strings,h,tokens[i],texts[i]),"allocated prompt remains after update");release(pack);
 memcpy(update+20,original_forms,sizeof(original_forms));put32(update+16,sizeof(original_forms)+24);put32(update+20+sizeof(original_forms),0xdf000004);
 check(!db->update_list(db,h,update),"rollback original forms");
 pack=export_pack(db,h,&n);f=form(pack,n,&fn);check(f&&fn==sizeof(original_forms)&&!memcmp(f,original_forms,fn),"rollback forms exact");
 check(other_packages_equal(before,before_n,pack,n),"rollback leaves all other packages intact");
 release(pack);release(before);release(changed);release(update);
 check(!((REMOVE_LIST)db->remove_list)(db,h),"isolated W890 lab package removed");
 n=0;check(db->export_list(db,h,&n,0)==ERR(14),"no remaining lab HII package");
 trace("W890_HII_LAB01_PASS\n");finish(0x10);return 0;
}
