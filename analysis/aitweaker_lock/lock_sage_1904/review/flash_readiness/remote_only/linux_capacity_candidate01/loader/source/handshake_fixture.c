/* VM TEST ONLY. This is an EFI protocol consumer, not the Linux kernel. */
#include "efi_min.h"
#include "sha256.h"
typedef ES(EA *LOCATE_DP)(GUID*,void**,HANDLE*);
typedef struct LF2 LF2;struct LF2{ES(EA*load)(LF2*,uint8_t*,uint8_t,UN*,void*);};
static GUID li_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID lf_guid={0x4006c0c1,0xfcb3,0x403e,{0x99,0x6d,0x4a,0x6c,0x87,0x24,0xe0,0x6d}};
static uint8_t path[24]={4,3,20,0,0x27,0xe4,0x68,0x55,0xfc,0x68,0x3d,0x4f,0xac,0x74,0xca,0x55,0x52,0x31,0xcc,0x68,0x7f,0xff,4,0};
static void trace(const char*s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354U&&c==0x43544743U&&d==0x47435447U;}
#define CHECK(c) do{if(!(c)){trace("LC01_FIXTURE_FAIL\n");return ERR(7);}}while(0)
ES EA efi_main(HANDLE self,ST*st){
 if(!tcg())return ERR(3);trace("LC01_FIXTURE_ENTER\n");
 LOADED*li=0;CHECK(!st->bs->handle_protocol(self,&li_guid,(void**)&li)&&li);
 C16 expected[]=L"fixture_exact_commandline=LC01 no_fallback=1";CHECK(li->options_size==sizeof(expected)&&ap_constant_equal(li->options,expected,sizeof(expected)));
 void*remaining=path;HANDLE h=0;CHECK(!((LOCATE_DP)st->bs->locate_device_path)(&lf_guid,&remaining,&h)&&h);
 LF2*p=0;CHECK(!st->bs->handle_protocol(h,&lf_guid,(void**)&p)&&p);
 UN n=0;CHECK(p->load(p,remaining,0,&n,0)==ERR(5)&&n==4096);
 CHECK(p->load(p,remaining,1,&n,0)==ERR(3));CHECK(p->load(p,remaining,0,0,0)==ERR(2));CHECK(p->load(0,remaining,0,&n,0)==ERR(2));
 uint8_t badpath[]={0x7f,1,4,0};CHECK(p->load(p,badpath,0,&n,0)==ERR(14));
 uint8_t*data=0;CHECK(!st->bs->allocate_pool(2,4096+16,(void**)&data)&&data);
 for(unsigned i=0;i<4112;i++)data[i]=0xa5;n=4095;CHECK(p->load(p,remaining,0,&n,data)==ERR(5)&&n==4096&&data[0]==0xa5);
 n=4096;CHECK(!p->load(p,remaining,0,&n,data)&&n==4096);
 for(unsigned i=0;i<4096;i++)CHECK(data[i]==(uint8_t)(i*17+3));for(unsigned i=4096;i<4112;i++)CHECK(data[i]==0xa5);
 CHECK(!st->bs->free_pool(data));trace("LC01_FIXTURE_LOADFILE2_ABI_PASS\nLC01_FIXTURE_RETURN_SUCCESS\n");return 0;
}
