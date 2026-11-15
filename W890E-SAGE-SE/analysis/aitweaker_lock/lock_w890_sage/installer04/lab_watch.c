/* Timing/identity lab. Original W890 image is LoadImage'd but never started. */
#include "source/cold_watch.h"
#include "watch_fixture.h"
static ST *st;static unsigned seen,load_stage;static const CW_TICKET *escaped;static HANDLE observed;
static ST table_copy;static BS boot_copy;
#if CW_PREEXIST==3
static void *saved_handle_protocol;
#endif
void *memcpy(void*d,const void*s,size_t n){uint8_t*a=d;const uint8_t*b=s;while(n--)*a++=*b++;return d;}
void *memset(void*d,int x,size_t n){uint8_t*a=d;while(n--)*a++=(uint8_t)x;return d;}
int memcmp(const void*a,const void*b,size_t n){const uint8_t*x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
static void trace(const char*s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void stop(unsigned x){__asm__ volatile("outl %0,%1"::"a"(x),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int x,const char*s){trace(x?"PASS ":"FAIL ");trace(s);trace("\n");if(!x)stop(0x11);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
static int EA consume(const CW_TICKET*t){
 HANDLE h=0;LOADED*li=0;check(cw_valid(t,&h,&li)&&h&&li&&li->image_size==909312,"private notification ticket validates exact loaded W890 module");
 UN prior=st->bs->raise_tpl(16);st->bs->restore_tpl(prior);
 check(prior==8,"real load notification executes at TPL_CALLBACK");
 check(load_stage==1&&!seen,"notification arrives before LoadImage returns and before any StartImage");
 seen++;escaped=t;observed=h;
#if CW_PREEXIST==2
 extern void cw_lab_reentry(void);cw_lab_reentry();check(cw_state()==CW_FAULT&&!cw_valid(t,0,0),"nested notification faults live window immediately");
#elif CW_PREEXIST==3
 saved_handle_protocol=(void*)boot_copy.handle_protocol;boot_copy.handle_protocol=(void*)consume;
#endif
 return 1;
}
static uint8_t path[24]={4,6,20,0,0xdf,0x0a,0xda,0xb1,0x77,0x4f,0x70,0x40,0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a,0x7f,0xff,4,0};
ES EA efi_main(HANDLE image,ST*system){
 if(!tcg())return ERR(3);st=system;trace("W890_COLD_WATCH_BEGIN\n");HANDLE child=0;
 /* Service replacement touches only a private copy of the table. */
 memcpy(&table_copy,system,sizeof(table_copy));memcpy(&boot_copy,system->bs,sizeof(boot_copy));table_copy.bs=&boot_copy;
#if CW_PREEXIST==1
 load_stage=1;check(!st->bs->load_image(0,image,path,(void*)original_amitse_file,sizeof(original_amitse_file),&child)&&child,"standard LoadImage original W890 without executing its entry");load_stage=2;
 check(cw_arm(st,consume)==ERR(15)&&cw_state()==CW_FAULT&&!seen,"already loaded target refuses late installation authority");
#else
 check(!cw_arm(&table_copy,consume)&&cw_state()==CW_ARMED,"arm before target exists");
 load_stage=1;check(!st->bs->load_image(0,image,path,(void*)original_amitse_file,sizeof(original_amitse_file),&child)&&child,"standard LoadImage original W890 without executing its entry");load_stage=2;
#if CW_PREEXIST==2
 check(seen==1&&cw_state()==CW_FAULT,"outer successful consumer cannot overwrite nested fault");
#elif CW_PREEXIST==3
 check(seen==1&&cw_state()==CW_FAULT,"changed pinned service rejects outer consumer success");
 boot_copy.handle_protocol=saved_handle_protocol;
#else
 check(seen==1&&observed==child&&cw_state()==CW_OBSERVED,"exact target observed once during loader notification");
#endif
 check(!cw_valid(escaped,0,0),"ticket expires when notification returns");
#endif
 check(!cw_close()&&cw_state()==CW_CLOSED,"all watcher notifications closed");
 check(!st->bs->unload_image(child),"unload unstarted original W890 image");
 trace("W890_COLD_WATCH_PASS\n");stop(0x10);return 0;
}
