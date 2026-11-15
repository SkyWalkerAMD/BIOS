#include "../password_runtime02/source/efi.h"
#include "loader_fixture.h"
static void trace(const char*s){while(*s)__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s++),"Nd"((uint16_t)0x402));}
static void hex(uint64_t n){char b[17];b[16]=0;for(int i=15;i>=0;i--){b[i]="0123456789abcdef"[n&15];n>>=4;}trace(b);}
static void stop(unsigned x){__asm__ volatile("outl %0,%1"::"a"(x),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int yes,const char*s){trace(yes?"PASS ":"FAIL ");trace(s);trace("\n");if(!yes)stop(0x11);}
ES EA efi_main(HANDLE parent,ST*st){
 uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));
 if(b!=0x54474354||c!=0x43544743||d!=0x47435447)return ERR(3);
 trace("W890_PACKAGING_LOADER_BEGIN\n");
 static GUID guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
 for(unsigned run=0;run<2;run++){
  HANDLE image=0;LOADED*li=0;ES status=st->bs->load_image(0,parent,0,(void*)composed_fixture,sizeof(composed_fixture),&image);
  trace("LOAD_STATUS ");hex(status);trace("\n");check(!status&&image,"actual OVMF LoadImage accepts composed original AMITSE PE");
  check(!st->bs->handle_protocol(image,&guid,(void**)&li)&&li&&li->image_size==EXPECTED_IMAGE_SIZE,"actual LoadedImage has exact expanded size");
  uintptr_t base=(uintptr_t)li->image_base;trace("ACTUAL_IMAGE_BASE ");hex(base);trace("\nHEADER_IMAGE_BASE ");hex(*(uint64_t*)(base+192+24+24));trace("\n");
  /* Record every changed header byte before identity check to diagnose loader
   * transformations; no original vendor entry or hardware protocol is called. */
  for(unsigned j=0;j<1024;j++)if(((uint8_t*)base)[j]!=composed_fixture[j]){trace("HEADER_DELTA ");hex(j);trace(" ");hex(composed_fixture[j]);trace(" ");hex(((uint8_t*)base)[j]);trace("\n");}
  typedef int(EA*LIVE)(uintptr_t,uint64_t);
  check(((LIVE)(base+LAYOUT_LIVE_RVA))(base,li->image_size)==1,"real loaded image satisfies fixed identity validator");
#if FUNCTIONAL_AGGREGATE
  check(!st->bs->unload_image(image),"actual functional aggregate unloads before any vendor entry executes");continue;
#else
  if(run==0){check(!st->bs->unload_image(image),"unstarted composed image unload succeeds");continue;}
  status=st->bs->start_image(image,0,0);trace("START_STATUS ");hex(status);trace("\n");
  check(status==0,"actual StartImage reaches only TCG fixture entry");
  check(*(uint64_t*)(base+STARTED_RVA)==UINT64_C(0x57533839304c4142),"entry passed real handle ST identity relocations function pointer and zero BSS");
#endif
 }
 trace("W890_PACKAGING_LOADER_PASS\n");stop(0x10);return 0;
}
