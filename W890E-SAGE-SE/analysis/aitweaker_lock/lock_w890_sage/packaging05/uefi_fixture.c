/* Only for the OVMF composition lab. Never starts original AMITSE code. */
#include "layout.h"
#include "../password_runtime02/source/efi.h"
extern uint64_t i05_fixture_entry(void*,void*);
__declspec(dllexport) uint64_t i05_fixture_started;
__declspec(dllexport) ES EA i05_uefi_fixture_entry(HANDLE image,ST *st){
 uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));
 if(b!=0x54474354||c!=0x43544743||d!=0x47435447)return ERR(3);
 static GUID guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
 LOADED *li=0;
 if(!st||st->hdr.sig!=UINT64_C(0x5453595320494249)||!st->bs||st->bs->handle_protocol(image,&guid,(void**)&li)||!li)return ERR(15);
 if(!i05_layout_live((uintptr_t)li->image_base,li->image_size))return ERR(15);
 if(i05_fixture_entry((void*)0x11223344,(void*)0x55667788)!=(UINT64_C(0x4c4b5041434b3035)^UINT64_C(0x1234567812345678)))return ERR(7);
 i05_fixture_started=UINT64_C(0x57533839304c4142);return 0;
}
