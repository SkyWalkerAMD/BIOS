/* VM-only boot-service driver used to measure lifecycle and storage. */
#include "lab.h"
static LAB_PROTOCOL protocol;
static ES EA operation(LAB_PROTOCOL*p,unsigned op){if(p!=&protocol||p->signature!=LAB_SIGNATURE)return ERR(2);p->calls++;if(op==1)p->unlocked=1;else if(op==2)p->unlocked=0;else if(op!=0)return ERR(3);return 0;}
ES EA efi_main(HANDLE self,ST*st){
 if(!st||!st->bs||!tcg())return ERR(3);
 LAB_PROTOCOL*existing=0;if(!st->bs->locate_protocol(&lab_guid,0,(void**)&existing))return ERR(20);
 trace("RESIDENT_ENTRY\n");uint64_t boots=0;ES e=read_u64(st,(C16*)L"Lab1904Boots",&boots);if(e&&e!=ERR(14))return e;
 e=write_u64(st,(C16*)L"Lab1904Boots",boots+1);if(e)return e;
 protocol.signature=LAB_SIGNATURE;protocol.owner=self;protocol.boot_counter=boots+1;protocol.operation=operation;
 HANDLE h=0;e=((INSTALL)st->bs->install_protocol)(&h,&lab_guid,0,&protocol);event("RESIDENT_INSTALLED",e);return e;
}
