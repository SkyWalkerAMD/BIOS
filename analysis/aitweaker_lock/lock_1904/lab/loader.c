#include "lab.h"
ES EA efi_main(HANDLE self,ST*st){
 if(!st||!st->bs||!tcg())return ERR(3);HANDLE driver=0;ES e=start_file(st,self,(C16*)L"\\RESIDENT.EFI",&driver);event("LOADER_DRIVER_START",e);if(e)return e;
 LAB_PROTOCOL*p=0;e=st->bs->locate_protocol(&lab_guid,0,(void**)&p);if(e||!p)return ERR(7);e=p->operation(p,1);trace("LOADER_RETURN\n");return e;
}
