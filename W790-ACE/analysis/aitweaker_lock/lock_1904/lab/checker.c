#include "lab.h"
ES EA efi_main(HANDLE self,ST*st){
 (void)self;if(!st||!st->bs||!tcg())return ERR(3);LAB_PROTOCOL*p=0;ES e=st->bs->locate_protocol(&lab_guid,0,(void**)&p);
 if(e||!p||p->signature!=LAB_SIGNATURE||p->unlocked!=1)return ERR(7);
 e=p->operation(p,0);event("CHECKER_DRIVER_CALL",e);return e;
}
