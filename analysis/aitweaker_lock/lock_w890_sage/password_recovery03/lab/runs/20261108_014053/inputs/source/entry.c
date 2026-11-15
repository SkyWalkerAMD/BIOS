#include "recovery.h"
ES EA rc_application(HANDLE image,ST *st){
 (void)image;
 /* No authority has yet been established to prove an original boot with no
  * resident writer. Never replace this NULL with a compatibility switch. */
 if(!rc_initialize(st,0,0,0))return ERR(15);
 RC_RESULT result=rc_ui_attempt();rc_shutdown();
 return result==RC_OK||result==RC_ABSENT||result==RC_CANCELLED?0:ERR(15);
}
ES EA efi_main(HANDLE image,ST *st){return rc_application(image,st);}
