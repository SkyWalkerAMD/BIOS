#include "ui_engine.inc"
RC_RESULT rc_ui_attempt(void){
 SCREEN screen;uint8_t bytes[128];size_t length=0;RC_RESULT result=RC_CANCELLED;KEY keypress;
 memset(&screen,0,sizeof(screen));memset(bytes,0,sizeof(bytes));
 if(ui_busy||!rc_alive())return RC_IO;ui_busy=1;current_screen=&screen;
 if(!screen_open(&screen)){result=RC_IO;goto done;}
 if(!print(U("Ai Tweaker - independent recovery\r\n\r\nESC returns without deleting a password.\r\n\r\n"))){result=RC_IO;goto done;}
 if(!rc_authorized()){
  result=RC_READ_ONLY;
  print(U("Read-only: original boot / writer exclusion or exact board identity is not proven.\r\nNo password will be requested and no variable will be changed.\r\n"));goto acknowledge;
 }
 {uint8_t record[128];result=rc_read(record);int enabled=result==RC_OK&&record[12]==1;ap_secure_zero(record,128);
  if(result==RC_ABSENT){print(U("The private credential variable is already absent.\r\n"));goto acknowledge;}
  if(result!=RC_OK){print(U("The private credential record is invalid or unreadable. No deletion is permitted.\r\n"));goto acknowledge;}
  if(!enabled){result=RC_DENIED;print(U("Disabled records have no password verifier. Recovery ownership is unproven; deletion is refused.\r\n"));goto acknowledge;}
 }
 {int input=password(U("Known test password: "),bytes,&length);if(input<0){result=RC_INVALID;goto acknowledge;}if(!input)goto done;}
 if(!print(U("Delete only the authenticated Ai Tweaker test record? Press Y to confirm.\r\n"))||!key(&keypress)||(keypress.ch!='y'&&keypress.ch!='Y'))goto done;
 result=rc_delete_known(bytes,length);ap_secure_zero(bytes,128);
 if(result==RC_OK)print(U("Recovery complete. The private credential variable is verified absent.\r\n"));
 else if(result==RC_ABSENT)print(U("The private credential variable is already absent.\r\n"));
 else if(result==RC_DENIED)print(U("Password not accepted or the record is disabled. Nothing was deleted.\r\n"));
 else if(result==RC_READ_ONLY)print(U("Identity or writer exclusion changed. No deletion authorized.\r\n"));
 else print(U("Recovery could not be confirmed. Keep the encrypted recovery journal.\r\n"));
acknowledge:
 ap_secure_zero(bytes,128);if(print(U("Press any key to return.\r\n")))key(&keypress);
done:
 ap_secure_zero(bytes,128);int restored=screen_close(&screen);current_screen=0;ui_busy=0;
 if(!restored){rc_shutdown();return RC_IO;}return result;
}
