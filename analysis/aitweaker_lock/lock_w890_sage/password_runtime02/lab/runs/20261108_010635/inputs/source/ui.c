#include "runtime.h"
static GUID gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
typedef struct {GOP *gop;PIXEL *pixels;TEXTOUT *out;OUTMODE mode;UN width,height;uint32_t gop_mode;} SCREEN;
static int ui_busy;
static int print(C16 *text){return w890_runtime_active()&&!FAILED(w890_system_table->out->out(w890_system_table->out,text))&&w890_runtime_active();}
static int screen_open(SCREEN *s){
 memset(s,0,sizeof(*s));if(!w890_runtime_active())return 0;ST *st=w890_system_table;
 if(!w890_memory_present(st->out,sizeof(*st->out),0)||!w890_memory_present(st->in,sizeof(*st->in),0)||
    !st->in->read||!st->out->out||!st->out->attribute||!st->out->clear||!st->out->enable_cursor||!st->out->cursor||
    !w890_memory_present(st->out->mode,sizeof(OUTMODE),0))return 0;
 s->out=st->out;s->mode=*st->out->mode;
 if(s->mode.column<0||s->mode.row<0||s->mode.attribute<0||s->mode.mode<0)return 0;
 ES status=st->bs->locate_protocol(&gop_guid,0,(void **)&s->gop);
 if(!w890_runtime_active()||FAILED(status)||!w890_memory_present(s->gop,sizeof(*s->gop),0)||!s->gop->blt||
    !w890_memory_present(s->gop->mode,sizeof(*s->gop->mode),0)||!w890_memory_present(s->gop->mode->info,sizeof(GOPINFO),0))return 0;
 s->width=s->gop->mode->info->width;s->height=s->gop->mode->info->height;s->gop_mode=s->gop->mode->mode;
 if(!s->width||!s->height||s->width>4096||s->height>2160)return 0;
 s->pixels=w890_alloc(s->width*s->height*sizeof(PIXEL));if(!s->pixels)return 0;
 status=s->gop->blt(s->gop,s->pixels,BLT_VIDEO_TO_BUFFER,0,0,0,0,s->width,s->height,0);
 if(!w890_runtime_active()||FAILED(status)){w890_release(s->pixels);s->pixels=0;return 0;}
 /* No visible change occurs before a complete, restorable screenshot exists. */
 status=s->out->attribute(s->out,0x1f);if(!w890_runtime_active()||FAILED(status))return 0;
 status=s->out->clear(s->out);if(!w890_runtime_active()||FAILED(status))return 0;
 status=s->out->enable_cursor(s->out,1);return w890_runtime_active()&&!FAILED(status);
}
static int screen_close(SCREEN *s){
 int ok=1;
 if(s->pixels){
  if(!w890_runtime_active()||w890_system_table->out!=s->out||!s->gop->mode||!s->gop->mode->info||
     s->gop->mode->mode!=s->gop_mode||s->gop->mode->info->width!=s->width||s->gop->mode->info->height!=s->height)ok=0;
  if(ok){ES r=s->out->attribute(s->out,(UN)s->mode.attribute);ok=w890_runtime_active()&&!FAILED(r);}
  if(ok){ES r=s->out->cursor(s->out,(UN)s->mode.column,(UN)s->mode.row);ok=w890_runtime_active()&&!FAILED(r);}
  if(ok){ES r=s->out->enable_cursor(s->out,s->mode.cursor);ok=w890_runtime_active()&&!FAILED(r);}
  if(ok){ES r=s->gop->blt(s->gop,s->pixels,BLT_BUFFER_TO_VIDEO,0,0,0,0,s->width,s->height,0);ok=w890_runtime_active()&&!FAILED(r);}
  ap_secure_zero(s->pixels,s->width*s->height*sizeof(PIXEL));w890_release(s->pixels);s->pixels=0;
 }
 return ok;
}
static int key(KEY *k){
 if(!w890_runtime_active())return 0;
 for(;;){
  ES s=w890_system_table->in->read(w890_system_table->in,k);if(!w890_runtime_active())return 0;
  if(!FAILED(s))return 1;if(s!=ERR(6))return 0;
  s=w890_system_table->bs->stall(1000);if(!w890_runtime_active()||FAILED(s))return 0;
 }
}
static int password(C16 *prompt,uint8_t bytes[AP_PASSWORD_MAX],size_t *length){
 KEY k;size_t n=0;int invalid=0;memset(bytes,0,AP_PASSWORD_MAX);*length=0;
 if(!print(prompt))return 0;
 while(key(&k)){
  if(k.scan==0x17||k.ch==27)break;
  if(k.ch=='\r'){
   if(invalid){ap_secure_zero(bytes,AP_PASSWORD_MAX);return -1;}
   if(!print(U("\r\n")))break;*length=n;return 1;
  }
  if(k.ch=='\b'){if(n){bytes[--n]=0;if(!print(U("\b \b")))break;}continue;}
  if(k.ch>=32&&k.ch<=126){if(n>=AP_PASSWORD_MAX)invalid=1;else{bytes[n++]=(uint8_t)k.ch;if(!print(U("*")))break;}}
  else if(k.ch)invalid=1;
 }
 ap_secure_zero(bytes,AP_PASSWORD_MAX);return 0;
}
static void message(AP_STATUS status){
 if(status==AP_OK)print(U("\r\nDone.\r\n"));
 else if(status==AP_RATE_LIMITED)print(U("\r\nPlease wait at least 5 seconds before retrying.\r\n"));
 else if(status==AP_UNCONFIGURED)print(U("\r\nSet an independent password under Security first.\r\n"));
 else if(status==AP_BAD_ARGUMENT)print(U("\r\nUse matching passwords with 8-128 printable ASCII characters.\r\n"));
 else if(status==AP_STORAGE_FAILED||status==AP_CREDENTIAL_ERROR||status==AP_ENTROPY_FAILED||status==AP_CLOCK_FAILED)
  print(U("\r\nPassword storage or platform service failed. Access remains locked.\r\n"));
 else print(U("\r\nPassword was not accepted. No change was authorized.\r\n"));
}
static void acknowledge(void){KEY k;if(print(U("\r\nPress any key to return.\r\n")))key(&k);}
int EA w890_console_prompt(int operation){
 uint8_t current[AP_PASSWORD_MAX],next[AP_PASSWORD_MAX],confirm[AP_PASSWORD_MAX];size_t cn=0,nn=0,vn=0;SCREEN screen;KEY k;
 AP_STATUS status=AP_CANCELLED;int restore=0;
 memset(current,0,sizeof(current));memset(next,0,sizeof(next));memset(confirm,0,sizeof(confirm));memset(&screen,0,sizeof(screen));
 if(ui_busy||!w890_runtime_active()||w890_password_core.busy||operation< -1||operation>1)return 0;
 ui_busy=1;uint64_t token=w890_password_core.session_token;
 if(!screen_open(&screen))goto done;
 if(!print(U("Ai Tweaker - independent password\r\n\r\nESC cancels. 8-128 printable ASCII characters.\r\n\r\n")))goto done;
 if(w890_password_core.mode==AP_MODE_FAULT){status=AP_CREDENTIAL_ERROR;goto show;}
 if(operation<0&&w890_password_core.mode==AP_MODE_UNCONFIGURED){status=AP_UNCONFIGURED;goto show;}
 {uint64_t remaining=ap_retry_remaining_ms(&w890_password_core);if(remaining){status=remaining==UINT64_MAX?AP_CLOCK_FAILED:AP_RATE_LIMITED;goto show;}}
 if(operation<0){
  int input=password(U("Password: "),current,&cn);if(input<0){status=AP_BAD_ARGUMENT;goto show;}if(!input)goto done;
  status=w890_runtime_active()?w890_management_action(&w890_password_core,token,W890_VERIFY_QID,current,cn,0,0,0,0):AP_OUTSIDE_SESSION;
  if(status!=AP_OK)goto show;goto done;
 }
 if(w890_password_core.mode==AP_MODE_ENABLED){
  int input=password(U("Current password: "),current,&cn);if(input<0){status=AP_BAD_ARGUMENT;goto show;}if(!input)goto done;
 }
 if(operation==1){
  if(!print(U("Disable Ai Tweaker password protection? Press Y to confirm.\r\n"))||!key(&k)||(k.ch!='Y'&&k.ch!='y'))goto done;
  status=w890_runtime_active()?w890_management_action(&w890_password_core,token,W890_CLEAR_QID,current,cn,0,0,0,0):AP_OUTSIDE_SESSION;
 }else{
  int input=password(U("New password: "),next,&nn);if(input<0){status=AP_BAD_ARGUMENT;goto show;}if(!input)goto done;
  input=password(U("Confirm password: "),confirm,&vn);if(input<0){status=AP_BAD_ARGUMENT;goto show;}if(!input)goto done;
  status=w890_runtime_active()?w890_management_action(&w890_password_core,token,W890_SET_QID,current,cn,next,nn,confirm,vn):AP_OUTSIDE_SESSION;
 }
show:
 ap_secure_zero(current,sizeof(current));ap_secure_zero(next,sizeof(next));ap_secure_zero(confirm,sizeof(confirm));message(status);acknowledge();
done:
 if(status==AP_CANCELLED)ap_cancel(&w890_password_core,token);
 ap_secure_zero(current,sizeof(current));ap_secure_zero(next,sizeof(next));ap_secure_zero(confirm,sizeof(confirm));
 restore=screen_close(&screen);ui_busy=0;if(!restore)w890_provider_fault();
 return restore&&status==AP_OK&&w890_runtime_active()&&token==w890_password_core.session_token;
}
