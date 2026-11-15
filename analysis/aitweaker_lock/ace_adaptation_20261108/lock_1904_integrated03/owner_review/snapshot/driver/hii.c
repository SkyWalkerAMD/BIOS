#include "lock.h"
static GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID strings_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID setup_package={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
static CALLBACK original_callback;
static ROUTE original_route;
static CONFIG *setup_config;
HANDLE setup_hii;
static int manager_installed;
static ES EA config_callback(CONFIG *this,UN action,uint16_t q,uint8_t type,void *value,BROWSER_ACTION_REQUEST *request) {
 if(q==LOCK_QID || q==LOCK_CLEAR_QID) {
  if(request)*request=0;
  if((action==0 || action==1) && !platform_session_owned())return ERR(15);
  if(action==0)return manage_password(q==LOCK_CLEAR_QID)?0:ERR(15);
  return action==1?0:ERR(3);
 }
 if((action==0 || action==1) && policy_question(q) && !platform_can_enter() &&
    (!platform_session_owned() || !ensure_unlocked() || !platform_can_enter()))return ERR(15);
 return original_callback(this,action,q,type,value,request);
}
static int nibble(C16 c) {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int route_is_protected(const C16 *s) {
 if(!s)return 0;
 size_t n=c16len(s);
 if(n==1048576)return 1;
 for(size_t i=0;i+37<=n;i++) {
  if(i && s[i-1]!='&')continue;
  if(s[i]!='G'||s[i+1]!='U'||s[i+2]!='I'||s[i+3]!='D'||s[i+4]!='=')continue;
  uint8_t bytes[16];int valid=1;
  for(unsigned j=0;j<16;j++) {int a=nibble(s[i+5+2*j]),b=nibble(s[i+6+2*j]);if(a<0||b<0){valid=0;break;}bytes[j]=(uint8_t)((a<<4)|b);}
  if(valid && !memcmp(bytes,&oc_guid,16))return 1;
 }
 return 0;
}
static ES EA config_route(CONFIG *this,C16 *configuration,C16 **progress) {
 if(password_core.mode!=AP_MODE_DISABLED && route_is_protected(configuration) && !platform_can_enter()) {
  if(progress)*progress=configuration;
  audit(23,ERR(15));return ERR(15);
 }
 return original_route(this,configuration,progress);
}
static uint16_t add_string(STRINGS *strings,HANDLE handle,C16 *text) {
 UN n=0;uint16_t id=0;
 if(strings->languages(strings,handle,0,&n)!=ERR(5) || !n || n>4096)return 0;
 char *languages=alloc(n);if(!languages)return 0;
 if(FAILED(strings->languages(strings,handle,languages,&n)) || !n || languages[n-1]) {release(languages);return 0;}
 for(UN i=0;i<n;) {
  char *language=languages+i;UN j=i;while(j<n && languages[j] && languages[j]!=';')j++;
  if(j==i || j==n){id=0;break;}
  char end=languages[j];languages[j]=0;
  ES s=id?strings->set_string(strings,handle,id,language,text,0):strings->new_string(strings,handle,&id,language,0,text,0);
  if(FAILED(s)){id=0;break;}
  if(!end)break;i=j+1;
 }
 release(languages);return id;
}
static void *export(HII *db,HANDLE handle,UN *n) {
 *n=0;if(db->export_list(db,handle,n,0)!=ERR(5) || *n<24 || *n>4*1024*1024)return 0;
 void *p=alloc(*n);if(!p)return 0;
 if(FAILED(db->export_list(db,handle,n,p))) {release(p);return 0;}
 return p;
}
int install_hii_management(uint8_t *setup,UN setup_size) {
 if(manager_installed)return 1;
 if(!setup || setup_size<0x1535)return 0;
 HII *db=0;STRINGS *strings=0;UN n=0;HANDLE *handles=0;int result=0;
 if(FAILED(system_table->bs->locate_protocol(&database_guid,0,(void **)&db)) || !db)return 0;
 if(FAILED(system_table->bs->locate_protocol(&strings_guid,0,(void **)&strings)) || !strings)return 0;
 if(db->list(db,0,0,&n,0)!=ERR(5) || !n || n>8192 || n%sizeof(HANDLE))return 0;
 handles=alloc(n);if(!handles)return 0;
 if(FAILED(db->list(db,0,0,&n,handles)))goto done;
 for(UN i=0;i<n/sizeof(HANDLE);i++) {
  UN size=0;uint8_t *pack=export(db,handles[i],&size);if(!pack)continue;
  int matched=!memcmp(pack,&setup_package,16);release(pack);if(!matched)continue;
  HANDLE driver=0;CONFIG *config=0;
  if(FAILED(db->get_driver(db,handles[i],&driver)) || !driver || FAILED(system_table->bs->handle_protocol(driver,&config_guid,(void **)&config)) || !config)break;
  if(config->callback!=(CALLBACK)(void *)(setup+0x1534) || config->route!=(ROUTE)(void *)(setup+0x152c))break;
  uint16_t a=add_string(strings,handles[i],U("Ai Tweaker Password"));
  uint16_t b=add_string(strings,handles[i],U("Set or change the independent Ai Tweaker password. Current password is required to change it."));
  uint16_t c=add_string(strings,handles[i],U("Clear Ai Tweaker Password"));
  uint16_t d=add_string(strings,handles[i],U("Authenticate the current password to explicitly disable Ai Tweaker protection."));
  if(!a||!b||!c||!d)break;
  pack=export(db,handles[i],&size);if(!pack)break;
  uint8_t *changed=alloc(size+30);UN written=0;
  if(!changed || !policy_ifr_insert(pack,size,a,b,c,d,changed,size+30,&written)) {release(changed);release(pack);break;}
  original_callback=config->callback;original_route=config->route;setup_config=config;
  CONFIG replacement=*config;replacement.callback=config_callback;replacement.route=config_route;
  if(patch_memory(config,&replacement,sizeof(replacement)) && !FAILED(db->update_list(db,handles[i],changed))) {
   setup_hii=handles[i];manager_installed=1;result=1;audit(31,written);
  } else {
   replacement.callback=original_callback;replacement.route=original_route;patch_memory(config,&replacement,sizeof(replacement));
  }
  release(changed);release(pack);break;
 }
done:
 release(handles);return result;
}
