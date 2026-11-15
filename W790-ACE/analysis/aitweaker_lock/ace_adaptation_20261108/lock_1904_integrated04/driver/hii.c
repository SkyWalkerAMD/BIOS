#include "lock.h"
#include "save_feedback.h"
static GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID strings_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID setup_package={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
static CALLBACK original_callback;
static ROUTE original_route;
static CONFIG *setup_config;
HANDLE setup_hii;
static int manager_installed,manager_busy,manager_failed;
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
  save_feedback_note_denial(ERR(15));audit(23,ERR(15));return ERR(15);
 }
 return original_route(this,configuration,progress);
}
/* A provider callback may retire Boot Services before returning. In that case
 * leave temporary boot allocations to firmware teardown; do not call FreePool. */
static void hii_release(void *p) {if(!boot_services_ended)release(p);}
static void *hii_alloc(UN n) {if(boot_services_ended)return 0;void *p=alloc(n);return boot_services_ended?0:p;}
static uint16_t add_string(STRINGS *strings,HANDLE handle,C16 *text) {
 UN n=0;uint16_t id=0;
 if(boot_services_ended || strings->languages(strings,handle,0,&n)!=ERR(5) || boot_services_ended || !n || n>4096)return 0;
 UN capacity=n;char *languages=hii_alloc(n);if(!languages)return 0;
 if(FAILED(strings->languages(strings,handle,languages,&n)) || boot_services_ended || !n || n>capacity || languages[n-1]) {hii_release(languages);return 0;}
 for(UN i=0;i<n;) {
  char *language=languages+i;UN j=i;while(j<n && languages[j] && languages[j]!=';')j++;
  if(j==i || j==n){id=0;break;}
  char end=languages[j];languages[j]=0;
  ES s=id?strings->set_string(strings,handle,id,language,text,0):strings->new_string(strings,handle,&id,language,0,text,0);
  if(FAILED(s) || boot_services_ended){id=0;break;}
  if(!end)break;i=j+1;
 }
 hii_release(languages);return id;
}
static void *export(HII *db,HANDLE handle,UN *n) {
 *n=0;if(boot_services_ended || db->export_list(db,handle,n,0)!=ERR(5) || boot_services_ended || *n<24 || *n>4*1024*1024)return 0;
 UN capacity=*n;void *p=hii_alloc(capacity);if(!p)return 0;
 if(FAILED(db->export_list(db,handle,n,p)) || boot_services_ended || *n<24 || *n>capacity) {hii_release(p);return 0;}
 return p;
}
static uint16_t hii16(const uint8_t *p) {return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static uint32_t hii32(const uint8_t *p) {return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int hii_question(uint8_t op) {return op==5||op==6||op==7||op==8||op==12||op==15||op==0x1a||op==0x1b||op==0x1c||op==0x23;}
/* Validate only the two management actions in a bounded live package export.
 * They must remain unique direct children of Security, never hidden inside a
 * conditional scope or reassigned to a different formset/question opcode. */
static int management_actions(const uint8_t *src,UN n) {
 static const uint8_t formset[16]={0x4a,0x10,0x59,0x7b,0x0d,0xc0,0x58,0x41,0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15};
 unsigned set=0,clear=0,security=0,ended=0;
 if(!src || n<24 || n>4*1024*1024 || hii32(src+16)!=n || memcmp(src,&setup_package,16))return 0;
 for(UN p=20;p<n;) {
  if(n-p<4)return 0;
  uint32_t header=hii32(src+p),length=header&0xffffffu;uint8_t type=(uint8_t)(header>>24);
  if(length<4 || length>n-p)return 0;
  if(type==0xdf) {if(length!=4 || p+length!=n)return 0;ended=1;}
  if(type==2) {
   uint8_t stack[64];unsigned depth=0;int target_set=-1,target_form=-1;
   for(UN q=p+4;q<p+length;) {
    if(p+length-q<2)return 0;
    uint8_t op=src[q],size=src[q+1]&0x7f,scope=src[q+1]>>7;
    if(size<2 || size>p+length-q)return 0;
    if(hii_question(op)) {
     if(size<13)return 0;
     uint16_t id=hii16(src+q+6);
     if(id==LOCK_QID || id==LOCK_CLEAR_QID) {
      if(op!=0x0c || size!=15 || scope || target_set<0 || target_form<0 || depth!=(unsigned)target_form+1 ||
         !hii16(src+q+2) || !hii16(src+q+4) || hii16(src+q+8) || hii16(src+q+10)!=0xffff ||
         src[q+12]!=4 || hii16(src+q+13))return 0;
      if(id==LOCK_QID) {if(++set!=1)return 0;} else if(++clear!=1)return 0;
     }
    }
    if(op==0x0e) {
     if(size<23 || !scope || target_set>=0)return 0;
     if(!memcmp(src+q+2,formset,16))target_set=(int)depth;
    }
    if(op==1) {
     if(size<6 || !scope || target_form>=0)return 0;
     if(target_set>=0 && hii16(src+q+2)==0x271e) {target_form=(int)depth;if(++security!=1)return 0;}
    }
    if(op==0x29) {
     if(size!=2 || scope || !depth)return 0;
     depth--;
     if((int)depth==target_form) {if(stack[depth]!=1)return 0;target_form=-1;}
     if((int)depth==target_set) {if(stack[depth]!=0x0e)return 0;target_set=-1;}
    } else if(scope) {if(depth>=sizeof(stack))return 0;stack[depth++]=op;}
    q+=size;
   }
   if(depth || target_set>=0 || target_form>=0)return 0;
  }
  p+=length;
 }
 return ended && security==1 && set==1 && clear==1;
}
static int config_owned(CONFIG *config) {
 return !boot_services_ended && memory_present(config,sizeof(*config),0) &&
        config->callback==config_callback && config->route==config_route;
}
static int manager_live(HII *db,HANDLE handle,CONFIG *config) {
 if(!handle || !config_owned(config))return 0;
 UN n=0;uint8_t *pack=export(db,handle,&n);
 int valid=pack && management_actions(pack,n);hii_release(pack);
 return valid && config_owned(config);
}
static void manager_fault(void) {
 manager_failed=1;manager_installed=0;ap_fault(&password_core);audit(32,ERR(7));
}
int install_hii_management(uint8_t *setup,UN setup_size) {
 if(boot_services_ended || manager_failed || manager_busy)return 0;
 if(!setup || setup_size<0x1535)return 0;
 HII *db=0;STRINGS *strings=0;UN n=0;HANDLE *handles=0;int result=0;
 manager_busy=1;
 if(FAILED(system_table->bs->locate_protocol(&database_guid,0,(void **)&db)) || boot_services_ended || !db)goto done;
 if(manager_installed) {
  result=manager_live(db,setup_hii,setup_config);
  goto done;
 }
 if(FAILED(system_table->bs->locate_protocol(&strings_guid,0,(void **)&strings)) || boot_services_ended || !strings)goto done;
 if(db->list(db,0,0,&n,0)!=ERR(5) || boot_services_ended || !n || n>8192 || n%sizeof(HANDLE))goto done;
 UN handle_capacity=n;handles=hii_alloc(n);if(!handles)goto done;
 if(FAILED(db->list(db,0,0,&n,handles)) || boot_services_ended || n>handle_capacity || n%sizeof(HANDLE))goto done;
 for(UN i=0;i<n/sizeof(HANDLE);i++) {
  UN size=0;uint8_t *pack=export(db,handles[i],&size);if(!pack)continue;
  int matched=!memcmp(pack,&setup_package,16);hii_release(pack);if(!matched)continue;
  HANDLE driver=0;CONFIG *config=0;
  if(boot_services_ended || FAILED(db->get_driver(db,handles[i],&driver)) || boot_services_ended || !driver ||
     FAILED(system_table->bs->handle_protocol(driver,&config_guid,(void **)&config)) || boot_services_ended ||
     !memory_present(config,sizeof(*config),0))break;
  if(config->callback!=(CALLBACK)(void *)(setup+0x1534) || config->route!=(ROUTE)(void *)(setup+0x152c))break;
  uint16_t a=add_string(strings,handles[i],U("Ai Tweaker Password"));
  uint16_t b=add_string(strings,handles[i],U("Set or change the independent Ai Tweaker password. Current password is required to change it."));
  uint16_t c=add_string(strings,handles[i],U("Clear Ai Tweaker Password"));
  uint16_t d=add_string(strings,handles[i],U("Authenticate the current password to explicitly disable Ai Tweaker protection."));
  if(!a||!b||!c||!d)break;
  pack=export(db,handles[i],&size);if(!pack)break;
  uint8_t *changed=hii_alloc(size+30);UN written=0;
  if(!changed || !policy_ifr_insert(pack,size,a,b,c,d,changed,size+30,&written) ||
     config->callback!=(CALLBACK)(void *)(setup+0x1534) || config->route!=(ROUTE)(void *)(setup+0x152c)) {hii_release(changed);hii_release(pack);break;}
  original_callback=config->callback;original_route=config->route;setup_config=config;
  CONFIG replacement=*config;replacement.callback=config_callback;replacement.route=config_route;
  if(patch_memory(config,&replacement,sizeof(replacement)) && !boot_services_ended && !FAILED(db->update_list(db,handles[i],changed)) &&
     manager_live(db,handles[i],config)) {
   setup_hii=handles[i];manager_installed=1;result=1;audit(31,written);
  } else {
   /* A provider error may follow a committed write. Restore only pointers we
    * still own, then retire this management attempt even if rollback succeeds.
    * Do not blindly reinsert actions into a partly updated package. */
   if(config_owned(config)) {
    replacement=*config;replacement.callback=original_callback;replacement.route=original_route;
    if(!patch_memory(config,&replacement,sizeof(replacement)))audit(33,ERR(7));
   }
   manager_fault();
  }
  hii_release(changed);hii_release(pack);break;
 }
done:
 hii_release(handles);if(boot_services_ended)result=0;
 if(manager_installed && !result)manager_fault();
 manager_busy=0;return result;
}
