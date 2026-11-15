/* Add two management actions while preserving both permanent ConfigAccess
 * guards. All exported packages are verified after UpdatePackageList. */
#include "provider.h"
#include "guard_binding.h"
static GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID strings_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID setup_package={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
HANDLE setup_hii;
static int manager_state,installing;
static int idle(void){return !boot_services_ended&&native_browser_state()==1;}
static uint16_t add_string(STRINGS *strings,HANDLE handle,C16 *text){
 UN n=0;uint16_t id=0;if(!idle())return 0;
 ES s=strings->languages(strings,handle,0,&n);if(boot_services_ended||s!=ERR(5)||!n||n>4096)return 0;
 UN capacity=n;char *languages=alloc(n);if(!languages)return 0;
 s=strings->languages(strings,handle,languages,&n);
 if(boot_services_ended||FAILED(s)||!n||n>capacity||languages[n-1]){release(languages);return 0;}
 for(UN i=0;i<n;){
  if(!idle()){id=0;break;}
  char *language=languages+i;UN j=i;while(j<n&&languages[j]&&languages[j]!=';')j++;
  if(j==i||j==n){id=0;break;}char end=languages[j];languages[j]=0;
  s=id?strings->set_string(strings,handle,id,language,text,0):strings->new_string(strings,handle,&id,language,0,text,0);
  if(boot_services_ended||FAILED(s)){id=0;break;}if(!end)break;i=j+1;
 }release(languages);return boot_services_ended?0:id;
}
static uint8_t *export(HII *db,HANDLE handle,UN *n){
 *n=0;if(boot_services_ended)return 0;ES s=db->export_list(db,handle,n,0);
 if(boot_services_ended||s!=ERR(5)||*n<24||*n>4*1024*1024)return 0;
 UN allocated=*n;uint8_t *p=alloc(allocated);if(!p)return 0;
 s=db->export_list(db,handle,n,p);if(boot_services_ended||FAILED(s)||*n<24||*n>allocated){release(p);return 0;}return p;
}
static int exact_package(HII *db,HANDLE h,const uint8_t *expected,UN bytes){
 UN n=0;uint8_t *check=export(db,h,&n);int same=check&&n==bytes&&!memcmp(check,expected,bytes);release(check);return !boot_services_ended&&same;
}
int install_management(void){
 if(boot_services_ended)return -1;if(manager_state)return manager_state;if(installing)return 0;
 installing=1;
 uint8_t *setup=0;UN setup_size=0;
 HII *db=0;STRINGS *strings=0;HANDLE *handles=0,chosen=0;CONFIG *cfg=0;UN n=0;int result=0;
 if(!locate_bound_setup(&setup,&setup_size)||setup_size!=SETUP_IMAGE_BYTES||!idle())goto done;
 ES s=system_table->bs->locate_protocol(&database_guid,0,(void **)&db);
 if(boot_services_ended||FAILED(s)||!db||!db->list||!db->export_list||!db->update_list||!db->get_driver)goto done;
 s=system_table->bs->locate_protocol(&strings_guid,0,(void **)&strings);
 if(boot_services_ended||FAILED(s)||!strings||!strings->languages||!strings->new_string||!strings->set_string)goto done;
 s=db->list(db,0,0,&n,0);if(boot_services_ended||s!=ERR(5)||!n||n>8192||n%sizeof(HANDLE))goto done;
 handles=alloc(n);if(!handles)goto done;UN capacity=n;
 s=db->list(db,0,0,&n,handles);if(boot_services_ended||FAILED(s)||!n||n>capacity||n%sizeof(HANDLE))goto done;
 for(UN i=0;i<n/sizeof(HANDLE);i++){
  UN bytes=0;uint8_t *pack=export(db,handles[i],&bytes);if(!pack)goto done;
  int match=!memcmp(pack,&setup_package,16);release(pack);if(boot_services_ended)goto done;if(!match)continue;
  HANDLE driver=0;CONFIG *current=0;
  if(chosen)goto done;s=db->get_driver(db,handles[i],&driver);if(boot_services_ended||FAILED(s)||!driver)goto done;
  s=system_table->bs->handle_protocol(driver,&config_guid,(void **)&current);if(boot_services_ended||FAILED(s)||!memory_present(current,sizeof(*current),0))goto done;
  if(current->callback!=(CALLBACK)(setup+SETUP_CALLBACK_RVA)||current->route!=(ROUTE)(setup+SETUP_ROUTE_RVA))goto done;
  chosen=handles[i];cfg=current;
 }
 if(!chosen||!idle())goto done;
 uint16_t a=add_string(strings,chosen,U("Ai Tweaker Password"));
 uint16_t b=add_string(strings,chosen,U("Set or change the independent Ai Tweaker password. Current password is required to change it."));
 uint16_t c=add_string(strings,chosen,U("Clear Ai Tweaker Password"));
 uint16_t d=add_string(strings,chosen,U("Authenticate the current password to explicitly disable Ai Tweaker protection."));
 if(!a||!b||!c||!d){manager_state=-1;provider_fault();goto done;}
 UN size=0,written=0;uint8_t *original=export(db,chosen,&size);uint8_t *changed=original?alloc(size+30):0;
 if(!original||!changed||!policy_ifr_insert(original,size,a,b,c,d,changed,size+30,&written)){
  release(changed);release(original);manager_state=-1;provider_fault();goto done;
 }
 if(!idle()){release(changed);release(original);manager_state=-1;provider_fault();goto done;}
 ES updated=db->update_list(db,chosen,changed);
 if(!boot_services_ended&&!FAILED(updated)&&exact_package(db,chosen,changed,written)&&idle()&&cfg->callback==(CALLBACK)(setup+SETUP_CALLBACK_RVA)&&cfg->route==(ROUTE)(setup+SETUP_ROUTE_RVA)){
  setup_hii=chosen;manager_state=result=1;audit(31,written);
 }else{
  /* Best-effort bounded restoration is checked independently. Never report
   * installation success merely because UpdatePackageList returned success. */
  int restored=0;
  if(idle()){ES rollback=db->update_list(db,chosen,original);restored=!boot_services_ended&&!FAILED(rollback)&&exact_package(db,chosen,original,size);}
  audit(32,(uint64_t)restored);manager_state=-1;provider_fault();result=-1;
 }
 release(changed);release(original);
done:
 release(handles);installing=0;return boot_services_ended?-1:(manager_state?manager_state:result);
}
