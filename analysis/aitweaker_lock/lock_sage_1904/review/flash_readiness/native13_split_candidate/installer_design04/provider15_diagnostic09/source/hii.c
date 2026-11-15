/* Publish a separate RAM-test management formset. Never UpdatePackageList the
 * OEM forms and never replace their ConfigAccess pointers here. */
#include "split_owner.h"
#include "management_package.h"
#include "diagnostic_provider.h"
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID cfg_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
HANDLE setup_hii,split_management_hii;
static HANDLE management_handle;
static int installing,installed;
static ES EA extract(CONFIG *this,C16 *request,C16 **progress,C16 **results){
 (void)this;if(boot_services_ended)return ERR(15);
 if(progress&&memory_present(progress,8,1))*progress=request;
 if(results&&memory_present(results,8,1))*results=0;return ERR(3);
}
static ES EA route(CONFIG *this,C16 *configuration,C16 **progress){
 (void)this;if(boot_services_ended)return ERR(15);if(progress&&memory_present(progress,8,1))*progress=configuration;return ERR(3);
}
static ES EA callback(CONFIG *this,UN action,uint16_t id,uint8_t type,void *value,BROWSER_ACTION_REQUEST *request){
 (void)this;(void)type;(void)value;
 if(boot_services_ended)return ERR(15);
 if(request){if(!memory_present(request,sizeof(*request),1))return ERR(2);*request=0;}
 if(id<0xffe0||id>0xffe2)return ERR(3);
 if(!platform_session_owned())return ERR(15);
 if(action==1)return 0;if(action!=0)return ERR(3);
 return id==0xffe2?diagnostic_verify_request():native_provider.manage(&native_provider,id==0xffe1);
}
static CONFIG management_config={(void *)extract,route,callback};
static int idle(void){return !boot_services_ended&&native_browser_state()==1;}
int install_split_management(HANDLE image){
 (void)image;if(boot_services_ended)return -1;if(installed)return installed;if(installing)return 0;if(!idle())return 0;
 installing=1;HII *db=0;int result=-1;
 ES status=system_table->bs->locate_protocol(&db_guid,0,(void **)&db);
 if(boot_services_ended||FAILED(status)||!memory_present(db,sizeof(*db),0)||!db->new_list||!db->export_list||!idle())goto done;
 status=system_table->bs->install_protocol(&management_handle,&cfg_guid,0,&management_config);
 if(boot_services_ended||FAILED(status)||!management_handle||!idle())goto done;
 ES(EA *new_list)(HII *,void *,HANDLE,HANDLE *)=db->new_list;
 status=new_list(db,(void *)management_package,management_handle,&split_management_hii);
 if(boot_services_ended||FAILED(status)||!split_management_hii||!idle())goto done;
 UN n=0;status=db->export_list(db,split_management_hii,&n,0);
 if(boot_services_ended||status!=ERR(5)||n!=sizeof(management_package))goto done;
 uint8_t *copy=alloc(n);if(!copy)goto done;
 status=db->export_list(db,split_management_hii,&n,copy);
 int exact=!boot_services_ended&&!FAILED(status)&&n==sizeof(management_package)&&!memcmp(copy,management_package,n);
 release(copy);
 if(!boot_services_ended&&exact&&idle()){result=1;setup_hii=split_management_hii;}
done:
 installing=0;installed=boot_services_ended?-1:result;if(installed<0)provider_fault();return installed;
}
int install_management(void){return install_split_management(0);}
