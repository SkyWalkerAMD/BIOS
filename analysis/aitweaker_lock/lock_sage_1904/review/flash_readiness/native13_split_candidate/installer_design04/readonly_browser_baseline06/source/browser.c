/* Independent ASUS SendForm baseline. No provider, detour or variable setter.
 * ConfigAccess callbacks record bounded numeric metadata in own RAM only and
 * return EFI_UNSUPPORTED; they do not inspect Value or request strings and do
 * not call firmware, render, change TPL or write an output pointer. Rejecting
 * lifecycle callbacks is an explicit limitation, not a claim of neutral OEM
 * behavior. All protocol/HII resources stay resident until power off. */
#include "baseline.h"
#include "management_package.h"
typedef struct BROWSER BROWSER;
typedef ES(EA *SEND)(BROWSER *,HANDLE *,UN,GUID *,uint16_t,void *,BROWSER_ACTION_REQUEST *);
struct BROWSER{SEND send;void *callback;};
static GUID private_guid={0x750e9d9d,0xf2d8,0x4e14,{0x9b,0x53,0x89,0x23,0xa7,0x19,0x04,0x61}};
static GUID oc_guid={0xa3a3b874,0x7636,0x4182,{0xba,0x1e,0xf5,0x2c,0x58,0x44,0x94,0xe3}};
static GUID mem_guid={0x98cf19ed,0x4109,0x4681,{0xb7,0x9d,0x91,0x96,0x75,0x7c,0x78,0x24}};
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID cfg_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID package_guid={0xcc575054,0x4f92,0x4f04,{0xa3,0x48,0x59,0xef,0xa1,0x4c,0x90,0x13}};
static GUID formset_guid={0xb16b94e6,0x99f4,0x4f60,{0x8f,0x7b,0xb6,0xd2,0x34,0xe4,0xa5,0x13}};
static GUID gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static C16 private_name[]=L"AiTweakerPassword1904",oc_name[]=L"VARSTORE_OCMR_SETTINGS_NAME",mem_name[]=L"SocketMemoryConfig";
static uint8_t oc_before[26681],mem_before[1392],scratch[26681],hii_copy[4*1024*1024];
static uint32_t oc_attrs,mem_attrs;static HANDLE hii_handles[512],driver_handle,management_hii;
static BROWSER *initial_browser;static SEND initial_send;static RT *initial_rt;static RT rt_copy;static GETVAR getvar;
static HII *database;static int captured,publish_attempted,published,invoked;
typedef struct{UN action;uint16_t id;uint8_t type,kind;ES status;}CALL_RECORD;
static CALL_RECORD calls[64];static unsigned call_count,call_overflow;
static void record(uint8_t kind,UN action,uint16_t id,uint8_t type,ES status){
 if(call_count<64){CALL_RECORD *r=&calls[call_count++];r->kind=kind;r->action=action;r->id=id;r->type=type;r->status=status;}
 else call_overflow=1;
}
ES EA baseline_extract(CONFIG *this,C16 *request,C16 **progress,C16 **results){
 (void)this;(void)request;(void)progress;(void)results;ES s=app_ended?ERR(15):ERR(3);record(1,0,0,0,s);return s;
}
ES EA baseline_route(CONFIG *this,C16 *configuration,C16 **progress){
 (void)this;(void)configuration;(void)progress;ES s=app_ended?ERR(15):ERR(3);record(2,0,0,0,s);return s;
}
ES EA baseline_callback(CONFIG *this,UN action,uint16_t id,uint8_t type,void *value,BROWSER_ACTION_REQUEST *request){
 (void)this;(void)value;(void)request;ES s=app_ended?ERR(15):ERR(3);record(3,action,id,type,s);return s;
}
static CONFIG config={(void *)baseline_extract,baseline_route,baseline_callback};
static void boundary(void){
 app_require_services();
 if(initial_rt&&(app_st->rt!=initial_rt||memcmp(initial_rt,&rt_copy,sizeof(rt_copy))))app_hold(0xB6060001u);
}
int baseline_private_absent(void){
 UN n=0;uint32_t a=0;boundary();ES s=getvar(private_name,&private_guid,&a,&n,0);boundary();
 app_number("PrivateSizeOnlyQueryStatus",s);return s==ERR(14);
}
static int read_store(C16 *name,GUID *guid,uint8_t *out,UN size,uint32_t *attrs){
 UN n=size;*attrs=0;boundary();ES s=getvar(name,guid,attrs,&n,out);boundary();
 return s==0&&n==size&&(*attrs==3||*attrs==7);
}
int baseline_compare_stores(void){
 uint32_t a=0;int oc=read_store(oc_name,&oc_guid,scratch,sizeof(oc_before),&a)&&a==oc_attrs&&!memcmp(scratch,oc_before,sizeof(oc_before));
 ap_secure_zero(scratch,sizeof(scratch));int mem=read_store(mem_name,&mem_guid,scratch,sizeof(mem_before),&a)&&a==mem_attrs&&!memcmp(scratch,mem_before,sizeof(mem_before));
 ap_secure_zero(scratch,sizeof(scratch));app_result("complete OCMR values and attributes unchanged",oc);app_result("complete memory values and attributes unchanged",mem);return oc&&mem;
}
static void callback_report(void){
 app_number("ConfigAccessCallCount",call_count);app_number("ConfigAccessCallOverflow",call_overflow);
 for(unsigned i=0;i<call_count;i++){app_number("CallbackKind",calls[i].kind);app_number("CallbackAction",calls[i].action);app_number("CallbackQuestionId",calls[i].id);app_number("CallbackType",calls[i].type);app_number("CallbackStatus",calls[i].status);}
 app_log("CONFIG_ACCESS_REJECTS_ALL_ACTIONS_INCLUDING_LIFECYCLE\r\nCALLBACK_VALUE_AND_REQUEST_CONTENTS_NOT_READ\r\n");
}
static void display_metadata(const char *label){
 boundary();app_log(label);app_log("\r\n");
 if(!baseline_map())return;
 if(baseline_access(app_st->out,sizeof(TEXTOUT),0)&&baseline_access(app_st->out->mode,sizeof(OUTMODE),0)){
  app_number("ConsoleMode",(uint32_t)app_st->out->mode->mode);app_number("ConsoleColumnsCursor",(uint32_t)app_st->out->mode->column);app_number("ConsoleRowsCursor",(uint32_t)app_st->out->mode->row);
 }
 GOP *gop=0;boundary();ES s=app_st->bs->handle_protocol(app_st->out_handle,&gop_guid,(void **)&gop);boundary();
 if(FAILED(s)||!gop){gop=0;boundary();s=app_st->bs->locate_protocol(&gop_guid,0,(void **)&gop);boundary();}
 if(s||!baseline_map()||!baseline_access(gop,sizeof(GOP),0)||!baseline_access(gop->mode,sizeof(GOPMODE),0)||gop->mode->info_size<sizeof(GOPINFO)||!baseline_access(gop->mode->info,sizeof(GOPINFO),0)){app_result("GOP metadata readable",0);return;}
 app_number("GopMode",gop->mode->mode);app_number("GopWidth",gop->mode->info->width);app_number("GopHeight",gop->mode->info->height);app_number("GopPixelFormat",gop->mode->info->format);
}
int browser_capture(void){
 if(captured||!app_st->rt||!app_st->rt->get_variable||!app_browser)return 0;
 initial_rt=app_st->rt;rt_copy=*initial_rt;getvar=initial_rt->get_variable;initial_browser=app_browser;initial_send=initial_browser->send;
 baseline_tpl();if(!baseline_private_absent()){app_result("initial private credential absent; existing or unknown preserved",0);return 0;}
 app_result("initial private credential absent",1);
 int oc=read_store(oc_name,&oc_guid,oc_before,sizeof(oc_before),&oc_attrs),mem=read_store(mem_name,&mem_guid,mem_before,sizeof(mem_before),&mem_attrs);
 app_result("initial complete OCMR snapshot read only",oc);app_result("initial complete memory snapshot read only",mem);
 captured=oc&&mem;return captured;
}
static int unique_package(int expect_present){
 UN bytes=sizeof(hii_handles);boundary();ES s=database->list(database,0,0,&bytes,hii_handles);boundary();
 if(s||!bytes||bytes>sizeof(hii_handles)||bytes%sizeof(HANDLE))return 0;
 unsigned matches=0;
 for(UN i=0;i<bytes/sizeof(HANDLE);i++){
  UN n=0;boundary();s=database->export_list(database,hii_handles[i],&n,0);boundary();if(s!=ERR(5)||n<20||n>sizeof(hii_copy))return 0;
  UN expected=n;boundary();s=database->export_list(database,hii_handles[i],&n,hii_copy);boundary();if(s||n!=expected)return 0;
  if(!memcmp(hii_copy,&package_guid,16)){
   matches++;if(expect_present&&(hii_handles[i]!=management_hii||n!=sizeof(management_package)||memcmp(hii_copy,management_package,n)))return 0;
  }
  ap_secure_zero(hii_copy,n);
 }
 return matches==(unsigned)expect_present;
}
int browser_publish(void){
 if(!captured||publish_attempted)return 0;publish_attempted=1;baseline_tpl();
 boundary();ES s=app_st->bs->locate_protocol(&db_guid,0,(void **)&database);boundary();
 if(s||!baseline_map()||!baseline_access(database,sizeof(HII),0)||!database->new_list||!database->list||!database->export_list||!app_st->bs->install_protocol||!unique_package(0))return 0;
 if(!baseline_private_absent()||!baseline_compare_stores()||!baseline_original_unchanged())return 0;
 boundary();s=app_st->bs->install_protocol(&driver_handle,&cfg_guid,0,&config);boundary();app_number("ConfigAccessInstallStatus",s);if(s||!driver_handle)return 0;
 ES(EA *new_list)(HII *,void *,HANDLE,HANDLE *)=database->new_list;
 boundary();s=new_list(database,(void *)management_package,driver_handle,&management_hii);boundary();app_number("NewPackageListStatus",s);if(s||!management_hii)return 0;
 published=unique_package(1);app_result("unique exact frozen P13 package published without provider",published);return published;
}
int browser_invoke(void){
 if(!captured||!published||invoked)return 0;invoked=1;baseline_tpl();boundary();
 if(app_browser!=initial_browser||initial_browser->send!=initial_send||!baseline_original_unchanged()||!unique_package(1)||!baseline_private_absent()||!baseline_compare_stores())return 0;
 baseline_globals("BEFORE_NATIVE_SEND_FORM_GLOBALS");display_metadata("BEFORE_NATIVE_SEND_FORM_DISPLAY");
 baseline_tpl();boundary();BROWSER_ACTION_REQUEST request=0;
 app_log("NATIVE_SEND_FORM_BEGIN\r\n");
 ES status=initial_send(initial_browser,&management_hii,1,&formset_guid,1,0,&request);
 /* No firmware call between native return and EBS/TPL boundary checks. */
 boundary();baseline_tpl();app_log("NATIVE_SEND_FORM_RETURNED\r\n");app_number("NativeSendFormStatus",status);app_number("NativeActionRequest",request);
 callback_report();baseline_globals("AFTER_NATIVE_SEND_FORM_GLOBALS");display_metadata("AFTER_NATIVE_SEND_FORM_DISPLAY");
 int identity=baseline_original_unchanged(),absent=baseline_private_absent(),same=baseline_compare_stores();
 app_result("original text header snapshots and twelve sites unchanged",identity);app_result("private credential still absent; no content read",absent);
 app_log("OEM_INTERNAL_VARIABLE_WRITES_NOT_GLOBALLY_PROVEN_ABSENT\r\nBASELINE_RETURN_IS_NOT_PASSWORD_OR_GUARD_ACCEPTANCE\r\n");
 return status==0&&request==0&&identity&&absent&&same&&!call_overflow&&initial_browser==app_browser&&initial_browser->send==initial_send;
}
