/* Temporary, independently owned native test UI. No RuntimeServices hook and
 * no generic variable setter. The only direct write is deletion of the fixed
 * private credential after an exact comparison with this test's last observed
 * valid record. Original OC/MEM values are observed, never restored by writing.
 * The original firmware browser may have other internal effects; two snapshots
 * cannot establish absence of every OEM variable write during SendForm.
 */
#include "app.h"
#include "ui_bindings.h"

typedef struct UI_BROWSER UI_BROWSER;
struct UI_BROWSER {
 ES(EA *send_form)(UI_BROWSER *,HANDLE *,UN,GUID *,uint16_t,void *,BROWSER_ACTION_REQUEST *);
 void *callback;
};
typedef ES(EA *SEND_FORM)(UI_BROWSER *,HANDLE *,UN,GUID *,uint16_t,void *,BROWSER_ACTION_REQUEST *);
enum {PRIVATE_UNSET=0,PRIVATE_ABSENT=1,PRIVATE_OWNED=2,PRIVATE_UNKNOWN=3,PRIVATE_RESTORED=4};
static GUID credential_guid={0x750e9d9d,0xf2d8,0x4e14,{0x9b,0x53,0x89,0x23,0xa7,0x19,0x04,0x61}};
static GUID oc_guid={0xa3a3b874,0x7636,0x4182,{0xba,0x1e,0xf5,0x2c,0x58,0x44,0x94,0xe3}};
static GUID memory_guid={0x98cf19ed,0x4109,0x4681,{0xb7,0x9d,0x91,0x96,0x75,0x7c,0x78,0x24}};
static GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID package_guid={0xcc575054,0x4f92,0x4f04,{0xa3,0x48,0x59,0xef,0xa1,0x4c,0x90,0x13}};
static GUID management_formset={0xb16b94e6,0x99f4,0x4f60,{0x8f,0x7b,0xb6,0xd2,0x34,0xe4,0xa5,0x13}};
static GUID setup_formset={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
static C16 credential_name[]=L"AiTweakerPassword1904";
static C16 oc_name[]=L"VARSTORE_OCMR_SETTINGS_NAME",memory_name[]=L"SocketMemoryConfig";
static uint8_t oc_before[26681],memory_before[1392],store_scratch[26681];
static uint8_t private_owned[AP_RECORD_BYTES];
static HANDLE hii_handles[512];
static uint8_t hii_copy[4u*1024u*1024u];
static ST *initial_st;
static RT *initial_rt;
static GETVAR initial_get;
static SETVAR initial_set;
static HDR initial_rt_header;
static UI_BROWSER *initial_browser;
static SEND_FORM initial_send;
static HANDLE initial_setup_hii;
static uint32_t oc_attributes,memory_attributes,private_state;
static int capture_attempted,stores_ready,capture_ready,delete_attempted;

static void boundary(void){
 app_require_services();
 if(initial_st&&(app_st!=initial_st||app_st->rt!=initial_rt||
    initial_rt->get_variable!=initial_get||initial_rt->set_variable!=initial_set||
    memcmp(&initial_rt->hdr,&initial_rt_header,sizeof(initial_rt_header))))
  app_hold(0x55350002u);
}
static int application_tpl(void){
 boundary();
 if(!app_st||!app_st->bs||!app_st->bs->raise_tpl||!app_st->bs->restore_tpl)return 0;
 UN prior=app_st->bs->raise_tpl(31);boundary();
 if(prior!=4){app_result("UI at application TPL",0);app_hold(0x55350003u);}
 app_st->bs->restore_tpl(prior);boundary();
 app_result("UI at application TPL",1);return 1;
}
static ES get_private(uint8_t *record,UN *n,uint32_t *attributes){
 boundary();ES s=initial_get(credential_name,&credential_guid,attributes,n,record);boundary();return s;
}
static void unknown_private(const char *label){
 private_state=PRIVATE_UNKNOWN;ap_secure_zero(private_owned,sizeof(private_owned));app_result(label,0);
}
static int capture_store(C16 *name,GUID *guid,uint8_t *out,UN expected,uint32_t *attributes){
 UN n=expected;*attributes=0;boundary();ES status=initial_get(name,guid,attributes,&n,out);boundary();
 return status==0&&n==expected&&(*attributes==3||*attributes==7);
}
static int compare_store(C16 *name,GUID *guid,const uint8_t *before,UN expected,uint32_t attributes){
 uint32_t actual=0;int read_ok=capture_store(name,guid,store_scratch,expected,&actual);
 int same=read_ok&&actual==attributes&&!memcmp(before,store_scratch,(size_t)expected);
 ap_secure_zero(store_scratch,sizeof(store_scratch));return same;
}
int ui_capture_initial(void){
 app_require_services();if(capture_attempted)return 0;capture_attempted=1;
 if(!app_st||!app_st->rt||!app_st->rt->get_variable||!app_st->rt->set_variable||
    !app_browser||!((UI_BROWSER *)app_browser)->send_form||!app_setup_hii)return 0;
 initial_st=app_st;initial_rt=app_st->rt;initial_get=initial_rt->get_variable;
 initial_set=initial_rt->set_variable;initial_rt_header=initial_rt->hdr;
 initial_browser=app_browser;initial_send=initial_browser->send_form;initial_setup_hii=app_setup_hii;
 if(!application_tpl())return 0;
 /* A size-only query never reads or adopts a pre-existing credential. */
 UN n=0;uint32_t attributes=0;ES status=get_private(0,&n,&attributes);
 if(status!=ERR(14)){unknown_private("initial private credential must be absent; existing or unknown preserved");return 0;}
 private_state=PRIVATE_ABSENT;app_result("initial private credential absent",1);
 int oc_ok=capture_store(oc_name,&oc_guid,oc_before,sizeof(oc_before),&oc_attributes);
 int mem_ok=capture_store(memory_name,&memory_guid,memory_before,sizeof(memory_before),&memory_attributes);
 stores_ready=oc_ok&&mem_ok;capture_ready=stores_ready;
 app_result("initial complete OCMR snapshot read only",oc_ok);
 app_result("initial complete memory snapshot read only",mem_ok);
 app_log("OC_MEMORY_SNAPSHOTS_DO_NOT_PROVE_ALL_OEM_VARIABLE_WRITES_ABSENT\r\n");
 app_log("M_SEPARATE_TEST_FORM_NOT_PERMANENT_ASUS_SECURITY_MENU\r\n");
 return capture_ready;
}
int ui_compare_original_stores(void){
 boundary();if(!stores_ready)return 0;
 int oc_same=compare_store(oc_name,&oc_guid,oc_before,sizeof(oc_before),oc_attributes);
 int mem_same=compare_store(memory_name,&memory_guid,memory_before,sizeof(memory_before),memory_attributes);
 app_result("complete OCMR values and attributes unchanged",oc_same);
 app_result("complete memory values and attributes unchanged",mem_same);
 return oc_same&&mem_same;
}
static int private_matches_before(void){
 uint8_t now[AP_RECORD_BYTES];UN n=sizeof(now);uint32_t attributes=0;
 if(private_state!=PRIVATE_ABSENT&&private_state!=PRIVATE_OWNED)return 0;
 ES status=get_private(now,&n,&attributes);
 int ok=private_state==PRIVATE_ABSENT?status==ERR(14):
  status==0&&n==sizeof(now)&&attributes==3&&ap_constant_equal(now,private_owned,sizeof(now));
 ap_secure_zero(now,sizeof(now));
 if(!ok)unknown_private("private credential changed outside observed UI; preserved");
 return ok;
}
static uint64_t generation(const uint8_t *record){
 uint64_t n=0;for(unsigned i=0;i<8;i++)n|=(uint64_t)record[24+i]<<(i*8);return n;
}
static int observe_private_after(void){
 uint8_t now[AP_RECORD_BYTES];UN n=sizeof(now);uint32_t attributes=0;
 ES status=get_private(now,&n,&attributes);int ok=0;
 if(status==ERR(14)&&private_state==PRIVATE_ABSENT)ok=1;
 else if(status==0&&n==sizeof(now)&&attributes==3&&ap_record_valid(now,sizeof(now))){
  /* Same record is legal; a changed record must advance the provider's
   * generation. This is a cooperative test observation, not an authenticated
   * compare-and-swap against hostile parallel runtime writers. */
  ok=private_state==PRIVATE_ABSENT||
    (private_state==PRIVATE_OWNED&&(ap_constant_equal(now,private_owned,sizeof(now))||
                                  generation(now)>generation(private_owned)));
  if(ok){memcpy(private_owned,now,sizeof(now));private_state=PRIVATE_OWNED;}
 }
 ap_secure_zero(now,sizeof(now));
 if(!ok)unknown_private("post-UI private record unknown or invalid; preserved");
 app_result("private record observed only in RAM without contents or digest",ok);return ok;
}
static int quiescent_state(RAM_SESSION *s,int cleanup){
 boundary();
 if(!s||s->mode!=2||s->tx.magic!=TX_MAGIC||s->tx.busy||s->tx.ended||s->tx.held||
    (!cleanup&&s->tx.phase!=TX_INSTALLED)||
    (cleanup&&s->tx.phase!=TX_INSTALLED&&s->tx.phase!=TX_RETIRED))return 0;
 uint64_t base=s->provider_context.state_base;
 if(base<4096||(base&4095)||base!=s->tx.plan.state_base||
    s->provider_context.state_size!=4096||s->tx.plan.state_size!=4096)
  app_hold(0x55350001u);
 SPLIT_STATE *state=(void *)(uintptr_t)base;
 if(state->magic!=SPLIT_STATE_MAGIC||state->reserved||state->ui_head||state->save_head||
    (state->phase!=1&&!(cleanup&&s->tx.phase==TX_RETIRED&&state->phase==2)))
  app_hold(0x55350001u);
 return 1;
}
static int provider_idle(RAM_SESSION *s){
 if(!s->provider_started||!s->provider_image||!s->provider||
    s->provider->magic!=PROVIDER_MAGIC||s->provider->revision!=1||
    s->provider->size!=sizeof(GATE_PROVIDER)||!s->provider->query)return 0;
 boundary();uint32_t flags=s->provider->query(s->provider);boundary();
 if(!application_tpl())return 0;
 int ok=flags==PROVIDER_READY||flags==(PROVIDER_READY|PROVIDER_DISABLED);
 app_number("UiProviderFlags",flags);return ok;
}
static int ready_for_ui(RAM_SESSION *s){
 if(!capture_ready||!quiescent_state(s,0)||!provider_idle(s)||!application_tpl())return 0;
 if(app_browser!=initial_browser||initial_browser->send_form!=initial_send||app_setup_hii!=initial_setup_hii)return 0;
 return private_matches_before()&&ui_compare_original_stores();
}
static HANDLE locate_management(void){
 if(!app_st->bs->locate_protocol)return 0;
 HII *db=0;boundary();ES status=app_st->bs->locate_protocol(&database_guid,0,(void **)&db);boundary();
 if(status||!db||!db->list||!db->export_list)return 0;
 UN bytes=sizeof(hii_handles);boundary();status=db->list(db,0,0,&bytes,hii_handles);boundary();
 if(status||!bytes||bytes>sizeof(hii_handles)||bytes%sizeof(HANDLE))return 0;
 HANDLE match=0;unsigned matches=0;
 for(UN i=0;i<bytes/sizeof(HANDLE);i++){
  UN n=0;boundary();status=db->export_list(db,hii_handles[i],&n,0);boundary();
  if(status!=ERR(5)||n<20||n>sizeof(hii_copy))return 0;
  UN expected=n;boundary();status=db->export_list(db,hii_handles[i],&n,hii_copy);boundary();
  if(status||n!=expected){ap_secure_zero(hii_copy,expected);return 0;}
  if(!memcmp(hii_copy,&package_guid,16)){
   if(n!=sizeof(ui_management_package)||memcmp(hii_copy,ui_management_package,n)){
    ap_secure_zero(hii_copy,expected);return 0;
   }
   matches++;match=hii_handles[i];
  }
  ap_secure_zero(hii_copy,n);
 }
 app_result("unique exact independent P14 HII package",matches==1);return matches==1?match:0;
}
static int send_form(RAM_SESSION *s,HANDLE hii,GUID *formset,uint16_t form_id){
 if(!hii)return 0;
 /* Enumeration may have called other firmware code. Recheck immediately
  * before allowing the original browser to reach a password-writing action. */
 if(!ready_for_ui(s)||!platform_native_globals("UI_NATIVE_GLOBALS_BEFORE_SENDFORM"))return 0;
 /* The diagnostic GetMemoryMap is a firmware boundary too. Revalidate the
  * owned state/provider/credential immediately before entering the browser. */
 if(!ready_for_ui(s))return 0;
 /* Native 1904 SendForm only writes this OUT value for selected requests;
  * ordinary ESC may leave it unchanged. NONE is the defined initial state. */
 BROWSER_ACTION_REQUEST request=0;boundary();
 ES status=initial_send(initial_browser,&hii,1,formset,form_id,0,&request);boundary();
 /* No further service after a browser that returned with dangling ownership. */
 if(!quiescent_state(s,0))app_hold(0x55350001u);
 if(!application_tpl())return 0;
 app_result("SendForm returned with both owned chains empty",1);
 int globals=platform_native_globals("UI_NATIVE_GLOBALS_AFTER_SENDFORM");
 int observed=observe_private_after();
 int unchanged=ui_compare_original_stores();int idle=provider_idle(s);
 app_number("UiSendFormStatus",status);app_number("UiActionRequest",request);
 app_result("original FormBrowser2 interface unchanged",app_browser==initial_browser&&initial_browser->send_form==initial_send);
 app_log("UI_RETURN_IS_NOT_DIRECT_DEL_OR_PERMANENT_SECURITY_MENU_ACCEPTANCE\r\n");
 return status==0&&request==0&&globals&&observed&&unchanged&&idle&&
        app_browser==initial_browser&&initial_browser->send_form==initial_send;
}
int ui_open_management(RAM_SESSION *s){
 if(!ready_for_ui(s))return 0;
 HANDLE hii=locate_management();
 return send_form(s,hii,&management_formset,1);
}
int ui_open_original_setup(RAM_SESSION *s){
 if(!ready_for_ui(s))return 0;
 /* Form 0 asks the original browser for this formset's default first form. */
 return send_form(s,initial_setup_hii,&setup_formset,0);
}
int ui_restore_credential(RAM_SESSION *s){
 boundary();if(!capture_ready||!quiescent_state(s,1)||!application_tpl())return 0;
 if(private_state==PRIVATE_RESTORED)return 1;
 if(private_state==PRIVATE_UNKNOWN||private_state==PRIVATE_UNSET||delete_attempted){
  ap_secure_zero(private_owned,sizeof(private_owned));app_result("unknown private credential retained; no delete",0);return 0;
 }
 uint8_t now[AP_RECORD_BYTES];UN n=sizeof(now);uint32_t attributes=0;
 ES status=get_private(now,&n,&attributes);
 if(status==ERR(14)){
  int expected=private_state==PRIVATE_ABSENT;
  ap_secure_zero(now,sizeof(now));ap_secure_zero(private_owned,sizeof(private_owned));private_state=PRIVATE_RESTORED;
  app_result("private absence confirmed without a write",expected);return expected;
 }
 int exact=private_state==PRIVATE_OWNED&&status==0&&n==sizeof(now)&&attributes==3&&
           ap_record_valid(now,sizeof(now))&&ap_constant_equal(now,private_owned,sizeof(now));
 ap_secure_zero(now,sizeof(now));
 if(!exact){unknown_private("cleanup private record not exactly owned; no delete");return 0;}
 delete_attempted=1;
 /* This is the sole direct SetVariable call in this module: fixed name/GUID,
  * deletion only, immediately after exact readback. No generic write API. */
 boundary();ES deleted=initial_set(credential_name,&credential_guid,0,0,0);boundary();
 n=0;attributes=0;ES absent=get_private(0,&n,&attributes);
 ap_secure_zero(private_owned,sizeof(private_owned));
 private_state=absent==ERR(14)?PRIVATE_RESTORED:PRIVATE_UNKNOWN;
 app_number("TemporaryCredentialDeleteStatus",deleted);
 app_result("temporary private deletion read back absent",absent==ERR(14));
 return deleted==0&&absent==ERR(14);
}
