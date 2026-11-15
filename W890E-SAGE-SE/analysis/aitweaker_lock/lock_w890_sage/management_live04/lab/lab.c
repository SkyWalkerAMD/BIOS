/* TCG ONLY. All native ownership and original module handles are fixtures.
 * HII/String/notification, graphics and Runtime02 execution are real OVMF. */
#include "../internal.h"
#include "fixtures.h"
#include "../../password_runtime02/lab/profile_fixture.h"
typedef ES(EA *NEW_LIST)(HII*,const void*,HANDLE,HANDLE*);
typedef ES(EA *REMOVE_LIST)(HII*,HANDLE);
typedef ES(EA *GET_STRING)(STRINGS*,const char*,HANDLE,uint16_t,C16*,UN*,void**);
typedef ES(EA *NOTIFY_HII)(uint8_t,GUID*,void*,HANDLE,UN);
typedef ES(EA *REGISTER_HII)(HII*,uint8_t,GUID*,NOTIFY_HII,UN,HANDLE*);
typedef ES(EA *UNREGISTER_HII)(HII*,HANDLE);
static ST*real_st;static ST shadow_st;static BS shadow_bs;static RT shadow_rt;static INPUT input;
static HII*real_db;static STRINGS*real_strings;static HII db;static STRINGS strings;
static CONFIG config;static LOADED setup_li,tse_li;static HANDLE image_handle,hii,notify[3];
static MP_STATE state;static MP_BINDING binding;static MP_AUTHORITY auth;
static MP_PATCH patch;
static uint8_t setup_path[24]={4,6,20,0,0xd7,7,0x94,0x89,0xfe,0x99,0xd8,0x43,0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21,0x7f,0xff,4,0};
static uint8_t tse_path[24]={4,6,20,0,0xdf,0x0a,0xda,0xb1,0x77,0x4f,0x70,0x40,0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a,0x7f,0xff,4,0};
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}},str_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}},config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static unsigned checks,failmode,new_calls,set_calls,update_calls,get_calls,notifications,input_calls,nv_writes,management_live,scope_live,provider_calls;
static int window_open=1;static uint64_t session;
static void trace(const char*s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static void finish(unsigned code){__asm__ volatile("outl %0,%1"::"a"(code),"Nd"((uint16_t)0xf4));for(;;)__asm__ volatile("hlt");}
static void check(int ok,const char*s){checks++;trace(ok?"PASS ":"FAIL ");trace(s);trace("\n");if(!ok)finish(0x11);}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
static void*alloc(UN n){void*p=0;check(!real_st->bs->allocate_pool(4,n,&p)&&p,"lab allocate private fixture");return p;}
static ES EA hp(HANDLE handle,GUID*g,void**out){
 if(handle==image_handle&&!memcmp(g,&loaded_guid,16)){*out=&setup_li;return 0;}
 if(handle==image_handle&&!memcmp(g,&config_guid,16)){*out=&config;return 0;}
 if(handle==&tse_li&&!memcmp(g,&loaded_guid,16)){*out=&tse_li;return 0;}
 return real_st->bs->handle_protocol(handle,g,out);
}
static ES EA export_list(HII*this,HANDLE h,UN*n,void*p){(void)this;return real_db->export_list(real_db,h,n,p);}
static ES EA get_driver(HII*this,HANDLE h,HANDLE*d){(void)this;return real_db->get_driver(real_db,h,d);}
static ES EA changed(uint8_t type,GUID*g,void*p,HANDLE h,UN what){(void)type;(void)g;(void)p;(void)what;if(h==hii)notifications++;return 0;}
static ES EA update(HII*this,HANDLE h,void*p){
 (void)this;update_calls++;
 if((failmode==4&&update_calls==1)||(failmode==6&&update_calls==2))return 0;
 ES r=real_db->update_list(real_db,h,p);
 if(failmode==5&&update_calls==1)return ERR(7);
 if(failmode==7&&update_calls==1)window_open=0;
 if(failmode==8&&update_calls==1)config.route=0;
 if(failmode==9&&update_calls==1)mp_end_boot(&state);
 if(failmode==13&&update_calls==1)db.get_driver=real_db->get_driver;
 return r;
}
static ES EA new_string(STRINGS*this,HANDLE h,uint16_t*id,char*lang,C16*ln,C16*text,void*font){
 (void)this;new_calls++;ES r=real_strings->new_string(real_strings,h,id,lang,ln,text,font);
 return failmode==1&&new_calls==3?ERR(7):r;
}
static ES EA set_string(STRINGS*this,HANDLE h,uint16_t id,char*lang,C16*text,void*font){
 (void)this;set_calls++;ES r=real_strings->set_string(real_strings,h,id,lang,text,font);
 return failmode==2&&set_calls==2?ERR(7):r;
}
static ES EA get_string(STRINGS*this,const char*lang,HANDLE h,uint16_t id,C16*text,UN*n,void**font){
 (void)this;get_calls++;ES r=((GET_STRING)real_strings->get_string)(real_strings,lang,h,id,text,n,font);
 if(failmode==3&&get_calls==3&&!r&&text&&*n>=2)text[0]^=1;
 return r;
}
static ES EA languages(STRINGS*this,HANDLE h,char*lang,UN*n){(void)this;ES r=real_strings->languages(real_strings,h,lang,n);if(!r&&failmode==10)memcpy(lang,"en-US;en-US",12);return r;}
static int EA window(void*c,uint64_t t){return c==&state&&window_open&&t==42&&!state.ended;}
static int EA published(void*c,uint64_t t,const uint16_t ids[6],const uint8_t digest[32]){
 if(!window(c,t))return 0;uint8_t*out=alloc(sizeof(original_forms)+45),sha[32];size_t n=0;
 int ok=w890_security_insert(original_forms,sizeof(original_forms),ids,out,sizeof(original_forms)+45,&n)&&n==sizeof(original_forms)+45;
 ap_sha256(out,n,sha);ok=ok&&!memcmp(sha,digest,32);real_st->bs->free_pool(out);return ok;
}
static int EA restored(void*c,uint64_t t){return window(c,t);}
__attribute__((noinline))static ES dispatch(UN action,uint16_t qid,UN*request){ES r=config.callback(&config,action,qid,10,0,request);__asm__ volatile("":::"memory");return r;}
static int EA manage_enter(void*c,void*caller,CONFIG*this,UN action,uint16_t qid,uint8_t type,void*value,UN*request,uint64_t*t){
 (void)type;(void)value;(void)request;uintptr_t a=(uintptr_t)caller,b=(uintptr_t)dispatch;
 if(c!=&state||!management_live||this!=&config||a<=b||a>b+128||qid<0xffd0||qid>0xffd2||action>1||scope_live)return 0;
 scope_live=1;*t=73;return 1;
}
static int EA manage_valid(void*c,uint64_t t){return c==&state&&scope_live&&management_live&&t==73;}
static void EA manage_leave(void*c,uint64_t t){if(c==&state&&t==73)scope_live=0;}
static int EA profile(void){return 1;}
static int EA tpl(void){UN old=real_st->bs->raise_tpl(31);real_st->bs->restore_tpl(old);return old==4;}
static int EA owner_caller(void*c,unsigned op,uint64_t*out,uint64_t token,uint32_t depth){(void)c;(void)out;(void)token;return op==1?depth==0:op==2&&depth==1;}
static int EA owner_active(uint64_t token,uint32_t depth){return token&&token==session&&depth==1;}
static int EA writable(void*p,size_t n){return w890_memory_present(p,n,1);}
static int EA authorize(void*caller,int op,uint64_t token,uint32_t depth){
 uint16_t q=0;uint64_t t=0;void*n=0;
 int good=mp_provider_caller(caller)&&mp_management_scope(&state,&q,&t,&n)&&manage_valid(&state,t)&&owner_active(token,depth)&&op==(q==0xffd2?-1:q==0xffd1);
 if(good)provider_calls++;return good;
}
static ES EA read_key(INPUT*this,KEY*k){(void)this;input_calls++;k->scan=0x17;k->ch=0;return 0;}
static ES EA deny_set(C16*name,GUID*g,uint32_t attr,UN n,void*p){(void)name;(void)g;(void)attr;(void)n;(void)p;nv_writes++;return ERR(15);}
static void open_case(unsigned mode){
 failmode=0;window_open=1;new_calls=set_calls=update_calls=get_calls=0;management_live=0;scope_live=0;
 config.extract=(uint8_t*)setup_li.image_base+0x2240;config.route=(ROUTE)((uint8_t*)setup_li.image_base+0x2248);config.callback=(CALLBACK)((uint8_t*)setup_li.image_base+0x2250);
 check(!((NEW_LIST)real_db->new_list)(real_db,original_package,image_handle,&hii)&&hii,"isolated two-language original package created");binding.hii=hii;
 check(mp_bind(&state,&binding,&auth)==MP_OK,"actual publisher binds exact inert module images and HII owner");config.callback=mp_callback;failmode=mode;
}
static void close_case(void){
 failmode=0;window_open=1;config.route=(ROUTE)((uint8_t*)setup_li.image_base+0x2248);config.callback=state.original_callback;
 check(mp_dispose(&state,42)==MP_OK,"dispose after callback restoration");check(!((REMOVE_LIST)real_db->remove_list)(real_db,hii),"remove isolated package");hii=0;
}
ES EA efi_main(HANDLE image,ST*st){
 if(!tcg())return ERR(3);real_st=st;image_handle=image;trace("MP04_LAB_BEGIN\n");
 check(!st->bs->locate_protocol(&db_guid,0,(void**)&real_db)&&real_db,"actual OVMF HII Database");check(!st->bs->locate_protocol(&str_guid,0,(void**)&real_strings)&&real_strings,"actual OVMF HII String");
 db=*real_db;db.export_list=export_list;db.get_driver=get_driver;db.update_list=update;
 strings=*real_strings;strings.new_string=new_string;strings.set_string=set_string;strings.get_string=(void*)get_string;strings.languages=languages;
 shadow_st=*st;shadow_bs=*st->bs;shadow_rt=*st->rt;shadow_bs.handle_protocol=hp;shadow_st.bs=&shadow_bs;shadow_rt.set_variable=deny_set;shadow_st.rt=&shadow_rt;input=*st->in;input.read=read_key;shadow_st.in=&input;
 setup_li.revision=tse_li.revision=0x1000;setup_li.image_size=2154496;tse_li.image_size=909312;setup_li.filepath=setup_path;tse_li.filepath=tse_path;
 setup_li.image_base=alloc(setup_li.image_size);tse_li.image_base=alloc(tse_li.image_size);memset(setup_li.image_base,0,setup_li.image_size);memset(tse_li.image_base,0,tse_li.image_size);
 memcpy(setup_li.image_base,setup_headers,sizeof(setup_headers));memcpy((uint8_t*)setup_li.image_base+4096,setup_text,sizeof(setup_text));memcpy(tse_li.image_base,amitse_headers,sizeof(amitse_headers));memcpy((uint8_t*)tse_li.image_base+4096,amitse_text,sizeof(amitse_text));
 binding=(MP_BINDING){&shadow_st,&db,&strings,0,image,&config,setup_li.image_base,setup_li.image_size,&tse_li,tse_li.image_base,tse_li.image_size,0,0,0};
 auth=(MP_AUTHORITY){MP_REVISION,sizeof(auth),&state,window,published,restored,manage_enter,manage_valid,manage_leave};
 for(unsigned i=0;i<3;i++){UN flags[]={1,2,8};check(!((REGISTER_HII)real_db->register_notify)(real_db,2,0,changed,flags[i],&notify[i])&&notify[i],"actual HII notification registered separately for one notification type");}
 open_case(0);check(mp_publish(&state,0)==MP_DENIED&&new_calls==0,"missing cold publication ticket denies before HII writes");
 MP_RESULT first=mp_publish(&state,42);
 check(first==MP_OK&&state.stage==MP_PUBLISHED&&state.language_count==2,"actual six actions strings and three IFR controls published in both languages");
 check(new_calls==6&&set_calls==6&&get_calls>=24,"actual NewString SetString GetString all-language calls executed");check(notifications>0,"real synchronous update notification occurred while lease remained valid");
 W890_HOST host={1,sizeof(host),profile,tpl,owner_caller,owner_active,writable,0,authorize};
 check(w890_runtime_bind(&shadow_st,&host,fixture_setup_sha,fixture_tse_sha)==AP_UNCONFIGURED,"actual Runtime02 binds real OVMF services with explicit lab native authority");
 check(!w890_provider_begin(&w890_provider,&session)&&session,"actual provider opens test native session");
 UN request=UINT64_MAX;check(dispatch(0,0xffd0,&request)==ERR(15)&&request==UINT64_MAX,"management action denied without native management frame");
 management_live=1;check(!dispatch(1,0xffd0,&request)&&request==0,"actual bridge forwards CHANGED acknowledgement to provider");
 check(mp_callback(&config,0,0xffd0,0,0,&request)==ERR(3)&&!scope_live,"wrong native action type rejected before management scope");
 check(dispatch(2,0xffd0,&request)==ERR(3)&&!scope_live,"unsupported browser action rejected before management scope");
 check(!mp_provider_caller((void*)(uintptr_t)1)&&!mp_provider_caller((void*)(uintptr_t)UINT64_MAX),"unmapped caller claims rejected without pointer dereference");
 unsigned before=input_calls;check(dispatch(0,0xffd0,&request)==ERR(15)&&provider_calls==1&&input_calls>before,"actual compiled bridge and provider callsite reach real masked UI then Escape cancels");
 check(!(w890_provider_query(&w890_provider)&W890_PROVIDER_GRANTED)&&nv_writes==0,"cancelled setting leaves locked and no NVRAM writes");
 check(w890_provider_manage(&w890_provider,0)==ERR(15)&&provider_calls==1,"direct provider management call cannot borrow bridge permission");management_live=0;
 check(!w890_provider_end(&w890_provider,session),"end actual provider session");session=0;
 check(mp_rollback(&state,42)==MP_OK&&!state.dirty,"entire original package and all added strings restored");close_case();
 open_case(10);check(mp_publish(&state,42)==MP_IO&&new_calls==0&&!state.dirty,"duplicate language list rejects before any HII mutation");close_case();
 for(unsigned mode=1;mode<=5;mode++){
  open_case(mode);check(mp_publish(&state,42)==MP_ROLLED_BACK&&state.stage==MP_RESTORED&&!state.dirty,"partial string or Update failure restores exact complete original package");close_case();
 }
 open_case(6);check(mp_publish(&state,42)==MP_OK,"publish before rollback false-success injection");check(mp_rollback(&state,42)==MP_DIRTY&&state.dirty&&state.original_package,"false-success rollback retains dirty snapshot");failmode=0;check(mp_rollback(&state,42)==MP_OK,"retry with actual HII restoration succeeds");close_case();
 for(unsigned mode=7;mode<=8;mode++){
  open_case(mode);check(mp_publish(&state,42)==MP_DIRTY&&state.dirty&&update_calls==1,"lost window or changed identity prevents unsafe compensating write");failmode=0;window_open=1;config.route=(ROUTE)((uint8_t*)setup_li.image_base+0x2248);check(mp_rollback(&state,42)==MP_OK,"fresh verified window can recover retained package snapshot");close_case();
 }
 open_case(13);check(mp_publish(&state,42)==MP_DIRTY&&state.dirty&&update_calls==1,"substituted HII method invalidates all further service calls");db.get_driver=get_driver;failmode=0;check(mp_rollback(&state,42)==MP_OK,"restored pinned method and fresh lease permit exact rollback");close_case();
 memset(&patch,0,sizeof(patch));patch.module=0;patch.rva=0x6480;patch.length=14;memcpy(patch.original,(uint8_t*)tse_li.image_base+patch.rva,14);memcpy(patch.installed,patch.original,14);patch.installed[0]^=0x80;binding.patches=&patch;binding.patch_count=1;
 open_case(0);memcpy((uint8_t*)tse_li.image_base+patch.rva,patch.installed,14);check(mp_publish(&state,42)==MP_OK,"reviewed exact installed overlay normalizes to official module text hash");
 check(mp_rollback(&state,42)==MP_OK,"exact complete HII rollback while reviewed overlay remains installed");memcpy((uint8_t*)tse_li.image_base+patch.rva,patch.original,14);close_case();
 open_case(0);((uint8_t*)tse_li.image_base)[patch.rva+14]^=1;check(mp_publish(&state,42)==MP_DENIED&&new_calls==0,"module byte outside reviewed overlay denies publication");((uint8_t*)tse_li.image_base)[patch.rva+14]^=1;close_case();binding.patches=0;binding.patch_count=0;
 open_case(0);check(mp_publish(&state,42)==MP_OK,"publish before unrelated original string edit");
 check(!real_strings->set_string(real_strings,hii,1,"en-US",U("Foreign edit"),0),"lab injects unrelated original string change");
 check(mp_rollback(&state,42)==MP_DIRTY&&state.dirty&&update_calls==1,"publisher refuses to overwrite unrelated changed original strings");
 check(!real_db->update_list(real_db,hii,state.original_package),"lab owner explicitly repairs its own isolated package");check(mp_rollback(&state,42)==MP_OK,"verified original package permits clearing retained transaction");close_case();
 open_case(9);check(mp_publish(&state,42)==MP_ENDED&&state.dirty&&update_calls==1,"end-boot revocation stops all subsequent HII updates");
 check(mp_rollback(&state,42)==MP_ENDED&&mp_callback(&config,0,0xffd0,0,0,&request)==ERR(15)&&update_calls==1,"ended publisher and bridge stay closed");
 check(nv_writes==0,"all lab paths wrote zero password or OC variables");
 for(unsigned i=0;i<3;i++)check(!((UNREGISTER_HII)real_db->unregister_notify)(real_db,notify[i]),"lab unregisters its own notification before VM shutdown");trace("MP04_LAB_PASS\n");finish(0x10);return 0;
}
