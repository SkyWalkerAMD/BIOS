/* Standard HII ConfigAccess + private NVRAM. Does not patch AMI Setup offsets.
 * Firmware DXE and USB loader use these exact same driver bytes.
 */
#include "m1.h"
#include "hii_abi.h"
#include "forms.h"
static GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID string_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID routing_guid={0x587e72d7,0xcc50,0x4f79,{0x82,0x09,0xca,0x29,0x1f,0xc1,0xa1,0x0f}};
static GUID access_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID ready_guid={0x7ce88fb3,0x4bd7,0x4679,{0x87,0xa8,0xa8,0xd8,0xde,0xe5,0x0d,0x2b}};
static HDB *db;static HSTR *strings;static ROUTING *routing;
static HANDLE driver_handle,hii_handle,ready_event;
static int has_dp,has_access,has_api,auto_seen,showing;
static ES EA extract(ACCESS *,const C16 *,C16 **,C16 **);
static ES EA route(ACCESS *,const C16 *,C16 **);
static ES EA callback(ACCESS *,UN,uint16_t,uint8_t,void *,UN *);
static ES EA show(void);
static const char *EA get_log(UN *n){if(n)*n=audit_len;return audit;}
static ACCESS access={extract,route,callback};
static M1_API api={1,sizeof(M1_API),show,get_log};
static size_t wlen(const C16 *s){size_t n=0;if(s)while(n<4096 && s[n])n++;return n;}
static C16 lower(C16 c){return c>='A'&&c<='Z'?(C16)(c+32):c;}
static int matches_header(const C16 *s){
    if(!s || wlen(s)>=4096)return 0;
    size_t n=(sizeof(config_hdr)/2)-1;
    for(size_t i=0;i<n;i++)if(!s[i] || lower(s[i])!=lower(config_hdr[i]))return 0;
    return s[n]==0 || s[n]=='&';
}
static void update_string(uint16_t id,const char *s){
    C16 wide[256];unsigned i=0;while(i<255 && s[i]){wide[i]=(uint8_t)s[i];i++;}wide[i]=0;
    ES e=strings->set_string(strings,hii_handle,id,"en-US",wide,0);
    if(FAILED(e)){logtext("HII_SET_STRING_FAILED ");loghex(id,4);logtext(" ");loghex(e,16);logtext("\r\n");}
}
static void append(char *s,size_t cap,const char *t){size_t n=0;while(n<cap && s[n])n++;if(n<cap)strcopy(s+n,cap-n,t);}
static void decimal(char *s,size_t cap,uint32_t n){char b[11];unsigned i=10;b[i]=0;do{b[--i]=(char)('0'+n%10);n/=10;}while(n);append(s,cap,b+i);}
static void refresh_strings(void){
    char b[256];CONFIG c;ES e=config_read(&c);
    update_string(S_CONFIG_VALUE,FAILED(e)?"Invalid/unreadable; initialization blocked":c.enabled?"Enabled":"Disabled");
    strcopy(b,sizeof(b),report.board[0]?report.board:"SMBIOS unavailable");append(b,sizeof(b)," / ");append(b,sizeof(b),report.bios);
    update_string(S_TARGET_VALUE,b);
    update_string(S_BMC_VALUE,report.identity?"Matches tested 1.3.13 Device ID":"Not verified");
    update_string(S_RESULT_VALUE,report.result[0]?report.result:"Not run");
    b[0]=0;decimal(b,sizeof(b),report.targets);append(b,sizeof(b),"/16 SDRs; ");decimal(b,sizeof(b),report.readable);append(b,sizeof(b)," readable; OEM ");decimal(b,sizeof(b),report.acknowledged);append(b,sizeof(b),"/4");
    update_string(S_COUNT_VALUE,b);
    lock_read();update_string(S_LOCK_VALUE,report.locked?"LOCKED across boots":report.attempted?"Attempt consumed this session":"Ready; no pending attempt");
}
static ES EA extract(ACCESS *this,const C16 *request,C16 **progress,C16 **results){
    (void)this;if(!progress||!results)return ERR(2);*progress=(C16 *)request;*results=0;
    if(request && !matches_header(request))return ERR(14);
    CONFIG c;config_read(&c); /* Invalid storage is represented as disabled. */
    const C16 *use=request;C16 *temporary_progress=0;size_t hdrlen=sizeof(config_hdr)/2-1;
    int whole=!request || !request[hdrlen];if(whole)use=full_request;
    ES e=routing->block_to_config(routing,use,(uint8_t *)&c,sizeof(c),results,&temporary_progress);
    if(whole)*progress=request?(C16 *)request+wlen(request):0;
    else *progress=temporary_progress;
    return e;
}
static ES EA route(ACCESS *this,const C16 *configuration,C16 **progress){
    (void)this;if(!configuration||!progress)return ERR(2);*progress=(C16 *)configuration;
    if(!matches_header(configuration))return ERR(14);
    CONFIG c;config_read(&c);UN n=sizeof(c);
    ES e=routing->config_to_block(routing,configuration,(uint8_t *)&c,&n,progress);
    if(FAILED(e))return e;
    e=config_write(&c);
    logtext("CONFIG_SAVE enabled=");loghex(c.enabled,2);logtext(" status=");loghex(e,16);logtext("\r\n");
    refresh_strings();return e;
}
static ES EA callback(ACCESS *this,UN action,uint16_t question,uint8_t type,void *value,UN *request){
    (void)this;(void)type;(void)value;if(!request)return ERR(2);*request=0;
    if(action==3 || action==5){refresh_strings();return 0;}
    if(action==4)return 0;
    if(action==0 && question>=2 && question<=5)return 0;
    if(action!=1)return ERR(3);
    if(question==2){*request=6;return 0;} /* FORM_APPLY; RouteConfig owns persistence. */
    if(question==3)engine_run(0);
    else if(question==4)engine_run(1);
    else if(question==5){
        CONFIG c;ES e=config_read(&c);
        if(FAILED(e)||c.enabled)result("Save Auto initialize as disabled before clearing the attempt lock.");
        else if(FAILED(lock_write(0)))result("Attempt lock could not be cleared.");
        else result("Attempt lock cleared. BMC state was not changed; this session's attempt limit remains.");
    }else return ERR(3);
    refresh_strings();return 0; /* Operation result is displayed and logged. */
}
static void EA ready_callback(HANDLE event,void *context){
    (void)event;(void)context;if(auto_seen)return;auto_seen=1;
    CONFIG c;ES e=config_read(&c);
    if(FAILED(e)){result("ReadyToBoot: invalid/unreadable configuration; auto-init skipped.");return;}
    if(!c.enabled){logtext("READY_TO_BOOT_AUTO_DISABLED\r\n");return;}
    logtext("READY_TO_BOOT_AUTO_ENABLED\r\n");engine_run(1);refresh_strings();
}
static ES EA show(void){
    if(showing)return ERR(20);BROWSER *browser=0;
    ES e=gST->bs->locate_protocol(&browser_guid,0,(void **)&browser);
    if(FAILED(e)||!browser)return FAILED(e)?e:ERR(14);
    refresh_strings();showing=1;UN requested=0;
    e=browser->send_form(browser,&hii_handle,1,&form_guid,1,0,&requested);
    showing=0;logtext("SEND_FORM_RETURN ");loghex(e,16);logtext(" action=");loghex(requested,16);logtext("\r\n");return e;
}
static ES EA unload(HANDLE image){
    (void)image;if(showing)return ERR(15);
    if(ready_event){ES e=gST->bs->close_event(ready_event);if(FAILED(e))return e;ready_event=0;}
    if(has_api){ES e=gST->bs->uninstall_protocol(driver_handle,&api_guid,&api);if(FAILED(e))return e;has_api=0;}
    if(hii_handle){ES e=db->remove_packages(db,hii_handle);if(FAILED(e))return e;hii_handle=0;}
    if(has_access){ES e=gST->bs->uninstall_protocol(driver_handle,&access_guid,&access);if(FAILED(e))return e;has_access=0;}
    if(has_dp){ES e=gST->bs->uninstall_protocol(driver_handle,&dp_guid,(void *)vendor_path);if(FAILED(e))return e;has_dp=0;}
    return 0;
}
ES EA efi_main(HANDLE image,ST *system){
    gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);
    void *existing=0;ES e=gST->bs->locate_protocol(&api_guid,0,&existing);
    if(e!=ERR(14))return FAILED(e)?e:ERR(20);
    logtext("HERO-IPMI-SETUP-M1 / private config / default disabled\r\n");
    detect_board();result("Loaded. No hardware query on entry. Auto initialization defaults to disabled.");
    if(FAILED(e=gST->bs->locate_protocol(&database_guid,0,(void **)&db))||!db)return FAILED(e)?e:ERR(14);
    if(FAILED(e=gST->bs->locate_protocol(&string_guid,0,(void **)&strings))||!strings)return FAILED(e)?e:ERR(14);
    if(FAILED(e=gST->bs->locate_protocol(&routing_guid,0,(void **)&routing))||!routing)return FAILED(e)?e:ERR(14);
    LOADED *loaded=0;
    if(FAILED(e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))||!loaded)return FAILED(e)?e:ERR(14);
    loaded->unload=unload;
    e=gST->bs->install_protocol(&driver_handle,&dp_guid,0,(void *)vendor_path);if(FAILED(e))goto fail;has_dp=1;
    e=gST->bs->install_protocol(&driver_handle,&access_guid,0,&access);if(FAILED(e))goto fail;has_access=1;
    e=db->new_packages(db,hii_packages,driver_handle,&hii_handle);if(FAILED(e))goto fail;
    e=gST->bs->create_event_ex(0x200,8,ready_callback,0,&ready_guid,&ready_event);if(FAILED(e))goto fail;
    e=gST->bs->install_protocol(&driver_handle,&api_guid,0,&api);if(FAILED(e))goto fail;has_api=1;
    refresh_strings();return 0;
fail:
    /* If cleanup cannot detach a published interface, stay resident rather
     * than returning an error that would free code still referenced by firmware. */
    if(FAILED(unload(image)))return 0;
    return e;
}
