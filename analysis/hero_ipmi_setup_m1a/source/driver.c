/* M1a USB diagnostic driver. Entry publishes only the private API.
 * HII registration/display is explicit. No ReadyToBoot event is registered,
 * even if an earlier M1 session saved Auto initialize as enabled.
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
static GUID legacy_guid={0x40823e46,0x8089,0x43f6,{0xaa,0x64,0xa6,0x33,0x42,0x12,0xbb,0x12}};
static HDB *db;static HSTR *strings;static ROUTING *routing;
static HANDLE driver_handle,hii_handle,minimal_handle;
static int has_dp,has_access,has_api,showing,busy;
static ES EA extract(ACCESS *,const C16 *,C16 **,C16 **);
static ES EA route(ACCESS *,const C16 *,C16 **);
static ES EA callback(ACCESS *,UN,uint16_t,uint8_t,void *,UN *);
static ES EA show(uint32_t,TRACE *);
static ES EA query(TRACE *);
static const char *EA get_log(UN *n){if(n)*n=audit_len;return audit;}
static ACCESS access={extract,route,callback};
static M1_API api={2,sizeof(M1_API),show,query,get_log};
#define STEP(name,expression) do { \
    e=checkpoint(name "_BEFORE",0);if(FAILED(e))goto done; \
    e=(expression);ES logged=checkpoint(name "_AFTER",e); \
    if(FAILED(logged)){e=logged;goto done;}if(FAILED(e))goto done; \
} while(0)
static size_t wlen(const C16 *s){size_t n=0;if(s)while(n<4096 && s[n])n++;return n;}
static C16 lower(C16 c){return c>='A'&&c<='Z'?(C16)(c+32):c;}
static int matches_header(const C16 *s){
    if(!s || wlen(s)>=4096)return 0;
    size_t n=(sizeof(config_hdr)/2)-1;
    for(size_t i=0;i<n;i++)if(!s[i] || lower(s[i])!=lower(config_hdr[i]))return 0;
    return s[n]==0 || s[n]=='&';
}
static ES update_string(uint16_t id,const char *s){
    ES e=0;C16 wide[256];unsigned i=0;while(i<255 && s[i]){wide[i]=(uint8_t)s[i];i++;}wide[i]=0;
    logtext("STRING_ID=");loghex(id,4);logtext("\r\n");
    STEP("HII_SET_STRING",strings->set_string(strings,hii_handle,id,"en-US",wide,0));
done:return e;
}
static void append(char *s,size_t cap,const char *t){size_t n=0;while(n<cap && s[n])n++;if(n<cap)strcopy(s+n,cap-n,t);}
static void decimal(char *s,size_t cap,uint32_t n){char b[11];unsigned i=10;b[i]=0;do{b[--i]=(char)('0'+n%10);n/=10;}while(n);append(s,cap,b+i);}
static ES refresh_strings(void){
    char b[256];CONFIG c;ES e=config_read(&c);
    if(FAILED(e=update_string(S_CONFIG_VALUE,FAILED(e)?"Invalid/unreadable; initialization blocked":c.enabled?"Enabled (USB auto-run suppressed)":"Disabled")))return e;
    strcopy(b,sizeof(b),report.board[0]?report.board:"SMBIOS unavailable");append(b,sizeof(b)," / ");append(b,sizeof(b),report.bios);
    if(FAILED(e=update_string(S_TARGET_VALUE,b)))return e;
    if(FAILED(e=update_string(S_BMC_VALUE,report.identity?"Matches tested 1.3.13 Device ID":"Not verified")))return e;
    if(FAILED(e=update_string(S_RESULT_VALUE,report.result[0]?report.result:"Not run")))return e;
    b[0]=0;decimal(b,sizeof(b),report.targets);append(b,sizeof(b),"/16 SDRs; ");decimal(b,sizeof(b),report.readable);append(b,sizeof(b)," readable; OEM ");decimal(b,sizeof(b),report.acknowledged);append(b,sizeof(b),"/4");
    if(FAILED(e=update_string(S_COUNT_VALUE,b)))return e;
    lock_read();return update_string(S_LOCK_VALUE,report.locked?"LOCKED across boots":report.attempted?"Attempt consumed this session":"Ready; no pending attempt");
}
static ES EA extract(ACCESS *this,const C16 *request,C16 **progress,C16 **results){
    (void)this;if(!progress||!results)return ERR(2);*progress=(C16 *)request;*results=0;
    if(request && !matches_header(request))return ERR(14);
    ES e=checkpoint("EXTRACT_CONFIG_BEFORE",0);if(FAILED(e))return e;
    CONFIG c;config_read(&c);
    const C16 *use=request;C16 *temporary_progress=0;size_t hdrlen=sizeof(config_hdr)/2-1;
    int whole=!request || !request[hdrlen];if(whole)use=full_request;
    e=routing->block_to_config(routing,use,(uint8_t *)&c,sizeof(c),results,&temporary_progress);
    if(whole)*progress=request?(C16 *)request+wlen(request):0;
    else *progress=temporary_progress;
    ES logged=checkpoint("EXTRACT_CONFIG_AFTER",e);return FAILED(logged)?logged:e;
}
static ES EA route(ACCESS *this,const C16 *configuration,C16 **progress){
    (void)this;if(!configuration||!progress)return ERR(2);*progress=(C16 *)configuration;
    if(!matches_header(configuration))return ERR(14);
    ES e=checkpoint("ROUTE_CONFIG_BEFORE",0);if(FAILED(e))return e;
    CONFIG c;config_read(&c);UN n=sizeof(c);
    e=routing->config_to_block(routing,configuration,(uint8_t *)&c,&n,progress);
    if(!FAILED(e))e=config_write(&c);
    logtext("CONFIG_SAVE enabled=");loghex(c.enabled,2);logtext(" status=");loghex(e,16);logtext("\r\n");
    /* Do not issue HiiSetString from inside a browser callback. The next
     * explicit H invocation refreshes snapshots outside SendForm. */
    ES logged=checkpoint("ROUTE_CONFIG_AFTER",e);return FAILED(logged)?logged:e;
}
static ES EA callback(ACCESS *this,UN action,uint16_t question,uint8_t type,void *value,UN *request){
    (void)this;(void)type;(void)value;if(!request)return ERR(2);*request=0;
    logtext("CALLBACK action=");loghex(action,16);logtext(" question=");loghex(question,4);logtext("\r\n");
    ES e=checkpoint("CALLBACK_ENTER",0);if(FAILED(e))return e;
    if(action==3 || action==4 || action==5)return 0;
    if(action==0 && question>=2 && question<=5)return 0;
    if(action!=1)return ERR(3);
    if(question==2){*request=6;return 0;}
    if(question==3){STEP("MANUAL_READ_ONLY",engine_run(0));}
    else if(question==4){STEP("MANUAL_INITIALIZE",engine_run(1));}
    else if(question==5){
        CONFIG c;e=config_read(&c);
        if(FAILED(e)||c.enabled)result("Save Auto initialize as disabled before clearing the attempt lock.");
        else if(FAILED(lock_write(0)))result("Attempt lock could not be cleared.");
        else result("Attempt lock cleared. BMC unchanged; this session's attempt limit remains.");
    }else return ERR(3);
done:
    checkpoint("CALLBACK_OPERATION_END",e);
    return FAILED(trace_status())?trace_status():0;
}
static ES prepare(uint32_t minimal){
    ES e=0;
    if(!db){STEP("LOCATE_HII_DATABASE",gST->bs->locate_protocol(&database_guid,0,(void **)&db));if(!db)return ERR(14);}
    if(minimal){
        if(!minimal_handle){STEP("MINIMAL_NEW_PACKAGES",db->new_packages(db,minimal_packages,0,&minimal_handle));}
        return minimal_handle?0:ERR(14);
    }
    if(!strings){STEP("LOCATE_HII_STRING",gST->bs->locate_protocol(&string_guid,0,(void **)&strings));if(!strings)return ERR(14);}
    if(!routing){STEP("LOCATE_CONFIG_ROUTING",gST->bs->locate_protocol(&routing_guid,0,(void **)&routing));if(!routing)return ERR(14);}
    if(!has_dp){
        STEP("INSTALL_DEVICE_PATH",(e=gST->bs->install_protocol(&driver_handle,&dp_guid,0,(void *)vendor_path),has_dp=!FAILED(e),e));
    }
    if(!has_access){
        STEP("INSTALL_CONFIG_ACCESS",(e=gST->bs->install_protocol(&driver_handle,&access_guid,0,&access),has_access=!FAILED(e),e));
    }
    if(!hii_handle){STEP("FULL_NEW_PACKAGES",db->new_packages(db,hii_packages,driver_handle,&hii_handle));}
    if(!hii_handle)return ERR(14);
    STEP("FULL_REFRESH_STRINGS",refresh_strings());
done:return e;
}
static ES EA show(uint32_t minimal,TRACE *trace){
    if(busy || showing)return ERR(20);if(minimal>1)return ERR(2);
    ES e=trace_bind(trace);if(FAILED(e))return e;busy=1;
    BROWSER *browser=0;
    STEP("PREPARE_HII",prepare(minimal));
    STEP("LOCATE_FORM_BROWSER",gST->bs->locate_protocol(&browser_guid,0,(void **)&browser));
    if(!browser){e=ERR(14);goto done;}
    e=checkpoint(minimal?"MINIMAL_SEND_FORM_BEFORE":"FULL_SEND_FORM_BEFORE",0);if(FAILED(e))goto done;
    showing=1;UN requested=0;
    e=browser->send_form(browser,minimal?&minimal_handle:&hii_handle,1,minimal?&minimal_guid:&form_guid,1,0,&requested);
    showing=0;logtext("BROWSER_ACTION_REQUEST=");loghex(requested,16);logtext("\r\n");
    checkpoint(minimal?"MINIMAL_SEND_FORM_AFTER":"FULL_SEND_FORM_AFTER",e);
done:
    checkpoint("SHOW_RETURN",e);if(FAILED(trace_status()))e=trace_status();
    busy=0;trace_unbind();return e;
}
static ES EA query(TRACE *trace){
    if(busy || showing)return ERR(20);
    ES e=trace_bind(trace);if(FAILED(e))return e;busy=1;
    STEP("TEXT_READ_ONLY",engine_run(0));
done:
    checkpoint("TEXT_READ_ONLY_RETURN",e);if(FAILED(trace_status()))e=trace_status();
    busy=0;trace_unbind();return e;
}
static ES EA unload(HANDLE image){
    (void)image;if(showing || busy)return ERR(15);
    if(minimal_handle){ES e=db->remove_packages(db,minimal_handle);if(FAILED(e))return e;minimal_handle=0;}
    if(hii_handle){ES e=db->remove_packages(db,hii_handle);if(FAILED(e))return e;hii_handle=0;}
    if(has_access){ES e=gST->bs->uninstall_protocol(driver_handle,&access_guid,&access);if(FAILED(e))return e;has_access=0;}
    if(has_dp){ES e=gST->bs->uninstall_protocol(driver_handle,&dp_guid,(void *)vendor_path);if(FAILED(e))return e;has_dp=0;}
    if(has_api){ES e=gST->bs->uninstall_protocol(driver_handle,&api_guid,&api);if(FAILED(e))return e;has_api=0;}
    return 0;
}
ES EA efi_main(HANDLE image,ST *system){
    gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);
    LOADED *loaded=0;ES e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded);
    if(FAILED(e)||!loaded)return FAILED(e)?e:ERR(14);
    /* Direct execution without our paired launcher is intentionally rejected. */
    if(loaded->options_size!=sizeof(TRACE))return ERR(2);
    e=trace_bind((TRACE *)loaded->options);loaded->options_size=0;loaded->options=0;
    if(FAILED(e))return e;
    void *existing=0;
    logtext("HERO-IPMI-SETUP-M1a / USB diagnostic / auto-run unconditionally suppressed\r\n");
    e=checkpoint("DRIVER_ENTRY",0);if(FAILED(e))goto done;
    e=gST->bs->locate_protocol(&legacy_guid,0,&existing);if(e!=ERR(14)){e=FAILED(e)?e:ERR(20);goto done;}
    e=gST->bs->locate_protocol(&api_guid,0,&existing);if(e!=ERR(14)){e=FAILED(e)?e:ERR(20);goto done;}
    e=checkpoint("SMBIOS_BEFORE",0);if(FAILED(e))goto done;
    detect_board();logtext("BOARD=");logtext(report.board);logtext(" BIOS=");logtext(report.bios);logtext("\r\n");
    e=checkpoint("SMBIOS_AFTER",0);if(FAILED(e))goto done;
    result("M1a loaded. HII deferred; no BMC query; no automatic initialization.");
    loaded->unload=unload;
    /* Mark publication before logging AFTER so failure cleanup is correct. */
    e=checkpoint("INSTALL_API_BEFORE",0);if(FAILED(e))goto done;
    e=gST->bs->install_protocol(&driver_handle,&api_guid,0,&api);if(!FAILED(e))has_api=1;
    {ES logged=checkpoint("INSTALL_API_AFTER",e);if(FAILED(logged))e=logged;}
done:
    if(FAILED(e)){
        ES cleanup=unload(image);
        checkpoint("ENTRY_CLEANUP",cleanup);
        if(FAILED(cleanup))e=0; /* Do not free published code on partial cleanup. */
    }
    checkpoint("DRIVER_ENTRY_RETURN",e);
    trace_unbind();return e;
}
