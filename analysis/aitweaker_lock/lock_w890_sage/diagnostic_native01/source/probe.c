/* P3 KVM: same P2 inventory, display-only export; not a password lock. */
#include "efi_min.h"
#include "probe_core.h"
#include "profiles.h"
#include "kvm.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID hii_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID post_guid={0x8a91b1e1,0x56c7,0x4adc,{0xab,0xeb,0x1c,0x2c,0xa1,0x72,0x9e,0xff}};
static GUID tse_guid={0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}};
static GUID setup_guid={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
int native_read_only(ST *,void *,void *,void (*)(const char *));
static void *w890_tse,*w890_setup;
static ST *st;
static HANDLE *images;
static UN image_count;
static char logbuf[65536];
static size_t loglen;
static int truncated;
static unsigned warnings,known_modules,hii_valid;
void *memset(void *p,int c,size_t n) { uint8_t *a=p;while(n--)*a++=(uint8_t)c;return p; }
void *memcpy(void *p,const void *q,size_t n) { uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;return p; }
static int equal(const void *p,const void *q,size_t n) {
    const uint8_t *a=p,*b=q;while(n--)if(*a++!=*b++)return 0;return 1;
}
static void screen(const char *s) {
    C16 w[160];size_t n=0;
    if (!st->out || !st->out->out)return;
    while(*s) {
        w[n++]=(uint8_t)*s++;
        if(n==159 || !*s) { w[n]=0;st->out->out(st->out,w);n=0; }
    }
}
static void emit(const char *s) {
    while(*s) { if(loglen<sizeof(logbuf))logbuf[loglen++]=*s;else truncated=1;s++; }
}
static void hex(uint64_t n,unsigned digits) {
    static const char h[]="0123456789ABCDEF";char b[17];
    if(digits>16)digits=16;
    for(unsigned i=0;i<digits;i++)b[i]=h[(n>>((digits-i-1)*4))&15];
    b[digits]=0;emit(b);
}
static void number(uint64_t n) {
    char b[24];unsigned k=23;b[k]=0;
    do { b[--k]=(char)('0'+n%10);n/=10; }while(n);
    emit(b+k);
}
static void status(const char *s,ES e) { emit(s);emit("=0x");hex(e,16);emit("\r\n"); }
static void warning(const char *s,ES e) { warnings++;status(s,e); }
static void release(void *p) {
    ES e=st->bs->free_pool(p);
    if(FAILED(e))warning("FreePool",e);
}
static void guid_text(const GUID *g) {
    hex(g->a,8);emit("-");hex(g->b,4);emit("-");hex(g->c,4);emit("-");
    for(unsigned k=0;k<8;k++) { if(k==2)emit("-");hex(g->d[k],2); }
}
static int fv_guid(LOADED *li,GUID *g) {
    const uint8_t *p=li->filepath;
    if(!p)return 0;
    for(size_t pos=0;pos+4<=1024;) {
        uint16_t n=(uint16_t)(p[pos+2]|((uint16_t)p[pos+3]<<8));
        if(n<4 || n>1024-pos || p[pos]==0x7f)return 0;
        if(p[pos]==4 && p[pos+1]==6 && n==20) { memcpy(g,p+pos+4,16);return 1; }
        pos+=n;
    }
    return 0;
}
static LOADED *loaded(HANDLE h) {
    LOADED *li=0;
    if(FAILED(st->bs->handle_protocol(h,&loaded_guid,(void **)&li)))return 0;
    return li;
}
static void owner(const char *label,void *fn) {
    emit(label);emit(" ");
    if(!fn) { emit("NULL\r\n");warnings++;return; }
    for(UN k=0;k<image_count;k++) {
        LOADED *li=loaded(images[k]);
        if(!li || !li->image_base)continue;
        UN addr=(UN)fn,base=(UN)li->image_base;
        if(addr<base || addr-base>=li->image_size)continue;
        GUID g;
        if(fv_guid(li,&g))guid_text(&g);else emit("NON_FV_IMAGE");
        emit(" RVA=0x");hex(addr-base,8);emit("\r\n");return;
    }
    emit("OWNER_NOT_RESOLVED\r\n");warnings++;
}
static void inspect_images(void) {
    ES e=st->bs->locate_handles(2,&loaded_guid,0,&image_count,&images);
    status("LoadedImage.enumerate",e);
    if(FAILED(e)||!images||!image_count||image_count>4096) {
        warnings++;
        /* Output parameters from a failed service are not trusted. */
        if(!FAILED(e)&&images)release(images);
        images=0;image_count=0;return;
    }
    emit("LoadedImage.count=");number(image_count);emit("\r\n");
    unsigned matched=0;
    for(UN k=0;k<image_count && !truncated;k++) {
        LOADED *li=loaded(images[k]);GUID g;
        if(!li || !fv_guid(li,&g))continue;
        if(!equal(&g,&tse_guid,16)&&!equal(&g,&setup_guid,16))continue;
        matched++;
        emit(equal(&g,&tse_guid,16)?"AMITSE ":"Setup ");
        IMAGE_INFO info;
        if(!probe_image(li->image_base,(size_t)li->image_size,&info)) {
            emit("IMAGE_PARSE_FAILED\r\n");warnings++;continue;
        }
        emit("text_crc32=0x");hex(info.text_crc,8);
        emit(" text_rva=0x");hex(info.text_rva,8);
        emit(" text_size=0x");hex(info.text_size,8);
        emit(" entry=0x");hex(info.entry,8);emit("\r\n");
        const char *name="UNKNOWN_BUILD";
        for(unsigned i=0;i<sizeof(profiles)/sizeof(profiles[0]);i++) {
            const PROFILE *p=&profiles[i];
            if(equal(&g,&p->guid,16)&&info.text_crc==p->crc&&info.text_rva==p->rva&&
               info.text_size==p->size&&info.entry==p->entry&&info.image_size==p->image_size) {
                name=p->name;known_modules|=equal(&g,&tse_guid,16)?1U:2U;if(i==4)w890_tse=li->image_base;if(i==5)w890_setup=li->image_base;break;
            }
        }
        emit("Build fingerprint: ");emit(name);emit("\r\n");
        if(equal(name,"UNKNOWN_BUILD",13))warnings++;
    }
    emit("Target modules found=");number(matched);emit("\r\n");
    if(known_modules!=3)warnings++;
}
static void inspect_protocols(void) {
    BROWSER *browser=0;void *post=0;
    ES e=st->bs->locate_protocol(&browser_guid,0,(void **)&browser);
    status("FormBrowser2.locate",e);
    if(!FAILED(e)&&browser) {
        owner("FormBrowser2.SendForm",browser->send_form);
        owner("FormBrowser2.BrowserCallback",browser->browser_callback);
    } else warnings++;
    e=st->bs->locate_protocol(&post_guid,0,&post);
    status("AMI.PostManager.locate",e);
    emit("AMI.PostManager.interface=");emit(!FAILED(e)&&post?"PRESENT\r\n":"ABSENT\r\n");
    if(FAILED(e)||!post)warnings++;
    /* The private AMI protocol is intentionally not dereferenced or called. */
}
static void inspect_hii(void) {
    HII *hii=0;HANDLE *handles=0;UN bytes=0;
    ES e=st->bs->locate_protocol(&hii_guid,0,(void **)&hii);
    status("HiiDatabase.locate",e);
    if(FAILED(e)||!hii) { warnings++;return; }
    if(!hii->list||!hii->export_list||!hii->get_driver) {
        warning("HiiDatabase.missing_method",ERR(3));return;
    }
    e=hii->list(hii,2,0,&bytes,0);
    if(e!=ERR(5)||!bytes||bytes>32768||bytes%sizeof(HANDLE)) { warning("HiiDatabase.list_size",e);return; }
    UN capacity=bytes;
    e=st->bs->allocate_pool(4,capacity,(void **)&handles);
    if(FAILED(e)||!handles) { warning("HiiDatabase.allocate",e);return; }
    e=hii->list(hii,2,0,&bytes,handles);
    if(FAILED(e)||!bytes||bytes>capacity||bytes%sizeof(HANDLE)) { warning("HiiDatabase.list",e);release(handles);return; }
    emit("HII form-package handles=");number(bytes/sizeof(HANDLE));emit("\r\n");
    for(UN i=0;i<bytes/sizeof(HANDLE) && !truncated;i++) {
        UN size=0;uint8_t *buffer=0;
        e=hii->export_list(hii,handles[i],&size,0);
        if((e!=ERR(5)&&e!=ERR(9))||size<20||size>16*1024*1024) { warning("HII export_size",e);continue; }
        UN cap=size;
        e=st->bs->allocate_pool(4,cap,(void **)&buffer);
        if(FAILED(e)||!buffer) { warning("HII allocate",e);continue; }
        e=hii->export_list(hii,handles[i],&size,buffer);
        if(FAILED(e)||size>cap) { warning("HII export",e);release(buffer);continue; }
        HII_INFO info;
        if(!probe_hii(buffer,(size_t)size,&info)) {
            emit("HII package parse failed\r\n");warnings++;release(buffer);continue;
        }
        hii_valid++;
        /* Log only structural counts and module ownership; no HII strings,
         * question values, password buffers, or package contents are saved. */
        emit("HII ");guid_text((GUID *)buffer);emit(" handle=0x");hex((UN)handles[i],16);
        emit(" forms=");number(info.forms);emit(" password_controls=");number(info.password_questions);
        emit(" main_form_2713=");number(info.form_2713);emit(" main_form_2714=");number(info.form_2714);emit("\r\n");
        HANDLE driver=0;
        e=hii->get_driver(hii,handles[i],&driver);
        if(!FAILED(e)&&driver) {
            CONFIG *config=0;
            e=st->bs->handle_protocol(driver,&config_guid,(void **)&config);
            if(!FAILED(e)&&config) {
                owner("  ConfigAccess.ExtractConfig",config->extract);
                owner("  ConfigAccess.RouteConfig",config->route);
                owner("  ConfigAccess.Callback",config->callback);
            } else warning("  ConfigAccess.locate",e);
        } else warning("  HII.driver",e);
        release(buffer);
    }
    release(handles);
}

/* No SimpleFileSystem or RuntimeServices are called. Display-only log export. */
ES EA efi_main(HANDLE image,ST *system_table) {
    (void)image;st=system_table;
    if(!st||!st->bs)return ERR(2);
    if(!st->bs->allocate_pool||!st->bs->free_pool||!st->bs->handle_protocol||
       !st->bs->locate_handles||!st->bs->locate_protocol||!st->bs->stall)return ERR(3);
    loglen=0;truncated=0;warnings=0;known_modules=0;hii_valid=0;images=0;image_count=0;
    screen("Ai Tweaker P3 KVM - collecting read-only inventory...\r\n");
    emit("AITWEAKER-PROBE-P3-KVM\r\nRead-only interface inventory. No password values collected.\r\n");
    typedef ES (EA *WD)(UN,uint64_t,UN,C16 *);
    ES watchdog=st->bs->set_watchdog?((WD)st->bs->set_watchdog)(0,0,0,0):ERR(3);
    if(FAILED(watchdog))warning("Watchdog.disable",watchdog);
    else status("Watchdog.disable",watchdog);
    w890_tse=0;w890_setup=0;inspect_images();inspect_protocols();inspect_hii();
    if(!native_read_only(st,w890_tse,w890_setup,emit))warnings++;
    if(images)release(images);
    images=0;image_count=0;
    if(!hii_valid)warnings++;
    emit("Collection.warnings=");number(warnings);emit("\r\n");
    emit(warnings?"COLLECTION_STATUS=PARTIAL\r\n":"COLLECTION_STATUS=COMPLETE\r\n");
    emit("PROBE_COMPLETE\r\n");
    if(truncated){screen("Log exceeded 64 KiB. Incomplete inventory NOT exported.\r\n");return ERR(9);}
    return kvm_present(st,logbuf,loglen,warnings);
}
