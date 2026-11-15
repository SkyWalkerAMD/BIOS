/* M1c: isolate static HII registration from SendForm. No IPMI driver, PCI,
 * BMC, variables or callbacks. Each durable boundary closes the file and
 * volume, then reopens and reads back the complete log before proceeding.
 */
#include "efi_min.h"
#include "minimal.h"
#define W(s) ((C16 *)L##s)
static ST *st;static HANDLE own_image,boot_device;
static FS *fs;
static ES log_error;
static int log_attempted,log_ready,prepare_attempted,prepared,show_attempted;
static char audit[32768],readback[32769];static UN used,saved;
static C16 filename[]=L"\\M1C000.TXT";
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
typedef struct DB DB;
struct DB {ES (EA *add)(DB *,const void *,HANDLE,HANDLE *);ES (EA *remove)(DB *,HANDLE);};
typedef struct BROWSER BROWSER;
struct BROWSER {ES (EA *show)(BROWSER *,HANDLE *,UN,GUID *,uint16_t,void *,UN *);void *callback;};
static DB *db;static BROWSER *browser;static HANDLE form_handle,hii;
static void *form_path;static int path_installed;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static int equal(const void *a,const void *b,UN n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static ES text(const char *s){
    if(!st->out||!st->out->out)return ERR(14);
    while(*s){C16 w[160];unsigned i=0;while(*s&&i<159)w[i++]=(uint8_t)*s++;w[i]=0;
        ES e=st->out->out(st->out,w);if(FAILED(e))return e;}return 0;
}
static void hex(char out[19],ES v){out[0]='0';out[1]='x';for(unsigned i=0;i<16;i++)out[i+2]="0123456789ABCDEF"[(v>>((15-i)*4))&15];out[18]=0;}
static void note(const char *name,ES value){
    char line[192],h[19];hex(h,value);unsigned n=0;const char *parts[]={"M1C ",name," status=",h,"\r\n"};
    for(unsigned p=0;p<5;p++)for(const char *s=parts[p];*s&&n<sizeof(line)-1;s++)line[n++]=*s;
    line[n]=0;text(line);
    if(n>sizeof(audit)-used){log_error=ERR(9);return;}
    memcpy(audit+used,line,n);used+=n;
}
static ES close_file(FILEP **p,ES status){
    if(*p){ES e=(*p)->close?(*p)->close(*p):ERR(14);*p=0;if(FAILED(e)&&!FAILED(status))status=e;}return status;
}
/* Readback is a firmware-filesystem check, not a guarantee against every
 * physical device/firmware cache failure. Never claim success before Close.
 * No file handle remains open after this function returns, including errors.
 */
static ES commit(int create){
    if(FAILED(log_error))return log_error;
    if(!fs||!fs->open_volume||(!create&&!log_ready))return ERR(15);
    FILEP *root=0,*file=0;ES e=fs->open_volume(fs,&root);
    if(FAILED(e)||!root){if(!FAILED(e))e=ERR(14);goto done;}
    e=root->open(root,&file,filename,create?0x8000000000000003ULL:3,0);
    if(FAILED(e)||!file){if(!FAILED(e))e=ERR(14);goto done;}
    if(!file->write||!file->flush||!file->set_position){e=ERR(14);goto done;}
    e=file->set_position(file,create?0:saved);if(FAILED(e))goto done;
    UN n=used-(create?0:saved),wrote=n;
    e=file->write(file,&wrote,audit+(create?0:saved));if(FAILED(e))goto done;
    if(wrote!=n){e=ERR(7);goto done;}
    e=file->flush(file);if(FAILED(e))goto done;
    e=close_file(&file,e);e=close_file(&root,e);if(FAILED(e))goto done;
    /* Reopen both root and file so the verification is not an in-handle
     * position read. No HII service is called unless all bytes match. */
    e=fs->open_volume(fs,&root);if(FAILED(e)||!root){if(!FAILED(e))e=ERR(14);goto done;}
    e=root->open(root,&file,filename,1,0);if(FAILED(e)||!file){if(!FAILED(e))e=ERR(14);goto done;}
    if(!file->read){e=ERR(14);goto done;}
    n=used+1;e=file->read(file,&n,readback);if(FAILED(e))goto done;
    if(n!=used || !equal(audit,readback,used)){e=ERR(33);goto done;}
done:
    e=close_file(&file,e);e=close_file(&root,e);
    if(FAILED(e)){log_error=e;text("LOG VERIFY FAILED. Stop here and press Q.\r\n");}
    else {saved=used;text("LOG_CLOSED_AND_READ_BACK: ");if(st->out&&st->out->out)st->out->out(st->out,filename);text("\r\n");}
    return e;
}
static ES start_log(void){
    if(log_attempted){text("L already attempted.\r\n");return log_error;}log_attempted=1;
    LOADED *loaded=0;FILEP *root=0,*file=0;ES e;
    note("LOADED_IMAGE_BEFORE",0);e=st->bs->handle_protocol(own_image,&loaded_guid,(void **)&loaded);note("LOADED_IMAGE_AFTER",e);
    if(FAILED(e)||!loaded||!loaded->device){if(!FAILED(e))e=ERR(14);goto done;}boot_device=loaded->device;
    note("FILESYSTEM_BEFORE",0);e=st->bs->handle_protocol(boot_device,&fs_guid,(void **)&fs);note("FILESYSTEM_AFTER",e);
    if(FAILED(e)||!fs||!fs->open_volume){if(!FAILED(e))e=ERR(14);goto done;}
    note("OPEN_ROOT_BEFORE",0);e=fs->open_volume(fs,&root);note("OPEN_ROOT_AFTER",e);
    if(FAILED(e)||!root){if(!FAILED(e))e=ERR(14);goto done;}
    note("MARKER_BEFORE",0);e=root->open(root,&file,W("\\HERO-IPMI-M1C.TAG"),1,0);note("MARKER_AFTER",e);
    if(FAILED(e)||!file||!file->read){if(!FAILED(e))e=ERR(14);goto done;}
    char marker[32];UN n=sizeof(marker);e=file->read(file,&n,marker);e=close_file(&file,e);
    if(FAILED(e))goto done;
    if(n!=14 || !equal(marker,"HERO-HII-M1C\r\n",14)){e=ERR(15);goto done;}
    for(unsigned i=0;i<1000;i++){
        filename[4]=(C16)('0'+i/100);filename[5]=(C16)('0'+i/10%10);filename[6]=(C16)('0'+i%10);
        e=root->open(root,&file,filename,1,0);
        if(!FAILED(e)){
            if(!file){e=ERR(14);goto done;}e=close_file(&file,e);if(FAILED(e))goto done;continue;
        }
        if(e!=ERR(14))goto done;
        e=close_file(&root,0);if(FAILED(e))goto done;
        note("L_LOG_CREATE_AND_VERIFY",0);e=commit(1);
        if(!FAILED(e)){log_ready=1;text("L complete: LOG_VERIFIED. P is registration only.\r\n");}
        goto done;
    }
    e=ERR(9);
done:
    e=close_file(&file,e);e=close_file(&root,e);
    if(FAILED(e)){log_error=e;note("L_FAILED",e);text("Check HERO-IPMI-M1C.TAG at the root of the boot USB.\r\n");}
    return e;
}
static ES boundary(const char *name,ES status){note(name,status);return commit(0);}
#define DO(name,call) do {e=boundary(name "_BEFORE",0);if(FAILED(e))goto done; \
    e=(call);ES logged=boundary(name "_AFTER",e);if(FAILED(logged)){e=logged;goto done;}if(FAILED(e))goto done;}while(0)
static ES prepare(void){
    if(!log_ready||FAILED(log_error)){text("L must report LOG_VERIFIED first.\r\n");return ERR(15);}
    if(prepare_attempted){text("P already attempted.\r\n");return prepared?0:ERR(20);}prepare_attempted=1;
    ES e=0;
    DO("LOCATE_HII_DATABASE",st->bs->locate_protocol(&db_guid,0,(void **)&db));
    if(!db||!db->add||!db->remove){e=ERR(14);goto done;}
    DO("ALLOCATE_DEVICE_PATH",st->bs->allocate_pool(4,24,&form_path));
    if(!form_path){e=ERR(9);goto done;}
    uint8_t *p=form_path;p[0]=1;p[1]=4;p[2]=20;p[3]=0;memcpy(p+4,&minimal_guid,16);p[20]=0x7f;p[21]=0xff;p[22]=4;p[23]=0;
    DO("INSTALL_DEVICE_PATH",(e=st->bs->install_protocol(&form_handle,&dp_guid,0,form_path),path_installed=!FAILED(e),e));
    if(!form_handle){e=ERR(14);goto done;}
    /* Unlike M1a's unassociated static package, use a real device-path
     * handle. This is a compatibility variation, not a proven root fix. */
    DO("NEW_PACKAGES",db->add(db,minimal_packages,form_handle,&hii));
    if(!hii){e=ERR(14);goto done;}
    DO("LOCATE_FORM_BROWSER",st->bs->locate_protocol(&browser_guid,0,(void **)&browser));
    if(!browser||!browser->show){e=ERR(14);goto done;}
    e=boundary("P_READY_NO_SEND_FORM",0);if(!FAILED(e)){prepared=1;text("P complete: REGISTERED. Screen was not opened.\r\n");}
done:
    if(FAILED(e)){note("P_FAILED",e);text("P failed. Press Q and return M1Cxxx.TXT.\r\n");}
    return e;
}
static ES show(void){
    if(!prepared||FAILED(log_error)){text("P must report REGISTERED first.\r\n");return ERR(15);}
    if(show_attempted){text("S already attempted. Press Q and return the log.\r\n");return ERR(20);}show_attempted=1;
    ES e=boundary("ENTER_SEND_FORM",0);if(FAILED(e))return e;
    text("Calling SendForm now. Esc should return. All log files are closed.\r\n");
    UN action=0;
    /* No file I/O or launcher trace callback exists inside SendForm. */
    e=browser->show(browser,&hii,1,&minimal_guid,1,0,&action);
    note("BROWSER_ACTION",action);ES logged=boundary("SEND_FORM_RETURN",e);
    return FAILED(logged)?logged:e;
}
static ES cleanup(void){
    ES e=0,c;
    if(hii){note("REMOVE_PACKAGES_BEFORE",0);if(log_ready&&!FAILED(log_error))commit(0);
        c=db->remove(db,hii);note("REMOVE_PACKAGES_AFTER",c);if(FAILED(c))e=c;else hii=0;}
    if(!hii && path_installed){
        note("UNINSTALL_PATH_BEFORE",0);c=st->bs->uninstall_protocol(form_handle,&dp_guid,form_path);note("UNINSTALL_PATH_AFTER",c);
        if(FAILED(c))e=c;else path_installed=0;
    }
    if(form_path&&!path_installed){c=st->bs->free_pool(form_path);form_path=0;if(FAILED(c))e=c;}
    /* On cleanup failure, the retained device path is boot-services pool,
     * not application memory. There is no installed callback into this app. */
    if(FAILED(e))text("HII cleanup failed. Reboot before another diagnostic.\r\n");
    return e;
}
static ES key_read(KEY *key){
    if(!st->in||!st->in->read)return ERR(14);
    for(;;){ES e=st->in->read(st->in,key);if(e!=ERR(6))return e;
        if(!st->in->wait)return ERR(14);UN index=0;e=st->bs->wait_for_event(1,&st->in->wait,&index);if(FAILED(e))return e;}
}
static ES EA run(HANDLE,ST *);
static ES (EA * volatile entry_target)(HANDLE,ST *)=run;
ES EA efi_main(HANDLE image,ST *system){return entry_target(image,system);}
static ES EA run(HANDLE image,ST *system){
    st=system;own_image=image;if(!st||st->hdr.sig!=0x5453595320494249ULL||!st->bs)return ERR(2);
    ES e=ERR(14);if(st->out&&st->out->out)e=st->out->out(st->out,W("\r\nHERO HII M1c - ENTRY REACHED\r\n"));
    note("FIRST_TEXT",e);
    if(st->out&&st->out->set_attribute)st->out->set_attribute(st->out,15);
    note("WATCHDOG_BEFORE",0);e=st->bs->set_watchdog(0,0,0,0);note("WATCHDOG_AFTER",e);
    ES first_error=0;
    for(;;){
        text("\r\nL = create/close/read-back log; P = register static page only\r\nS = show registered page; Q/Esc = exit\r\nFirst pass: L, P, Q. No log before L.\r\n");
        KEY key={0};e=key_read(&key);
        if(FAILED(e)){note("KEY_ERROR",e);st->bs->stall(5000000);first_error=e;break;}
        unsigned k=key.unicode;if(k>='a'&&k<='z')k-=32;
        if(k=='Q'||key.scan==0x17)break;
        if(k=='L')e=start_log();else if(k=='P')e=prepare();else if(k=='S')e=show();else continue;
        if(FAILED(e)&&!FAILED(first_error))first_error=e;
    }
    e=cleanup();if(FAILED(e)&&!FAILED(first_error))first_error=e;
    note("SESSION_END",first_error);if(log_ready&&!FAILED(log_error))commit(0);
    if(FAILED(log_error))first_error=log_error;
    text("M1c finished; returning to firmware.\r\n");return first_error;
}
