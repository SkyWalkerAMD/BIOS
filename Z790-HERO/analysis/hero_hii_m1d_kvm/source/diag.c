/* M1d: read-only-media HII diagnostic. The log exists in RAM and on the
 * console only. Capture it on the remote KVM before rebooting. No file I/O,
 * IPMI/PCI, runtime variables, graphics-mode changes or config callbacks. */
#include "efi_min.h"
#include "minimal.h"
#include "kvm.h"
#define W(s) ((C16 *)L##s)
#define LOG_COUNT 96
#define LOG_WIDTH 88
static ST *st;
static char lines[LOG_COUNT][LOG_WIDTH];static unsigned count;
static char run_id[17];static char snapshot[LOG_COUNT*LOG_WIDTH+128];
static ES output_error;static int overflow,prepare_attempted,prepared,show_attempted;
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
static ES text(const char *s){
    ES e=0;if(!st->out||!st->out->out)e=ERR(14);
    else while(*s){C16 w[120];unsigned n=0;while(*s&&n<119)w[n++]=(uint8_t)*s++;w[n]=0;
        e=st->out->out(st->out,w);if(FAILED(e))break;}
    if(FAILED(e)&&!FAILED(output_error))output_error=e;return e;
}
static void digits(char out[4],unsigned v){out[0]=(char)('0'+v/100%10);out[1]=(char)('0'+v/10%10);out[2]=(char)('0'+v%10);out[3]=0;}
static ES note(const char *name,ES value){
    if(count==LOG_COUNT){overflow=1;return ERR(9);}
    char *line=lines[count];unsigned n=0;char num[4];digits(num,++count);
    line[n++]='#';for(unsigned i=0;i<3;i++)line[n++]=num[i];line[n++]=' ';
    while(*name&&n<LOG_WIDTH-25)line[n++]=*name++;
    line[n++]='=';line[n++]='0';line[n++]='x';
    for(unsigned i=0;i<16;i++)line[n++]="0123456789ABCDEF"[(value>>((15-i)*4))&15];
    line[n++]='\r';line[n++]='\n';line[n]=0;return text(line);
}
static ES key_read(KEY *key){
    if(!st->in||!st->in->read)return ERR(14);
    for(;;){ES e=st->in->read(st->in,key);if(e!=ERR(6))return e;
        if(!st->in->wait)return ERR(14);UN index=0;e=st->bs->wait_for_event(1,&st->in->wait,&index);if(FAILED(e))return e;}
}
static unsigned upper(unsigned k){return k>='a'&&k<='z'?k-32:k;}
static ES capture(void){
    unsigned n=0;const char *head="HERO-HII-M1D-KVM\r\nRUN=";
    while(*head)snapshot[n++]=*head++;
    for(unsigned i=0;i<16;i++)snapshot[n++]=run_id[i];snapshot[n++]='\r';snapshot[n++]='\n';
    for(unsigned i=0;i<count;i++)for(const char *p=lines[i];*p;p++)snapshot[n++]=*p;
    const char *tail="SNAPSHOT_END\r\n";while(*tail)snapshot[n++]=*tail++;
    snapshot[n]=0;
    text("Opening QR snapshot. Save every page; Esc returns here.\r\n");
    return kvm_present(st,snapshot,n,(unsigned)overflow);
}
static ES view_log(void){
    unsigned page=0;
    for(;;){
        char p[4],total[4];digits(p,page+1);digits(total,(count+7)/8);
        text("\r\n--- M1d RAM LOG page ");text(p);text("/");text(total);text(" ---\r\n");
        for(unsigned i=page*8;i<count&&i<(page+1)*8;i++)text(lines[i]);
        text("Capture this page. N=next, B=back, Esc/Q=leave log view.\r\n");
        if(FAILED(output_error))return output_error;
        KEY key={0};ES e=key_read(&key);if(FAILED(e))return e;
        unsigned k=upper(key.unicode);if(k=='Q'||key.scan==0x17)return 0;
        if(k=='N'&&(page+1)*8<count)page++;
        if(k=='B'&&page)page--;
    }
}
#define DO(name,call) do {e=note(name "_BEFORE",0);if(FAILED(e))goto done; \
    e=(call);ES logged=note(name "_AFTER",e);if(FAILED(logged)){e=logged;goto done;}if(FAILED(e))goto done;}while(0)
static ES prepare(void){
    if(FAILED(output_error)||overflow)return FAILED(output_error)?output_error:ERR(9);
    if(prepare_attempted){text("P already attempted.\r\n");return prepared?0:ERR(20);}prepare_attempted=1;
    ES e=0;
    DO("LOCATE_HII_DATABASE",st->bs->locate_protocol(&db_guid,0,(void **)&db));
    if(!db||!db->add||!db->remove){e=ERR(14);goto done;}
    DO("ALLOCATE_DEVICE_PATH",st->bs->allocate_pool(4,24,&form_path));
    if(!form_path){e=ERR(9);goto done;}
    uint8_t *p=form_path;p[0]=1;p[1]=4;p[2]=20;p[3]=0;memcpy(p+4,&minimal_guid,16);p[20]=0x7f;p[21]=0xff;p[22]=4;p[23]=0;
    DO("INSTALL_DEVICE_PATH",(e=st->bs->install_protocol(&form_handle,&dp_guid,0,form_path),path_installed=!FAILED(e),e));
    if(!form_handle){e=ERR(14);goto done;}
    DO("NEW_PACKAGES",db->add(db,minimal_packages,form_handle,&hii));
    if(!hii){e=ERR(14);goto done;}
    DO("LOCATE_FORM_BROWSER",st->bs->locate_protocol(&browser_guid,0,(void **)&browser));
    if(!browser||!browser->show){e=ERR(14);goto done;}
    e=note("P_READY_NO_SEND_FORM",0);if(!FAILED(e)){prepared=1;text("P complete: REGISTERED. Capture this screen.\r\n");}
done:
    if(FAILED(e)){note("P_FAILED",e);text("P failed. V=review RAM log; Q=finish.\r\n");}
    return e;
}
static ES show(void){
    if(!prepared){text("P must report REGISTERED first.\r\n");return ERR(15);}
    if(FAILED(output_error)||overflow)return FAILED(output_error)?output_error:ERR(9);
    if(show_attempted){text("S already attempted. V=review RAM log; Q=finish.\r\n");return ERR(20);}
    ES e=note("PRE_SEND_FORM_CAPTURE_READY",0);if(FAILED(e))return e;
    text("\r\nCAPTURE NOW - SendForm has NOT been called.\r\n");
    text("Save a KVM screenshot and start video capture on your computer.\r\n");
    text("C=QR snapshot; Enter=call SendForm; Esc/Q=cancel.\r\n");
    if(FAILED(output_error))return output_error;
    for(;;){
        KEY key={0};e=key_read(&key);if(FAILED(e))return e;
        if(upper(key.unicode)=='C'){
            e=capture();if(FAILED(e))return e;
            text("CAPTURE NOW - SendForm has NOT been called.\r\n");
            text("C=QR snapshot; Enter=call SendForm; Esc/Q=cancel.\r\n");continue;
        }
        if(key.scan==0x17||upper(key.unicode)=='Q'){note("SHOW_CANCELLED",0);return 0;}
        if(key.unicode=='\r')break;
    }
    e=note("ENTER_SEND_FORM",0);if(FAILED(e))return e;
    show_attempted=1;UN action=0;
    /* Direct call: no tracing callback, open file or asynchronous event. */
    e=browser->show(browser,&hii,1,&minimal_guid,1,0,&action);
    note("BROWSER_ACTION",action);ES logged=note("SEND_FORM_RETURN",e);
    text("RETURNED_FROM_SEND_FORM. Capture screen; V=RAM log; Q=finish.\r\n");
    return FAILED(logged)?logged:e;
}
static ES cleanup(void){
    ES e=0,c;
    if(hii){note("REMOVE_PACKAGES_BEFORE",0);c=db->remove(db,hii);note("REMOVE_PACKAGES_AFTER",c);if(FAILED(c))e=c;else hii=0;}
    if(!hii&&path_installed){
        note("UNINSTALL_PATH_BEFORE",0);c=st->bs->uninstall_protocol(form_handle,&dp_guid,form_path);note("UNINSTALL_PATH_AFTER",c);
        if(FAILED(c))e=c;else path_installed=0;
    }
    if(form_path&&!path_installed){c=st->bs->free_pool(form_path);form_path=0;if(FAILED(c))e=c;}
    if(FAILED(e))text("HII cleanup failed. Reboot before another diagnostic.\r\n");
    return e;
}
static ES EA run(HANDLE,ST *);
static ES (EA * volatile entry_target)(HANDLE,ST *)=run;
ES EA efi_main(HANDLE image,ST *system){return entry_target(image,system);}
static ES EA run(HANDLE image,ST *system){
    (void)image;st=system;if(!st||st->hdr.sig!=0x5453595320494249ULL||!st->bs)return ERR(2);
    ES e=ERR(14);if(st->out&&st->out->out)e=st->out->out(st->out,W("\r\nHERO HII M1d - KVM / READ-ONLY ISO\r\n"));
    if(FAILED(e))output_error=e;
    /* Non-secret run discriminator for avoiding accidental capture mixing.
     * No clock/NVRAM service is used; this is not a hardware identity. */
    uint32_t lo,hi;__asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));
    uint64_t token=((uint64_t)hi<<32)|lo;
    for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
    note("FIRST_TEXT",e);if(st->out&&st->out->set_attribute)st->out->set_attribute(st->out,15);
    note("WATCHDOG_BEFORE",0);e=st->bs->set_watchdog(0,0,0,0);note("WATCHDOG_AFTER",e);
    text("Log storage: RAM + screen. No TXT file is created.\r\n");
    text("Save KVM captures before reset/exit; RAM log will be lost.\r\n");
    ES first_error=output_error;int keyboard_failed=0;
    for(;;){
        if(FAILED(output_error)){first_error=output_error;break;}
        text("\r\nP=register; S=show checkpoint; C=QR; V=text log; Q/Esc=finish.\r\n");
        KEY key={0};e=key_read(&key);
        if(FAILED(e)){note("KEY_ERROR",e);first_error=e;keyboard_failed=1;break;}
        unsigned k=upper(key.unicode);if(k=='Q'||key.scan==0x17)break;
        if(k=='P')e=prepare();else if(k=='S')e=show();else if(k=='V')e=view_log();else if(k=='C')e=capture();
        else {if(k=='L')text("ISO mode: no file log. Use V or KVM screenshot/video.\r\n");continue;}
        if(FAILED(e)&&!FAILED(first_error))first_error=e;
    }
    e=cleanup();if(FAILED(e)&&!FAILED(first_error))first_error=e;
    note("SESSION_END",first_error);
    if(!keyboard_failed&&!FAILED(output_error))for(;;){
        text("\r\nEND OF SESSION - save KVM captures now.\r\n");
        text("C=final QR; V=text log; Enter/Esc/Q=return to firmware.\r\n");
        KEY key={0};e=key_read(&key);if(FAILED(e)){first_error=e;keyboard_failed=1;break;}
        unsigned k=upper(key.unicode);if(k=='V'||k=='C'){e=k=='V'?view_log():capture();if(FAILED(e)){first_error=e;break;}}
        else if(k=='Q'||key.scan==0x17||key.unicode=='\r')break;
    }
    if(keyboard_failed||FAILED(output_error))st->bs->stall(5000000);
    text("M1d finished; returning to firmware.\r\n");return FAILED(output_error)?output_error:first_error;
}
