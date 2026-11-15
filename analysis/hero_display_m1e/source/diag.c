/* M1e: inspect display/protocol metadata without invoking a forms browser.
 * No file, PCI/BMC, runtime-variable, controller reconnect or SetMode calls.
 * D reads protocol metadata; R exports text without entering graphics code. */
#include "efi_min.h"
#include "kvm.h"
#define W(s) ((C16 *)L##s)
#define MAX_LOG 256
#define LINE_WIDTH 88
static ST *st;static char lines[MAX_LOG][LINE_WIDTH],snapshot[MAX_LOG*LINE_WIDTH+128],run_id[17];
static unsigned count;static int inspected,overflow;static ES output_error;
static GUID gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
typedef struct {uint32_t version,width,height,format,masks[4],stride;} GINFO;
typedef struct {uint32_t max,current;GINFO *info;UN info_size;uint64_t framebuffer;UN framebuffer_size;} GMODE;
typedef struct GOP GOP;
struct GOP {ES(EA *query)(GOP *,uint32_t,UN *,GINFO **);void *set_mode,*blt;GMODE *mode;};
typedef struct {void *send_form,*callback;} BROWSER;
OFF(GOP,mode,24);OFF(GMODE,info_size,16);OFF(GINFO,stride,32);OFF(LOADED,image_base,0x40);OFF(LOADED,image_size,0x48);
extern uint32_t probe_crc32(const void *,size_t);
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static ES text(const char *s){
    ES e=0;if(!st->out||!st->out->out)e=ERR(14);
    else while(*s){C16 w[120];unsigned n=0;while(*s&&n<119)w[n++]=(uint8_t)*s++;w[n]=0;e=st->out->out(st->out,w);if(FAILED(e))break;}
    if(FAILED(e)&&!FAILED(output_error))output_error=e;return e;
}
static void note(const char *name,uint64_t value){
    if(count==MAX_LOG){overflow=1;return;}char *p=lines[count++];unsigned n=0;
    p[n++]='#';p[n++]=(char)('0'+count/100);p[n++]=(char)('0'+count/10%10);p[n++]=(char)('0'+count%10);p[n++]=' ';
    while(*name&&n<LINE_WIDTH-25)p[n++]=*name++;
    p[n++]='=';p[n++]='0';p[n++]='x';for(unsigned i=0;i<16;i++)p[n++]="0123456789ABCDEF"[(value>>((15-i)*4))&15];
    p[n++]='\r';p[n++]='\n';p[n]=0;text(p);
}
static ES key_read(KEY *key){
    if(!st->in||!st->in->read)return ERR(14);
    for(;;){ES e=st->in->read(st->in,key);if(e!=ERR(6))return e;if(!st->in->wait)return ERR(14);
        UN index=0;e=st->bs->wait_for_event(1,&st->in->wait,&index);if(FAILED(e))return e;}
}
static unsigned upper(unsigned k){return k>='a'&&k<='z'?k-32:k;}
static void item(unsigned index,const char *name,uint64_t value){
    char label[64]="GOP00_";label[3]=(char)('0'+index/10);label[4]=(char)('0'+index%10);unsigned n=6;
    while(*name&&n<63)label[n++]=*name++;label[n]=0;note(label,value);
}
static void inspect_gop(unsigned index,HANDLE handle){
    GOP *g=0;item(index,"HANDLE",(UN)handle);
    ES e=st->bs->handle_protocol(handle,&gop_guid,(void **)&g);item(index,"HANDLE_STATUS",e);
    if(FAILED(e)||!g)return;item(index,"INTERFACE",(UN)g);item(index,"BLT_PRESENT",g->blt!=0);
    item(index,"MODE_PTR",(UN)g->mode);if(!g->mode)return;
    GMODE *m=g->mode;item(index,"MAX_MODE",m->max);item(index,"CURRENT_MODE",m->current);item(index,"INFO_SIZE",m->info_size);
    item(index,"INFO_PRESENT",m->info!=0);
    if(m->info&&m->info_size>=sizeof(GINFO)){
        item(index,"WIDTH",m->info->width);item(index,"HEIGHT",m->info->height);item(index,"PIXEL_FORMAT",m->info->format);item(index,"STRIDE",m->info->stride);
        item(index,"FRAMEBUFFER_SIZE",m->framebuffer_size);
        item(index,"M1D_SIZE_ACCEPTED",m->info->width>=640&&m->info->height>=480&&m->info->width<=4096&&m->info->height<=2160);
    }
    if(g->query&&m->max&&m->current<m->max){
        GINFO *info=0;UN size=0;item(index,"QUERY_CURRENT_BEFORE",0);e=g->query(g,m->current,&size,&info);item(index,"QUERY_CURRENT_AFTER",e);
        if(!FAILED(e)&&info&&size>=sizeof(GINFO)){item(index,"QUERY_WIDTH",info->width);item(index,"QUERY_HEIGHT",info->height);}
        if(info){e=st->bs->free_pool(info);item(index,"QUERY_FREE_STATUS",e);}
    }
}
static void browser_owner(void){
    BROWSER *browser=0;note("FORM_BROWSER_LOCATE_BEFORE",0);
    ES e=st->bs->locate_protocol(&browser_guid,0,(void **)&browser);note("FORM_BROWSER_LOCATE_STATUS",e);
    if(FAILED(e)||!browser)return;
    UN address=(UN)browser->send_form;note("SENDFORM_ADDRESS_NOT_CALLED",address);if(!address)return;
    HANDLE *handles=0;UN n=0;note("LOADED_IMAGES_ENUM_BEFORE",0);
    e=st->bs->locate_handles(2,&loaded_guid,0,&n,&handles);note("LOADED_IMAGES_ENUM_STATUS",e);
    if(FAILED(e)||!handles){if(handles)st->bs->free_pool(handles);return;}
    note("LOADED_IMAGES_COUNT",n);if(n>1024){note("LOADED_IMAGES_LIMIT",1024);n=1024;}
    unsigned found=0;
    for(UN i=0;i<n;i++){
        LOADED *image=0;e=st->bs->handle_protocol(handles[i],&loaded_guid,(void **)&image);
        if(FAILED(e)||!image||!image->image_base||image->image_size>0x40000000ULL)continue;
        UN base=(UN)image->image_base;
        if(address<base||address-base>=image->image_size)continue;
        note("BROWSER_OWNER_BASE",base);note("BROWSER_OWNER_SIZE",image->image_size);note("BROWSER_SENDFORM_RVA",address-base);
        /* Never follow an unowned function pointer or scan outside the image. */
        if(image->image_size-(address-base)>=64)note("BROWSER_FIRST64_CRC32",probe_crc32((const void *)address,64));
        found=1;break;
    }
    note("BROWSER_OWNER_FOUND",found);e=st->bs->free_pool(handles);note("LOADED_IMAGES_FREE_STATUS",e);
}
static void inspect(void){
    if(inspected){text("D already completed. R=text capture; C=QR capture.\r\n");return;}inspected=1;
    note("CONSOLE_IN_HANDLE",(UN)st->in_handle);note("CONSOLE_OUT_HANDLE",(UN)st->out_handle);
    note("TEXT_OUT_PRESENT",st->out!=0);
    if(st->out&&st->out->mode){
        note("TEXT_MODE",(UN)(int64_t)st->out->mode->mode);note("TEXT_MAX_MODE",(UN)(int64_t)st->out->mode->max);
        if(st->out->query_mode&&st->out->mode->mode>=0){UN c=0,r=0;note("TEXT_QUERY_BEFORE",0);
            ES e=st->out->query_mode(st->out,(UN)st->out->mode->mode,&c,&r);note("TEXT_QUERY_AFTER",e);
            if(!FAILED(e)){note("TEXT_COLUMNS",c);note("TEXT_ROWS",r);}}
    }
    GOP *direct=0,*located=0;
    note("CONOUT_GOP_BEFORE",0);
    ES e=st->bs->handle_protocol(st->out_handle,&gop_guid,(void **)&direct);note("CONOUT_GOP_STATUS",e);note("CONOUT_GOP_PTR",(UN)direct);
    note("LOCATE_GOP_BEFORE",0);e=st->bs->locate_protocol(&gop_guid,0,(void **)&located);note("LOCATE_GOP_STATUS",e);note("LOCATE_GOP_PTR",(UN)located);
    HANDLE *handles=0;UN n=0;note("GOP_ENUM_BEFORE",0);
    e=st->bs->locate_handles(2,&gop_guid,0,&n,&handles);note("GOP_ENUM_STATUS",e);
    if(!FAILED(e)&&handles){
        note("GOP_HANDLE_COUNT",n);if(n>8){note("GOP_INSPECT_LIMIT",8);n=8;}
        for(UN i=0;i<n;i++)inspect_gop((unsigned)i,handles[i]);
    }
    if(handles){e=st->bs->free_pool(handles);note("GOP_HANDLES_FREE_STATUS",e);}
    browser_owner();note("DISPLAY_INVENTORY_COMPLETE",0);
    text("D complete: INVENTORY_CAPTURED. R=text capture, C=QR capture.\r\n");
}
static ES capture(int force_text){
    unsigned n=0;const char *head="HERO-HII-M1E-KVM\r\nRUN=";while(*head)snapshot[n++]=*head++;
    for(unsigned i=0;i<16;i++)snapshot[n++]=run_id[i];snapshot[n++]='\r';snapshot[n++]='\n';
    for(unsigned i=0;i<count;i++)for(const char *p=lines[i];*p;p++)snapshot[n++]=*p;
    const char *tail="SNAPSHOT_END\r\n";while(*tail)snapshot[n++]=*tail++;snapshot[n]=0;
    return kvm_present(st,snapshot,n,(unsigned)overflow|(force_text?2U:0U));
}
static ES EA run(HANDLE,ST *);
static ES (EA * volatile entry_target)(HANDLE,ST *)=run;
ES EA efi_main(HANDLE image,ST *system){return entry_target(image,system);}
static ES EA run(HANDLE image,ST *system){
    (void)image;st=system;if(!st||st->hdr.sig!=0x5453595320494249ULL||!st->bs)return ERR(2);
    ES e=ERR(14);if(st->out&&st->out->out)e=st->out->out(st->out,W("\r\nHERO M1e - DISPLAY INVENTORY / NO SENDFORM\r\n"));
    if(FAILED(e))output_error=e;
    uint32_t lo,hi;__asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));uint64_t token=((uint64_t)hi<<32)|lo;
    for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
    note("FIRST_TEXT",e);if(st->out&&st->out->set_attribute)st->out->set_attribute(st->out,15);
    note("WATCHDOG_BEFORE",0);e=st->bs->set_watchdog(0,0,0,0);note("WATCHDOG_AFTER",e);
    text("First pass: D then R. This app does not call SendForm.\r\n");
    text("Values include counts, addresses and status codes. Nonzero is not always error.\r\n");
    ES result=0;int key_error=0;
    for(;;){
        if(FAILED(output_error)){result=output_error;break;}
        text("\r\nD=inspect display; R=text capture; C=QR capture; Q/Esc=finish.\r\n");
        KEY key={0};e=key_read(&key);if(FAILED(e)){note("KEY_ERROR",e);result=e;key_error=1;break;}
        unsigned k=upper(key.unicode);if(k=='Q'||key.scan==0x17)break;
        if(k=='D')inspect();else if(k=='R'||k=='C'){
            e=capture(k=='R');if(FAILED(e)){note("CAPTURE_RETURN",e);result=e;}
        }else if(k=='P'||k=='S')text("Display inventory only. No forms are registered or opened.\r\n");
    }
    note("SESSION_END",result);
    if(!key_error&&!FAILED(output_error))for(;;){
        text("END OF SESSION: R=text, C=QR, Enter/Esc/Q=return to firmware.\r\n");
        KEY key={0};e=key_read(&key);if(FAILED(e)){result=e;key_error=1;break;}
        unsigned k=upper(key.unicode);if(k=='R'||k=='C'){e=capture(k=='R');if(FAILED(e)){result=e;break;}}
        else if(k=='Q'||key.scan==0x17||key.unicode=='\r')break;
    }
    if(key_error||FAILED(output_error))st->bs->stall(5000000);
    text("M1e finished; returning to firmware.\r\n");return FAILED(output_error)?output_error:result;
}
