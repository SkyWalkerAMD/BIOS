/* S0 boot/display/filesystem isolation. No IPMI, PCI, SMBIOS, HII, child
 * images or variable access. Startup does not touch any filesystem.
 * First firmware service: OutputString. File logging requires explicit L.
 */
#include "efi_min.h"
#define W(s) ((C16 *)L##s)
static ST *st;
static HANDLE own_image;
static FILEP *root,*logfile;
static ES file_error;
static int log_attempted,graphics_attempted;
static char audit[32768];
static UN used,saved;
static C16 logname[]=L"\\HERO-S0-000.TXT";
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static int equal(const void *a,const void *b,UN n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static void remember(const char *s){while(*s && used<sizeof(audit)-1)audit[used++]=*s++;audit[used]=0;}
static void number_hex(ES n,char b[19]){b[0]='0';b[1]='x';for(unsigned i=0;i<16;i++)b[i+2]="0123456789ABCDEF"[(n>>((15-i)*4))&15];b[18]=0;}
static ES text(const char *s){
    if(!st->out || !st->out->out)return ERR(14);
    ES e=0;while(*s){C16 w[160];unsigned i=0;while(*s && i<159)w[i++]=(uint8_t)*s++;w[i]=0;e=st->out->out(st->out,w);if(FAILED(e))break;}return e;
}
static ES flush_log(void){
    if(FAILED(file_error))return file_error;
    if(!logfile || saved==used)return 0;
    UN n=used-saved,wrote=n;ES e=logfile->write(logfile,&wrote,audit+saved);
    if(!FAILED(e) && wrote!=n)e=ERR(7);
    if(!FAILED(e))e=logfile->flush(logfile);
    if(FAILED(e)){file_error=e;text("S0 LOG WRITE/FLUSH FAILED. Keep the last visible stage.\r\n");}
    else saved=used;
    return e;
}
static ES stage(const char *name,ES status){
    char h[19];number_hex(status,h);
    remember("S0 ");remember(name);remember(" status=");remember(h);remember("\r\n");
    text("S0 ");text(name);text(" status=");text(h);text("\r\n");
    return flush_log();
}
static ES EA run(HANDLE,ST *);
/* A used function pointer supplies a real PE relocation, just as B2c has. */
static ES (EA * volatile entry_target)(HANDLE,ST *)=run;
ES EA efi_main(HANDLE image,ST *system){return entry_target(image,system);}
static ES get_key(KEY *k){
    if(!st->in || !st->in->read)return ERR(14);
    for(;;){
        ES e=st->in->read(st->in,k);if(e!=ERR(6))return e;
        if(!st->in->wait)return ERR(14);UN index=0;
        e=st->bs->wait_for_event(1,&st->in->wait,&index);if(FAILED(e))return e;
    }
}
static ES start_log(void){
    if(log_attempted){stage("LOG_ALREADY_ATTEMPTED",file_error);return file_error;}
    log_attempted=1;LOADED *loaded=0;FS *fs=0;FILEP *file=0;ES e;
    stage("10_LOADED_IMAGE_BEFORE",0);
    e=st->bs->handle_protocol(own_image,&loaded_guid,(void **)&loaded);stage("11_LOADED_IMAGE_AFTER",e);
    if(FAILED(e)||!loaded){if(!FAILED(e))e=ERR(14);goto done;}
    stage("12_BOOT_FILESYSTEM_BEFORE",0);
    e=st->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs);stage("13_BOOT_FILESYSTEM_AFTER",e);
    if(FAILED(e)||!fs){if(!FAILED(e))e=ERR(14);goto done;}
    stage("14_OPEN_VOLUME_BEFORE",0);
    e=fs->open_volume(fs,&root);stage("15_OPEN_VOLUME_AFTER",e);
    if(FAILED(e)||!root){if(!FAILED(e))e=ERR(14);goto done;}
    stage("16_MARKER_OPEN_BEFORE",0);
    e=root->open(root,&file,W("\\HERO-BOOT-S0.TAG"),1,0);stage("17_MARKER_OPEN_AFTER",e);
    if(FAILED(e)||!file){if(!FAILED(e))e=ERR(14);text("Copy HERO-BOOT-S0.TAG to the root of this boot USB.\r\n");goto done;}
    char marker[32]={0};UN n=sizeof(marker);
    stage("18_MARKER_READ_BEFORE",0);
    e=file->read(file,&n,marker);stage("19_MARKER_READ_AFTER",e);
    ES closed=file->close(file);file=0;stage("20_MARKER_CLOSE",closed);
    if(FAILED(e))goto done;if(FAILED(closed)){e=closed;goto done;}
    if(n!=14 || !equal(marker,"HERO-BOOT-S0\r\n",14)){e=ERR(15);stage("MARKER_CONTENT_WRONG",e);goto done;}
    for(unsigned i=0;i<1000;i++){
        logname[9]=(C16)('0'+i/100);logname[10]=(C16)('0'+i/10%10);logname[11]=(C16)('0'+i%10);
        stage("21_CHECK_LOG_NAME_BEFORE",0);
        e=root->open(root,&file,logname,1,0);
        if(!FAILED(e)){
            if(!file){e=ERR(14);goto done;}
            e=file->close(file);file=0;if(FAILED(e))goto done;continue;
        }
        if(e!=ERR(14))goto done;
        stage("22_CREATE_LOG_BEFORE",0);
        e=root->open(root,&logfile,logname,0x8000000000000003ULL,0);
        if(FAILED(e)||!logfile){if(!FAILED(e))e=ERR(14);goto done;}
        /* stage appends the result and flushes all earlier RAM stages. */
        e=stage("23_CREATE_LOG_AFTER",0);if(FAILED(e))goto done;
        e=stage("24_USB_LOG_READY",0);
        if(!FAILED(e)){
            text("Log file: ");if(st->out && st->out->out)st->out->out(st->out,logname);text("\r\n");
        }
        goto done;
    }
    e=ERR(9);stage("ALL_LOG_NAMES_OCCUPIED",e);
done:
    if(file)file->close(file);
    if(FAILED(e))file_error=e;
    stage("LOG_TEST_RETURN",e);return e;
}
typedef struct {uint32_t version,width,height,format,masks[4],stride;} GOPINFO;
typedef struct {uint32_t max,mode;GOPINFO *info;UN info_size;uint64_t framebuffer;UN framebuffer_size;} GOPMODE;
typedef struct {uint8_t blue,green,red,reserved;} PIXEL;
typedef struct GOP GOP;
struct GOP {void *query,*set_mode;ES (EA *blt)(GOP *,PIXEL *,uint32_t,UN,UN,UN,UN,UN,UN,UN);GOPMODE *mode;};
OFF(GOP,blt,16);OFF(GOP,mode,24);OFF(GOPMODE,info,8);OFF(GOPMODE,info_size,16);
_Static_assert(sizeof(GOPINFO)==36 && sizeof(GOPMODE)==40,"GOP ABI");
static ES graphics_test(void){
    if(graphics_attempted)return ERR(20);graphics_attempted=1;
    HANDLE *handles=0;UN count=0;ES e=stage("30_GOP_HANDLES_BEFORE",0);if(FAILED(e))return e;
    e=st->bs->locate_handles(2,&gop_guid,0,&count,&handles);stage("31_GOP_HANDLES_AFTER",e);
    if(FAILED(e)||!handles)return FAILED(e)?e:ERR(14);
    unsigned painted=0;ES first_error=0;
    for(UN i=0;i<count && i<8;i++){
        GOP *gop=0;e=stage("32_GOP_PROTOCOL_BEFORE",i);if(FAILED(e))break;
        e=st->bs->handle_protocol(handles[i],&gop_guid,(void **)&gop);stage("33_GOP_PROTOCOL_AFTER",e);
        if(FAILED(e)){if(!first_error)first_error=e;continue;}
        if(!gop || !gop->blt || !gop->mode || !gop->mode->info || gop->mode->info_size<sizeof(GOPINFO))continue;
        GOPINFO *info=gop->mode->info;
        if(!info->width || !info->height || info->width>32768 || info->height>32768)continue;
        UN w=info->width/12,h=info->height/8;if(w>64)w=64;if(h>64)h=64;
        if(!w || !h)continue;
        UN left=info->width-3*w,top=info->height/4;
        const PIXEL colors[3]={{0,0,255,0},{0,255,0,0},{255,0,0,0}};
        for(unsigned c=0;c<3;c++){
            e=stage("34_GOP_BLT_BEFORE",c);if(FAILED(e))break;
            e=gop->blt(gop,(PIXEL *)&colors[c],0,0,0,left+c*w,top,w,h,0);
            stage("35_GOP_BLT_AFTER",e);
            if(FAILED(e)){if(!first_error)first_error=e;break;}
            painted++;
        }
        if(FAILED(file_error))break;
    }
    ES freed=st->bs->free_pool(handles);stage("36_GOP_HANDLES_FREE",freed);
    if(FAILED(file_error))return file_error;
    return painted?0:first_error?first_error:ERR(14);
}
static void menu(void){
    text("\r\nL = test USB log; G = draw red/green/blue blocks\r\n");
    text("T = try text mode 0; Q or Esc = exit\r\n");
    text("No IPMI/HII/PCI access. No log before L is normal.\r\n");
}
static ES EA run(HANDLE image,ST *system){
    st=system;own_image=image;
    if(!st || st->hdr.sig!=0x5453595320494249ULL || !st->bs)return ERR(2);
    /* No file, marker, protocol discovery, video mode or watchdog call
     * precedes this first direct text output. */
    ES e=ERR(14);
    if(st->out && st->out->out)e=st->out->out(st->out,W("\r\nHERO BOOT S0 - ENTRY REACHED\r\n"));
    char h[19];number_hex(e,h);remember("S0 FIRST_OUTPUT status=");remember(h);remember("\r\n");
    /* Attribute changes are separate from a graphics/text mode switch. */
    if(st->out && st->out->set_attribute){
        stage("01_TEXT_ATTRIBUTE_BEFORE",0);e=st->out->set_attribute(st->out,0x0f);stage("02_TEXT_ATTRIBUTE_AFTER",e);
    }
    text("HERO BOOT S0 - ENTRY REACHED\r\n");
    stage("03_WATCHDOG_BEFORE",0);
    e=st->bs->set_watchdog(0,0,0,0);stage("04_WATCHDOG_AFTER",e);
    if(FAILED(e))text("Firmware watchdog could not be disabled.\r\n");
    stage("05_WAITING_FOR_KEY_NO_FILESYSTEM",0);
    for(;;){
        menu();KEY key={0};e=get_key(&key);
        if(FAILED(e)){
            stage("KEY_INPUT_FAILED",e);text("Returning to firmware in 5 seconds.\r\n");st->bs->stall(5000000);break;
        }
        unsigned k=key.unicode;if(k>='a' && k<='z')k-=32;
        if(k=='Q' || key.scan==0x17){e=0;break;}
        if(k=='L')start_log();
        else if(k=='G'){e=graphics_test();stage("GRAPHICS_TEST_RETURN",e);}
        else if(k=='T'){
            stage("TEXT_MODE0_BEFORE",0);
            e=st->out && st->out->set_mode?st->out->set_mode(st->out,0):ERR(14);
            stage("TEXT_MODE0_AFTER",e);
        }
        if(FAILED(file_error)){text("USB log test failed. Note the last stage, then press Q.\r\n");}
    }
    stage("SESSION_END",e);
    if(logfile){ES c=logfile->close(logfile);logfile=0;if(FAILED(c)&&!FAILED(e))e=c;stage("LOG_CLOSE",c);}
    if(root){ES c=root->close(root);root=0;if(FAILED(c)&&!FAILED(e))e=c;}
    if(FAILED(file_error))e=file_error;
    return e;
}
