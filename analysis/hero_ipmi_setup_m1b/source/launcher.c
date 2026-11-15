/* M1b launcher repair. Paired M1a driver is byte-for-byte unchanged.
 * First firmware call is text output. L gates filesystem access, D gates
 * driver loading, and S/H/R gate its exported operations. No automatic mode
 * switch, HII registration, BMC access or variable access at startup.
 */
#include "m1.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID legacy_guid={0x40823e46,0x8089,0x43f6,{0xaa,0x64,0xa6,0x33,0x42,0x12,0xbb,0x12}};
static HANDLE own_image,boot_device,child;
static FILEP *root,*journal;
static M1_API *api;
static ES journal_error,operation_error;
static int log_attempted,log_ready,driver_attempted,sink_busy;
static char early[32768];
static UN early_len;
static C16 logname[]=L"\\HERO-M1B-000.TXT";

static ES say(const char *s){
    if(!gST->out || !gST->out->out)return ERR(14);
    ES e=0;
    while(*s){C16 w[192];unsigned i=0;while(*s && i<191)w[i++]=(uint8_t)*s++;w[i]=0;
        e=gST->out->out(gST->out,w);if(FAILED(e))break;}
    return e;
}
static void hex(char b[19],ES e){b[0]='0';b[1]='x';for(unsigned i=0;i<16;i++)b[i+2]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[18]=0;}
static ES remember(const char *data,UN n){
    if(n>sizeof(early)-early_len)return journal_error=ERR(9);
    memcpy(early+early_len,data,n);early_len+=n;return 0;
}
/* Main-loop records run at application TPL. Do not raise TPL just to write
 * the first log. File errors latch and prevent driver operations. */
static ES write_log(const char *data,UN n){
    if(FAILED(journal_error))return journal_error;
    if(!journal || !journal->write || !journal->flush)return journal_error=ERR(14);
    if(sink_busy)return journal_error=ERR(20);
    sink_busy=1;UN wrote=n;ES e=journal->write(journal,&wrote,(void *)data);
    if(!FAILED(e) && wrote!=n)e=ERR(7);
    if(!FAILED(e))e=journal->flush(journal);
    sink_busy=0;
    if(FAILED(e)){journal_error=e;say("USB write/flush failed. Note the last stage; press Q.\r\n");}
    return e;
}
/* Keep the M1a scoped driver trace contract: synchronous checkpoints remain
 * durable before the driver proceeds. Only this explicit D/S/H/R path probes
 * TPL; no such call occurs during initial display or L. */
static ES EA emit(void *context,const char *data,UN n){
    if(context!=&journal || !log_ready || !data || n>131072)return ERR(2);
    if(FAILED(journal_error))return journal_error;
    if(sink_busy)return journal_error=ERR(20);
    UN previous=gST->bs->raise_tpl(31);gST->bs->restore_tpl(previous);
    if(previous>4)return journal_error=ERR(3);
    return write_log(data,n);
}
static TRACE trace={TRACE_MAGIC,1,sizeof(TRACE),emit,&journal};
static ES record(const char *name,ES e){
    char line[192],number[19];hex(number,e);unsigned i=0;
    const char *parts[]={"M1B ",name," status=",number,"\r\n"};
    for(unsigned p=0;p<5;p++)for(const char *s=parts[p];*s && i<sizeof(line)-1;s++)line[i++]=*s;
    line[i]=0;say(line);
    if(FAILED(journal_error))return journal_error;
    return journal?write_log(line,i):remember(line,i);
}
static ES key_read(KEY *key){
    if(!gST->in || !gST->in->read)return ERR(14);
    for(;;){
        ES e=gST->in->read(gST->in,key);if(e!=ERR(6))return e;
        if(!gST->in->wait)return ERR(14);
        UN index=0;e=gST->bs->wait_for_event(1,&gST->in->wait,&index);if(FAILED(e))return e;
    }
}
#define STEP(name,expression) do { \
    e=record(name "_BEFORE",0);if(FAILED(e))goto done; \
    e=(expression);ES logged=record(name "_AFTER",e); \
    if(FAILED(logged)){e=logged;goto done;}if(FAILED(e))goto done; \
} while(0)

static ES start_log(void){
    if(log_attempted){say(log_ready?"Log already ready.\r\n":"L already attempted. Return this result before another boot.\r\n");return journal_error;}
    log_attempted=1;ES e=0;LOADED *loaded=0;FS *fs=0;FILEP *file=0;
    STEP("10_LOADED_IMAGE",gST->bs->handle_protocol(own_image,&loaded_guid,(void **)&loaded));
    if(!loaded || !loaded->device){e=ERR(14);goto done;}boot_device=loaded->device;
    STEP("11_BOOT_FILESYSTEM",gST->bs->handle_protocol(boot_device,&fs_guid,(void **)&fs));
    if(!fs || !fs->open_volume){e=ERR(14);goto done;}
    STEP("12_OPEN_VOLUME",fs->open_volume(fs,&root));
    if(!root || !root->open || !root->close){e=ERR(14);goto done;}
    STEP("13_MARKER_OPEN",root->open(root,&file,W("\\HERO-IPMI-M1B.TAG"),1,0));
    if(!file || !file->read || !file->close){e=ERR(14);goto done;}
    char marker[32]={0};UN n=sizeof(marker);
    STEP("14_MARKER_READ",file->read(file,&n,marker));
    STEP("15_MARKER_CLOSE",(e=file->close(file),file=0,e));
    if(n!=21 || !eq(marker,"HERO-IPMI-SETUP-M1B\r\n",21)){e=ERR(15);goto done;}
    e=record("16_FIND_UNUSED_LOG_NAME",0);if(FAILED(e))goto done;
    for(unsigned i=0;i<1000;i++){
        logname[10]=(C16)('0'+i/100);logname[11]=(C16)('0'+i/10%10);logname[12]=(C16)('0'+i%10);
        e=root->open(root,&file,logname,1,0);
        if(!FAILED(e)){
            if(!file || !file->close){e=ERR(14);goto done;}
            e=file->close(file);file=0;if(FAILED(e))goto done;continue;
        }
        if(e!=ERR(14))goto done;
        e=record("17_CREATE_LOG_BEFORE",0);if(FAILED(e))goto done;
        e=root->open(root,&journal,logname,0x8000000000000003ULL,0);
        if(FAILED(e)||!journal){if(!FAILED(e))e=ERR(14);goto done;}
        say("M1B 18_INITIAL_LOG_WRITE_BEFORE\r\n");
        e=write_log(early,early_len);if(FAILED(e))goto done;
        e=record("19_INITIAL_LOG_COMMITTED",0);if(FAILED(e))goto done;
        log_ready=1;
        goto done;
    }
    e=ERR(9);
done:
    if(file && file->close){ES c=file->close(file);if(FAILED(c)&&!FAILED(e))e=c;}
    {ES logged=record("LOG_TEST_RETURN",e);if(FAILED(logged))e=logged;}
    if(FAILED(e)){journal_error=e;log_ready=0;say("L failed. Check the last stage and HERO-IPMI-M1B.TAG at USB root.\r\n");}
    else {say("L complete: USB_LOG_READY\r\nLog: ");
        if(gST->out && gST->out->out)gST->out->out(gST->out,logname);say("\r\n");}
    return e;
}

static ES file_path(void **out){
    uint8_t *base=0;*out=0;ES e=gST->bs->handle_protocol(boot_device,&dp_guid,(void **)&base);
    if(FAILED(e)||!base)return FAILED(e)?e:ERR(14);
    UN n=0;int ended=0;
    while(n<=4096-4){
        uint16_t len=u16(base+n+2);if(len<4 || len>4096-n)return ERR(33);
        if(base[n]==0x7f){if(base[n+1]!=0xff || len!=4)return ERR(3);ended=1;break;}n+=len;
    }
    if(!ended)return ERR(33);
    static const C16 path[]=L"\\EFI\\HERO\\HeroIpmiM1a.efi";
    UN tail=4+sizeof(path),total=n+tail+4;uint8_t *p=0;
    e=gST->bs->allocate_pool(4,total,(void **)&p);if(FAILED(e)||!p)return FAILED(e)?e:ERR(9);
    memcpy(p,base,n);p[n]=4;p[n+1]=4;p[n+2]=(uint8_t)tail;p[n+3]=(uint8_t)(tail>>8);
    memcpy(p+n+4,path,sizeof(path));p[n+tail]=0x7f;p[n+tail+1]=0xff;p[n+tail+2]=4;p[n+tail+3]=0;
    *out=p;return 0;
}
/* A failed StartImage can already have freed its image. Reacquire the loaded
 * image protocol instead of dereferencing the cached pointer or blindly
 * calling UnloadImage. Security-rejected but loaded images are also owned. */
static ES release_child(void){
    if(!child)return 0;
    LOADED *live=0;record("CHILD_LIVENESS_BEFORE",0);
    ES e=gST->bs->handle_protocol(child,&loaded_guid,(void **)&live);record("CHILD_LIVENESS_AFTER",e);
    if(e==ERR(2)||e==ERR(3)||e==ERR(14)){child=0;api=0;return 0;}
    if(FAILED(e)||!live)return FAILED(e)?e:ERR(14);
    if(live->options==&trace){live->options_size=0;live->options=0;}
    record("UNLOAD_IMAGE_BEFORE",0);e=gST->bs->unload_image(child);record("UNLOAD_IMAGE_AFTER",e);
    if(!FAILED(e)){child=0;api=0;}return e;
}
static ES load_driver(void){
    if(!log_ready || FAILED(journal_error)){say("Press L successfully before D.\r\n");return ERR(15);}
    if(driver_attempted){say(api?"Driver already loaded.\r\n":"D already attempted. Press Q and return the log.\r\n");return api?0:ERR(20);}
    driver_attempted=1;ES e=0;FILEP *file=0;void *buffer=0,*path=0,*found=0;LOADED *loaded=0;
    STEP("CHECK_LEGACY",(e=gST->bs->locate_protocol(&legacy_guid,0,&found),e==ERR(14)?0:FAILED(e)?e:ERR(20)));
    STEP("CHECK_M1A",(e=gST->bs->locate_protocol(&api_guid,0,&found),e==ERR(14)?0:FAILED(e)?e:ERR(20)));
    STEP("OPEN_DRIVER",root->open(root,&file,W("\\EFI\\HERO\\HeroIpmiM1a.efi"),1,0));
    if(!file || !file->read || !file->close){e=ERR(14);goto done;}
    STEP("ALLOCATE_DRIVER",gST->bs->allocate_pool(4,1048576,&buffer));
    if(!buffer){e=ERR(9);goto done;}
    UN n=1048576;STEP("READ_DRIVER",file->read(file,&n,buffer));
    STEP("CLOSE_DRIVER",(e=file->close(file),file=0,e));
    if(n<512 || n>=1048576){e=ERR(4);goto done;}
    STEP("DRIVER_DEVICE_PATH",file_path(&path));
    STEP("LOAD_IMAGE",gST->bs->load_image(0,own_image,path,buffer,n,&child));
    if(!child){e=ERR(14);goto done;}
    STEP("CHILD_LOADED_PROTOCOL",gST->bs->handle_protocol(child,&loaded_guid,(void **)&loaded));
    if(!loaded){e=ERR(14);goto done;}
    loaded->options_size=sizeof(trace);loaded->options=&trace;
    STEP("START_IMAGE",gST->bs->start_image(child,0,0));
    STEP("LOCATE_M1A_API",gST->bs->locate_protocol(&api_guid,0,(void **)&api));
    if(!api || api->version!=2 || api->size!=sizeof(M1_API) || !api->show || !api->query || !api->log){api=0;e=ERR(3);goto done;}
done:
    if(file && file->close){ES c=file->close(file);if(FAILED(c)&&!FAILED(e))e=c;}
    if(FAILED(e)){api=0;ES c=release_child();if(FAILED(c))record("DRIVER_CLEANUP_FAILED",c);operation_error=e;}
    if(buffer)gST->bs->free_pool(buffer);if(path)gST->bs->free_pool(path);
    {ES logged=record("DRIVER_LOAD_RETURN",e);if(FAILED(logged))e=logged;}
    if(!FAILED(e))say("D complete: DRIVER_READY. S opens the simple test page.\r\n");
    else operation_error=e;
    return e;
}

static void print_result(void){
    UN n=0;const char *data=api->log(&n);if(!data || n>131072)return;
    UN last=n;
    for(UN i=0;i+8<=n;i++)if(eq(data+i,"RESULT: ",8))last=i;
    if(last==n)return;
    char b[192];UN i=0;
    while(i<sizeof(b)-1 && i<n-last && data[last+i] && data[last+i]!='\r' && data[last+i]!='\n'){b[i]=data[last+i];i++;}
    b[i]=0;say(b);say("\r\n");
}
static ES driver_operation(unsigned k){
    if(!api || FAILED(operation_error)||FAILED(journal_error)){say("D must complete successfully before S/H/R. Stop after an error.\r\n");return ERR(15);}
    ES e=record(k=='S'?"KEY_S_MINIMAL":k=='H'?"KEY_H_FULL":"KEY_R_READ_ONLY",0);
    if(FAILED(e))return e;
    say(k=='R'?"Reading BMC status...\r\n":"Opening selected page. Esc returns here.\r\n");
    e=k=='R'?api->query(&trace):api->show(k=='S',&trace);
    ES logged=record("EXPLICIT_OPERATION_RETURN",e);if(FAILED(logged))e=logged;
    if(k=='R' && !FAILED(e))print_result();
    if(FAILED(e)){operation_error=e;say("Operation failed. Press Q and return the log.\r\n");}
    return e;
}

static GUID gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
typedef struct {uint32_t version,width,height,format,masks[4],stride;} GOPINFO;
typedef struct {uint32_t max,mode;GOPINFO *info;UN info_size;uint64_t framebuffer;UN framebuffer_size;} GOPMODE;
typedef struct {uint8_t blue,green,red,reserved;} PIXEL;
typedef struct GOP GOP;
struct GOP {void *query,*set_mode;ES (EA *blt)(GOP *,PIXEL *,uint32_t,UN,UN,UN,UN,UN,UN,UN);GOPMODE *mode;};
OFF(GOP,blt,16);OFF(GOP,mode,24);OFF(GOPMODE,info,8);
_Static_assert(sizeof(GOPINFO)==36 && sizeof(GOPMODE)==40,"GOP ABI");
static ES graphics_test(void){
    static int attempted;if(attempted)return ERR(20);attempted=1;
    HANDLE *handles=0;UN count=0;record("GOP_HANDLES_BEFORE",0);
    ES e=gST->bs->locate_handles(2,&gop_guid,0,&count,&handles);record("GOP_HANDLES_AFTER",e);
    if(FAILED(e)||!handles)return FAILED(e)?e:ERR(14);
    unsigned outputs=0;
    for(UN i=0;i<count && i<8;i++){
        GOP *gop=0;e=gST->bs->handle_protocol(handles[i],&gop_guid,(void **)&gop);
        if(FAILED(e)||!gop||!gop->blt||!gop->mode||!gop->mode->info||gop->mode->info_size<sizeof(GOPINFO))continue;
        GOPINFO *info=gop->mode->info;
        if(!info->width||!info->height||info->width>32768||info->height>32768)continue;
        UN w=info->width/12,h=info->height/8;if(w>64)w=64;if(h>64)h=64;if(!w||!h)continue;
        const PIXEL colors[3]={{0,0,255,0},{0,255,0,0},{255,0,0,0}};
        unsigned drawn=0;
        for(unsigned c=0;c<3;c++){
            record("GOP_BLT_BEFORE",c);
            e=gop->blt(gop,(PIXEL *)&colors[c],0,0,0,info->width-3*w+c*w,info->height/4,w,h,0);
            record("GOP_BLT_AFTER",e);if(FAILED(e))break;drawn++;
        }
        if(drawn==3)outputs++;
    }
    ES freed=gST->bs->free_pool(handles);record("GOP_HANDLES_FREE",freed);
    return FAILED(freed)?freed:outputs?0:ERR(14);
}
static ES EA run(HANDLE image,ST *system);
/* Conventional PE relocation retained in the final launcher. */
static ES (EA * volatile entry_target)(HANDLE,ST *)=run;
ES EA efi_main(HANDLE image,ST *system){return entry_target(image,system);}
static ES EA run(HANDLE image,ST *system){
    gST=system;own_image=image;
    if(!gST||gST->hdr.sig!=0x5453595320494249ULL||!gST->bs)return ERR(2);
    ES e=ERR(14);
    if(gST->out && gST->out->out)e=gST->out->out(gST->out,W("\r\nHERO IPMI Setup M1b - ENTRY REACHED\r\n"));
    record("FIRST_OUTPUT",e);
    if(gST->out && gST->out->set_attribute){
        record("TEXT_ATTRIBUTE_BEFORE",0);e=gST->out->set_attribute(gST->out,0x0f);record("TEXT_ATTRIBUTE_AFTER",e);
    }
    say("HERO IPMI Setup M1b - ENTRY REACHED\r\n");
    record("WATCHDOG_BEFORE",0);e=gST->bs->set_watchdog(0,0,0,0);record("WATCHDOG_AFTER",e);
    record("WAITING_FOR_KEY_NO_FILESYSTEM",0);
    for(;;){
        say("\r\nL = USB log; D = load driver; S = simple page\r\nH = settings; R = read status; G = RGB blocks; Q/Esc = exit\r\nStart with L. No log before L is normal.\r\n");
        KEY key={0};e=key_read(&key);
        if(FAILED(e)){record("KEY_INPUT_FAILED",e);say("Returning to firmware in 5 seconds.\r\n");gST->bs->stall(5000000);break;}
        unsigned k=key.unicode;if(k>='a' && k<='z')k-=32;
        if(k=='Q'||key.scan==0x17){e=0;break;}
        if(k=='L')start_log();
        else if(k=='D')load_driver();
        else if(k=='S'||k=='H'||k=='R')driver_operation(k);
        else if(k=='G'){ES g=graphics_test();record("GRAPHICS_TEST_RETURN",g);}
    }
    record("SESSION_END_BEFORE_CLEANUP",e);
    ES c=release_child();if(FAILED(c)&&!FAILED(e))e=c;
    if(FAILED(operation_error)&&!FAILED(e))e=operation_error;
    if(FAILED(journal_error))e=journal_error;
    record("SESSION_END",e);
    if(journal && journal->close){say("Closing log...\r\n");c=journal->close(journal);journal=0;if(FAILED(c)&&!FAILED(e))e=c;}
    if(root && root->close){say("Closing USB volume...\r\n");c=root->close(root);root=0;if(FAILED(c)&&!FAILED(e))e=c;}
    /* SESSION_END itself may fail to flush. Preserve that failure too. */
    if(FAILED(journal_error))e=journal_error;
    say("M1b finished; returning to firmware.\r\n");return e;
}
