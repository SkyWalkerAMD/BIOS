/* M1a: checkpointed USB launcher. File is created/flushed BEFORE console
 * mode changes, driver loading or any HII call. No firmware/disk flashing. */
#include "m1.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID legacy_guid={0x40823e46,0x8089,0x43f6,{0xaa,0x64,0xa6,0x33,0x42,0x12,0xbb,0x12}};
static FILEP *journal;
static ES journal_error;
static int sink_busy;
static void say(const char *s){
    if(!gST->out || !gST->out->out)return;
    C16 w[192];while(*s){unsigned i=0;while(*s && i<191)w[i++]=(uint8_t)*s++;w[i]=0;gST->out->out(gST->out,w);}
}
/* Keep a real relocation in this application, matching conventional UEFI PE
 * images. M1's PIC-only launcher had no relocation directory. */
static void (* volatile print_console)(const char *)=say;
static void hex(char b[19],ES e){b[0]='0';b[1]='x';for(unsigned i=0;i<16;i++)b[i+2]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[18]=0;}
static void status(const char *s,ES e){char b[19];hex(b,e);say(s);say(b);say("\r\n");}
static ES EA emit(void *context,const char *data,UN n){
    if(context!=&journal || !journal || !data || n>131072)return ERR(2);
    if(FAILED(journal_error))return journal_error;
    if(sink_busy)return journal_error=ERR(20);
    /* Synchronous FAT operations only at application TPL. Never block inside
     * a high-TPL firmware notification while attempting diagnostic logging. */
    UN previous=gST->bs->raise_tpl(31);gST->bs->restore_tpl(previous);
    if(previous>4)return journal_error=ERR(3);
    sink_busy=1;UN wrote=n;ES e=journal->write(journal,&wrote,(void *)data);
    if(!FAILED(e) && wrote!=n)e=ERR(7);
    if(!FAILED(e))e=journal->flush(journal);
    sink_busy=0;journal_error=e;return e;
}
static TRACE trace={TRACE_MAGIC,1,sizeof(TRACE),emit,&journal};
static ES record(const char *name,ES e){
    char line[192],number[19];hex(number,e);unsigned i=0;
    const char *parts[]={"LAUNCHER ",name," status=",number,"\r\n"};
    for(unsigned p=0;p<5;p++)for(const char *s=parts[p];*s && i<sizeof(line)-1;s++)line[i++]=*s;
    line[i]=0;return emit(&journal,line,i);
}
static ES key_read(KEY *key){
    if(!gST->in || !gST->in->read)return ERR(14);
    ES e;while((e=gST->in->read(gST->in,key))==ERR(6)){
        UN index;e=gST->bs->wait_for_event(1,&gST->in->wait,&index);if(FAILED(e))return e;
    }return e;
}
static ES file_path(HANDLE device,void **out){
    uint8_t *base=0;*out=0;ES e=gST->bs->handle_protocol(device,&dp_guid,(void **)&base);
    if(FAILED(e)||!base)return FAILED(e)?e:ERR(14);
    UN n=0;
    while(n<4096){
        uint16_t len=u16(base+n+2);if(len<4 || len>4096-n)return ERR(33);
        if(base[n]==0x7f){if(base[n+1]!=0xff || len!=4)return ERR(3);break;}n+=len;
    }
    if(n>=4096)return ERR(33);
    static const C16 path[]=L"\\EFI\\HERO\\HeroIpmiM1a.efi";
    UN tail=4+sizeof(path),total=n+tail+4;uint8_t *p=0;
    e=gST->bs->allocate_pool(4,total,(void **)&p);if(FAILED(e)||!p)return FAILED(e)?e:ERR(9);
    memcpy(p,base,n);p[n]=4;p[n+1]=4;p[n+2]=(uint8_t)tail;p[n+3]=(uint8_t)(tail>>8);
    memcpy(p+n+4,path,sizeof(path));p[n+tail]=0x7f;p[n+tail+1]=0xff;p[n+tail+2]=4;p[n+tail+3]=0;
    *out=p;return 0;
}
#define STEP(name,expression) do { \
    e=record(name "_BEFORE",0);if(FAILED(e))goto done; \
    e=(expression);ES logged=record(name "_AFTER",e); \
    if(FAILED(logged)){e=logged;goto done;}if(FAILED(e))goto done; \
} while(0)
ES EA efi_main(HANDLE image,ST *system){
    gST=system;if(!gST || !gST->bs)return ERR(2);
    ES e=ERR(7);LOADED *loaded=0,*child_loaded=0;FS *fs=0;FILEP *root=0,*file=0;
    HANDLE child=0;void *buffer=0,*path=0;M1_API *api=0;int owns=0,quit=0,console_saved=0;
    TEXTMODE saved={0};C16 logname[]=L"\\HERO-M1A-000.TXT";
    if(FAILED(e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))||!loaded)goto done;
    if(FAILED(e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs))||!fs)goto done;
    if(FAILED(e=fs->open_volume(fs,&root))||!root)goto done;
    if(FAILED(e=root->open(root,&file,W("\\HERO-IPMI-M1A.TAG"),1,0))||!file)goto done;
    char marker[32]={0};UN n=sizeof(marker);e=file->read(file,&n,marker);file->close(file);file=0;
    if(FAILED(e)||n!=21||!eq(marker,"HERO-IPMI-SETUP-M1A\r\n",21)){e=ERR(15);goto done;}
    for(unsigned i=0;i<1000;i++){
        logname[10]=(C16)('0'+i/100);logname[11]=(C16)('0'+i/10%10);logname[12]=(C16)('0'+i%10);
        e=root->open(root,&file,logname,1,0);
        if(!FAILED(e)){file->close(file);file=0;continue;}if(e!=ERR(14))goto done;
        e=root->open(root,&journal,logname,0x8000000000000003ULL,0);break;
    }
    if(FAILED(e)||!journal){if(!FAILED(e))e=ERR(9);goto done;}
    e=record("M1A_START_LOG_CREATED",0);if(FAILED(e))goto done;
    STEP("DISABLE_WATCHDOG",gST->bs->set_watchdog(0,0,0,0));
    if(gST->out && gST->out->mode){saved=*gST->out->mode;console_saved=1;}
    /* Mode 0 is the UEFI standard 80x25 text mode. Log first, so a display
     * driver hang here remains distinguishable from a LoadImage/HII hang. */
    if(gST->out && gST->out->set_mode){
        e=record("CONSOLE_MODE0_BEFORE",0);if(FAILED(e))goto done;
        e=gST->out->set_mode(gST->out,0);if(FAILED(record("CONSOLE_MODE0_AFTER",e)))goto done;
    }
    if(gST->out && gST->out->set_attribute){
        e=record("CONSOLE_ATTRIBUTE_BEFORE",0);if(FAILED(e))goto done;
        e=gST->out->set_attribute(gST->out,0x0f);if(FAILED(record("CONSOLE_ATTRIBUTE_AFTER",e)))goto done;
    }
    e=record("FIRST_TEXT_BEFORE",0);if(FAILED(e))goto done;
    print_console("HERO IPMI Setup M1a - black-screen diagnostic\r\n");
    say("USB only. Automatic initialization is suppressed.\r\nLog: ");
    if(gST->out && gST->out->out)gST->out->out(gST->out,logname);say("\r\n");
    e=record("TEXT_READY_NO_DRIVER_NO_HII",0);if(FAILED(e))goto done;
    for(;;){
        say("\r\nD = load driver only (no HII/BMC query)\r\nS = simple display test; H = IPMI settings\r\nR = read BMC status; Q/Esc = save and exit\r\n");
        if(api)say("Driver loaded. Start with S, Esc, then H, Esc.\r\n");
        else say("Start with D. S/H/R require D first.\r\n");
        KEY key={0};e=key_read(&key);if(FAILED(e))goto done;
        unsigned k=key.unicode;if(k>='a' && k<='z')k-=32;
        if(k=='Q' || key.scan==0x17){quit=1;e=0;break;}
        if(k=='D'){
            if(api){say("Driver already loaded.\r\n");continue;}
            void *found=0;
            e=gST->bs->locate_protocol(&legacy_guid,0,&found);if(e!=ERR(14)){e=FAILED(e)?e:ERR(20);record("OLD_M1_ALREADY_RESIDENT",e);goto done;}
            e=gST->bs->locate_protocol(&api_guid,0,&found);if(e!=ERR(14)){e=FAILED(e)?e:ERR(20);record("M1A_ALREADY_RESIDENT",e);goto done;}
            STEP("OPEN_DRIVER",root->open(root,&file,W("\\EFI\\HERO\\HeroIpmiM1a.efi"),1,0));
            STEP("ALLOCATE_DRIVER",gST->bs->allocate_pool(4,1048576,&buffer));
            n=1048576;STEP("READ_DRIVER",file->read(file,&n,buffer));file->close(file);file=0;
            if(n<512 || n==1048576){e=ERR(4);goto done;}
            STEP("DRIVER_DEVICE_PATH",file_path(loaded->device,&path));
            /* Record ownership before AFTER logging, including a sink failure. */
            STEP("LOAD_IMAGE",(e=gST->bs->load_image(0,image,path,buffer,n,&child),owns=!FAILED(e),e));
            STEP("CHILD_LOADED_PROTOCOL",gST->bs->handle_protocol(child,&loaded_guid,(void **)&child_loaded));
            if(!child_loaded){e=ERR(14);goto done;}
            child_loaded->options_size=sizeof(trace);child_loaded->options=&trace;
            STEP("START_IMAGE",gST->bs->start_image(child,0,0));
            /* Successful driver entry cleared its LoadOptions and trace sink. */
            STEP("LOCATE_M1A_API",gST->bs->locate_protocol(&api_guid,0,(void **)&api));
            if(!api || api->version!=2 || api->size!=sizeof(M1_API)){e=ERR(3);goto done;}
            say("D complete: driver ready; no HII registration or BMC query.\r\n");
        }else if(k=='S' || k=='H' || k=='R'){
            if(!api){say("Press D first.\r\n");continue;}
            e=record(k=='S'?"KEY_S_MINIMAL":k=='H'?"KEY_H_FULL":"KEY_R_READ_ONLY",0);if(FAILED(e))goto done;
            say(k=='R'?"Reading BMC status...\r\n":"Opening selected page. Esc returns here.\r\n");
            e=k=='R'?api->query(&trace):api->show(k=='S',&trace);
            ES operation=e;
            if(FAILED(record("EXPLICIT_OPERATION_RETURN",operation))){e=journal_error;goto done;}
            /* Restore readable text after firmware browser returns. */
            if(gST->out && gST->out->set_attribute)gST->out->set_attribute(gST->out,0x0f);
            status("Operation returned: ",operation);
            if(k=='R'){
                const char *data=api->log(&n);if(data && n<131072){
                    /* Only print the last result, not thousands of KCS bytes. */
                    const char *last=0;
                    for(UN i=0;i+8<=n;i++)if(eq(data+i,"RESULT: ",8))last=data+i;
                    if(last){char b[192];unsigned i=0;while(i<191 && last[i] && last[i]!='\r' && last[i]!='\n'){b[i]=last[i];i++;}b[i]=0;say(b);say("\r\n");}
                }
            }
            if(FAILED(operation))say("Error logged. Stop here and return the log before another test.\r\n");
        }
    }
done:
    if(FAILED(journal_error))e=journal_error;
    if(journal)record("SESSION_END_BEFORE_CLEANUP",e);
    if(file)file->close(file);
    if(owns && child){
        record("UNLOAD_IMAGE_BEFORE",0);ES unloaded=gST->bs->unload_image(child);record("UNLOAD_IMAGE_AFTER",unloaded);
        status("Driver unload: ",unloaded);if(FAILED(unloaded) && !FAILED(e))e=unloaded;
    }
    if(buffer)gST->bs->free_pool(buffer);if(path)gST->bs->free_pool(path);
    if(journal){record("SESSION_END",e);ES closed=journal->close(journal);journal=0;if(FAILED(closed)&&!FAILED(e))e=closed;}
    if(root)root->close(root);
    status("M1a session result: ",e);
    if(!quit){say("Press any key to return to firmware.\r\n");KEY key;key_read(&key);}
    if(console_saved && gST->out){
        if(saved.mode>=0 && saved.mode<saved.max)gST->out->set_mode(gST->out,(UN)saved.mode);
        gST->out->set_attribute(gST->out,(UN)(saved.attribute&0x7f));
        gST->out->enable_cursor(gST->out,saved.cursor);
    }
    return e;
}
