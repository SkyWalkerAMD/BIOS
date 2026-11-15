/* USB no-flash entry point. Opens the real firmware HII browser, then saves
 * the driver's RAM audit to a new file on this same marked USB filesystem.
 * It never installs a boot option, flashes firmware or writes another disk.
 */
#include "m1.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static void say(const char *s){C16 w[192];while(*s){unsigned i=0;while(*s && i<191)w[i++]=(uint8_t)*s++;w[i]=0;gST->out->out(gST->out,w);}}
static void status(const char *s,ES e){char b[19]="0x";for(unsigned i=0;i<16;i++)b[i+2]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[18]=0;say(s);say(b);say("\r\n");}
static void wait_key(void){KEY k;while(gST->in->read(gST->in,&k)==ERR(6)){UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))break;}}
ES EA efi_main(HANDLE image,ST *system){
    gST=system;ES e=ERR(7);LOADED *loaded=0;FS *fs=0;FILEP *root=0,*file=0,*log=0;
    HANDLE child=0;void *buffer=0;M1_API *api=0;int owns=0;
    gST->bs->set_watchdog(0,0,0,0);
    say("HERO IPMI Setup M1 - USB menu test (no flashing)\r\n");
    if(FAILED(e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))||!loaded)goto done;
    if(FAILED(e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs))||!fs)goto done;
    if(FAILED(e=fs->open_volume(fs,&root))||!root)goto done;
    if(FAILED(e=root->open(root,&file,W("\\HERO-IPMI-M1.TAG"),1,0))||!file)goto done;
    char marker[32]={0};UN n=sizeof(marker);e=file->read(file,&n,marker);file->close(file);file=0;
    if(FAILED(e)||n!=20||!eq(marker,"HERO-IPMI-SETUP-M1\r\n",20)){e=ERR(15);say("USB marker missing or wrong.\r\n");goto done;}
    C16 logname[]=L"\\HERO-M1-000.TXT";
    for(unsigned i=0;i<1000;i++){
        logname[9]=(C16)('0'+i/100);logname[10]=(C16)('0'+i/10%10);logname[11]=(C16)('0'+i%10);
        e=root->open(root,&file,logname,1,0);
        if(!FAILED(e)){file->close(file);file=0;continue;}
        if(e!=ERR(14))goto done;
        e=root->open(root,&log,logname,0x8000000000000003ULL,0);break;
    }
    if(FAILED(e)||!log){if(!FAILED(e))e=ERR(9);say("Cannot create a new log file.\r\n");goto done;}
    const char *intro="HERO-M1 USB session started. Final audit is written when the menu exits.\r\n";
    n=0;while(intro[n])n++;UN wrote=n;
    e=log->write(log,&wrote,(void *)intro);
    if(FAILED(e))goto done;if(wrote!=n){e=ERR(7);goto done;}if(FAILED(e=log->flush(log)))goto done;
    e=gST->bs->locate_protocol(&api_guid,0,(void **)&api);
    if(e==ERR(14)){
        e=root->open(root,&file,W("\\EFI\\HERO\\HeroIpmiM1.efi"),1,0);if(FAILED(e)||!file)goto done;
        e=gST->bs->allocate_pool(4,1048576,&buffer);if(FAILED(e)||!buffer)goto done;
        n=1048576;e=file->read(file,&n,buffer);file->close(file);file=0;
        if(FAILED(e)||n<512||n==1048576){e=ERR(4);goto done;}
        e=gST->bs->load_image(0,image,0,buffer,n,&child);if(FAILED(e))goto done;
        owns=1;e=gST->bs->start_image(child,0,0);if(FAILED(e))goto done;
        e=gST->bs->locate_protocol(&api_guid,0,(void **)&api);
    }
    if(FAILED(e)||!api||api->version!=1||api->size!=sizeof(M1_API)){e=ERR(3);goto done;}
    say("Opening firmware HII browser. Save configuration before Initialize now.\r\n");
    say("This USB load is after ReadyToBoot; it does not establish automatic boot loading.\r\n");
    e=api->show();status("Browser return: ",e);
    const char *data=api->log(&n);wrote=n;
    ES saved=(!data || n>131072)?ERR(4):log->write(log,&wrote,(void *)data);
    if(!FAILED(saved) && wrote!=n)saved=ERR(7);
    if(!FAILED(saved))saved=log->flush(log);
    if(FAILED(saved)){status("Audit save failed: ",saved);e=saved;}
    else {say("Audit saved: ");gST->out->out(gST->out,logname);say("\r\n");}
done:
    if(file)file->close(file);if(log)log->close(log);if(root)root->close(root);if(buffer)gST->bs->free_pool(buffer);
    if(owns && child){ES unloaded=gST->bs->unload_image(child);status("Driver unload: ",unloaded);}
    status("Session result: ",e);say("Press any key to return to firmware.\r\n");wait_key();return e;
}
