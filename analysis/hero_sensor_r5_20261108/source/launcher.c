/* Text control of the same R2 driver embedded in the review CAP.
 * ISO/USB loads always set explicit MANUAL_ONLY options before StartImage.
 * File logs use only the marked boot volume, opened by L. No HII or SendForm.
 */
#include "r2.h"
#include "kvm.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static R2_API *service;
static R3_API *service3;
static FILEP *root,*file_log;
static char snapshot[131072],run_id[17];
static UN snapshot_len;
static unsigned snapshot_bad;
static void say(const char *s){
 C16 w[160];while(*s){unsigned i=0;while(*s&&i<159)w[i++]=(uint8_t)*s++;w[i]=0;gST->out->out(gST->out,w);}
}
static void status(const char *s,ES e){char b[19]="0x";for(unsigned i=0;i<16;i++)b[i+2]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[18]=0;say(s);say(b);say("\r\n");}
static int key(void){
 KEY k;
 for(;;){ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;
  if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;
 }
}
static void add_n(const char *s,UN n){
 if(n>sizeof(snapshot)-1-snapshot_len){snapshot_bad=1;return;}
 memcpy(snapshot+snapshot_len,s,n);snapshot_len+=n;snapshot[snapshot_len]=0;
}
static void add(const char *s){UN n=0;while(s[n])n++;add_n(s,n);}
static void hex(uint64_t v,unsigned n){char b[17];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-1-i)*4))&15];b[n]=0;add(b);}
static int prefix(const char *p,UN n,const char *s){for(UN i=0;s[i];i++)if(i>=n||p[i]!=s[i])return 0;return 1;}
static ES make_snapshot(int full){
 snapshot_len=0;snapshot_bad=0;
 add(full?"HERO-IPMI-R5-FULL\r\nRUN=":"HERO-IPMI-R5-SUMMARY\r\nRUN=");add(run_id);add("\r\n");
 CONFIG c={0};uint32_t source=2;ES e=service->config(&c,&source);
 add("CONFIG status=");hex(e,16);add(" source=");hex(source,2);add(" enabled=");hex(c.enabled,2);add("\r\n");
 add("LOAD manual_only=");hex(service->manual_only,2);add("\r\n");
 UN n=0;const char *data=service->log(&n);if(!data||n>=131072)return ERR(4);
 if(full)add_n(data,n);
 else for(UN at=0;at<n;){
  UN end=at;while(end<n&&data[end]!='\n')end++;if(end<n)end++;
  const char *p=data+at;UN length=end-at;
  if(prefix(p,length,"HERO-")||prefix(p,length,"LOAD_")||prefix(p,length,"R5_")||prefix(p,length,"FAN_")||prefix(p,length,"DMI_")||prefix(p,length,"DASHBOARD_")||prefix(p,length,"BOARD ")||
     prefix(p,length,"RESULT:")||prefix(p,length,"BMC_ID ")||prefix(p,length,"READY_")||prefix(p,length,"OEM_")||
     prefix(p,length,"SDR_SNAPSHOT")||prefix(p,length,"SENSOR ")||prefix(p,length,"PCI_ENABLE ")||
     prefix(p,length,"PCI_RESTORE ")||prefix(p,length,"CONFIG_SAVE ")||prefix(p,length,"ATTEMPT_UNLOCK "))add_n(p,length);
  at=end;
 }
 REPORT r;memset(&r,0,sizeof(r));e=service->status(&r);if(FAILED(e))return e;
 add("FINAL requests=");hex(r.requests,8);add(" oem_ack=");hex(r.acknowledged,2);
 add(" targets=");hex(r.targets,2);add(" readable=");hex(r.readable,2);
 add(" locked=");hex(r.locked,2);add(" attempted=");hex(r.attempted,2);
 add(" pci_restored=");hex(r.restore_ok,2);add(" kcs_error=");hex(r.kcs_error,8);
 add(" last_status=");hex(r.last_status,2);add(" pci_io=");hex(r.io_status,16);add("\r\n");
 R3_REPORT r3;memset(&r3,0,sizeof(r3));e=service3->status(&r3);if(e)return e;
 add("R3 sensor_status=");hex(r3.sensor_status,16);add(" dashboard_status=");hex(r3.dashboard_status,16);
 add(" source_status=");hex(r3.source_status,16);add(" table_crc=");hex(r3.source_crc,8);add(" table_bytes=");hex(r3.source_bytes,8);
 add(" dmi_matched=");hex(r3.dmi_matched,2);add(" dmi_written=");hex(r3.dmi_written,2);add(" dmi_attempted=");hex(r3.dmi_attempted,2);
 add(" dmi_locked=");hex(r3.dmi_locked,2);add(" ready_seen=");hex(r3.ready_seen,2);add("\r\n");
 add("DASHBOARD_RESULT: ");add(r3.dashboard_result);add("\r\n");
 add(full?"END FULL AUDIT\r\n":"END SUMMARY - full raw TX/RX available with A/V/L\r\n");
 return snapshot_bad?ERR(5):0;
}
static ES save_file(void){
 if(!file_log)return ERR(14);
 /* Full core audit, no truncation; a fixed session header identifies this run. */
 ES e=file_log->set_position(file_log,0);if(FAILED(e))return e;
 char header[40]="HERO-IPMI-R5 FILE RUN=";unsigned h=0;while(header[h])h++;for(unsigned i=0;i<16;i++)header[h++]=run_id[i];header[h++]='\r';header[h++]='\n';
 UN size=h;e=file_log->write(file_log,&size,header);if(FAILED(e)||size!=h)return FAILED(e)?e:ERR(7);
 UN n=0;const char *p=service->log(&n);if(!p||n>=131072)return ERR(4);
 size=n;e=file_log->write(file_log,&size,(void *)p);if(FAILED(e)||size!=n)return FAILED(e)?e:ERR(7);
 return file_log->flush(file_log);
}
static ES open_log(void){
 if(file_log)return save_file();if(!root)return ERR(14);
 C16 name[]=L"\\R5LOG000.TXT";
 for(unsigned i=0;i<1000;i++){
  name[6]=(C16)('0'+i/100);name[7]=(C16)('0'+i/10%10);name[8]=(C16)('0'+i%10);
  FILEP *test=0;ES e=root->open(root,&test,name,1,0);
  if(!FAILED(e)){if(test)test->close(test);continue;}
  if(e!=ERR(14))return e;
  e=root->open(root,&file_log,name,0x8000000000000003ULL,0);if(FAILED(e)||!file_log)return FAILED(e)?e:ERR(7);
  e=save_file();if(!FAILED(e)){say("File log: ");gST->out->out(gST->out,name);say("\r\n");}return e;
 }
 return ERR(9);
}
static void summary(void){
 REPORT r;CONFIG c;uint32_t source=2;memset(&r,0,sizeof(r));service->status(&r);
 say("Target: ");say(r.board);say(" / ");say(r.bios);say("\r\n");
 say("Result: ");say(r.result);say("\r\n");
 ES e=service->config(&c,&source);
 if(FAILED(e))status("Configuration unreadable: ",e);
 else {say(c.enabled?"Auto-init: ENABLED":"Auto-init: DISABLED");say(source==0?" (R2 default; no saved value)\r\n":" (saved)\r\n");}
 say(service->manual_only?"Driver mode: MANUAL ONLY. No boot callback is registered.\r\n":"Driver mode: RESIDENT FIRMWARE. Boot callback is one-shot.\r\n");
}
static int confirm(const char *text,int expected){say(text);say("\r\nPress the same action key again to confirm; any other key cancels.\r\n");int k=key();if(k>='a'&&k<='z')k-=32;return k==expected;}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt||!gST->out||!gST->out->out||!gST->in||!gST->in->read)return ERR(2);
 say("HERO IPMI R5 - SENSOR + DASHBOARD / MANUAL TEST\r\n");
 ES wd=gST->bs->set_watchdog(0,0,0,0);status("UEFI boot watchdog disabled: ",wd);
 if(wd){say("Watchdog disable failed. Q=return; no driver operation.\r\n");while(key()!='Q'){}return wd;}
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));uint64_t token=((uint64_t)high<<32)|low;
 for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
 ES e=ERR(7);LOADED *loaded=0,*child_loaded=0;FS *fs=0;FILEP *file=0;
 void *buffer=0,*options=0;HANDLE child=0;int owns=0,started=0,connected=0;
 if(FAILED(e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))||!loaded)goto done;
 if(FAILED(e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs))||!fs)goto done;
 if(FAILED(e=fs->open_volume(fs,&root))||!root)goto done;
 if(FAILED(e=root->open(root,&file,W("\\HERO_R5.TAG"),1,0))||!file)goto done;
 char marker[20]={0};UN n=sizeof(marker);e=file->read(file,&n,marker);file->close(file);file=0;
 if(FAILED(e)||n!=14||!eq(marker,"HERO-IPMI-R5\r\n",14)){e=ERR(15);goto done;}
 e=gST->bs->locate_protocol(&api_guid,0,(void **)&service);
 if(e==ERR(14)){
  say("Loading sensor core in explicit manual mode...\r\n");
  e=root->open(root,&file,W("\\EFI\\HERO\\HeroIpmiR5.efi"),1,0);if(FAILED(e)||!file)goto done;
  e=gST->bs->allocate_pool(4,1048576,&buffer);if(FAILED(e)||!buffer)goto done;
  n=1048576;e=file->read(file,&n,buffer);file->close(file);file=0;
  if(FAILED(e)||n<512||n==1048576){e=ERR(4);goto done;}
  e=gST->bs->load_image(0,image,0,buffer,n,&child);if(FAILED(e))goto done;owns=1;
  e=gST->bs->handle_protocol(child,&loaded_guid,(void **)&child_loaded);if(FAILED(e)||!child_loaded)goto done;
  e=gST->bs->allocate_pool(4,sizeof(LOAD_OPTIONS),&options);if(FAILED(e)||!options)goto done;
  *(LOAD_OPTIONS *)options=(LOAD_OPTIONS){MANUAL_MAGIC,sizeof(LOAD_OPTIONS)};
  child_loaded->options_size=sizeof(LOAD_OPTIONS);child_loaded->options=options;
  e=gST->bs->start_image(child,0,0);if(FAILED(e)){owns=0;goto done;}started=1;
  e=gST->bs->locate_protocol(&api_guid,0,(void **)&service);
 }
 if(FAILED(e)||!service||service->version!=2||service->size!=sizeof(R2_API)||!service->run||!service->log||!service->status||!service->config||!service->enable||!service->unlock){e=ERR(3);goto done;}
 if(owns&&!service->manual_only){e=ERR(15);goto done;}
 e=gST->bs->locate_protocol(&r3_api_guid,0,(void **)&service3);
 if(e||!service3||service3->version!=3||service3->size!=sizeof(R3_API)||!service3->run||!service3->log||!service3->status||!service3->unlock){e=ERR(3);goto done;}
 UN core_n=0;const char *core_log=service3->log(&core_n);
 if(!core_log||!prefix(core_log,core_n,"HERO-IPMI-R5 CORE /")){e=ERR(3);goto done;}
 connected=1;
 say("CORE_READY. No initialization has been requested by this launcher.\r\n");summary();
 for(;;){
  say("\r\nD=sensors read; I=initialize sensors + sync Dashboard; S=sensors init only; B=Dashboard compare; H=Dashboard sync\r\n");
  say("C=summary QR; R=summary text; A=full QR; V=full text; L=file log; Q=exit\r\n1/0=save enabled/disabled; U=sensor unlock; J=Dashboard unlock (disabled only)\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){e=ERR(7);break;}if(k=='Q'){e=0;break;}
  if(k=='C'||k=='R'||k=='A'||k=='V'){
   ES s=make_snapshot(k=='A'||k=='V');if(!FAILED(s))s=kvm_present(gST,snapshot,snapshot_len,(k=='R'||k=='V')?2U:0U);status("Capture viewer: ",s);continue;
  }
  if(k=='L'){status("File log result: ",open_log());continue;}
  if(k=='D'||k=='I'||k=='S'||k=='B'||k=='H'){
   if((k=='I'||k=='S'||k=='H')&&!confirm("Apply selected BMC stage? Changes BMC state; no BIOS/SPI write.",k))continue;
   if(k=='B')say("Dashboard GET may create an empty missing BMC file; no SET.\r\n");
   if(file_log)status("Pre-operation log: ",save_file());say("Core operation running; bounded KCS readiness wait.\r\n");
   uint32_t flags=k=='D'?R3_SENSORS:k=='I'?(R3_SENSORS|R3_DASHBOARD|R3_WRITE):k=='S'?(R3_SENSORS|R3_WRITE):k=='B'?R3_DASHBOARD:(R3_DASHBOARD|R3_WRITE);
   status("Core operation: ",service3->run(flags));summary();
   R3_REPORT detail;service3->status(&detail);status("Sensor stage: ",detail.sensor_status);status("Dashboard stage: ",detail.dashboard_status);say(detail.dashboard_result);say("\r\n");
  }else if(k=='0'||k=='1'){
   if(!confirm(k=='1'?"Save ENABLED for the resident firmware core on later boots?":"Save DISABLED for automatic initialization?",k))continue;
   status("Save configuration: ",service->enable(k=='1'));summary();
  }else if(k=='U'||k=='J'){
   if(!confirm("Clear the previous attempt lock? Requires saved disabled. Does not roll back BMC changes.",k))continue;
   status("Clear attempt lock: ",service3->unlock(k=='U'?R3_SENSORS:R3_DASHBOARD));summary();
  }
  if(file_log)status("File log updated: ",save_file());
 }
done:
 if(!connected&&!FAILED(e))e=ERR(7);
 if(file_log){status("Final file log: ",save_file());file_log->close(file_log);file_log=0;}
 if(file)file->close(file);if(root){root->close(root);root=0;}if(buffer)gST->bs->free_pool(buffer);
 if(owns&&child){ES u=gST->bs->unload_image(child);status("Driver unload: ",u);if(FAILED(u)){options=0;if(!FAILED(e))e=u;}else child_loaded=0;}
 /* Failed StartImage unloads a nonresident image. Successful but failed unload
  * retains its LoadOptions allocation; never leave a dangling options buffer. */
 if(options){if(owns&&!started&&child_loaded){child_loaded->options=0;child_loaded->options_size=0;}gST->bs->free_pool(options);}
 status("Session result: ",e);say("Session ended. Press Q again to return to firmware. Enter/Esc do not exit.\r\n");
 for(;;){int k=key();if(k=='Q'||k=='q')break;}return e;
}
