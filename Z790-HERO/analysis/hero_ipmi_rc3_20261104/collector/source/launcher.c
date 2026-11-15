/* RC3 resident audit capture. Never loads or runs a driver. */
#include "r2.h"
#include "kvm.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static R2_API *service;
static FILEP *root,*file_log;
static HANDLE current_image;
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
 add(full?"HERO-IPMI-RC3-AUTO-FULL\r\nRUN=":"HERO-IPMI-RC3-AUTO-SUMMARY\r\nRUN=");add(run_id);add("\r\n");
 CONFIG c={0};uint32_t source=2;ES e=service->config(&c,&source);
 add("CONFIG status=");hex(e,16);add(" source=");hex(source,2);add(" enabled=");hex(c.enabled,2);add("\r\n");
 add("LOAD manual_only=");hex(service->manual_only,2);add("\r\n");
 UN n=0;const char *data=service->log(&n);if(!data||n>=131072)return ERR(4);
 if(full)add_n(data,n);
 else for(UN at=0;at<n;){
  UN end=at;while(end<n&&data[end]!='\n')end++;if(end<n)end++;
  const char *p=data+at;UN length=end-at;
  if(prefix(p,length,"HERO-")||prefix(p,length,"LOAD_")||prefix(p,length,"R2_")||prefix(p,length,"BOARD ")||
     prefix(p,length,"RESULT:")||prefix(p,length,"BMC_ID ")||prefix(p,length,"READY_")||prefix(p,length,"OEM_")||
     prefix(p,length,"SDR_SNAPSHOT")||prefix(p,length,"SENSOR ")||prefix(p,length,"PCI_ENABLE ")||
     prefix(p,length,"PCI_RESTORE ")||prefix(p,length,"CONFIG_SAVE ")||prefix(p,length,"ATTEMPT_UNLOCK "))add_n(p,length);
  at=end;
 }
 REPORT r;memset(&r,0,sizeof(r));e=service->status(&r);if(FAILED(e))return e;
 add("LAST_RUN_REPORT (lock may be unqueried) requests=");hex(r.requests,8);add(" oem_ack=");hex(r.acknowledged,2);
 add(" targets=");hex(r.targets,2);add(" readable=");hex(r.readable,2);
 add(" locked=");hex(r.locked,2);add(" attempted=");hex(r.attempted,2);
 add(" pci_restored=");hex(r.restore_ok,2);add(" kcs_error=");hex(r.kcs_error,8);
 add(" last_status=");hex(r.last_status,2);add(" pci_io=");hex(r.io_status,16);add("\r\n");
 add(full?"END FULL AUDIT\r\n":"END SUMMARY - full raw TX/RX available with A/V/L\r\n");
 return snapshot_bad?ERR(5):0;
}
static ES save_file(void){
 if(!file_log)return ERR(14);
 /* Full core audit, no truncation; a fixed session header identifies this run. */
 ES e=file_log->set_position(file_log,0);if(FAILED(e))return e;
 char header[64]="HERO-IPMI-RC3 AUTO FILE RUN=";unsigned h=0;while(header[h])h++;for(unsigned i=0;i<16;i++)header[h++]=run_id[i];header[h++]='\r';header[h++]='\n';
 UN size=h;e=file_log->write(file_log,&size,header);if(FAILED(e)||size!=h)return FAILED(e)?e:ERR(7);
 UN n=0;const char *p=service->log(&n);if(!p||n>=131072)return ERR(4);
 size=n;e=file_log->write(file_log,&size,(void *)p);if(FAILED(e)||size!=n)return FAILED(e)?e:ERR(7);
 return file_log->flush(file_log);
}
static ES mount_log_volume(void);
static ES open_log(void){
 if(file_log)return save_file();if(!root){ES mounted=mount_log_volume();if(FAILED(mounted))return mounted;}
 C16 name[]=L"\\R3LOG000.TXT";
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
 say("Last run report (lock field may be unqueried).\r\n");
 say("Result: ");say(r.result);say("\r\n");
 ES e=service->config(&c,&source);
 if(FAILED(e))status("Configuration unreadable: ",e);
 else {say(c.enabled?"Auto-init: ENABLED":"Auto-init: DISABLED");say(source==0?" (R2 default; no saved value)\r\n":" (saved)\r\n");}
 say(service->manual_only?"Driver mode: MANUAL ONLY. No boot callback is registered.\r\n":"Driver mode: RESIDENT FIRMWARE. Boot callback is one-shot.\r\n");
}

/* The marked boot volume is opened only after explicit L. No disk scan. */
static ES mount_log_volume(void){
 LOADED *loaded=0;FS *fs=0;FILEP *volume=0,*marker=0;ES e;
 e=gST->bs->handle_protocol(current_image,&loaded_guid,(void **)&loaded);if(FAILED(e)||!loaded)return FAILED(e)?e:ERR(14);
 e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs);if(FAILED(e)||!fs)return FAILED(e)?e:ERR(14);
 e=fs->open_volume(fs,&volume);if(FAILED(e)||!volume)return FAILED(e)?e:ERR(14);
 e=volume->open(volume,&marker,W("\\HERO_RC3.TAG"),1,0);
 if(FAILED(e)||!marker){volume->close(volume);return FAILED(e)?e:ERR(14);}
 char b[32]={0};UN n=sizeof(b);e=marker->read(marker,&n,b);marker->close(marker);
 const char expected[]="HERO-IPMI-RC3-LOG\r\n";
 if(FAILED(e)||n!=sizeof(expected)-1||!eq(b,expected,n)){volume->close(volume);return FAILED(e)?e:ERR(15);}
 root=volume;return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;current_image=image;
 if(!gST||!gST->bs||!gST->rt||!gST->out||!gST->out->out||!gST->in||!gST->in->read)return ERR(2);
 say("HERO RC3 AUTO LOG / CAPTURE ONLY\r\n");
 gST->bs->set_watchdog(0,0,0,0);
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));uint64_t token=((uint64_t)high<<32)|low;
 for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
 ES e=gST->bs->locate_protocol(&api_guid,0,(void **)&service);
 if(FAILED(e)||!service){
  say("RESIDENT R2 CORE NOT AVAILABLE. No driver will be loaded.\r\n");
  if(!FAILED(e))e=ERR(14);goto done;
 }
 if(service->version!=2||service->size!=sizeof(R2_API)||!service->log||!service->status||!service->config){
  say("Resident R2 API is incompatible. Capture stopped.\r\n");e=ERR(3);goto done;
 }
 if(service->manual_only){say("Manual-only R2 core found; this is not a firmware automatic run.\r\n");e=ERR(15);goto done;}
 say("RESIDENT_CORE_FOUND. Capturing existing boot audit only.\r\n");
 say("No initialization, hardware queries, configuration changes or retry keys.\r\n");
 summary();
 for(;;){
  say("\r\nC=summary QR; R=summary text; A=full QR; V=full text\r\n");
  say("L=USB file log; Q/Esc=exit. Save captures before restarting.\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){e=ERR(7);break;}if(k==27||k=='Q'){e=0;break;}
  if(k=='C'||k=='R'||k=='A'||k=='V'){
   ES s=make_snapshot(k=='A'||k=='V');if(!FAILED(s))s=kvm_present(gST,snapshot,snapshot_len,(k=='R'||k=='V')?2U:0U);
   status("Capture viewer: ",s);continue;
  }
  if(k=='L'){status("File log result: ",open_log());continue;}
  say("Capture-only key: use C/R/A/V/L or Q/Esc.\r\n");
 }
done:
 if(file_log){status("Final file log: ",save_file());file_log->close(file_log);file_log=0;}
 if(root){root->close(root);root=0;}
 status("Session result: ",e);say("Enter/Esc/Q = return to firmware.\r\n");
 for(;;){int k=key();if(k<0||k=='\r'||k==27||k=='Q'||k=='q')break;}return e;
}
