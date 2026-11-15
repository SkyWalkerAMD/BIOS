/* Two-pass real-BDS test. Never calls run(), SignalEvent(), CreateEvent(),
 * SetVariable(), ResetSystem(), ConnectController() or UnloadImage().
 * Only the separately loaded R3 driver owns its ReadyToBoot callback/data.
 * No LoadOptions buffer, application callback or application-owned context is
 * handed to the retained driver. ParentHandle is informational UEFI metadata. */
#include "r2.h"
#include "kvm.h"
#include "frozen_r3.h"
ST *gST;
static GUID v2_guid=API_GUID_INIT,v3_guid=R3_API_GUID_INIT;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static R2_API *api;static R3_API *api3;
static HANDLE child;static FILEP *root,*file_log;
static char snapshot[131072],run_id[17];static UN snapshot_len;
static unsigned snapshot_bad,first_pass;
static ES load_status=ERR(6),start_status=ERR(6),watchdog_status=ERR(6);
extern uint32_t probe_crc32(const void *,size_t);
static void say(const char *s){C16 w[160];while(*s){unsigned n=0;while(*s&&n<159)w[n++]=(uint8_t)*s++;w[n]=0;gST->out->out(gST->out,w);}}
static void status(const char *s,ES e){char b[19]="0x";for(unsigned i=0;i<16;i++)b[i+2]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[18]=0;say(s);say(b);say("\r\n");}
static int key(void){KEY k;for(;;){ES e=gST->in->read(gST->in,&k);if(!e){int c=k.unicode;return c>='a'&&c<='z'?c-32:c;}if(e!=ERR(6))return -1;UN i;if(gST->bs->wait_for_event(1,&gST->in->wait,&i))return -1;}}
static void add_n(const char *s,UN n){if(n>sizeof(snapshot)-1-snapshot_len){snapshot_bad=1;return;}memcpy(snapshot+snapshot_len,s,n);snapshot_len+=n;snapshot[snapshot_len]=0;}
static void add(const char *s){UN n=0;while(s[n])n++;add_n(s,n);}
static void hex(uint64_t v,unsigned n){char b[17];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-1-i)*4))&15];b[n]=0;add(b);}
static int prefix(const char *s,UN n,const char *p){for(UN i=0;p[i];i++)if(i>=n||s[i]!=p[i])return 0;return 1;}
static ES connect_api(void){
 ES e=gST->bs->locate_protocol(&v3_guid,0,(void **)&api3);if(e)return e;
 e=gST->bs->locate_protocol(&v2_guid,0,(void **)&api);if(e)return ERR(3);
 if(!api3||api3->version!=3||api3->size!=sizeof(R3_API)||!api3->status||!api3->log||api3->manual_only||
    !api||api->version!=2||api->size!=sizeof(R2_API)||!api->status||!api->log||api->manual_only)return ERR(3);
 return 0;
}
static ES load_core(HANDLE image){
 if(probe_crc32(frozen_r3,sizeof(frozen_r3))!=FROZEN_R3_CRC)return ERR(33);
 void *old=0;ES e=gST->bs->locate_protocol(&v2_guid,0,&old);if(e!=ERR(14))return e?e:ERR(20);
 load_status=gST->bs->load_image(0,image,0,(void *)frozen_r3,sizeof(frozen_r3),&child);status("LOAD_IMAGE=",load_status);if(load_status)return load_status;
 LOADED *loaded=0;e=gST->bs->handle_protocol(child,&loaded_guid,(void **)&loaded);if(e||!loaded)return e?e:ERR(14);
 /* Leave the fresh LoadedImage defaults untouched; NEVER supply manual options. */
 if(loaded->options_size||loaded->options)return ERR(2);
 start_status=gST->bs->start_image(child,0,0);status("START_IMAGE=",start_status);if(start_status)return start_status;
 first_pass=1;return connect_api();
}
static ES refresh(void){
 R3_REPORT r3;REPORT r;ES e=api3->status(&r3);if(e)return e;e=api->status(&r);if(e)return e;
 if(r3.version!=3||r3.size!=sizeof(r3))return ERR(3);
 say(first_pass?"FIRST_PASS_RESIDENT: driver remains loaded when this app returns.\r\n":"SECOND_PASS_OBSERVER: existing firmware-mode R3 found.\r\n");
 status("READY_SEEN=",r3.ready_seen);status("SENSOR_STATUS=",r3.sensor_status);status("DASHBOARD_STATUS=",r3.dashboard_status);
 status("BMC_REQUESTS=",r.requests);status("TARGET_SDRS=",r.targets);status("PCI_RESTORED=",r.restore_ok);status("DMI_MATCHED=",r3.dmi_matched);status("DMI_WRITTEN=",r3.dmi_written);
 if(first_pass&&r.requests==0&&r3.ready_seen==0)say("FIRST_PASS_NO_BMC_QUERY: only driver entry has executed.\r\n");
 else if(r3.ready_seen)say("READY_TO_BOOT_OBSERVED: launcher never called run or signaled the event.\r\n");
 else say("READY_TO_BOOT_NOT_OBSERVED: do not infer automatic execution.\r\n");
 return 0;
}
static ES make_snapshot(int full){
 snapshot_len=0;snapshot_bad=0;add(full?"HERO-R3AUTO-FULL\r\nRUN=":"HERO-R3AUTO-SUMMARY\r\nRUN=");add(run_id);add("\r\n");
 add("PASS=");hex(first_pass?1:2,2);add(" MANUAL_RUN_CALLS=0 SYNTHETIC_EVENT_SIGNALS=0 APP_CALLBACKS=0\r\n");
 add("FROZEN_R3_SHA256=7b715068892c7603a02648fb3739b7e90a79504634a1717e6c7ed49b5f9e6921\r\n");
 add("LOAD_IMAGE=");hex(load_status,16);add(" START_IMAGE=");hex(start_status,16);add(" WATCHDOG_DISABLE=");hex(watchdog_status,16);add("\r\n");
 UN n=0;const char *data=api3->log(&n);if(!data||n>=131072)return ERR(4);
 if(full)add_n(data,n);
 else for(UN at=0;at<n;){UN end=at;while(end<n&&data[end]!='\n')end++;if(end<n)end++;
  const char *p=data+at;UN length=end-at;
  if(prefix(p,length,"HERO-")||prefix(p,length,"LOAD_")||prefix(p,length,"READY_")||prefix(p,length,"R3_")||prefix(p,length,"BOARD ")||
     prefix(p,length,"RESULT:")||prefix(p,length,"DASHBOARD_")||prefix(p,length,"DMI_")||prefix(p,length,"OEM_")||prefix(p,length,"SDR_SNAPSHOT")||prefix(p,length,"SENSOR ")||prefix(p,length,"PCI_"))add_n(p,length);
  at=end;
 }
 R3_REPORT r3;REPORT r;ES e=api3->status(&r3);if(e)return e;e=api->status(&r);if(e)return e;
 add("R3 ready_seen=");hex(r3.ready_seen,2);add(" sensor_status=");hex(r3.sensor_status,16);add(" dashboard_status=");hex(r3.dashboard_status,16);add("\r\n");
 add("R3 source_status=");hex(r3.source_status,16);add(" table_crc=");hex(r3.source_crc,8);add(" dmi_matched=");hex(r3.dmi_matched,2);add(" dmi_written=");hex(r3.dmi_written,2);add(" dmi_locked=");hex(r3.dmi_locked,2);add("\r\n");
 add("FINAL requests=");hex(r.requests,8);add(" ack=");hex(r.acknowledged,2);add(" targets=");hex(r.targets,2);add(" readable=");hex(r.readable,2);add(" version_asserted=");hex(r.version_asserted,2);
 add(" locked=");hex(r.locked,2);add(" attempted=");hex(r.attempted,2);add(" pci_restored=");hex(r.restore_ok,2);add("\r\n");
 add(full?"END FULL AUDIT\r\n":"END SUMMARY - full raw TX/RX available with A/V/F\r\n");return snapshot_bad?ERR(5):0;
}
static ES file_save(HANDLE image){
 ES e=make_snapshot(1);if(e)return e;
 if(!root){LOADED *loaded=0;FS *fs=0;FILEP *marker=0;
  e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded);if(e||!loaded)return e?e:ERR(14);
  e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs);if(e||!fs)return e?e:ERR(14);
  e=fs->open_volume(fs,&root);if(e||!root)return e?e:ERR(14);
  e=root->open(root,&marker,W("\\HERO_R3A.TAG"),1,0);if(e||!marker){root->close(root);root=0;return e?e:ERR(14);}
  char check[32];UN n=sizeof(check);e=marker->read(marker,&n,check);marker->close(marker);if(e||n!=13||!eq(check,"HERO-R3AUTO\r\n",13)){root->close(root);root=0;return ERR(15);}
 }
 if(!file_log){C16 name[]=L"\\R3AUTO000.TXT";
  for(unsigned i=0;i<1000;i++){
   name[7]=(C16)('0'+i/100);name[8]=(C16)('0'+i/10%10);name[9]=(C16)('0'+i%10);FILEP *test=0;
   e=root->open(root,&test,name,1,0);if(!e){if(test)test->close(test);continue;}if(e!=ERR(14))return e;
   e=root->open(root,&file_log,name,0x8000000000000003ULL,0);if(e||!file_log)return e?e:ERR(7);break;
  }if(!file_log)return ERR(9);
 }
 e=file_log->set_position(file_log,0);if(e)return e;UN n=snapshot_len;e=file_log->write(file_log,&n,snapshot);if(e||n!=snapshot_len)return e?e:ERR(7);return file_log->flush(file_log);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->out||!gST->out->out||!gST->in||!gST->in->read)return ERR(2);
 say("HERO R3 AUTO - TWO-PASS BDS TEST\r\n");watchdog_status=gST->bs->set_watchdog(0,0,0,0);status("UEFI_WATCHDOG_DISABLE=",watchdog_status);
 uint32_t lo,hi;__asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));uint64_t token=((uint64_t)hi<<32)|lo;
 for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
 ES e=watchdog_status;if(e)goto end;e=connect_api();
 if(e==ERR(14)){
  say("FIRST PASS: L=load frozen R3 in firmware mode; Q=return without loading.\r\n");
  say("No manual initialize or event-signal operation exists in this app.\r\n");
  for(;;){int k=key();if(k=='Q'){e=0;goto end;}if(k<0){e=ERR(7);goto end;}if(k=='L')break;}
  e=load_core(image);
 }
 if(e){status("CORE_CONNECT_ERROR=",e);goto end;}
 e=refresh();if(e)goto end;
 for(;;){
  say("C=summary QR; A=full QR; R=summary text; V=full text; D=observe; F=USB file; Q=return\r\n");
  int k=key();if(k=='Q'){e=0;break;}if(k<0){e=ERR(7);break;}
  if(k=='D')status("OBSERVE_STATUS=",refresh());
  if(k=='F')status("FILE_LOG_STATUS=",file_save(image));
  if(k=='C'||k=='A'||k=='R'||k=='V'){ES s=make_snapshot(k=='A'||k=='V');if(!s)s=kvm_present(gST,snapshot,snapshot_len,(k=='R'||k=='V')?2:0);status("VIEWER_STATUS=",s);}
 }
end:
 if(file_log){file_log->flush(file_log);file_log->close(file_log);}if(root)root->close(root);
 say("RETURN PLAN: the R3 driver is intentionally retained in independent memory.\r\n");
 say("Do not reboot between passes. Return to BIOS, then Boot Override this ISO again.\r\n");
 status("APP_STATUS=",e);say("Press Q again to return to firmware. Enter/Esc do not exit.\r\n");
 while(key()!='Q'){}return e;
}
