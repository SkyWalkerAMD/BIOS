/* P6/R2 resident audit capture only. No loader, writer, refresh or timer API. */
#include "r2.h"
#include "kvm.h"
typedef struct {uint32_t version,size;const char *(EA *log)(UN *);const char *(EA *value)(unsigned);} P6_AUDIT;
_Static_assert(sizeof(P6_AUDIT)==24 && offsetof(P6_AUDIT,log)==8 && offsetof(P6_AUDIT,value)==16,"P6 audit ABI");
static GUID p6_guid={0x1f771753,0xbb7b,0x4e4c,{0xb6,0x98,0xe7,0x1e,0x8d,0xb2,0x5e,0x7a}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static P6_AUDIT *p6;
static R2_API *r2;
static ES p6_status,r2_status;
static FILEP *root;
static HANDLE current_image;
static char snapshot[278528],run_id[17];
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
static int add_bounded(const char *s,UN capacity){
 if(!s)return 0;UN n=0;while(n<capacity&&s[n])n++;
 if(n==capacity)return 0;add_n(s,n);return 1;
}
static void hex(uint64_t v,unsigned n){char b[17];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-1-i)*4))&15];b[n]=0;add(b);}
static int prefix(const char *p,UN n,const char *s){for(UN i=0;s[i];i++)if(i>=n||p[i]!=s[i])return 0;return 1;}
static int wanted_line(const char *p,UN n){
 const char *keys[]={"HERO-","LOAD_","P6_","P5_","R2_","BOARD ","RESULT:","BMC_ID ","READY_","OEM_",
  "SDR_SNAPSHOT","SENSOR ","PCI_ENABLE ","PCI_RESTORE ","CONFIG_SAVE ","ATTEMPT_UNLOCK "};
 for(unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);i++)if(prefix(p,n,keys[i]))return 1;return 0;
}
static ES append_audit(const char *data,UN n,int full){
 if(!data||n>=131072)return ERR(4);
 if(full)add_n(data,n);
 else for(UN at=0;at<n;){
  UN end=at;while(end<n&&data[end]!='\n')end++;if(end<n)end++;
  if(wanted_line(data+at,end-at))add_n(data+at,end-at);at=end;
 }
 return snapshot_bad?ERR(5):0;
}
static ES make_snapshot(int full){
 snapshot_len=0;snapshot_bad=0;
 add(full?"HERO-IPMI-P6-FULL\r\nRUN=":"HERO-IPMI-P6-SUMMARY\r\nRUN=");add(run_id);add("\r\n");
 add("CAPTURE_ONLY cached memory; no BMC queries or writes.\r\n");
 add("P6_API_STATUS=");hex(p6_status,16);add(" R2_API_STATUS=");hex(r2_status,16);add("\r\n");
 if(p6){
  add("BEGIN P6 AUDIT\r\n");UN n=0;const char *data=p6->log(&n);ES e=append_audit(data,n,full);if(FAILED(e))return e;
  add("\r\nEND P6 AUDIT\r\nBEGIN P6 CACHED VALUES (41)\r\n");
  for(unsigned i=0;i<41;i++){
   add("P6_VALUE[");hex(i,2);add("]=");
   if(!add_bounded(p6->value(i),160))return ERR(4);add("\r\n");
  }
  add("END P6 CACHED VALUES; index 28 hex / 40 decimal = configuration status\r\n");
 }else add("P6_AUDIT_UNAVAILABLE\r\n");
 if(r2){
  CONFIG c={0};uint32_t source=2;ES e=r2->config(&c,&source);
  add("R2_CONFIG status=");hex(e,16);add(" source=");hex(source,2);add(" enabled=");hex(c.enabled,2);add("\r\n");
  add("R2_LOAD manual_only=");hex(r2->manual_only,2);add("\r\nBEGIN R2 AUDIT\r\n");
  UN n=0;const char *data=r2->log(&n);e=append_audit(data,n,full);if(FAILED(e))return e;
  add("\r\nEND R2 AUDIT\r\n");
  REPORT report;memset(&report,0,sizeof(report));e=r2->status(&report);
  add("R2_REPORT_STATUS=");hex(e,16);add("\r\n");
  if(!FAILED(e)){
   add("R2_BOARD=");if(!add_bounded(report.board,sizeof(report.board)))return ERR(4);
   add(" BIOS=");if(!add_bounded(report.bios,sizeof(report.bios)))return ERR(4);add("\r\nR2_RESULT=");
   if(!add_bounded(report.result,sizeof(report.result)))return ERR(4);add("\r\n");
   add("LAST_RUN_REPORT (lock may be unqueried) requests=");hex(report.requests,8);add(" oem_ack=");hex(report.acknowledged,2);
   add(" targets=");hex(report.targets,2);add(" readable=");hex(report.readable,2);
   add(" locked=");hex(report.locked,2);add(" attempted=");hex(report.attempted,2);
   add(" pci_restored=");hex(report.restore_ok,2);add(" kcs_error=");hex(report.kcs_error,8);
   add(" last_status=");hex(report.last_status,2);add(" pci_io=");hex(report.io_status,16);add("\r\n");
  }
 }else add("R2_AUDIT_UNAVAILABLE\r\n");
 add(full?"END FULL AUDIT\r\n":"END SUMMARY - full raw TX/RX available with A/V/L\r\n");
 return snapshot_bad?ERR(5):0;
}
/* Only the marked boot volume may be opened, and only after explicit L. */
static ES mount_log_volume(void){
 LOADED *loaded=0;FS *fs=0;FILEP *volume=0,*marker=0;ES e;
 e=gST->bs->handle_protocol(current_image,&loaded_guid,(void **)&loaded);if(FAILED(e)||!loaded)return FAILED(e)?e:ERR(14);
 e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs);if(FAILED(e)||!fs)return FAILED(e)?e:ERR(14);
 e=fs->open_volume(fs,&volume);if(FAILED(e)||!volume)return FAILED(e)?e:ERR(14);
 e=volume->open(volume,&marker,W("\\HERO_P6.TAG"),1,0);
 if(FAILED(e)||!marker){volume->close(volume);return FAILED(e)?e:ERR(14);}
 char b[32]={0};UN n=sizeof(b);e=marker->read(marker,&n,b);marker->close(marker);
 const char expected[]="HERO-IPMI-P6-LOG\r\n";
 if(FAILED(e)||n!=sizeof(expected)-1||!eq(b,expected,n)){volume->close(volume);return FAILED(e)?e:ERR(15);}
 root=volume;return 0;
}
static ES save_new_file(void){
 ES e=make_snapshot(1);if(FAILED(e))return e;
 if(!root){e=mount_log_volume();if(FAILED(e))return e;}
 C16 name[]=L"\\P6LOG000.TXT";
 for(unsigned i=0;i<1000;i++){
  name[6]=(C16)('0'+i/100);name[7]=(C16)('0'+i/10%10);name[8]=(C16)('0'+i%10);
  FILEP *file=0;ES f=root->open(root,&file,name,1,0);
  if(!FAILED(f)){if(file)file->close(file);continue;}if(f!=ERR(14))return f;
  e=root->open(root,&file,name,0x8000000000000003ULL,0);if(FAILED(e)||!file)return FAILED(e)?e:ERR(7);
  UN n=snapshot_len;e=file->write(file,&n,snapshot);
  if(!FAILED(e)&&n!=snapshot_len)e=ERR(7);
  if(!FAILED(e))e=file->flush(file);
  ES close=file->close(file);if(!FAILED(e)&&FAILED(close))e=close;
  if(!FAILED(e)){say("File log: ");gST->out->out(gST->out,name);say("\r\n");}return e;
 }
 return ERR(9);
}
static void discover(void){
 void *found=0;p6_status=gST->bs->locate_protocol(&p6_guid,0,&found);
 if(!FAILED(p6_status)&&found){
  P6_AUDIT *a=found;
  if(a->version==6&&a->size==sizeof(P6_AUDIT)&&a->log&&a->value)p6=a;else p6_status=ERR(3);
 }else if(!FAILED(p6_status))p6_status=ERR(14);
 found=0;r2_status=gST->bs->locate_protocol(&api_guid,0,&found);
 if(!FAILED(r2_status)&&found){
  R2_API *a=found;
  if(a->version!=2||a->size!=sizeof(R2_API)||!a->log||!a->status||!a->config)r2_status=ERR(3);
  else if(a->manual_only)r2_status=ERR(15);
  else r2=a;
 }else if(!FAILED(r2_status))r2_status=ERR(14);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;current_image=image;
 if(!gST||!gST->bs||!gST->rt||!gST->out||!gST->out->out||!gST->in||!gST->in->read)return ERR(2);
 say("HERO P6 RC4 AUDIT / CAPTURE ONLY\r\n");
 say("For long diagnostics, DISABLE OS Watchdog in BIOS before booting this tool.\r\n");
 say("This tool does not stop, reload or change any watchdog.\r\n");
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));uint64_t token=((uint64_t)high<<32)|low;
 for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
 discover();status("P6 read-only audit API: ",p6_status);status("R2 resident audit API: ",r2_status);
 ES e=0;
 if(!p6&&!r2){
  say("NO RESIDENT P6 OR R2 AUDIT AVAILABLE. No driver will be loaded.\r\n");
  e=(p6_status==ERR(14)&&r2_status==ERR(14))?ERR(14):ERR(3);goto done;
 }
 say("Capturing existing cached boot audits only; no live hardware queries.\r\n");
 say(p6?"P6 resident configuration audit available.\r\n":"P6 audit unavailable; R2-only capture.\r\n");
 say(r2?"R2 resident sensor audit available.\r\n":"R2 audit unavailable; P6-only capture.\r\n");
 for(;;){
  say("\r\nC=summary QR; R=summary text; A=full QR; V=full text\r\n");
  say("L=marked USB file log; Q/Esc=exit. Save captures before restarting.\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){e=ERR(7);break;}if(k==27||k=='Q')break;
  if(k=='C'||k=='R'||k=='A'||k=='V'){
   ES s=make_snapshot(k=='A'||k=='V');if(!FAILED(s))s=kvm_present(gST,snapshot,snapshot_len,(k=='R'||k=='V')?2U:0U);
   status("Capture viewer: ",s);continue;
  }
  if(k=='L'){status("File log result: ",save_new_file());continue;}
  say("Capture-only key: use C/R/A/V/L or Q/Esc.\r\n");
 }
done:
 if(root){root->close(root);root=0;}
 status("Session result: ",e);say("Enter/Esc/Q = return to firmware.\r\n");
 for(;;){int k=key();if(k<0||k=='\r'||k==27||k=='Q'||k=='q')break;}return e;
}
