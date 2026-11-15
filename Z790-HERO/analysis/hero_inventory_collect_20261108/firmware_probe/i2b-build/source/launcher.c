/* Read-only firmware identity. Only explicit L writes a new marked-USB file.
 * No BMC, PCI, variable, watchdog, reset, driver-loading or protocol-install API.
 */
#include "collector.h"
#include "kvm.h"
#include "firmware_probe.h"
static ST *gST;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static HANDLE current_image;
static FILEP *root;
static char snapshot[SNAPSHOT_CAP],run_id[17];
static UN snapshot_len;
static unsigned snapshot_bad,captured,valid;
static void say(const char *s){C16 w[160];while(*s){unsigned i=0;while(*s&&i<159)w[i++]=(uint8_t)*s++;w[i]=0;gST->out->out(gST->out,w);}}
static void status(const char *s,ES e){char b[19]="0x";for(unsigned i=0;i<16;i++)b[i+2]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[18]=0;say(s);say(b);say("\r\n");}
static int key(void){
 KEY k;for(;;){ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;
  if(e!=ERR(6))return -1;UN index;if(!gST->bs->wait_for_event||FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;
 }
}
static void add_n(const char *s,UN n){if(n>sizeof(snapshot)-1-snapshot_len){snapshot_bad=1;return;}memcpy(snapshot+snapshot_len,s,n);snapshot_len+=n;snapshot[snapshot_len]=0;}
static void add(const char *s){UN n=0;while(s[n])n++;add_n(s,n);}
static void hex(uint64_t v,unsigned n){char b[17];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-1-i)*4))&15];b[n]=0;add(b);}
static void field(const char *name,uint64_t v,unsigned digits){add(name);add("=");hex(v,digits);add("\r\n");}
static void identity_append(void *ctx,const char *bytes,size_t length){(void)ctx;add_n(bytes,length);}
static ES collect(void){
 snapshot_len=0;snapshot_bad=0;valid=0;captured=1;
 add("HERO-FW-ID-I2B\r\nRUN=");add(run_id);add("\r\n");
 add("READ_ONLY firmware identity; no BMC, PCI, NV or initialization.\r\n");
 ES e=firmware_probe(gST,identity_append,0);valid=!FAILED(e);
 field("FP_PROBE_RETURN",e,16);field("CAPTURE_COMPLETE",valid,2);
 add("END FW ID SNAPSHOT\r\n");return snapshot_bad?ERR(5):e;
}
static ES mount_log_volume(void){
 LOADED *loaded=0;FS *fs=0;FILEP *volume=0,*marker=0;ES e;
 e=gST->bs->handle_protocol(current_image,&loaded_guid,(void **)&loaded);if(FAILED(e)||!loaded)return FAILED(e)?e:ERR(14);
 e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs);if(FAILED(e)||!fs)return FAILED(e)?e:ERR(14);
 e=fs->open_volume(fs,&volume);if(FAILED(e)||!volume)return FAILED(e)?e:ERR(14);
 e=volume->open(volume,&marker,W("\\HERO_ID.TAG"),1,0);
 if(FAILED(e)||!marker){volume->close(volume);return FAILED(e)?e:ERR(14);}
 char b[32]={0};UN n=sizeof(b);e=marker->read(marker,&n,b);marker->close(marker);
 const char expected[]="HERO-FW-ID-I2B\r\n";
 if(FAILED(e)||n!=sizeof(expected)-1||!eq(b,expected,n)){volume->close(volume);return FAILED(e)?e:ERR(15);}
 root=volume;return 0;
}
static ES save_new_file(void){
 if(!captured||snapshot_bad||!snapshot_len)return ERR(6);
 ES e=0;if(!root){e=mount_log_volume();if(FAILED(e))return e;}
 C16 name[]=L"\\FID000.TXT";
 for(unsigned i=0;i<1000;i++){
  name[4]=(C16)('0'+i/100);name[5]=(C16)('0'+i/10%10);name[6]=(C16)('0'+i%10);
  FILEP *file=0;ES f=root->open(root,&file,name,1,0);
  if(!FAILED(f)){if(file)file->close(file);continue;}if(f!=ERR(14))return f;
  e=root->open(root,&file,name,0x8000000000000003ULL,0);if(FAILED(e)||!file)return FAILED(e)?e:ERR(7);
  UN n=snapshot_len;e=file->write(file,&n,snapshot);if(!FAILED(e)&&n!=snapshot_len)e=ERR(7);
  if(!FAILED(e))e=file->flush(file);ES close=file->close(file);if(!FAILED(e)&&FAILED(close))e=close;
  if(!FAILED(e)){say("File log: ");gST->out->out(gST->out,name);say("\r\n");}return e;
 }
 return ERR(9);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;current_image=image;
 if(!gST||!gST->out||!gST->out->out)return ERR(2);
 say("HERO FW ID I2B - FIRST TEXT / WAITING FOR F\r\n");
 say("Read firmware identity only. F starts; Enter/Esc do nothing. Q then Q exits.\r\n");
 if(!gST->bs||!gST->in||!gST->in->read){say("Input/boot services missing.\r\n");return ERR(2);}
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));uint64_t token=((uint64_t)high<<32)|low;
 for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
 ES result=0;
 for(;;){
  say(captured?"\r\nC=raw QR; R=raw text; L=marked USB file. Q then Q=exit.\r\n":"\r\nF=capture firmware identity. Q then Q=exit.\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){result=ERR(7);break;}
  if(k=='Q'){say("Press Q again to return to firmware. Any other key cancels.\r\n");int confirm=key();if(confirm=='Q'||confirm=='q')break;continue;}
  if(k=='F'){
   if(captured){say("Snapshot already captured; original bytes retained.\r\n");continue;}
   say("FIRMWARE_ID_READ_BEGIN\r\n");result=collect();status("Firmware identity status: ",result);
   status("Export bytes: ",snapshot_len);
   say(valid?"FIRMWARE_ID_CAPTURE_READY. C exports QR; R exports text.\r\n":"FIRMWARE_ID_CAPTURE_INCOMPLETE. C/R preserve diagnostic metadata.\r\n");continue;
  }
  if((k=='C'||k=='R')&&captured&&!snapshot_bad){ES e=kvm_present(gST,snapshot,snapshot_len,k=='R'?2U:0U);status("Capture viewer: ",e);continue;}
  if(k=='L'&&captured){status("File log result: ",save_new_file());continue;}
  say("Use F, C, R, L, or Q. Enter/Esc do not exit this application.\r\n");
 }
 if(root){root->close(root);root=0;}say("HERO FW ID I2B RETURNING TO FIRMWARE\r\n");return result;
}
