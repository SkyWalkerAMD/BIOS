#include "network.h"
#include "kvm.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static FILEP *root,*file_log;static char snapshot[131072];
void say(const char *s){C16 w[160];while(*s){unsigned n=0;while(*s&&n<159)w[n++]=(uint8_t)*s++;w[n]=0;gST->out->out(gST->out,w);}}
void status(const char *name,ES e){char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[16]=0;logtext(name);logtext("=0x");logtext(b);logtext("\r\n");say(name);say("=0x");say(b);say("\r\n");}
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static ES save(void){if(!file_log)return ERR(14);ES e=file_log->set_position(file_log,0);if(FAILED(e))return e;UN n=audit_len;e=file_log->write(file_log,&n,audit);return FAILED(e)?e:n!=audit_len?ERR(7):file_log->flush(file_log);}
static ES open_log(void){if(file_log)return save();if(!root)return ERR(14);C16 name[]=L"\\R6LOG000.TXT";for(unsigned i=0;i<1000;i++){name[6]='0'+i/100;name[7]='0'+i/10%10;name[8]='0'+i%10;FILEP *p=0;ES e=root->open(root,&p,name,1,0);if(!FAILED(e)){if(p)p->close(p);continue;}if(e!=ERR(14))return e;e=root->open(root,&file_log,name,0x8000000000000003ULL,0);return FAILED(e)?e:save();}return ERR(9);}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt||!gST->out||!gST->in)return ERR(2);
 say("HERO Remote BIOS R6 - HOST INTERFACE TRANSPORT\r\n");gST->bs->set_watchdog(0,0,0,0);
 logtext("HERO-REMOTE-BIOS-R6\r\n");uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));logtext("RUN=");loghex(((uint64_t)high<<32)|low,16);logtext("\r\n");
 detect_board();logtext("BOARD=");logtext(report.board);logtext(" BIOS=");logtext(report.bios);logtext("\r\n");say(report.board);say(" BIOS ");say(report.bios);say("\r\n");
 LOADED *li=0;FS *fs=0;FILEP *marker=0;char tag[24];UN n=sizeof(tag);
 if(!FAILED(gST->bs->handle_protocol(image,&loaded_guid,(void **)&li))&&li&&!FAILED(gST->bs->handle_protocol(li->device,&fs_guid,(void **)&fs))&&fs&&!FAILED(fs->open_volume(fs,&root))&&root){
  ES e=root->open(root,&marker,W("\\HERO_R6.TAG"),1,0);if(!FAILED(e)&&marker){e=marker->read(marker,&n,tag);marker->close(marker);if(FAILED(e)||n!=15||!eq(tag,"HERO-REMOTE-R6\n",15)){root->close(root);root=0;}}else{root->close(root);root=0;}
 }
 say("First D. H queries only the internal service root. No pending queue reads.\r\n");
 for(;;){
  say("\r\nD=inventory N=connect USB stack H=GET root C=QR V=text L=file Q=exit\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0||k==27||k=='Q'){ES e=network_cleanup();status("NETWORK_CLEANUP",e);if(!FAILED(e))break;say("Cleanup incomplete; remain here, Q retries.\r\n");}
  else if(k=='D')network_inventory();
  else if(k=='H')status("HOST_INTERFACE_GET",network_get());
  else if(k=='N')status("CONNECT_USB_NETWORK",network_connect());
  else if(k=='C'||k=='V'){UN bytes=audit_len;memcpy(snapshot,audit,bytes);status("CAPTURE",kvm_present(gST,snapshot,bytes,k=='V'?2:0));}
  else if(k=='L')status("FILE_LOG",open_log());
  if(file_log)save();
 }
 logtext("SESSION_END\r\n");if(file_log){save();file_log->close(file_log);}if(root)root->close(root);
 say("Session ended. Enter/Esc/Q returns to BIOS.\r\n");for(;;){int k=key();if(k<0||k=='\r'||k==27||k=='Q'||k=='q')break;}return 0;
}
