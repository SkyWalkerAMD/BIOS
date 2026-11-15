#include "network.h"
#include "kvm.h"
#include "tls_client.h"
#include "snp_stage.h"
#include "depex_probe.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static FILEP *root;static char snapshot[131072];
static void probe_append(void *ctx,const char *data,size_t bytes){
 (void)ctx;char text[160];while(bytes){size_t n=bytes<sizeof(text)-1?bytes:sizeof(text)-1;memcpy(text,data,n);text[n]=0;logtext(text);data+=n;bytes-=n;}
}
void say(const char *s){C16 w[160];while(*s){unsigned n=0;while(*s&&n<159)w[n++]=(uint8_t)*s++;w[n]=0;gST->out->out(gST->out,w);}}
void status(const char *name,ES e){char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[16]=0;logtext(name);logtext("=0x");logtext(b);logtext("\r\n");say(name);say("=0x");say(b);say("\r\n");}
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static ES save_new_log(void){
 if(!root)return ERR(14);C16 name[]=L"\\I3A000.TXT";
 for(unsigned i=0;i<1000;i++){
  name[4]='0'+i/100;name[5]='0'+i/10%10;name[6]='0'+i%10;FILEP *p=0;
  ES e=root->open(root,&p,name,1,0);if(!FAILED(e)){if(p)p->close(p);continue;}if(e!=ERR(14))return e;
  e=root->open(root,&p,name,0x8000000000000003ULL,0);if(FAILED(e)||!p)return FAILED(e)?e:ERR(7);
  UN n=audit_len;e=p->write(p,&n,audit);if(!FAILED(e)&&n!=audit_len)e=ERR(7);if(!FAILED(e))e=p->flush(p);
  ES close=p->close(p);if(!FAILED(e)&&FAILED(close))e=close;return e;
 }return ERR(9);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->out||!gST->out->out)return ERR(2);
 say("HERO Inventory I3a - READ-ONLY INTERNAL USB/TLS\r\n");
 say("D / U / S / N / P / B are explicit. No POST, PATCH or BIOS settings calls.\r\n");
 if(!gST->bs||!gST->in||!gST->in->read)return ERR(2);
 logtext("HERO-INVENTORY-I3A\r\nBUILD=I3A-71-RAM-SNP-GET-ONLY\r\n");
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));logtext("RUN=");loghex(((uint64_t)high<<32)|low,16);logtext("\r\n");
 i3_identity_log();
 LOADED *li=0;FS *fs=0;FILEP *marker=0;char tag[32];UN n=sizeof(tag);
 if(!FAILED(gST->bs->handle_protocol(image,&loaded_guid,(void **)&li))&&li&&!FAILED(gST->bs->handle_protocol(li->device,&fs_guid,(void **)&fs))&&fs&&!FAILED(fs->open_volume(fs,&root))&&root){
  ES e=root->open(root,&marker,W("\\HERO_I3A.TAG"),1,0);if(!FAILED(e)&&marker){
   const char expected[]="HERO-INVENTORY-I3A\n";e=marker->read(marker,&n,tag);marker->close(marker);
   if(FAILED(e)||n!=sizeof(expected)-1||!eq(tag,expected,n)){root->close(root);root=0;}
  }else{root->close(root);root=0;}
 }
 for(;;){
  say("\r\nD=inspect U=RAM USB S=RAM SNP N=check link P=pinned TLS root\r\nB=GET inventory C=QR V=text L=new file Q then Q=exit\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){
   ES e=private_tls_cleanup();if(!FAILED(e))e=network_cleanup();status("I3_INPUT_FAILURE_CLEANUP",e);
   if(FAILED(e)){say("Input failed; callback resources retained until cleanup succeeds.\r\n");gST->bs->stall(100000);continue;}
   if(root){root->close(root);root=0;}return ERR(7);
  }
  if(k=='Q'){
   say("Press Q again to clean up and return. Other keys cancel.\r\n");int confirm=key();if(confirm!='Q'&&confirm!='q')continue;
   ES e=private_tls_cleanup();if(!FAILED(e))e=network_cleanup();status("I3_NETWORK_CLEANUP",e);
   if(!FAILED(e))break;say("Cleanup pending; retain application. Q then Q retries; C/V/L captures.\r\n");continue;
  }
  if(k=='C'||k=='V'){UN bytes=audit_len;memcpy(snapshot,audit,bytes);status("CAPTURE",kvm_present(gST,snapshot,bytes,k=='V'?2:0));continue;}
  if(k=='L'){status("FILE_LOG",save_new_log());continue;}
  if(private_tls_active()){say("TLS cleanup pending. Q then Q retries; C/V/L captures.\r\n");continue;}
  if(k!='D'&&k!='U'&&k!='S'&&k!='N'&&k!='P'&&k!='B'){say("Enter/Esc and all other keys leave this menu unchanged.\r\n");continue;}
  if(!i3_target_valid()){i3_identity_log();say("Exact .71 HERO3107 identity required; network action refused.\r\n");continue;}
  if(k=='D'){i3_identity_log();network_inventory();usb_inventory();tls_inventory();snp_stage_inventory();status("I3A_DEPEX_DIAGNOSTIC",depex_probe(gST,probe_append,0));}
  else if(k=='U'){
   HANDLE usb[2];if(!usb_target_handles(usb)){status("USB_TARGET_NOT_VERIFIED",ERR(15));continue;}
   say("Load the hash-checked RAM USB drivers on this verified host?\r\nPress U again to load; any other key cancels. Drivers remain until reset.\r\n");
   int confirm=key();if(confirm=='U'||confirm=='u'){
    ES e=load_network_drivers(image,root);status("USB_DRIVER_TEST",e);if(!FAILED(e))network_inventory();
   }
  }
  else if(k=='S'){
   say("Load RAM SNP only on the verified internal NII?\r\nPress S again; other keys cancel. No IP stack or saved setting change.\r\n");
   int confirm=key();if(confirm=='S'||confirm=='s'){
    ES e=snp_stage_load(image,root);status("I3A_SNP_STAGE",e);network_inventory();snp_stage_inventory();
   }
  }
  else if(k=='N')status("CHECK_USB_NETWORK",network_connect());
  else if(k=='P')status("PINNED_INTERFACE_GET",private_tls_get_pinned());
  else if(k=='B')status("INVENTORY_READONLY_GET",private_tls_read_inventory());
 }
 logtext("SESSION_END\r\n");if(root){root->close(root);root=0;}
 say("HERO Inventory I3a RETURNING TO FIRMWARE\r\n");return 0;
}
