#include "network.h"
#include "kvm.h"
#include "tls_client.h"
#include "depex_probe.h"
#include "dxe_state_probe.h"
#include "inventory_legacy71.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID old_r2_guid={0x40823e46,0x8089,0x43f6,{0xaa,0x64,0xa6,0x33,0x42,0x12,0xbb,0x12}};
static FILEP *root;static char snapshot[2097152];
static uint64_t run_epoch;
static int watchdog_disabled;
uint64_t i3_inventory_source_epoch(void){return run_epoch;}
int i3_publication_runtime_ready(void){return watchdog_disabled;}
void say(const char *s){C16 w[160];while(*s){unsigned n=0;while(*s&&n<159)w[n++]=(uint8_t)*s++;w[n]=0;gST->out->out(gST->out,w);}}
void status(const char *name,ES e){char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[16]=0;logtext(name);logtext("=0x");logtext(b);logtext("\r\n");say(name);say("=0x");say(b);say("\r\n");}
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static void dp_append(void *ctx,const char *bytes,size_t n){
 (void)ctx;char buffer[160];while(n){size_t take=n<159?n:159;memcpy(buffer,bytes,take);buffer[take]=0;logtext(buffer);bytes+=take;n-=take;}
}
static void old_r2_presence(void){
 void *p=0;ES e=gST->bs->locate_protocol?gST->bs->locate_protocol(&old_r2_guid,0,&p):ERR(3);
 status("I3D_OLD_R2_40823E46_LOCATE",e);status("I3D_OLD_R2_INTERFACE",(UN)p);
 status("I3D_OLD_R2_PRESENT_AT_CAPTURE",e==0);
 logtext("I3D_OLD_R2_METHODS_NOT_CALLED\r\n");
}
static ES save_new_log(void){
 if(!root)return ERR(14);C16 name[]=L"\\I3D000.TXT";
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
 say("HERO Inventory I3d - INVENTORY CONTINUATION\r\n");
 say("GET inspection and explicit limited inventory publication; no BIOS setting writes.\r\n");
 if(!gST->bs||!gST->in||!gST->in->read)return ERR(2);
 logtext("HERO-INVENTORY-I3D\r\nBUILD=I3D-71-CONTINUATION\r\n");
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));run_epoch=((uint64_t)high<<32)|low;logtext("RUN=");loghex(run_epoch,16);logtext("\r\n");
 ES watchdog=gST->bs->set_watchdog?gST->bs->set_watchdog(0,0,0,0):ERR(3);watchdog_disabled=watchdog==0;status("I3D_UEFI_APPLICATION_WATCHDOG_DISABLE",watchdog);
 i3_identity_log();
 LOADED *li=0;FS *fs=0;FILEP *marker=0;char tag[32];UN n=sizeof(tag);
 if(!FAILED(gST->bs->handle_protocol(image,&loaded_guid,(void **)&li))&&li&&!FAILED(gST->bs->handle_protocol(li->device,&fs_guid,(void **)&fs))&&fs&&!FAILED(fs->open_volume(fs,&root))&&root){
  ES e=root->open(root,&marker,W("\\HERO_I3D.TAG"),1,0);if(!FAILED(e)&&marker){
   const char expected[]="HERO-INVENTORY-I3D\n";e=marker->read(marker,&n,tag);marker->close(marker);
   if(FAILED(e)||n!=sizeof(expected)-1||!eq(tag,expected,n)){root->close(root);root=0;}
  }else{root->close(root);root=0;}
 }
 for(;;){
  say("\r\nD=inspect U=RAM USB drivers N=connect P=pinned TLS root\r\nB=GET inventory I=preflight W then W=one DIMM\r\nS then S=CPU summary C=QR V=text L=new file Q then Q=exit\r\n");
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
  if(k!='D'&&k!='U'&&k!='N'&&k!='P'&&k!='B'&&k!='I'&&k!='W'&&k!='S'){say("Enter/Esc and all other keys leave this menu unchanged.\r\n");continue;}
  if(!i3_target_valid()){i3_identity_log();say("Exact .71 HERO3107 identity required; network action refused.\r\n");continue;}
  if(k=='D'){i3_identity_log();network_inventory();usb_inventory();tls_inventory();status("I3D_DEPEX_DIAGNOSTIC",depex_probe(gST,dp_append,0));status("I3D_DXE_STATE_DIAGNOSTIC",dxe_state_probe(gST,dp_append,0));old_r2_presence();status("I3D_INVENTORY_SOURCE_EXACT",i3_inventory_source_valid());}
  else if(k=='U'){
   HANDLE usb[2];if(!usb_target_handles(usb)){status("USB_TARGET_NOT_VERIFIED",ERR(15));continue;}
   say("Load the hash-checked RAM USB drivers on this verified host?\r\nPress U again to load; any other key cancels. Drivers remain until reset.\r\n");
   int confirm=key();if(confirm=='U'||confirm=='u'){
    ES e=load_network_drivers(image,root);status("USB_DRIVER_TEST",e);if(!FAILED(e))network_inventory();
   }
  }
  else if(k=='N')status("CONNECT_USB_NETWORK",network_connect());
  else if(k=='P')status("PINNED_INTERFACE_GET",private_tls_get_pinned());
  else if(k=='B')status("INVENTORY_READONLY_GET",private_tls_read_inventory());
  else if(k=='I'){
   if(!watchdog_disabled){say("UEFI application watchdog could not be disabled; publication unavailable.\r\n");continue;}
   status("I3D_INVENTORY_PREFLIGHT",inventory_legacy71_preflight());
  }
  else if(k=='W'){
   if(!watchdog_disabled||!i3_inventory_source_valid()){status("I3D_PUBLICATION_RUNTIME_OR_SOURCE_REFUSED",ERR(15));continue;}
   say("Continue with one missing DIMM inventory item, then verify it.\r\nExisting matching objects are reused. CPU is not recreated.\r\nPress W again to continue; any other key cancels. No automatic retry.\r\n");
   int confirm=key();if(confirm=='W'||confirm=='w'){
    status("I3D_INVENTORY_STEP",inventory_legacy71_step());
    status("I3D_INVENTORY_STATE",inventory_legacy71_state());status("I3D_INVENTORY_DONE_MASK",inventory_legacy71_completed_mask());
    status("I3D_INVENTORY_INDEXED_MASK",inventory_legacy71_indexed_mask());
    status("I3D_SUMMARY_STATE",inventory_legacy71_summary_state());
   }
  }
  else if(k=='S'){
   if(!watchdog_disabled||!i3_inventory_source_valid()){status("I3D_SUMMARY_RUNTIME_OR_SOURCE_REFUSED",ERR(15));continue;}
   say("Update System ProcessorSummary Count and Model, then verify it.\r\nPress S again to apply; any other key cancels. No automatic retry.\r\n");
   int confirm=key();if(confirm=='S'||confirm=='s'){
    status("I3D_SUMMARY_STEP",inventory_legacy71_summary_step());
    status("I3D_INVENTORY_STATE",inventory_legacy71_state());status("I3D_INVENTORY_DONE_MASK",inventory_legacy71_completed_mask());
    status("I3D_INVENTORY_INDEXED_MASK",inventory_legacy71_indexed_mask());
    status("I3D_SUMMARY_STATE",inventory_legacy71_summary_state());
   }
  }
 }
 logtext("SESSION_END\r\n");if(root){root->close(root);root=0;}
 say("HERO Inventory I3d RETURNING TO FIRMWARE\r\n");return 0;
}
