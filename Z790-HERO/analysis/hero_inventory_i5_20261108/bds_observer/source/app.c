#include "i5.h"
#include "kvm.h"
#include "resident_image.h"
static GUID protocol=I5_API_GUID_INIT;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static FILEP *root;
static GUID witness_guid={0xc7805d12,0xaa9f,0x4d20,{0x93,0xea,0x16,0xb2,0xb9,0xe0,0x61,0x08}};
typedef struct {uint32_t magic,version,entries,preexisting;I5_API *api;uint32_t baseline_starts,baseline_runs;} WITNESS;
uint32_t probe_crc32(const void *,size_t);
void say(const char *s){
 if(!gST||!gST->out||!gST->out->out)return;
 C16 b[160];while(*s){unsigned n=0;while(*s&&n<159)b[n++]=(uint8_t)*s++;b[n]=0;gST->out->out(gST->out,b);}
}
void status(const char *n,ES e){logtext(n);logtext("=0x");loghex(e,16);logtext("\r\n");say(n);say("=0x");char h[17];for(unsigned i=0;i<16;i++)h[i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];h[16]=0;say(h);say("\r\n");}
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static void open_log_volume(HANDLE image){
 LOADED *li=0;FS *fs=0;FILEP *tag=0;char text[32];UN n=sizeof(text);
 if(FAILED(gST->bs->handle_protocol(image,&loaded_guid,(void **)&li))||!li||
    FAILED(gST->bs->handle_protocol(li->device,&fs_guid,(void **)&fs))||!fs||
    FAILED(fs->open_volume(fs,&root))||!root)return;
 ES e=root->open(root,&tag,W("\\HERO_I5N.TAG"),1,0);
 if(!FAILED(e)&&tag){e=tag->read(tag,&n,text);tag->close(tag);}
 const char expected[]="HERO-INVENTORY-I5N-BDS\n";
 if(FAILED(e)||!tag||n!=sizeof(expected)-1||!eq(text,expected,n)){root->close(root);root=0;}
}
static ES save_log(void){
 if(!root)return ERR(14);C16 name[]=L"\\I5N000.TXT";
 for(unsigned i=0;i<1000;i++){
  name[4]='0'+i/100;name[5]='0'+i/10%10;name[6]='0'+i%10;FILEP *p=0;
  ES e=root->open(root,&p,name,1,0);if(!FAILED(e)){if(p)p->close(p);continue;}if(e!=ERR(14))return e;
  e=root->open(root,&p,name,0x8000000000000003ULL,0);if(FAILED(e)||!p)return FAILED(e)?e:ERR(7);
  UN n=audit_len;e=p->write(p,&n,audit);if(!FAILED(e)&&n!=audit_len)e=ERR(7);if(!FAILED(e))e=p->flush(p);
  ES close=p->close(p);return !FAILED(e)&&FAILED(close)?close:e;
 }return ERR(9);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->out||!gST->in||!gST->in->read)return ERR(2);
 say("HERO Inventory I5n - PASSIVE TWO-ENTRY BDS OBSERVER\r\n");
 say("First entry installs the frozen I5D DriverBinding only.\r\n");
 say("Return to firmware, then launch this ISO again WITHOUT rebooting.\r\n");
 say("This launcher never calls ConnectController, run_once, or SignalEvent.\r\n");
 ES e=gST->bs->set_watchdog?gST->bs->set_watchdog(0,0,0,0):ERR(3);status("I5_APPLICATION_WATCHDOG_DISABLE",e);
 open_log_volume(image);
 I5_API *report_api=0;
 WITNESS *witness=0;int new_witness=0;
 if(!FAILED(e)){
  e=gST->bs->locate_protocol(&witness_guid,0,(void **)&witness);
  if(e==ERR(14)){
   e=gST->bs->allocate_pool(4,sizeof(WITNESS),(void **)&witness);
   if(!e&&witness){memset(witness,0,sizeof(*witness));witness->magic=0x4e354957;witness->version=1;HANDLE h=0;e=gST->bs->install_protocol(&h,&witness_guid,0,witness);if(e){gST->bs->free_pool(witness);witness=0;}else new_witness=1;}
  }
  if(e||!witness||witness->magic!=0x4e354957||witness->version!=1||witness->entries>1000){status("I5N_WITNESS_INVALID",e?e:ERR(33));goto menu;}
  witness->entries++;
  e=gST->bs->locate_protocol(&protocol,0,(void **)&report_api);
  if(new_witness&&e==0)witness->preexisting=1;
  if(e==ERR(14)){
   if(probe_crc32(resident_image,sizeof(resident_image))!=RESIDENT_CRC)e=ERR(33);
   else {HANDLE driver=0;e=gST->bs->load_image(0,image,0,(void *)resident_image,sizeof(resident_image),&driver);status("I5_DRIVER_LOAD",e);
    if(!FAILED(e)){say("Registering the resident DriverBinding; no explicit trigger.\r\n");e=gST->bs->start_image(driver,0,0);status("I5_DRIVER_START",e);}}
   if(!FAILED(e))e=gST->bs->locate_protocol(&protocol,0,(void **)&report_api);
  }
  if(!FAILED(e)&&report_api&&report_api->magic==I5_MAGIC&&report_api->version==2&&report_api->size==sizeof(I5_API)&&report_api->log&&report_api->log_bytes<sizeof(audit)-64){
   if(new_witness){witness->api=report_api;witness->baseline_starts=report_api->binding_starts;witness->baseline_runs=report_api->run_count;}
   else if(witness->api!=report_api){status("I5N_REPORT_CHANGED",ERR(33));goto menu;}
   audit_len=0;logtext("HERO-INVENTORY-I5N-BDS\r\n");memcpy(audit+audit_len,report_api->log,report_api->log_bytes);audit_len+=report_api->log_bytes;audit[audit_len]=0;
   status("I5N_LAUNCHER_ENTRY",witness->entries);status("I5N_PREEXISTING_DRIVER",witness->preexisting);
   status("I5N_BASELINE_STARTS",witness->baseline_starts);status("I5N_BASELINE_RUNS",witness->baseline_runs);
   status("I5_RESIDENT_STATE",report_api->state);status("I5_RESIDENT_RESULT",report_api->result);
   status("I5_RESIDENT_ENTRY_TPL",report_api->entry_tpl);
   status("I5_BINDING_STARTS",report_api->binding_starts);status("I5_CORE_RUNS",report_api->run_count);
   if(witness->preexisting||witness->baseline_starts||witness->baseline_runs)logtext("I5N_NOT_AN_UNTRIGGERED_BASELINE\r\n");
   else if(witness->entries>1&&report_api->binding_starts==1&&report_api->run_count==1)logtext("I5N_OBSERVED_AUTOMATIC_BINDING_AFTER_RETURN\r\n");
   else logtext("I5N_NO_AUTOMATIC_BINDING_OBSERVED_YET\r\n");
  }else status("I5_REPORT_UNAVAILABLE",FAILED(e)?e:ERR(33));
 }
menu:
 for(;;){
  say("\r\nC=QR capture V=text L=save new TXT file Q then Q=return to firmware\r\n");
  say("A fresh host reboot is required before the FIRST observation.\r\n");
  int k=key();if(k<0)break;if(k>='a'&&k<='z')k-=32;
  if(k=='C'||k=='V'){kvm_present(gST,audit,audit_len,k=='V'?2:0);continue;}
  if(k=='L'){status("I5_FILE_LOG",save_log());continue;}
  if(k=='Q'){say("Press Q again to return.\r\n");k=key();if(k=='Q'||k=='q')break;}
 }
 if(root)root->close(root);say("I5n returning to firmware. Resident driver retained until reset.\r\n");return 0;
}
