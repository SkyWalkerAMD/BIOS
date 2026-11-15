#include "p1.h"
#include "kvm.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID service_guid=P1_API_GUID;
static P1_API *service;
static FILEP *root,*file_log;
static void say(const char *s){C16 w[160];while(*s){unsigned i=0;while(*s&&i<159)w[i++]=(uint8_t)*s++;w[i]=0;gST->out->out(gST->out,w);}}
static void status(const char *label,ES e){char s[19]="0x";for(unsigned i=0;i<16;i++)s[2+i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];s[18]=0;say(label);say(s);say("\r\n");}
static int key(void){KEY k;for(;;){ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static ES save_file(void){
 if(!file_log)return ERR(14);UN n=0;const char *s=service->log(&n);if(!s||n>=131072)return ERR(4);
 ES e=file_log->set_position(file_log,0);if(FAILED(e))return e;UN size=n;e=file_log->write(file_log,&size,(void *)s);
 if(FAILED(e)||size!=n)return FAILED(e)?e:ERR(7);return file_log->flush(file_log);
}
static ES open_log(void){
 if(file_log)return save_file();C16 path[]=L"\\P1LOG000.TXT";
 for(unsigned i=0;i<1000;i++){
  path[6]=(C16)('0'+i/100);path[7]=(C16)('0'+i/10%10);path[8]=(C16)('0'+i%10);
  FILEP *test=0;ES e=root->open(root,&test,path,1,0);
  if(!FAILED(e)){if(test)test->close(test);continue;}if(e!=ERR(14))return e;
  e=root->open(root,&file_log,path,0x8000000000000003ULL,0);if(FAILED(e)||!file_log)return FAILED(e)?e:ERR(7);
  return save_file();
 }return ERR(9);
}
static void row(const char *name,unsigned id){say(name);say(": ");const char *v=service->value(id);say(v?v:"Unavailable");say("\r\n");}
static void summary(void){
 row("Self test",V_SELFTEST);row("BMC firmware",V_FIRMWARE);row("Watchdog",V_WDT_RUNNING);
 row("LAN channel",V_CHANNEL);row("Address source",V_SOURCE);row("IP address",V_IP);row("Subnet",V_MASK);row("Gateway",V_GATEWAY);
 row("SEL entries",V_SEL_COUNT);row("SEL view",V_SEL_RANGE);row("Result",V_RESULT);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt||!gST->out||!gST->in)return ERR(2);
 say("HERO IPMI P1 - Native BIOS menu / read-only functions\r\n");gST->bs->set_watchdog(0,0,0,0);
 LOADED *loaded=0;FS *fs=0;FILEP *f=0;void *buffer=0;HANDLE child=0;int owns=0,leave=0,connected=0;ES e=ERR(7);
 if(FAILED(e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))||!loaded)goto done;
 if(FAILED(e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs))||!fs)goto done;
 if(FAILED(e=fs->open_volume(fs,&root))||!root)goto done;
 if(FAILED(e=root->open(root,&f,W("\\HERO_P1.TAG"),1,0))||!f)goto done;
 char tag[20]={0};UN n=sizeof(tag);e=f->read(f,&n,tag);f->close(f);f=0;
 if(FAILED(e)||n!=14||!eq(tag,"HERO-IPMI-P1\r\n",14)){e=ERR(15);goto done;}
 e=gST->bs->locate_protocol(&service_guid,0,(void **)&service);
 if(e==ERR(14)){
  if(FAILED(e=root->open(root,&f,W("\\EFI\\HERO\\HeroIpmiP1.efi"),1,0))||!f)goto done;
  if(FAILED(e=gST->bs->allocate_pool(4,1048576,&buffer))||!buffer)goto done;
  n=1048576;e=f->read(f,&n,buffer);f->close(f);f=0;if(FAILED(e)||n<512||n==1048576){e=ERR(4);goto done;}
  if(FAILED(e=gST->bs->load_image(0,image,0,buffer,n,&child)))goto done;owns=1;
  e=gST->bs->start_image(child,0,0);if(FAILED(e)){owns=0;goto done;}
  e=gST->bs->locate_protocol(&service_guid,0,(void **)&service);
 }
 if(FAILED(e)||!service||service->version!=1||service->size!=sizeof(P1_API)||!service->refresh||!service->log||!service->value){e=ERR(3);goto done;}
 connected=1;say("P1_HII_READY. No hardware query on load.\r\n");
 for(;;){
  say("\r\nD=read BMC; N=return with native menu registered; L=USB file log\r\nC=QR log; R=text log; Q/Esc=unload and return\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){e=ERR(7);break;}if(k==27||k=='Q'){e=0;break;}
  if(k=='N'){leave=1;e=0;break;}
  if(k=='D'){say("Reading the expansion card...\r\n");status("Refresh status: ",service->refresh());summary();if(file_log)status("Log save: ",save_file());}
  if(k=='L')status("Log save: ",open_log());
  if(k=='C'||k=='R'){UN n=0;const char *s=service->log(&n);if(s&&n<131072)status("Capture: ",kvm_present(gST,s,n,k=='R'?2U:0U));}
 }
done:
 if(file_log){save_file();file_log->close(file_log);}if(f)f->close(f);if(root)root->close(root);if(buffer)gST->bs->free_pool(buffer);
 if(owns&&!leave){ES u=gST->bs->unload_image(child);status("Unload: ",u);if(FAILED(u)&&!FAILED(e))e=u;}
 if(leave)say("Menu remains in RAM until reset. Returning to firmware.\r\n");
 else if(!connected){status("P1 load failed: ",e);say("Enter/Esc to return.\r\n");key();}
 return e;
}
