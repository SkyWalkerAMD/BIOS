/* Native HERO settings over a text/KVM console. Explicit, single-byte updates.
 * No donor DXE execution, firmware flash, password export, or SendForm calls.
 */
#include "settings.h"
#include "kvm.h"
/* HERO 3107 rejected the single native-Setup write in the 2026-11-02 live
 * test. Keep the distributed build read-only until the native save context
 * is understood. The tested write-enabled binary is archived separately. */
#define R3_NATIVE_WRITES_ENABLED 0
static GUID setup_guid={0xec87d643,0xeba4,0x4bb5,{0xa1,0xe5,0x3f,0x3e,0x36,0xb2,0x0d,0xa9}};
static GUID tse_guid={0xc811fa38,0x42c8,0x4579,{0xa9,0xbb,0x60,0xe9,0x4e,0xdd,0xfb,0x34}};
static GUID txn_guid={0x585b45c8,0x2c32,0x46b0,{0x8e,0x55,0x55,0x72,0x68,0x87,0xdd,0x6f}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static uint8_t displayed[SETUP_SIZE],before[SETUP_SIZE],after[SETUP_SIZE],verified[SETUP_SIZE];
static uint32_t displayed_crc;static int target_ok,display_ok,staged=-1,write_denied;static unsigned staged_value;
static FILEP *root,*file_log;static char snapshot[131072];
static void say(const char *s){C16 w[160];while(*s){unsigned n=0;while(*s&&n<159)w[n++]=(uint8_t)*s++;w[n]=0;gST->out->out(gST->out,w);}}
static void number(uint32_t n){char b[12];unsigned i=11;b[i]=0;do{b[--i]=(char)('0'+n%10);n/=10;}while(n);say(b+i);}
static void status(const char *name,ES e){logtext(name);logtext("=0x");loghex(e,16);logtext("\r\n");say(name);say("=0x");char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[16]=0;say(b);say("\r\n");}
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static int confirm(const char *s){say(s);say("\r\nEnter=confirm; any other key=cancel.\r\n");return key()=='\r';}
static ES read_setup(uint8_t *b){UN n=SETUP_SIZE;uint32_t a=0;ES e=gST->rt->get_variable(W("Setup"),&setup_guid,&a,&n,b);if(FAILED(e))return e;return n==SETUP_SIZE&&a==7?0:ERR(33);}
static ES read_tx(TRANSACTION *t){UN n=sizeof(*t);uint32_t a=0;memset(t,0,sizeof(*t));ES e=gST->rt->get_variable(W("HeroRemoteBiosTxn"),&txn_guid,&a,&n,t);if(FAILED(e))return e;return n==sizeof(*t)&&a==3&&transaction_valid(t)?0:ERR(33);}
static ES clear_tx(void){ES e=gST->rt->set_variable(W("HeroRemoteBiosTxn"),&txn_guid,0,0,0);if(FAILED(e)&&e!=ERR(14))return e;TRANSACTION t;return read_tx(&t)==ERR(14)?0:ERR(7);}
static ES save_tx(TRANSACTION *t){
 ES e=gST->rt->set_variable(W("HeroRemoteBiosTxn"),&txn_guid,3,sizeof(*t),t);if(FAILED(e))return e;
 TRANSACTION v;e=read_tx(&v);return FAILED(e)?e:eq(t,&v,sizeof(v))?0:ERR(7);
}
static ES post_dependency(void){
 uint8_t v[81];UN n=sizeof(v);uint32_t a=0;ES e=gST->rt->get_variable(W("AMITSESetup"),&tse_guid,&a,&n,v);
 if(FAILED(e))return e;if(n!=81||a!=7||v[80]>2)return ERR(33);return v[80]?0:ERR(15);
}
static ES save_file(void){
 if(!file_log)return ERR(14);ES e=file_log->set_position(file_log,0);if(FAILED(e))return e;
 UN n=audit_len;e=file_log->write(file_log,&n,audit);if(FAILED(e)||n!=audit_len)return FAILED(e)?e:ERR(7);return file_log->flush(file_log);
}
static ES open_log(void){
 if(file_log)return save_file();if(!root)return ERR(14);C16 name[]=L"\\R3LOG000.TXT";
 for(unsigned i=0;i<1000;i++){name[6]=(C16)('0'+i/100);name[7]=(C16)('0'+i/10%10);name[8]=(C16)('0'+i%10);FILEP *p=0;ES e=root->open(root,&p,name,1,0);
  if(!FAILED(e)){if(p)p->close(p);continue;}if(e!=ERR(14))return e;e=root->open(root,&file_log,name,0x8000000000000003ULL,0);return FAILED(e)?e:save_file();}return ERR(9);
}
static ES refresh(void){
 staged=-1;display_ok=0;detect_board();target_ok=same(report.board,"ROG MAXIMUS Z790 HERO")&&same(report.bios,"3107");
 say("\r\nBoard: ");say(report.board);say("   BIOS: ");say(report.bios);say("\r\n");
 logtext("BOARD=");logtext(report.board);logtext(" BIOS=");logtext(report.bios);logtext("\r\n");
 if(!target_ok){status("TARGET_MISMATCH_WRITES_DISABLED",ERR(3));return ERR(3);}
 ES e=read_setup(displayed);status("READ_SETUP",e);if(FAILED(e))return e;displayed_crc=probe_crc32(displayed,sizeof(displayed));
 logtext("SETUP_SIZE=0D46 CRC32=");loghex(displayed_crc,8);logtext("\r\n");
 for(unsigned i=0;i<3;i++){
  unsigned v=displayed[settings[i].offset];say(settings[i].name);say(" = ");number(v);say(i==2?" seconds\r\n":" (0=Off, 1=On)\r\n");
  logtext("SETTING ");loghex(i,2);logtext(" offset=");loghex(settings[i].offset,4);logtext(" value=");loghex(v,2);logtext("\r\n");
  if(!setting_valid(i,v)){status("UNEXPECTED_CURRENT_VALUE",ERR(33));return ERR(33);}
 }
 status("POST_DELAY_DEPENDENCY",post_dependency());
 TRANSACTION t;ES j=read_tx(&t);status("TRANSACTION_READ",j);
 if(!FAILED(j)){say("Recovery record: ");say(settings[t.setting].name);say(" ");number(t.old_value);say(" -> ");number(t.new_value);say(". R=restore; K=keep.\r\n");logtext("TX setting=");loghex(t.setting,2);logtext(" old=");loghex(t.old_value,2);logtext(" new=");loghex(t.new_value,2);logtext(" before=");loghex(t.before_crc,8);logtext(" after=");loghex(t.after_crc,8);logtext("\r\n");}
 else if(j!=ERR(14)){say("Invalid recovery record. Writes blocked.\r\n");return j;}
 display_ok=1;return 0;
}
static ES commit(void){
 if(!R3_NATIVE_WRITES_ENABLED||write_denied)return ERR(3);
 if(!target_ok||!display_ok||staged<0||!setting_valid((unsigned)staged,staged_value))return ERR(15);
 TRANSACTION t,v;ES e=read_tx(&v);if(e!=ERR(14))return ERR(15);
 if(staged==2&&FAILED(e=post_dependency()))return e;
 e=read_setup(before);if(FAILED(e))return e;
 if(!prepare_update(before,sizeof(before),(unsigned)staged,staged_value,displayed_crc,after,&t))return ERR(15);
 /* Persist only the one-byte recovery metadata, never a raw Setup/password dump. */
 e=save_tx(&t);status("SAVE_RECOVERY",e);if(FAILED(e))return e;
 e=read_setup(verified);if(FAILED(e)||!eq(before,verified,sizeof(before)))return ERR(15);
 logtext("APPLY setting=");loghex(t.setting,2);logtext(" old=");loghex(t.old_value,2);logtext(" new=");loghex(t.new_value,2);logtext("\r\n");
 e=gST->rt->set_variable(W("Setup"),&setup_guid,7,sizeof(after),after);status("SET_VARIABLE",e);if(e==ERR(26))write_denied=1;if(FAILED(e))return e;
 e=read_setup(verified);if(FAILED(e))return e;if(!eq(after,verified,sizeof(after)))return ERR(7);
 logtext("APPLY_VERIFIED_EXACT_SINGLE_BYTE\r\n");return 0;
}
static ES restore(int keep){
 if(!target_ok)return ERR(15);TRANSACTION t;ES e=read_tx(&t);if(FAILED(e))return e;e=read_setup(before);if(FAILED(e))return e;
 if(keep){if(probe_crc32(before,sizeof(before))!=t.after_crc||before[settings[t.setting].offset]!=t.new_value)return ERR(15);logtext("KEEP_VERIFIED_VALUE\r\n");return clear_tx();}
 int action=prepare_restore(before,sizeof(before),&t,after);if(!action)return ERR(15);
 if(action==1){if(!R3_NATIVE_WRITES_ENABLED||write_denied)return ERR(3);e=gST->rt->set_variable(W("Setup"),&setup_guid,7,sizeof(after),after);status("RESTORE_SET_VARIABLE",e);if(e==ERR(26))write_denied=1;if(FAILED(e))return e;}
 e=read_setup(verified);if(FAILED(e)||!eq(after,verified,sizeof(after)))return FAILED(e)?e:ERR(7);
 logtext("RESTORE_VERIFIED_EXACT_ORIGINAL\r\n");return clear_tx();
}
static void protocols(void){
 static struct {const char *name;GUID guid;} p[]={
 {"EFI_REST",{0x0db48a36,0x4e54,0xea9c,{0x9b,9,0x1e,0xa5,0xbe,0x3a,0x66,0x0b}}},
 {"HTTP_SERVICE_BINDING",{0xbdc8e6af,0xd9bc,0x4379,{0xa7,0x2a,0xe0,0xc4,0xe7,0x5d,0xae,0x1c}}},
 {"SIMPLE_NETWORK",{0xa19832b9,0xac25,0x11d3,{0x9a,0x2d,0,0x90,0x27,0x3f,0xc1,0x4d}}},
 {"HII_CONFIG_ROUTING",{0x587e72d7,0xcc50,0x4f79,{0x82,9,0xca,0x29,0x1f,0xc1,0xa1,0x0f}}}};
 for(unsigned i=0;i<sizeof(p)/sizeof(p[0]);i++){HANDLE *h=0;UN n=0;ES e=gST->bs->locate_handles(2,&p[i].guid,0,&n,&h);status(p[i].name,e);logtext("HANDLE_COUNT=");loghex(n,8);logtext("\r\n");if(h)gST->bs->free_pool(h);}
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt||!gST->in||!gST->out)return ERR(2);
 say("HERO Remote BIOS R3 - read-only native settings / KVM\r\n");gST->bs->set_watchdog(0,0,0,0);
 logtext("HERO-REMOTE-BIOS-R3\r\n");uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));logtext("RUN=");loghex(((uint64_t)high<<32)|low,16);logtext("\r\n");
 LOADED *loaded=0;FS *fs=0;FILEP *marker=0;char tag[24];UN size=sizeof(tag);
 if(!FAILED(gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))&&loaded&&!FAILED(gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs))&&fs&&!FAILED(fs->open_volume(fs,&root))&&root){
  ES e=root->open(root,&marker,W("\\HERO_R3.TAG"),1,0);
  if(!FAILED(e)&&marker){e=marker->read(marker,&size,tag);marker->close(marker);if(FAILED(e)||size!=15||!eq(tag,"HERO-REMOTE-R3\n",15)){root->close(root);root=0;}}
  else{root->close(root);root=0;}
 }
 refresh();protocols();say("Native writes disabled: HERO 3107 rejected the live write test.\r\nUse the original BIOS over remote KVM to change settings.\r\n");
 for(;;){
  say("\r\nD=read R=check/clear unchanged recovery record\r\n");
  say("C=QR V=text log L=file log Q/Esc=exit\r\n");int k=key();if(k>='a'&&k<='z')k-=32;if(k<0||k==27||k=='Q')break;
  if(k=='D')refresh();
  else if(k=='N'||k=='F'||k=='T'){
   if(!R3_NATIVE_WRITES_ENABLED||write_denied){say("Native writes disabled. Use the original BIOS over remote KVM.\r\n");continue;}
   if(!target_ok||!display_ok){say("Read/target check must pass first.\r\n");continue;}
   unsigned id=k=='N'?0:k=='F'?1:2;
   if(id==2&&FAILED(post_dependency())){say("POST delay requires a valid, enabled Boot Logo setting.\r\n");continue;}
   staged_value=staged==(int)id?(staged_value+1)%(settings[id].maximum+1):(displayed[settings[id].offset]+1)%(settings[id].maximum+1);staged=(int)id;
   say("STAGED ONLY: ");say(settings[id].name);say(" ");number(displayed[settings[id].offset]);say(" -> ");number(staged_value);say(". S=save; D=cancel/reload.\r\n");
  }else if(k=='S'){
   if(staged<0){say("No staged change.\r\n");continue;}
   if(confirm("Save this one setting to native BIOS NVRAM?")){ES e=commit();status("APPLY_RESULT",e);refresh();if(FAILED(e))say("Save failed. No automatic retry or restart. R checks recovery.\r\n");else say("Write verified. Restart to check BIOS; R restores the saved original.\r\n");}
  }else if(k=='R'||k=='K'){
   if(confirm(k=='R'?"Restore the single saved setting if the full Setup state matches?":"Keep the verified new value and remove its recovery record?")){status(k=='R'?"RESTORE_RESULT":"KEEP_RESULT",restore(k=='K'));refresh();}
  }else if(k=='C'||k=='V'){
   UN n=audit_len;memcpy(snapshot,audit,n);status("CAPTURE",kvm_present(gST,snapshot,n,k=='V'?2:0));
  }else if(k=='L')status("FILE_LOG",open_log());
  if(file_log)save_file();
 }
 logtext("SESSION_END\r\n");if(file_log){save_file();file_log->close(file_log);}if(root)root->close(root);
 say("Session ended. Enter/Esc/Q returns to firmware.\r\n");for(;;){int k=key();if(k<0||k=='\r'||k==27||k=='q'||k=='Q')break;}return 0;
}
