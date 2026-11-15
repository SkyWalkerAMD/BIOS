/* Read-only HERO protection-state diagnostics over a text/KVM console.
 * No configuration writes, donor DXE execution, firmware flash or SendForm.
 */
#include "phase.h"
#include "kvm.h"
static GUID setup_guid={0xec87d643,0xeba4,0x4bb5,{0xa1,0xe5,0x3f,0x3e,0x36,0xb2,0x0d,0xa9}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static uint8_t displayed[SETUP_SIZE];
static HANDLE app_image;
static FILEP *root,*file_log;static char snapshot[131072];
static void say(const char *s){C16 w[160];while(*s){unsigned n=0;while(*s&&n<159)w[n++]=(uint8_t)*s++;w[n]=0;gST->out->out(gST->out,w);}}
static void number(uint32_t n){char b[12];unsigned i=11;b[i]=0;do{b[--i]=(char)('0'+n%10);n/=10;}while(n);say(b+i);}
static void status(const char *name,ES e){logtext(name);logtext("=0x");loghex(e,16);logtext("\r\n");say(name);say("=0x");char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(e>>((15-i)*4))&15];b[16]=0;say(b);say("\r\n");}
static int key(void){for(;;){KEY k;ES e=gST->in->read(gST->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;if(e!=ERR(6))return -1;UN index;if(FAILED(gST->bs->wait_for_event(1,&gST->in->wait,&index)))return -1;}}
static ES read_setup(uint8_t *b){UN n=SETUP_SIZE;uint32_t a=0;ES e=gST->rt->get_variable(W("Setup"),&setup_guid,&a,&n,b);if(FAILED(e))return e;return n==SETUP_SIZE&&a==7?0:ERR(33);}
static ES save_file(void){
 if(!file_log)return ERR(14);ES e=file_log->set_position(file_log,0);if(FAILED(e))return e;
 UN n=audit_len;e=file_log->write(file_log,&n,audit);if(FAILED(e)||n!=audit_len)return FAILED(e)?e:ERR(7);return file_log->flush(file_log);
}
static ES open_log(void){
 if(file_log)return save_file();if(!root)return ERR(14);C16 name[]=L"\\R4LOG000.TXT";
 for(unsigned i=0;i<1000;i++){name[6]=(C16)('0'+i/100);name[7]=(C16)('0'+i/10%10);name[8]=(C16)('0'+i%10);FILEP *p=0;ES e=root->open(root,&p,name,1,0);
  if(!FAILED(e)){if(p)p->close(p);continue;}if(e!=ERR(14))return e;e=root->open(root,&file_log,name,0x8000000000000003ULL,0);return FAILED(e)?e:save_file();}return ERR(9);
}
static GUID observer_guid=PHASE_GUID_INIT;
static PHASE_API *observer;
static char observer_log[65536];
static ES find_observer(void){
 observer=0;ES e=gST->bs->locate_protocol(&observer_guid,0,(void **)&observer);if(FAILED(e))return e;
 if(!observer||observer->magic!=PHASE_MAGIC||observer->version!=1||observer->size!=sizeof(PHASE_API)||!observer->image||!observer->sample||!observer->snapshot){observer=0;return ERR(33);}return 0;
}
static ES history(void){
 ES e=find_observer();if(FAILED(e))return e;UN n=sizeof(observer_log)-1;e=observer->snapshot(observer_log,&n);if(FAILED(e)||n>=sizeof(observer_log))return FAILED(e)?e:ERR(33);
 observer_log[n]=0;logtext("OBSERVER_SNAPSHOT_BEGIN\r\n");logtext(observer_log);logtext("OBSERVER_SNAPSHOT_END\r\n");say(observer_log);return 0;
}
static ES load_observer(void){
 ES e=find_observer();if(e!=ERR(14))return FAILED(e)?e:ERR(20);if(!root)return ERR(14);
 FILEP *f=0;e=root->open(root,&f,W("\\EFI\\BOOT\\H4OBS.EFI"),1,0);if(FAILED(e)||!f)return FAILED(e)?e:ERR(14);
 uint8_t *bytes=0;UN n=131072;e=gST->bs->allocate_pool(4,n,(void **)&bytes);if(FAILED(e)){f->close(f);return e;}
 e=f->read(f,&n,bytes);f->close(f);if(FAILED(e)||n<512||n>=131072){gST->bs->free_pool(bytes);return FAILED(e)?e:ERR(33);}
 HANDLE child=0;e=gST->bs->load_image(0,app_image,0,bytes,n,&child);gST->bs->free_pool(bytes);if(FAILED(e))return e;
 LOADED *loaded=0;e=gST->bs->handle_protocol(child,&loaded_guid,(void **)&loaded);
 if(FAILED(e)||!loaded){gST->bs->unload_image(child);return FAILED(e)?e:ERR(14);}
 uint32_t marker=PHASE_MAGIC;loaded->options=&marker;loaded->options_size=sizeof(marker);
 e=gST->bs->start_image(child,0,0);loaded->options=0;loaded->options_size=0;
 if(FAILED(e)){gST->bs->unload_image(child);return e;}return find_observer();
}
static void locate(const char *name,GUID guid){
 void *p=0;status(name,gST->bs->locate_protocol(&guid,0,&p));
}
static void refresh(void){
 detect_board();say("\r\nBoard: ");say(report.board);say(" BIOS: ");say(report.bios);say("\r\n");
 logtext("BOARD=");logtext(report.board);logtext(" BIOS=");logtext(report.bios);logtext("\r\n");
 if(same(report.board,"ROG MAXIMUS Z790 HERO")&&same(report.bios,"3107")){
  ES e=read_setup(displayed);status("READ_SETUP",e);
  if(!FAILED(e)){
   logtext("SETUP_CRC32=");loghex(probe_crc32(displayed,SETUP_SIZE),8);logtext("\r\n");
   say("NumLock=");number(displayed[0]);say(" F1Wait=");number(displayed[3293]);say(" POSTDelay=");number(displayed[3291]);say("\r\n");
   logtext("NUMLOCK=");loghex(displayed[0],2);logtext(" F1WAIT=");loghex(displayed[3293],2);logtext(" POSTDELAY=");loghex(displayed[3291],2);logtext("\r\n");
   say("Runtime variable password protection (Setup 0C8A)=");number(displayed[3210]);say("\r\n");
   logtext("RUNTIME_VARIABLE_PASSWORD_PROTECTION=");loghex(displayed[3210],2);logtext("\r\n");
  }
 }else status("SETUP_MAPPING_SKIPPED_WRONG_BOARD_OR_VERSION",ERR(3));
 PHASE_STATE p;phase_read(&p);phase_log(&p);say("NvLockMailbox status=");number((uint32_t)p.mailbox_status);say(" value=");number((uint32_t)p.mailbox);say("\r\n");
 say("AuthVarPreBootPhase status=");number((uint32_t)p.boot_status);say(" value=");number(p.boot_phase);say("\r\n");
 locate("EDKII_VARIABLE_LOCK",(GUID){0xcd3d0a05,0x9e24,0x437c,{0xa8,0x91,0x1e,0xe0,0x53,0xdb,0x76,0x38}});
 locate("EDKII_VARIABLE_POLICY",(GUID){0x81d1675c,0x86f6,0x48df,{0xbd,0x95,0x9a,0x6e,0x4f,0x09,0x25,0xc3}});
 HANDLE *handles=0;UN count=0;
 ES e=gST->bs->locate_handles(2,&loaded_guid,0,&count,&handles);
 UN address=(UN)gST->rt->set_variable;logtext("SET_VARIABLE_POINTER=");loghex(address,16);logtext("\r\n");
 if(!FAILED(e)&&count<=2048)for(UN i=0;i<count;i++){
  LOADED *li=0;if(FAILED(gST->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li))||!li)continue;
  UN base=(UN)li->image_base;if(address>=base&&address-base<li->image_size){logtext("SET_VARIABLE_OWNER_BASE=");loghex(base,16);logtext(" RVA=");loghex(address-base,8);logtext(" SIZE=");loghex(li->image_size,8);logtext("\r\n");}
 }
 if(handles)gST->bs->free_pool(handles);status("OBSERVER_PRESENT",find_observer());
}
ES EA efi_main(HANDLE image,ST *system){
 app_image=image;gST=system;if(!gST||!gST->bs||!gST->rt||!gST->out||!gST->in)return ERR(2);
 say("HERO Remote BIOS R4 - READ-ONLY PHASE OBSERVER\r\n");gST->bs->set_watchdog(0,0,0,0);
 logtext("HERO-REMOTE-BIOS-R4\r\n");uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));logtext("RUN=");loghex(((uint64_t)high<<32)|low,16);logtext("\r\n");
 LOADED *loaded=0;FS *fs=0;FILEP *marker=0;char tag[24];UN size=sizeof(tag);
 if(!FAILED(gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))&&loaded&&!FAILED(gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs))&&fs&&!FAILED(fs->open_volume(fs,&root))&&root){
  ES e=root->open(root,&marker,W("\\HERO_R4.TAG"),1,0);
  if(!FAILED(e)&&marker){e=marker->read(marker,&size,tag);marker->close(marker);if(FAILED(e)||size!=15||!eq(tag,"HERO-REMOTE-R4\n",15)){root->close(root);root=0;}}else{root->close(root);root=0;}
 }
 refresh();if(!FAILED(find_observer()))status("HISTORY_ON_REENTRY",history());
 say("No settings, protection flags, passwords or firmware are written.\r\n");
 say("O loads a 5-minute observer. Q returns to BIOS with observer in RAM.\r\nReboot clears it. To collect: boot this tool again, H, C; U unloads.\r\n");
 for(;;){
  say("\r\nD=read O=load observer H=history U=unload C=QR V=text L=file Q/Esc=exit\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;if(k<0||k==27||k=='Q')break;
  if(k=='D'){refresh();if(!FAILED(find_observer()))status("OBSERVER_SAMPLE",observer->sample());}
  else if(k=='O')status("OBSERVER_LOAD",load_observer());
  else if(k=='H')status("OBSERVER_HISTORY",history());
  else if(k=='U'){ES e=find_observer();if(!FAILED(e)){history();HANDLE h=observer->image;observer=0;e=gST->bs->unload_image(h);}status("OBSERVER_UNLOAD",e);}
  else if(k=='C'||k=='V'){UN n=audit_len;memcpy(snapshot,audit,n);status("CAPTURE",kvm_present(gST,snapshot,n,k=='V'?2:0));}
  else if(k=='L')status("FILE_LOG",open_log());
  if(file_log)save_file();
 }
 logtext("SESSION_END\r\n");if(file_log){save_file();file_log->close(file_log);}if(root)root->close(root);
 say("Session ended. Enter/Esc/Q returns to firmware; observer stays if loaded.\r\n");
 for(;;){int k=key();if(k<0||k=='\r'||k==27||k=='q'||k=='Q')break;}return 0;
}
