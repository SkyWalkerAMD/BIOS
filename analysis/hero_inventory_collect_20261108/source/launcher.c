/* Read-only SMBIOS inventory. Only explicit L writes a new marked-USB file.
 * No BMC, PCI, variable, watchdog, reset, driver-loading or protocol-install API.
 */
#include "collector.h"
#include "kvm.h"
static ST *gST;
static GUID sm3={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID sm2={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static HANDLE current_image;
static FILEP *root;
static uint8_t raw[TABLE_CAP],entry3[64],entry2[64];
static char snapshot[SNAPSHOT_CAP],run_id[17];
static UN snapshot_len;
static unsigned snapshot_bad,captured,valid,entry3_len,entry2_len;
static SM_ENTRY info3,info2,chosen;
static SM_TABLE metadata,second;
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
static void bytes(const uint8_t *p,UN n){for(UN i=0;i<n;i++){hex(p[i],2);if((i%32)==31||i+1==n)add("\r\n");}}
static int read_entry(const uint8_t *p,unsigned kind,uint8_t *copy,unsigned *length,SM_ENTRY *info){
 *length=0;if(!p)return SM_ADDRESS;
 unsigned n=p[kind==3?6:5],minimum=kind==3?24:31;
 if(n<minimum||n>64){memcpy(copy,p,8);*length=8;return SM_LENGTH;}
 memcpy(copy,p,n);*length=n;return smbios_entry(copy,n,kind,info);
}
static int copy_table(const SM_ENTRY *e){
 const uint8_t *p=(const uint8_t *)(UN)e->address;
 int check=smbios_table(p,e->bound,e->count,&metadata);if(check)return check;
 memcpy(raw,p,metadata.used);
 check=smbios_table(raw,metadata.used,e->count,&second);
 if(check||second.used!=metadata.used||second.count!=metadata.count||second.crc!=metadata.crc)return SM_CHANGED;
 chosen=*e;return SM_OK;
}
static ES collect(void){
 snapshot_len=0;snapshot_bad=0;valid=0;captured=1;
 add("HERO-SMBIOS-I1\r\nRUN=");add(run_id);add("\r\n");
 add("READ_ONLY firmware SMBIOS; no BMC, PCI, variable or reset calls.\r\n");
 const uint8_t *p3=0,*p2=0;unsigned count3=0,count2=0;
 int e3=SM_ADDRESS,e2=SM_ADDRESS,t3=SM_ADDRESS,t2=SM_ADDRESS;
 if(!gST->tables||!gST->table_count||gST->table_count>1024){field("CONFIG_TABLE_ERROR",SM_ARGUMENT,8);goto finish;}
 for(UN i=0;i<gST->table_count;i++){
  CT *t=&gST->tables[i];
  if(eq(&t->guid,&sm3,16)){count3++;p3=t->table;}
  if(eq(&t->guid,&sm2,16)){count2++;p2=t->table;}
 }
 field("ENTRY3_MATCHES",count3,8);field("ENTRY2_MATCHES",count2,8);
 if(count3==1)e3=read_entry(p3,3,entry3,&entry3_len,&info3);
 if(count2==1)e2=read_entry(p2,2,entry2,&entry2_len,&info2);
 field("ENTRY3_STATUS",e3,8);field("ENTRY3_BYTES",entry3_len,8);add("ENTRY3_HEX_BEGIN\r\n");bytes(entry3,entry3_len);add("ENTRY3_HEX_END\r\n");
 field("ENTRY2_STATUS",e2,8);field("ENTRY2_BYTES",entry2_len,8);add("ENTRY2_HEX_BEGIN\r\n");bytes(entry2,entry2_len);add("ENTRY2_HEX_END\r\n");
 if(!e3)t3=copy_table(&info3);
 if(!t3)valid=1;
 else if(!e2){t2=copy_table(&info2);if(!t2)valid=1;}
 field("TABLE3_STATUS",t3,8);field("TABLE2_STATUS",t2,8);
 if(valid){
  field("SOURCE_KIND",chosen.kind,2);field("MAJOR",chosen.major,2);field("MINOR",chosen.minor,2);field("DOCREV",chosen.docrev,2);
  field("TABLE_ADDRESS",chosen.address,16);field("TABLE_BOUND",chosen.bound,8);field("TABLE_USED",metadata.used,8);
  field("STRUCTURES",metadata.count,8);field("TYPE127_OFFSET",metadata.end_offset,8);field("TABLE_CRC32",metadata.crc,8);
  const uint8_t types[]={0,1,2,3,4,9,16,17,41,127};
  for(unsigned i=0;i<sizeof(types);i++){add("TYPE_");hex(types[i],2);add("_COUNT=");hex(metadata.types[types[i]],8);add("\r\n");}
  add("TABLE_HEX_BEGIN\r\n");bytes(raw,metadata.used);add("TABLE_HEX_END\r\n");
 }
finish:
 field("CAPTURE_VALID",valid,2);add("END SMBIOS SNAPSHOT\r\n");
 if(snapshot_bad)return ERR(5);return valid?0:ERR(33);
}
static ES mount_log_volume(void){
 LOADED *loaded=0;FS *fs=0;FILEP *volume=0,*marker=0;ES e;
 e=gST->bs->handle_protocol(current_image,&loaded_guid,(void **)&loaded);if(FAILED(e)||!loaded)return FAILED(e)?e:ERR(14);
 e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs);if(FAILED(e)||!fs)return FAILED(e)?e:ERR(14);
 e=fs->open_volume(fs,&volume);if(FAILED(e)||!volume)return FAILED(e)?e:ERR(14);
 e=volume->open(volume,&marker,W("\\HERO_INV.TAG"),1,0);
 if(FAILED(e)||!marker){volume->close(volume);return FAILED(e)?e:ERR(14);}
 char b[32]={0};UN n=sizeof(b);e=marker->read(marker,&n,b);marker->close(marker);
 const char expected[]="HERO-SMBIOS-I1\r\n";
 if(FAILED(e)||n!=sizeof(expected)-1||!eq(b,expected,n)){volume->close(volume);return FAILED(e)?e:ERR(15);}
 root=volume;return 0;
}
static ES save_new_file(void){
 if(!captured||snapshot_bad||!snapshot_len)return ERR(6);
 ES e=0;if(!root){e=mount_log_volume();if(FAILED(e))return e;}
 C16 name[]=L"\\INV000.TXT";
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
 say("HERO SMBIOS I1 - FIRST TEXT / WAITING FOR S\r\n");
 say("Inventory capture only. S starts; Enter/Esc do nothing. Q then Q exits.\r\n");
 if(!gST->bs||!gST->in||!gST->in->read){say("Input/boot services missing.\r\n");return ERR(2);}
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));uint64_t token=((uint64_t)high<<32)|low;
 for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
 ES result=0;
 for(;;){
  say(captured?"\r\nC=raw QR; R=raw text; L=marked USB file. Q then Q=exit.\r\n":"\r\nS=capture SMBIOS. Q then Q=exit.\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){result=ERR(7);break;}
  if(k=='Q'){say("Press Q again to return to firmware. Any other key cancels.\r\n");int confirm=key();if(confirm=='Q'||confirm=='q')break;continue;}
  if(k=='S'){
   if(captured){say("Snapshot already captured; original bytes retained.\r\n");continue;}
   say("SMBIOS_READ_BEGIN\r\n");result=collect();status("SMBIOS capture status: ",result);
   status("Raw table bytes: ",valid?metadata.used:0);status("Export bytes: ",snapshot_len);
   say(valid?"SMBIOS_CAPTURE_READY. C exports QR; R exports text.\r\n":"SMBIOS_CAPTURE_INCOMPLETE. C/R preserve diagnostic metadata.\r\n");continue;
  }
  if((k=='C'||k=='R')&&captured&&!snapshot_bad){ES e=kvm_present(gST,snapshot,snapshot_len,k=='R'?2U:0U);status("Capture viewer: ",e);continue;}
  if(k=='L'&&captured){status("File log result: ",save_new_file());continue;}
  say("Use S, C, R, L, or Q. Enter/Esc do not exit this application.\r\n");
 }
 if(root){root->close(root);root=0;}say("HERO SMBIOS I1 RETURNING TO FIRMWARE\r\n");return result;
}
