"""Create a separate capture-only source snapshot from the existing viewer."""
from pathlib import Path
import hashlib,json,shutil
P=Path(__file__).resolve().parent
ROOT=P.parents[2]
OLD=ROOT/'analysis/hero_ipmi_r2/source'
S=P/'source'
S.mkdir(parents=True,exist_ok=True)
for name in ('efi_min.h','r2.h','probe_core.h','kvm.h','compat','vendor'):
    src=OLD/name;dst=S/name
    if src.is_dir():shutil.copytree(src,dst,dirs_exist_ok=True)
    else:shutil.copy2(src,dst)
common='''#include "r2.h"
ST *gST;
GUID api_guid=API_GUID_INIT;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
'''
(S/'common.c').write_text(common,encoding='utf-8')
kvm=(OLD/'kvm.c').read_text()
kvm=kvm.replace('HERO IPMI R2 - KVM LOG','HERO RC3 AUTO LOG').replace('HERO IPMI R2 KVM - log capture','HERO RC3 AUTO LOG - capture only').replace('R2 log viewer closed.','RC3 log viewer closed.')
# Keep the already verified QR wire format to retain decoder compatibility.
(S/'kvm.c').write_text(kvm,encoding='utf-8')
source=(OLD/'launcher.c').read_text()
source=source[source.index('#include'):source.index('static int confirm(')]
source=source.replace('static FILEP *root,*file_log;','static FILEP *root,*file_log;\nstatic HANDLE current_image;')
source=source.replace('HERO-IPMI-R2-FULL','HERO-IPMI-RC3-AUTO-FULL').replace('HERO-IPMI-R2-SUMMARY','HERO-IPMI-RC3-AUTO-SUMMARY')
source=source.replace('char header[40]="HERO-IPMI-R2 FILE RUN="','char header[64]="HERO-IPMI-RC3 AUTO FILE RUN="')
source=source.replace('R2LOG000.TXT','R3LOG000.TXT')
source=source.replace('static ES open_log(void){','static ES mount_log_volume(void);\nstatic ES open_log(void){')
source=source.replace('if(file_log)return save_file();if(!root)return ERR(14);','if(file_log)return save_file();if(!root){ES mounted=mount_log_volume();if(FAILED(mounted))return mounted;}')
source=source.replace('add("FINAL requests=");','add("LAST_RUN_REPORT (lock may be unqueried) requests=");')
source=source.replace('say("Result: ");','say("Last run report (lock field may be unqueried).\\r\\n");\n say("Result: ");')
source+='''
/* The marked boot volume is opened only after explicit L. No disk scan. */
static ES mount_log_volume(void){
 LOADED *loaded=0;FS *fs=0;FILEP *volume=0,*marker=0;ES e;
 e=gST->bs->handle_protocol(current_image,&loaded_guid,(void **)&loaded);if(FAILED(e)||!loaded)return FAILED(e)?e:ERR(14);
 e=gST->bs->handle_protocol(loaded->device,&fs_guid,(void **)&fs);if(FAILED(e)||!fs)return FAILED(e)?e:ERR(14);
 e=fs->open_volume(fs,&volume);if(FAILED(e)||!volume)return FAILED(e)?e:ERR(14);
 e=volume->open(volume,&marker,W("\\\\HERO_RC3.TAG"),1,0);
 if(FAILED(e)||!marker){volume->close(volume);return FAILED(e)?e:ERR(14);}
 char b[32]={0};UN n=sizeof(b);e=marker->read(marker,&n,b);marker->close(marker);
 const char expected[]="HERO-IPMI-RC3-LOG\\r\\n";
 if(FAILED(e)||n!=sizeof(expected)-1||!eq(b,expected,n)){volume->close(volume);return FAILED(e)?e:ERR(15);}
 root=volume;return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;current_image=image;
 if(!gST||!gST->bs||!gST->rt||!gST->out||!gST->out->out||!gST->in||!gST->in->read)return ERR(2);
 say("HERO RC3 AUTO LOG / CAPTURE ONLY\\r\\n");
 gST->bs->set_watchdog(0,0,0,0);
 uint32_t low,high;__asm__ volatile("rdtsc":"=a"(low),"=d"(high));uint64_t token=((uint64_t)high<<32)|low;
 for(unsigned i=0;i<16;i++)run_id[i]="0123456789ABCDEF"[(token>>((15-i)*4))&15];run_id[16]=0;
 ES e=gST->bs->locate_protocol(&api_guid,0,(void **)&service);
 if(FAILED(e)||!service){
  say("RESIDENT R2 CORE NOT AVAILABLE. No driver will be loaded.\\r\\n");
  if(!FAILED(e))e=ERR(14);goto done;
 }
 if(service->version!=2||service->size!=sizeof(R2_API)||!service->log||!service->status||!service->config){
  say("Resident R2 API is incompatible. Capture stopped.\\r\\n");e=ERR(3);goto done;
 }
 if(service->manual_only){say("Manual-only R2 core found; this is not a firmware automatic run.\\r\\n");e=ERR(15);goto done;}
 say("RESIDENT_CORE_FOUND. Capturing existing boot audit only.\\r\\n");
 say("No initialization, hardware queries, configuration changes or retry keys.\\r\\n");
 summary();
 for(;;){
  say("\\r\\nC=summary QR; R=summary text; A=full QR; V=full text\\r\\n");
  say("L=USB file log; Q/Esc=exit. Save captures before restarting.\\r\\n");
  int k=key();if(k>='a'&&k<='z')k-=32;
  if(k<0){e=ERR(7);break;}if(k==27||k=='Q'){e=0;break;}
  if(k=='C'||k=='R'||k=='A'||k=='V'){
   ES s=make_snapshot(k=='A'||k=='V');if(!FAILED(s))s=kvm_present(gST,snapshot,snapshot_len,(k=='R'||k=='V')?2U:0U);
   status("Capture viewer: ",s);continue;
  }
  if(k=='L'){status("File log result: ",open_log());continue;}
  say("Capture-only key: use C/R/A/V/L or Q/Esc.\\r\\n");
 }
done:
 if(file_log){status("Final file log: ",save_file());file_log->close(file_log);file_log=0;}
 if(root){root->close(root);root=0;}
 status("Session result: ",e);say("Enter/Esc/Q = return to firmware.\\r\\n");
 for(;;){int k=key();if(k<0||k=='\\r'||k==27||k=='Q'||k=='q')break;}return e;
}
'''
(S/'launcher.c').write_text('/* RC3 resident audit capture. Never loads or runs a driver. */\n'+source,encoding='utf-8')
provenance={str(p.relative_to(OLD)):hashlib.sha256(p.read_bytes()).hexdigest() for p in OLD.rglob('*') if p.is_file() and (p.relative_to(OLD).parts[0] in ('compat','vendor') or p.name in ('efi_min.h','r2.h','probe_core.h','kvm.h','kvm.c','launcher.c'))}
(P/'source-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
print('Prepared capture-only source:',S)
