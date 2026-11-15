/* Explicit one-shot read-only inventory, RAM log and KVM export only. */
#include "collector.h"
#include "i4_collect.h"
#include "kvm.h"
static ST *st;
static char snapshot[SNAPSHOT_CAP],run[17];
static size_t used;static unsigned captured,overflow;
static ES watchdog=ERR(3);
static void say(const char *s){C16 w[160];while(*s){unsigned i=0;while(*s&&i<159)w[i++]=(uint8_t)*s++;w[i]=0;st->out->out(st->out,w);}}
static void show(const char *s,uint64_t v){char b[19]="0x";for(unsigned i=0;i<16;i++)b[2+i]="0123456789ABCDEF"[(v>>((15-i)*4))&15];b[18]=0;say(s);say(b);say("\r\n");}
static int key(void){for(;;){KEY k={0};ES e=st->in->read(st->in,&k);if(!FAILED(e))return k.scan==0x17?27:k.unicode;
 if(e!=ERR(6)||!st->in->wait||!st->bs->wait_for_event)return -1;UN n=0;if(FAILED(st->bs->wait_for_event(1,&st->in->wait,&n)))return -1;}}
static void add(const char *s){while(*s){if(used+1<sizeof(snapshot))snapshot[used++]=*s;else overflow=1;s++;}snapshot[used]=0;}
static void field(const char *name,uint64_t value){char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(value>>((15-i)*4))&15];b[16]=0;add(name);add("=");add(b);add("\r\n");}
static int append(void *user,const char *bytes,size_t length){(void)user;
 if(length>sizeof(snapshot)-512-used){overflow=1;return 0;}memcpy(snapshot+used,bytes,length);used+=length;snapshot[used]=0;return 1;
}
static ES collect(void){
 captured=1;used=0;overflow=0;add("HERO-PCIE-I4\r\nBUILD=I4-READONLY-1\r\nRUN=");add(run);add("\r\n");
 add("RAM SNAPSHOT: PCI config reads; BlockIo metadata; allowlisted DiskInfo Identify.\r\n");
 add("No PCI writes, BAR probing, Block reads/writes, PassThru, variables or driver loading.\r\n");
 field("UEFI_BOOT_WATCHDOG_DISABLE",watchdog);
 ES e=pcie_storage_collect(st,append,0);field("COLLECT_RETURN",e);field("LOG_OVERFLOW",overflow);
 field("CAPTURE_COMPLETE",!FAILED(e)&&!overflow);add("END I4 SNAPSHOT\r\n");return e;
}
ES EA efi_main(HANDLE image,ST *system){
 (void)image;st=system;if(!st||!st->out||!st->out->out)return ERR(2);
 say("HERO PCIe I4 - FIRST TEXT / WAITING FOR D\r\n");
 say("Read-only device catalogue. RAM log only. D starts once; Q then Q exits.\r\n");
 if(!st->bs||!st->in||!st->in->read){say("Input/boot services unavailable.\r\n");return ERR(2);}
 if(st->bs->set_watchdog)watchdog=st->bs->set_watchdog(0,0,0,0);show("UEFI boot watchdog disable: ",watchdog);
 uint32_t lo,hi;__asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));uint64_t stamp=((uint64_t)hi<<32)|lo;
 for(unsigned i=0;i<16;i++)run[i]="0123456789ABCDEF"[(stamp>>((15-i)*4))&15];run[16]=0;
 ES result=0;
 for(;;){
  say(captured?"\r\nC=QR; R=text. Q then Q=return to firmware.\r\n":"\r\nD=capture once. Q then Q=return to firmware.\r\n");
  int k=key();if(k>='a'&&k<='z')k-=32;if(k<0){result=ERR(7);break;}
  if(k=='Q'){say("Press Q again to return to firmware. Any other key cancels.\r\n");int confirm=key();if(confirm=='Q'||confirm=='q')break;continue;}
  if(k=='D'){
   if(captured){say("Snapshot already captured; original bytes retained.\r\n");continue;}
   if(FAILED(watchdog)){say("Capture held: boot watchdog disable did not succeed.\r\n");continue;}
   say("I4_READONLY_CAPTURE_BEGIN\r\n");result=collect();show("Collection status: ",result);show("Export bytes: ",used);
   say(!FAILED(result)&&!overflow?"I4_CAPTURE_READY. Optional interfaces may be absent; retain complete log.\r\n":"I4_CAPTURE_INCOMPLETE. Export retained diagnostic bytes with C or R.\r\n");continue;
  }
  if((k=='C'||k=='R')&&captured){show("Capture viewer: ",kvm_present(st,snapshot,used,(k=='R'?2U:0U)|(overflow?1U:0U)));continue;}
  say("Use D, C, R, or Q. Enter/Esc do not exit this application.\r\n");
 }
 say("HERO PCIe I4 RETURNING TO FIRMWARE\r\n");return result;
}
