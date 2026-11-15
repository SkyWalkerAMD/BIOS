/* Fixed descriptor READ only. Intel 743845-001, pp.398-400 and pinned
 * Intel Linux hardware-sequencing implementation define these DWORD accesses.
 * MMIO control writes are NOT flash programming. No flash write/erase opcode,
 * permission write, unlock, FDOC, software sequencer or fallback exists here.
 * Any ambiguous start/completion ends the capture, without a second command.
 */
#include "fd_core.h"
#include <string.h>
#define STS 4U
#define ADDR 8U
#define DONE 1U
#define ERROR_BITS 6U
#define BUSY 0x20U
#define LOCK_STATE 0xe800U
#define GO_READ64 0x3f010000U
static const uint32_t protected_offsets[9]={0x0c,0x50,0x54,0x84,0x88,0x8c,0x90,0x94,0x98};

static ES fail(FD_RESULT *r,uint32_t stage,uint32_t offset,ES status){
 if(!r->failure_stage){r->failure_stage=stage;r->failure_offset=offset;r->failure_status=status;}
 return status;
}
static ES rd(FD_IO *io,FD_RESULT *r,uint32_t off,uint32_t *value){
 r->reads++;ES s=io->read32(io->context,off,value);
 return FAILED(s)?fail(r,1,off,s):0;
}
static ES wr(FD_IO *io,FD_RESULT *r,uint32_t off,uint32_t value){
 r->writes++;if(off==STS&&(value&0x10000))r->go_attempts++;
 ES s=io->write32(io->context,off,value);
 return FAILED(s)?fail(r,2,off,s):0;
}
/* The profile is deliberately restricted to the measured locked state.
 * Require reserved bits, SMI-enable and write-enable-type to remain zero.
 * Hardware returns FGO as zero. Error bits are never silently acknowledged.
 */
static int status_valid(uint32_t s,int allow_busy){
 return (s&0xffd8U)==LOCK_STATE && !(s&ERROR_BITS) &&
        !(s&0xc0e10000U) && ((s>>17)&15)<=8 && (allow_busy||!(s&BUSY));
}
static ES snapshot(FD_IO *io,FD_RESULT *r,uint32_t out[9]){
 for(unsigned i=0;i<9;i++)if(FAILED(rd(io,r,protected_offsets[i],out+i)))return r->failure_status;
 if(out[0]==0xffffffff||out[1]!=0x00004acf||out[2])return fail(r,3,0x50,ERR(15));
 for(unsigned i=3;i<9;i++)if(out[i])return fail(r,3,protected_offsets[i],ERR(15));
 return 0;
}
static ES same_snapshot(FD_IO *io,FD_RESULT *r,const uint32_t before[9]){
 uint32_t after[9];if(FAILED(snapshot(io,r,after)))return r->failure_status;
 for(unsigned i=0;i<9;i++)if(before[i]!=after[i])return fail(r,4,protected_offsets[i],ERR(15));
 return 0;
}
static ES get_idle(FD_IO *io,FD_RESULT *r,uint32_t *status){
 if(FAILED(rd(io,r,STS,status)))return r->failure_status;r->last_status=*status;
 if(!status_valid(*status,0))return fail(r,5,STS,ERR(15));return 0;
}
static ES ack_done(FD_IO *io,FD_RESULT *r,uint32_t *status){
 if(FAILED(get_idle(io,r,status)))return r->failure_status;
 if(*status&DONE){
  /* DWORD RMW retains every control/lock bit, FGO is zero, and writing
   * existing FDONE=1 acknowledges only completion. AEL/FCERR are already 0. */
  uint32_t expected=*status&~DONE;
  if(FAILED(wr(io,r,STS,*status))||FAILED(get_idle(io,r,status)))return r->failure_status;
  if(*status!=expected)return fail(r,6,STS,ERR(7));
 }
 return 0;
}
ES fd_capture(FD_IO *io,uint8_t *first,uint8_t *second,FD_RESULT *r){
 if(!io||!first||!second||first==second||!r||!io->read32||!io->write32||!io->stall||!io->binding)return ERR(2);
 memset(r,0,sizeof(*r));memset(first,0,4096);memset(second,0,4096);
 uint32_t before[9],s=0,original_address=0,original_status=0;
 if(!io->binding(io->context))return fail(r,7,0,ERR(15));
 if(FAILED(snapshot(io,r,before))||FAILED(get_idle(io,r,&s))||FAILED(rd(io,r,ADDR,&original_address)))return r->failure_status;
 if(original_address&0xf8000000U)return fail(r,8,ADDR,ERR(15));
 original_status=s;r->initial_hsfc=s;r->initial_faddr=original_address;
 for(unsigned pass=0;pass<2;pass++){
  uint8_t *out=pass?second:first;
  for(uint32_t address=0;address<4096;address+=64){
   if(!io->binding(io->context))return fail(r,7,address,ERR(15));
   if(FAILED(same_snapshot(io,r,before))||FAILED(ack_done(io,r,&s)))return r->failure_status;
   if(FAILED(wr(io,r,ADDR,address)))return r->failure_status;
   uint32_t check=0;if(FAILED(rd(io,r,ADDR,&check)))return r->failure_status;
   if(check!=address)return fail(r,9,ADDR,ERR(7));
   uint32_t current=0;if(FAILED(get_idle(io,r,&current)))return r->failure_status;
   if(current!=s)return fail(r,10,STS,ERR(15));
   /* Fixed FCYCLE=0, FDBC=63. Low protection fields retain exact measured
    * values; all other control/status bits are zero. Never copy stale FGO. */
   if(FAILED(wr(io,r,STS,GO_READ64|LOCK_STATE)))return r->failure_status;
   unsigned complete=0;
   for(unsigned poll=0;poll<10000;poll++){
    if(FAILED(rd(io,r,STS,&s)))return r->failure_status;r->last_status=s;r->poll_observations++;
    /* FD01 physically observed FGO=1 together with SCIP=1, contrary to the
     * manual's read-zero wording. Tolerate ONLY that exact error-free busy
     * value as a reason to read again. No MMIO write or data read occurs here.
     * Idle checks remain unchanged and completion still requires FGO=0. */
    if(s==0x3f01e820U)r->busy_fgo_observations++;
    else if(!status_valid(s,1)||(s&0xffff0000U)!=0x3f000000U||(s&(BUSY|DONE))==(BUSY|DONE))return fail(r,11,STS,ERR(7));
    if(!(s&BUSY)&&(s&DONE)){complete=1;break;}
    ES delay=io->stall(io->context,10);if(FAILED(delay))return fail(r,12,0,delay);
   }
   if(!complete)return fail(r,13,STS,ERR(18));
   if(FAILED(rd(io,r,ADDR,&check)))return r->failure_status;
   if(check!=address)return fail(r,14,ADDR,ERR(15));
   for(uint32_t i=0;i<16;i++){
    uint32_t word=0;if(FAILED(rd(io,r,0x10+4*i,&word)))return r->failure_status;
    memcpy(out+address+4*i,&word,4);
   }
   uint32_t end_status=0;if(FAILED(get_idle(io,r,&end_status)))return r->failure_status;
   if(end_status!=s)return fail(r,15,STS,ERR(15));
   if(FAILED(same_snapshot(io,r,before)))return r->failure_status;
   r->blocks++;
  }
  r->passes++;
 }
 /* Only a fully completed, known-idle capture may restore transient command
  * fields. Failure/timeout paths issue no further controller writes. */
 if(!io->binding(io->context))return fail(r,7,0,ERR(15));
 if(FAILED(ack_done(io,r,&s)))return r->failure_status;
 if(FAILED(wr(io,r,ADDR,original_address)))return r->failure_status;
 uint32_t addr_after=0;if(FAILED(rd(io,r,ADDR,&addr_after)))return r->failure_status;
 if(addr_after!=original_address)return fail(r,16,ADDR,ERR(7));
 if(FAILED(wr(io,r,STS,original_status&~DONE))||FAILED(get_idle(io,r,&s)))return r->failure_status;
 if(s!=(original_status&~DONE))return fail(r,17,STS,ERR(7));
 r->final_transients_restored=1;
 if(FAILED(same_snapshot(io,r,before)))return r->failure_status;r->protection_unchanged=1;
 for(unsigned i=0;i<4096;i++)if(first[i]!=second[i])return fail(r,18,i,ERR(7));
 uint32_t signature=0;memcpy(&signature,first+0x10,4);
 if(signature!=0x0ff0a55aU)return fail(r,19,0x10,ERR(7));
 return 0;
}
