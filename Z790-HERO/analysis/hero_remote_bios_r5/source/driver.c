/* R5: one explicit NumLock transaction in the firmware's normal Setup phase.
 * Never changes NvLockMailbox, password protection, passwords, or SPI firmware.
 * A persistent, validated 64-byte journal is saved before a queued update.
 * A timer observes the existing lock; it never signals private firmware events.
 */
#include "phase.h"
static GUID phase_guid=PHASE_GUID_INIT;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID setup_guid={0xec87d643,0xeba4,0x4bb5,{0xa1,0xe5,0x3f,0x3e,0x36,0xb2,0x0d,0xa9}};
static GUID txn_guid={0x585b45c8,0x2c32,0x46b0,{0x8e,0x55,0x55,0x72,0x68,0x87,0xdd,0x6f}};
enum {IDLE,QUEUED,DEPARTED,ATTEMPTING,DONE,FAILED_STATE,CANCELLED,TIMED_OUT};
static HANDLE timer,installed_handle;
static uint32_t state,ticks,unlocked,operation,busy;
static TRANSACTION transaction;
static uint8_t before[SETUP_SIZE],after[SETUP_SIZE],verify[SETUP_SIZE];
static void record(const char *name,ES value){logtext(name);logtext("=");loghex(value,16);logtext("\r\n");}
static ES read_setup(uint8_t *b){UN n=SETUP_SIZE;uint32_t a=0;ES e=gST->rt->get_variable(W("Setup"),&setup_guid,&a,&n,b);return FAILED(e)?e:n==SETUP_SIZE&&a==7?0:ERR(33);}
static ES read_tx(TRANSACTION *t){UN n=sizeof(*t);uint32_t a=0;memset(t,0,sizeof(*t));ES e=gST->rt->get_variable(W("HeroRemoteBiosTxn"),&txn_guid,&a,&n,t);return FAILED(e)?e:n==sizeof(*t)&&a==3&&transaction_valid(t)&&t->setting==0?0:ERR(33);}
static ES clear_tx(void){ES e=gST->rt->set_variable(W("HeroRemoteBiosTxn"),&txn_guid,0,0,0);if(FAILED(e)&&e!=ERR(14))return e;TRANSACTION t;return read_tx(&t)==ERR(14)?0:ERR(7);}
static int target_ok(void){detect_board();return same(report.board,"ROG MAXIMUS Z790 HERO")&&same(report.bios,"3107");}
static int phase_is(const PHASE_STATE *p,uint64_t lock){return p->mailbox_status==0&&p->mailbox_attrs==2&&p->mailbox_size==8&&p->mailbox==lock&&p->boot_status==0&&p->boot_attrs==6&&p->boot_size==1&&p->boot_phase==0;}
static void stop_timer(void){if(timer)record("STOP_TIMER",gST->bs->set_timer(timer,0,0));}
static ES EA queue(uint32_t mode,uint32_t crc){
 if(busy||state!=IDLE||!target_ok()||(mode!=1&&mode!=2))return ERR(15);
 PHASE_STATE p;phase_read(&p);phase_log(&p);if(!phase_is(&p,1))return ERR(15);
 ES e=read_setup(before);if(FAILED(e))return e;
 if(probe_crc32(before,SETUP_SIZE)!=crc||before[3210]!=1||before[0]>1)return ERR(15);
 TRANSACTION check;e=read_tx(&check);
 if(mode==1){
  if(e!=ERR(14))return ERR(15);
  if(!prepare_update(before,SETUP_SIZE,0,1-before[0],crc,after,&transaction))return ERR(15);
  e=gST->rt->set_variable(W("HeroRemoteBiosTxn"),&txn_guid,3,sizeof(transaction),&transaction);record("SAVE_RECOVERY",e);if(FAILED(e))return e;
  e=read_tx(&check);if(FAILED(e)||!eq(&check,&transaction,sizeof(check)))return FAILED(e)?e:ERR(7);
 }else{
  if(FAILED(e))return e;transaction=check;
  int action=prepare_restore(before,SETUP_SIZE,&transaction,after);if(!action)return ERR(15);
  if(action==2){logtext("RESTORE_ALREADY_ORIGINAL\r\n");e=clear_tx();record("CLEAR_RECOVERY",e);state=FAILED(e)?FAILED_STATE:DONE;return e;}
 }
 e=read_setup(verify);if(FAILED(e)||!eq(before,verify,SETUP_SIZE))return FAILED(e)?e:ERR(15);
 operation=mode;ticks=0;unlocked=0;state=QUEUED;
 record("QUEUED_OPERATION",operation);record("BEFORE_CRC32",probe_crc32(before,SETUP_SIZE));record("AFTER_CRC32",probe_crc32(after,SETUP_SIZE));
 record("OLD_NUMLOCK",before[0]);record("NEW_NUMLOCK",after[0]);logtext("WAIT_FOR_APP_EXIT_AND_NATIVE_UNLOCK\r\n");return 0;
}
static ES EA depart(void){
 if(state!=QUEUED)return 0;state=DEPARTED;ticks=0;unlocked=0;
 ES e=gST->bs->set_timer(timer,1,5000000);record("DEPART_TIMER",e);if(FAILED(e))state=FAILED_STATE;return e;
}
static ES EA cancel(void){if(state==QUEUED||state==DEPARTED){state=CANCELLED;stop_timer();logtext("CANCELLED_RECOVERY_RETAINED\r\n");}return 0;}
static ES EA resume(void){logtext("APP_REENTERED\r\n");return cancel();}
static ES attempt(void){
 TRANSACTION check;ES e=read_tx(&check);if(FAILED(e)||!eq(&check,&transaction,sizeof(check)))return FAILED(e)?e:ERR(15);
 e=read_setup(verify);if(FAILED(e)||!eq(before,verify,SETUP_SIZE))return FAILED(e)?e:ERR(15);
 PHASE_STATE p;phase_read(&p);phase_log(&p);if(!phase_is(&p,0))return ERR(15);
 /* Exactly one ordinary SetVariable attempt; no bypass or automatic retries. */
 e=gST->rt->set_variable(W("Setup"),&setup_guid,7,SETUP_SIZE,after);record(operation==1?"SET_VARIABLE":"RESTORE_SET_VARIABLE",e);
 ES read=read_setup(verify);record("READBACK",read);
 if(!FAILED(read)){record("READBACK_CRC32",probe_crc32(verify,SETUP_SIZE));record("READBACK_NUMLOCK",verify[0]);}
 if(FAILED(e))return e;if(FAILED(read))return read;if(!eq(after,verify,SETUP_SIZE))return ERR(7);
 if(operation==1){logtext("APPLY_VERIFIED_EXACT_SINGLE_BYTE\r\n");return 0;}
 logtext("RESTORE_VERIFIED_EXACT_ORIGINAL\r\n");e=clear_tx();record("CLEAR_RECOVERY",e);return e;
}
static void EA on_timer(HANDLE event,void *context){
 (void)event;(void)context;if(busy||state!=DEPARTED)return;busy=1;++ticks;
 PHASE_STATE p;phase_read(&p);
 if(phase_is(&p,0))++unlocked;else unlocked=0;
 /* Two separate samples after application exit; no write in the app itself. */
 if(unlocked>=2){
  state=ATTEMPTING;record("NATIVE_UNLOCK_TICK",ticks);ES e=attempt();record("OPERATION_RESULT",e);state=FAILED(e)?FAILED_STATE:DONE;stop_timer();
 }else if(ticks>=600){state=TIMED_OUT;logtext("TIMEOUT_NO_WRITE_RECOVERY_RETAINED\r\n");stop_timer();}
 busy=0;
}
static ES EA sample(void){PHASE_STATE p;phase_read(&p);phase_log(&p);record("DRIVER_STATE",state);return 0;}
static ES EA snapshot(char *buffer,UN *size){
 if(!size)return ERR(2);UN old=gST->bs->raise_tpl(8);ES e=0;
 if(!buffer||*size<audit_len){*size=audit_len;e=ERR(5);}else{*size=audit_len;memcpy(buffer,audit,audit_len);}
 gST->bs->restore_tpl(old);return e;
}
static PHASE_API api={PHASE_MAGIC,1,sizeof(PHASE_API),0,0,sample,snapshot,queue,depart,resume,cancel};
static ES EA unload(HANDLE image){
 (void)image;if(busy)return ERR(15);cancel();
 if(timer){ES e=gST->bs->close_event(timer);if(FAILED(e))return e;timer=0;}
 if(installed_handle){ES e=gST->bs->uninstall_protocol(installed_handle,&phase_guid,&api);if(FAILED(e))return e;installed_handle=0;}return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);
 void *existing=0;ES e=gST->bs->locate_protocol(&phase_guid,0,&existing);if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 LOADED *loaded=0;e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded);if(FAILED(e)||!loaded)return ERR(14);
 if(loaded->options_size!=sizeof(uint32_t)||!loaded->options||*(uint32_t *)loaded->options!=PHASE_MAGIC)return ERR(3);
 loaded->unload=unload;api.image=image;logtext("HERO-R5-PHASE-CONFIG / NUMLOCK ONLY / EXPLICIT QUEUE\r\n");sample();
 e=gST->bs->create_event(0x80000200,8,on_timer,0,&timer);if(FAILED(e))return e;
 e=gST->bs->install_protocol(&installed_handle,&phase_guid,0,&api);if(FAILED(e)){if(FAILED(unload(image)))return 0;return e;}return 0;
}
