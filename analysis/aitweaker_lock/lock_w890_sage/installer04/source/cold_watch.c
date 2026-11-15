#include "cold_watch.h"
#include "../../password/core/password_core.h"
struct CW_TICKET {uint64_t marker,sequence;HANDLE handle;LOADED *loaded;LOADED snapshot;uintptr_t notify_frame;};
static struct {
 ST *st;BS *bs;EVENT event,end;void *registration;I04_VM vm;
 CW_CONSUMER consumer;uint32_t phase,busy;uint64_t sequence;
 void *methods[7];uint32_t pinned;
 HANDLE baseline[4096];UN baseline_count;struct CW_TICKET ticket;
} w;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID tse_guid={0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}};
static const uint8_t text_hash[32]={0xe0,0xb8,0x09,0x4c,0x48,0x2a,0x64,0x7d,0x71,0x96,0xd1,0x3a,0xa3,0xb0,0x59,0x90,0xd4,0x85,0x6d,0xc3,0x5d,0xe8,0xae,0xe1,0x03,0xb9,0xf9,0x35,0xfe,0x35,0xd9,0x58};
typedef ES(EA *LOCATE)(uint32_t,GUID *,void *,UN *,HANDLE *);
static uint16_t u16(const void*p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t u32(const void*p){uint32_t x;memcpy(&x,p,4);return x;}
static int alive(void){
 if(!w.st||!w.bs||w.phase==CW_ENDED||!i04_vm_current(&w.vm)||
    !i04_access(&w.vm,(uintptr_t)w.st,sizeof(ST),0,0)||!i04_access(&w.vm,(uintptr_t)w.bs,sizeof(BS),0,0)||w.st->bs!=w.bs)return 0;
 void *now[7]={(void*)w.bs->handle_protocol,w.bs->locate_handle,(void*)w.bs->create_event,(void*)w.bs->register_notify,
  (void*)w.bs->close_event,(void*)w.bs->raise_tpl,(void*)w.bs->restore_tpl};
 if(w.pinned&&memcmp(now,w.methods,sizeof(now)))return 0;
 for(unsigned i=0;i<7;i++)if(!i04_access(&w.vm,(uintptr_t)now[i],1,0,1))return 0;
 return 1;
}
static int fv_target(void *path){
 uintptr_t p=(uintptr_t)path;unsigned count=0;for(UN at=0;at+4<=1024;){
  if(!i04_access(&w.vm,p+at,4,0,0))return -1;uint16_t n=u16((void *)(p+at+2));
  if(n<4||n>1024-at||!i04_access(&w.vm,p+at,n,0,0))return -1;
  const uint8_t *b=(void *)(p+at);
  if(b[0]==4&&b[1]==6){if(n!=20)return -1;if(!memcmp(b+4,&tse_guid,16))count++;}
  if(b[0]==0x7f)return b[1]==0xff&&n==4?(count==1?1:count? -1:0):-1;at+=n;
 }return -1;
}
static int target(HANDLE h,LOADED **out){
 LOADED *li=0;ES status=w.bs->handle_protocol(h,&loaded_guid,(void **)&li);
 if(!alive()||FAILED(status)||!i04_capture(&w.vm,w.st)||!i04_access(&w.vm,(uintptr_t)li,sizeof(*li),0,0))return -1;
 if(!li->filepath)return 0;int path=fv_target(li->filepath);if(path<=0)return path;
 /* A matching FV name with wrong contents is an explicit fault, never skipped. */
 if(li->revision!=0x1000||li->image_size!=909312||((uintptr_t)li->image_base&4095)||!i04_access(&w.vm,(uintptr_t)li->image_base,4096,0,0))return -1;
 const uint8_t *p=li->image_base;uint32_t pe=u32(p+0x3c);
 if(u16(p)!=0x5a4d||pe<0x40||pe>0x800||u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664||u16(p+pe+24)!=0x20b||u32(p+pe+40)!=0x6480||u32(p+pe+80)!=909312||!i04_access(&w.vm,(uintptr_t)p+0x1000,597466,0,1))return -1;
 uint8_t hash[32];ap_sha256(p+0x1000,597466,hash);if(!ap_constant_equal(hash,text_hash,32))return -1;
 *out=li;return 1;
}
int cw_valid(const CW_TICKET *t,HANDLE *handle,LOADED **loaded){
 if(t!=&w.ticket||!alive()||w.phase!=CW_WINDOW||!w.busy||!t->marker||!t->sequence||!t->notify_frame||!i04_vm_current(&w.vm))return 0;
 if(!i04_access(&w.vm,(uintptr_t)t->loaded,sizeof(LOADED),0,0)||memcmp(t->loaded,&t->snapshot,sizeof(LOADED)))return 0;
 if(handle)*handle=t->handle;if(loaded)*loaded=t->loaded;return 1;
}
static void EA notified(EVENT event,void *context){
 (void)event;(void)context;if(!alive()||w.phase==CW_ARMING||w.phase==CW_FAULT||w.phase==CW_CLOSED)return;
 if(w.busy){w.phase=CW_FAULT;return;}w.busy=1;
 for(unsigned count=0;count<4096;count++){
  HANDLE h=0;UN n=sizeof(h);ES status=((LOCATE)w.bs->locate_handle)(1,0,w.registration,&n,&h);
  if(!alive())break;if(status==ERR(14))break;
  if(FAILED(status)||n!=sizeof(h)||!h){w.phase=CW_FAULT;break;}
  LOADED *li=0;int match=target(h,&li);if(match<0){w.phase=CW_FAULT;break;}if(!match)continue;
  int old=0;for(UN i=0;i<w.baseline_count;i++)if(w.baseline[i]==h)old=1;
  if(old||w.phase!=CW_ARMED){w.phase=CW_FAULT;break;}
  /* Event is TPL_CALLBACK. Standard StartImage requires TPL < CALLBACK;
   * the firmware therefore cannot synchronously start this image here. */
  w.phase=CW_WINDOW;w.ticket=(struct CW_TICKET){0x3430574330393857ULL,++w.sequence,h,li,*li,(uintptr_t)__builtin_frame_address(0)};
  int accepted=w.consumer(&w.ticket);w.ticket.marker=0;w.ticket.notify_frame=0;
  if(!alive()){if(w.phase!=CW_ENDED)w.phase=CW_FAULT;break;}
  /* A nested notification can invalidate the window. A true return from the
   * outer consumer cannot erase that fault or resurrect an ended window. */
  if(w.phase!=CW_WINDOW){if(w.phase!=CW_ENDED)w.phase=CW_FAULT;break;}
  w.phase=accepted?CW_OBSERVED:CW_FAULT;
  if(!accepted)break;
 }
 w.busy=0;
}
ES cw_arm(ST *st,CW_CONSUMER consumer){
 if(w.phase!=CW_EMPTY||!st||!consumer)return ERR(20);
 w.st=st;w.bs=st->bs;w.consumer=consumer;w.phase=CW_ARMING;
 if(!w.bs||!i04_capture(&w.vm,st)||!alive())goto failed;
 void *methods[7]={(void*)w.bs->handle_protocol,w.bs->locate_handle,(void*)w.bs->create_event,(void*)w.bs->register_notify,
  (void*)w.bs->close_event,(void*)w.bs->raise_tpl,(void*)w.bs->restore_tpl};
 memcpy(w.methods,methods,sizeof(methods));w.pinned=1;
 UN n=sizeof(w.baseline);ES status=((LOCATE)w.bs->locate_handle)(2,&loaded_guid,0,&n,w.baseline);
 if(!alive()||FAILED(status)||!n||n>sizeof(w.baseline)||n%8)goto failed;w.baseline_count=n/8;
 for(UN i=0;i<w.baseline_count;i++){LOADED *li=0;int match=target(w.baseline[i],&li);if(match!=0)goto failed;}
 status=w.bs->create_event(0x200,8,notified,0,&w.event);if(!alive()||FAILED(status)||!w.event)goto failed;
 status=w.bs->register_notify(&loaded_guid,w.event,&w.registration);if(!alive()||FAILED(status)||!w.registration)goto failed;
 status=w.bs->create_event(0x201,8,cw_end,0,&w.end);if(!alive()||FAILED(status)||!w.end)goto failed;
 /* Drain any prior installation/reinstallation. A target already present is
  * conservatively refused; notification timing is not assumed retroactively. */
 UN prior=w.bs->raise_tpl(16);int good=prior==4;
 n=sizeof(w.baseline);status=((LOCATE)w.bs->locate_handle)(2,&loaded_guid,0,&n,w.baseline);
 if(!alive()||FAILED(status)||!n||n>sizeof(w.baseline)||n%8)good=0;
 if(good){w.baseline_count=n/8;
  for(UN i=0;i<w.baseline_count;i++){LOADED *li=0;if(target(w.baseline[i],&li)!=0){good=0;break;}}}
 if(alive()){w.phase=good?CW_ARMED:CW_FAULT;w.bs->restore_tpl(prior);}else return ERR(15);
 if(!good||!alive()||w.phase==CW_FAULT)goto failed;
 return 0;
failed:if(w.phase!=CW_ENDED)w.phase=CW_FAULT;return ERR(15);
}
ES cw_close(void){
 if(!alive()||w.busy||w.phase==CW_WINDOW)return ERR(15);
 if(w.event){ES r=w.bs->close_event(w.event);if(!alive()||FAILED(r))return ERR(7);w.event=0;w.registration=0;}
 if(w.end){ES r=w.bs->close_event(w.end);if(!alive()||FAILED(r))return ERR(7);w.end=0;}
 w.phase=CW_CLOSED;return 0;
}
uint32_t cw_state(void){return w.phase;}
void EA cw_end(EVENT e,void *c){(void)e;(void)c;w.phase=CW_ENDED;w.vm.ended=1;w.ticket.marker=0;}
#if defined(CW_LAB_REENTRY)
/* Present only in the labeled TCG fault-injection build. The production
 * component exposes no way to manufacture notifications or private tickets. */
void cw_lab_reentry(void){notified(0,0);}
#endif
