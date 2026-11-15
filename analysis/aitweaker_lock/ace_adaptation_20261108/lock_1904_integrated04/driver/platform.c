/* W790-ACE 1904 ONLY. Private offsets are tied to both observed .text CRCs
 * and exact expected pointer/prologue bytes. See navigation/REA evidence.
 * This is a review candidate until the complete OEM UI is exercised. */
#include "lock.h"
#include "probe_core.h"
#include "save_feedback.h"
static uint8_t *tse_base,*setup_base;
static UN tse_bytes,setup_bytes;
static uint32_t loop_depth;
static int denied_this_turn;
static int publication_attempted;
static int platform_retired,loop_starting;
/* Installing callbacks inside an existing OEM loop does not make that loop
 * ours. Only entry through browser_loop owns an authentication session. */
int platform_session_owned(void) {
 return loop_depth>0 && loop_depth<=16 && password_core.active && !platform_retired && !boot_services_ended;
}
int platform_can_enter(void) {
 if(platform_retired || boot_services_ended || password_core.busy)return 0;
 if(password_core.mode==AP_MODE_DISABLED)return 1;
 return platform_session_owned() && ap_can_enter(&password_core);
}
int platform_attach_retry_safe(void) {
 return !publication_attempted && !platform_ready && !platform_retired && !boot_services_ended;
}
typedef uint64_t (EA *LOOP_FN)(void);
typedef ES (EA *PAGE_FN)(void *);
typedef ES (EA *INPUT_FN)(void *,void *);
typedef ES (EA *NAV_FN)(GUID *,uint16_t *,GUID *,uint16_t *);
typedef struct {void (EA *poll)(void);} POLL;
static LOOP_FN original_loop;
static PAGE_FN original_render;
static INPUT_FN original_page_input,original_app_input,original_frame_input;
static NAV_FN original_navigation;
static POLL *original_poll;
static GUID poll_guid={0xc7a047a8,0x82b1,0x48db,{0x8e,0x6a,0x7b,0x27,0xcc,0x7c,0x56,0x1f}};
static GUID setup_formset={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
static uint32_t dword(const void *p) {uint32_t v;memcpy(&v,p,4);return v;}
static uint16_t word(const void *p) {uint16_t v;memcpy(&v,p,2);return v;}
static void *pointer(const void *p) {void *v;memcpy(&v,p,8);return v;}
static uint8_t *app(void) {return tse_base?pointer(tse_base+0x82748):0;}
static uint8_t *page_at(uint8_t *a,uint32_t index) {
 if(!memory_present(a,0x60,0))return 0;
 uint32_t count=dword(a+0x2c);uint8_t *array=pointer(a+0x30);
 if(!count || count>8192 || index>=count || !memory_present(array,(UN)count*8,0))return 0;
 uint8_t *page=pointer(array+(UN)index*8);
 return memory_present(page,0x58,0)?page:0;
}
static int page_form(uint8_t *page,uint16_t *form) {
 if(!memory_present(page,0x58,0))return 0;
 uint16_t index=word(page+0x30);uint8_t *table=pointer(tse_base+0x92270),*records=pointer(tse_base+0x92b08);
 if(!memory_present(table,4,0))return 0;
 uint32_t count=dword(table);
 if(!count || count>8192 || index>=count || !memory_present(table+4+(UN)index*4,4,0))return 0;
 uint32_t offset=dword(table+4+(UN)index*4);
 if(offset>16*1024*1024 || !memory_present(records+offset,12,0))return 0;
 *form=word(records+offset+10);return 1;
}
static int question(uint8_t op) {return op==5||op==6||op==7||op==8||op==12||op==15||op==0x1a||op==0x1b||op==0x1c||op==0x23;}
static int frame_protected(uint8_t *frame) {
 if(!memory_present(frame,0x50,0))return -1;
 uint32_t count=dword(frame+0x3c);uint8_t *controls=pointer(frame+0x48);
 if(count>8192 || (count && !memory_present(controls,(UN)count*8,0)))return -1;
 for(uint32_t j=0;j<count;j++) {
  uint8_t *control=pointer(controls+(UN)j*8);if(!memory_present(control,0x50,0))return -1;
  if(setup_hii && pointer(control+0x20)!=setup_hii)continue;
  uint8_t *ifr=pointer(control+0x48);if(!ifr)continue;
  if(!memory_present(ifr,2,0))return -1;
  if(!question(ifr[0]))continue;
  unsigned size=ifr[1]&0x7f;if(size<13 || !memory_present(ifr,size,0))return -1;
  if(policy_inert_ifr(ifr,size))continue;
  uint16_t store=word(ifr+8),offset=word(ifr+10);
  if(store==29 || (store==33 && (offset==0x10 || offset==0xbd || offset==0xbe)))return 1;
 }
 return 0;
}
/* -1 malformed/unknown, 0 unrelated, 1 protected. Foreign HII IDs are never
 * interpreted as Setup variable-store IDs. Dynamic Favorites retain source HII. */
static int page_protected(uint8_t *page) {
 uint16_t form=0;
 if(!page_form(page,&form))return -1;
 HANDLE h=pointer(page+0x20);
 if((!setup_hii || h==setup_hii) && policy_form(form))return 1;
 uint32_t frames=dword(page+0x4c);uint8_t *array=pointer(page+0x50);
 if(frames>64 || (frames && !memory_present(array,(UN)frames*8,0)))return -1;
 for(uint32_t i=0;i<frames;i++) {
  int protected=frame_protected(pointer(array+(UN)i*8));if(protected)return protected;
 }
 return 0;
}
static int overlaps(const void *p,UN n,const void *q,UN m) {
 uintptr_t x=(uintptr_t)p,y=(uintptr_t)q;
 return x<=y ? y-x<n : x-y<m;
}
/* AMITSE 1904 native 0x10270 appends a destination to the last history
 * record, not to its old-page argument. A forced safe-page redirect must
 * replace the root as well as app.current, or Security's Esc leads back to
 * the denied Ai page. Layout is corroborated by original 0x1017c/0x10270.
 * Keep the OEM allocation; the browser still owns its normal cleanup. */
static int reset_history_root(uint8_t *a,uint8_t *page,uint32_t index) {
 if(!memory_present(tse_base+0x82754,0x28,0))return 0;
 uint32_t count=dword(a+0x2c),start=dword(tse_base+0x82754);
 uint32_t capacity=dword(tse_base+0x82758),used=dword(tse_base+0x82778);
 uint8_t *history=pointer(tse_base+0x82760);
 if(!count || count>8192 || index>=count || word(page+0x30)!=index ||
    word(page+0x32)!=0 || !pointer(page+0x20) || start>=count ||
    !capacity || capacity>8212 || !used || used>capacity ||
    !history || ((uintptr_t)history&7))return 0;
 UN bytes=(UN)capacity*32;
 if(overlaps(history,bytes,tse_base,tse_bytes) ||
    overlaps(history,bytes,setup_base,setup_bytes) ||
    overlaps(history,bytes,a,0x60) || overlaps(history,bytes,page,0x58) ||
    overlaps(history,bytes,pointer(a+0x30),(UN)count*8))return 0;
 if(!memory_present(history,bytes,1) ||
    !memory_present(tse_base+0x82754,4,1) ||
    !memory_present(tse_base+0x82778,4,1) ||
    !memory_present(a+0x28,4,1) || !memory_present(a+0x58,1,1))return 0;
 void *hii=pointer(page+0x20);uint32_t id=word(page+0x2a),one=1;
 memset(history,0,bytes);memcpy(history,&hii,8);memcpy(history+8,&id,4);
 memcpy(tse_base+0x82754,&index,4);memcpy(tse_base+0x82778,&one,4);
 return 1;
}
static void redirect(void) {
 uint8_t *a=app();if(!memory_present(a,0x60,0))return;
 uint32_t count=dword(a+0x2c);if(!count || count>8192)goto end_browser;
 for(unsigned pass=0;pass<2;pass++)for(uint32_t i=0;i<count;i++) {
  uint8_t *p=page_at(a,i);uint16_t form=0;
  if(!p || !page_form(p,&form) || !pointer(p+0x20) || (p[0x34]&1) ||
     word(p+0x32)!=0 || word(p+0x30)!=i)continue;
  if(pass==0 && form!=0x2713)continue;
  if(page_protected(p)!=0)continue;
  if(!reset_history_root(a,p,i))goto end_browser;
  memcpy(a+0x28,&i,4);a[0x58]=1;return;
 }
 /* No verified safe page exists. End this browser invocation, never draw a
  * protected/unknown page as an error fallback. */
end_browser:
 if(memory_present(a+0x5a,1,1))a[0x5a]=1;
}
static int gate(uint8_t *page,int prompt) {
 if(platform_can_enter())return 1;
 int protected=page_protected(page);
 if(!protected) {denied_this_turn=0;return 1;}
 if(protected==1 && prompt && !denied_this_turn && platform_session_owned() &&
    ensure_unlocked() && platform_can_enter())return 1;
 denied_this_turn=1;redirect();audit(40,(uint64_t)(int64_t)protected);return 0;
}
static void EA poll(void) {
 if(!original_poll)system_table->bs->locate_protocol(&poll_guid,0,(void **)&original_poll);
 if(original_poll && original_poll->poll)original_poll->poll();
 if(boot_services_ended || !tse_base || dword(tse_base+0x82628)!=5)return;
 show_save_notice();
 if(boot_services_ended || platform_retired)return;
 uint8_t *a=app();if(!memory_present(a,0x60,0)){ap_fault(&password_core);return;}
 gate(page_at(a,dword(a+0x28)),platform_session_owned());
}
static POLL proxy={poll};
static ES EA render(void *page) {
 if(!gate(page,0))return 0;
 return original_render(page);
}
static ES EA page_input(void *page,void *event) {
 /* Zero means consumed; returning ACCESS_DENIED would fall through to AppInput. */
 if(!gate(page,0))return 0;
 return original_page_input(page,event);
}
static ES EA app_input(void *application,void *event) {
 uint8_t *a=application;
 if(!memory_present(a,0x60,0) || !gate(page_at(a,dword(a+0x28)),0))return 0;
 return original_app_input(application,event);
}
static ES EA frame_input(void *frame,void *event) {
 /* Also catches direct/indirect calls from modal windows that run entirely
  * inside an AppInput call and do not re-enter the outer page polling loop. */
 if(!platform_can_enter()) {
  int protected=frame_protected(frame);
  if(protected && (protected<0 || !platform_session_owned() ||
     !ensure_unlocked() || !platform_can_enter())) {audit(46,(uint64_t)(int64_t)protected);return 0;}
 }
 return original_frame_input(frame,event);
}
static ES EA navigation(GUID *old_guid,uint16_t *old_form,GUID *new_guid,uint16_t *new_form) {
 ES status=original_navigation(old_guid,old_form,new_guid,new_form);
 if(status)return status;
 if(!memory_present(new_guid,16,0) || !memory_present(new_form,2,0))
  return platform_can_enter()?status:ERR(15);
 if(!memcmp(new_guid,&setup_formset,16) && policy_form(*new_form)) {
  if(!platform_can_enter() && (!platform_session_owned() || !ensure_unlocked() ||
     !platform_can_enter())) {denied_this_turn=1;return ERR(15);}
 }
 return status;
}
static uint64_t EA browser_loop(void) {
 /* HII providers can call external notification handlers during publication.
  * An entry before the outer owner is established cannot begin another owner. */
 if(loop_starting)return ERR(15);
 if(!platform_ready || platform_retired || loop_depth>=16 || boot_services_ended) {ap_session_end(&password_core);return ERR(15);}
 if(!loop_depth) {
  denied_this_turn=0;loop_starting=1;
  uint64_t token=ap_session_begin(&password_core);
  int management=token && password_core.active && install_hii_management(setup_base,setup_bytes);
  loop_starting=0;
  if(!management) {platform_ready=0;ap_fault(&password_core);audit(41,ERR(7));return ERR(15);}
  if(platform_retired || boot_services_ended || loop_depth || !password_core.active || token!=password_core.session_token) {
   ap_session_end(&password_core);return ERR(15);
  }
  audit(42,password_core.session_token);
 }
 uint64_t token=password_core.session_token;
 uint32_t entered_depth=++loop_depth;
 uint64_t result=original_loop();
 /* BeforeExit permanently resets ownership, including outstanding wrappers.
  * Do not decrement a retired depth or a different session's depth. */
 if(platform_retired || boot_services_ended) {ap_session_end(&password_core);return result;}
 if(loop_depth!=entered_depth || token!=password_core.session_token) {loop_depth=0;ap_fault(&password_core);return ERR(15);}
 loop_depth--;
 if(!loop_depth) {ap_session_end(&password_core);denied_this_turn=0;audit(43,result);}
 return result;
}
static void absolute_jump(uint8_t *out,void *target) {
 const uint8_t op[6]={0xff,0x25,0,0,0,0};memcpy(out,op,6);memcpy(out+6,&target,8);
}
typedef struct {uint32_t offset;void *expected,*replacement;} SLOT;
int attach_platform(uint8_t *tse,UN tse_size,uint8_t *setup,UN setup_size) {
 static const uint8_t prologue[18]={0x40,0x55,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0x6c,0x24,0xe1};
 static const uint8_t frame_prologue[15]={0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7c,0x24,0x20};
 IMAGE_INFO ti,si;uint64_t trampoline=0;uint8_t patch[18];
 SAVE_FEEDBACK_PATCH save_patches[2];
 if(publication_attempted || platform_ready || platform_retired || boot_services_ended ||
    !probe_image(tse,tse_size,&ti) || !probe_image(setup,setup_size,&si))return 0;
 if(ti.text_crc!=0x760c4005 || ti.text_rva!=0x2c0 || ti.text_size!=0x69ecf || ti.entry!=0x5a0 ||
    si.text_crc!=0x9e141291 || si.text_rva!=0x2c0 || si.text_size!=0x2746f || si.entry!=0x590)return 0;
 if(tse_size<0x92b10 || memcmp(tse+0xe208,prologue,18) || memcmp(tse+0x15370,frame_prologue,15) || memcmp(tse+0x1200c,"\x33\xc0\xc3",3))return 0;
 SLOT slots[]={
  {0x6af78,tse+0x16ae0,(void *)render},
  {0x6af80,tse+0x16c70,(void *)page_input},
  {0x6ae90,tse+0x121b8,(void *)app_input},
  {0x7cb30,tse+0x1200c,(void *)navigation},
  {0x82998,pointer(tse+0x82998),&proxy}
 };
 for(size_t i=0;i<sizeof(slots)/sizeof(slots[0]);i++)if(pointer(tse+slots[i].offset)!=slots[i].expected)return 0;
 if(FAILED(system_table->bs->allocate_pages(0,3,1,&trampoline)) || !trampoline)return 0;
 /* A failed permission check retains at most one unpublished page per attempt.
  * The discovery caller bounds pre-publication retries; nothing has escaped. */
 if(boot_services_ended || !memory_present((void *)(uintptr_t)trampoline,256,1))return 0;
 memcpy((void *)(uintptr_t)trampoline,prologue,18);absolute_jump((uint8_t *)(uintptr_t)trampoline+18,tse+0xe21a);
 memcpy((void *)(uintptr_t)(trampoline+64),frame_prologue,15);absolute_jump((uint8_t *)(uintptr_t)trampoline+79,tse+0x1537f);
 original_frame_input=(INPUT_FN)(uintptr_t)(trampoline+64);
 original_loop=(LOOP_FN)(uintptr_t)trampoline;original_render=(PAGE_FN)(void *)(tse+0x16ae0);
 original_page_input=(INPUT_FN)(void *)(tse+0x16c70);original_app_input=(INPUT_FN)(void *)(tse+0x121b8);
 original_navigation=(NAV_FN)(void *)(tse+0x1200c);original_poll=slots[4].expected;
 tse_base=tse;tse_bytes=tse_size;setup_base=setup;setup_bytes=setup_size;
 if(!save_feedback_prepare(tse,tse_size,(void *)(uintptr_t)(trampoline+128),128,save_patches))return 0;
 /* Even a failed guard write can publish a pointer. Rollback below is not a
  * complete transaction proof, so never retry after the first publication. */
 publication_attempted=1;
 if(!install_variable_guard())return 0;
 size_t installed=0;
 for(;installed<sizeof(slots)/sizeof(slots[0]);installed++)
  if(!patch_memory(tse+slots[installed].offset,&slots[installed].replacement,8))goto rollback;
 memset(patch,0x90,sizeof(patch));absolute_jump(patch,(void *)frame_input);
 if(!patch_memory(tse+0x15370,patch,15))goto rollback;
 for(unsigned i=0;i<2;i++)
  if(!patch_memory(save_patches[i].target,save_patches[i].replacement,save_patches[i].length))goto rollback;
 if(!save_feedback_commit())goto rollback;
 /* Publish the browser owner only after navigation and both save entries are
  * installed. Any residual owner after an error rejects entry while !ready. */
 memset(patch,0x90,sizeof(patch));absolute_jump(patch,(void *)browser_loop);
 if(!patch_memory(tse+0xe208,patch,sizeof(patch)))goto rollback;
 platform_ready=1;
 /* Publish management before AMITSE constructs its page cache when HII is
  * already ready; browser entry retries if DXE publication was still pending. */
 if(!install_hii_management(setup_base,setup_bytes))audit(47,ERR(14));
 audit(44,ti.text_crc);return 1;
rollback:
 patch_memory(tse+0xe208,prologue,18);
 {int restored=1;
  for(unsigned i=2;i>0;i--) {
   SAVE_FEEDBACK_PATCH *s=&save_patches[i-1];
   if(!patch_memory(s->target,s->original,s->length) || memcmp(s->target,s->original,(size_t)s->length))restored=0;
  }
  /* Retain gateways even after restoration. An armed or uncertain failure is
   * permanently retired, never treated as permission to reinstall hooks. */
  if(!restored || !save_feedback_cancel_unpublished())save_feedback_retire();
 }
 patch_memory(tse+0x15370,frame_prologue,15);
 for(size_t i=0;i<sizeof(slots)/sizeof(slots[0]);i++)patch_memory(tse+slots[i].offset,&slots[i].expected,8);
 ap_fault(&password_core);audit(45,installed);return 0;
}
void end_platform(void) {platform_retired=1;loop_depth=0;save_feedback_retire();}
