/* ACE1904 result feedback. See the integration contract in save_feedback.h.
 * Native save/initialization calls are retained. No NVRAM/cache rollback.
 */
#include "save_feedback.h"

#ifdef AITWK_SAVE_FEEDBACK_TEST_EXPORT
#define SF_EXPORT __declspec(dllexport)
#else
#define SF_EXPORT
#endif

typedef uint64_t (EA *SAVE_FN)(uint64_t,uint64_t,uint64_t,uint64_t);
typedef struct SCOPE {
 struct SCOPE *previous;
 ES first_denial;
 uint64_t epoch;
 uint8_t changed,unsaved;
} SCOPE;
static SAVE_FN native_save,native_stay;
static SCOPE *save_head,*action_head;
static uint32_t save_depth,action_depth;
static uint8_t *tse_base;
static int prepared,armed,retired;
static uint64_t epoch,notice_token;
static ES notice_status;
static SAVE_FEEDBACK_PATCH owned[2];
static const uint8_t save_prefix[18]={0x40,0x55,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0x6c,0x24,0xe1};
static const uint8_t stay_prefix[16]={0x48,0x83,0xec,0x28,0x48,0x8d,0x0d,0x09,0x74,0x02,0x00,0xe8,0xa0,0x01,0xfd,0xff};

static void absolute_jump(uint8_t *out,void *destination) {
 static const uint8_t op[6]={0xff,0x25,0,0,0,0};
 memcpy(out,op,6);memcpy(out+6,&destination,8);
}
static int has_bytes(const SAVE_FEEDBACK_PATCH *p,int replacement) {
 return memory_present(p->target,p->length,0) &&
  !memcmp(p->target,replacement?p->replacement:p->original,(size_t)p->length);
}
static int writable_flags(void) {
 return prepared && !retired && !boot_services_ended &&
  memory_present(tse_base+0x82789,1,1) && memory_present(tse_base+0x82738,1,1);
}
static void queue_notice(ES status) {
 if(!retired && !boot_services_ended && platform_session_owned()) {
  if(notice_token!=password_core.session_token)notice_status=0;
  notice_token=password_core.session_token;
  if(!notice_status)notice_status=status;
 }
}
static void snapshot(SCOPE *scope) {
 scope->epoch=epoch;scope->first_denial=0;
 scope->changed=tse_base[0x82789];scope->unsaved=tse_base[0x82738];
}
static int preserve_changed(const SCOPE *scope) {
 /* A native callback may rebuild tables. These are fixed module globals, not
  * cached heap pointers. Require this same installation to still own both
  * entry hooks before changing either flag. */
 if(scope->epoch!=epoch || !writable_flags() || !has_bytes(&owned[0],1) || !has_bytes(&owned[1],1)) {
  ap_fault(&password_core);audit(72,ERR(7));queue_notice(ERR(7));return 0;
 }
 if(!tse_base[0x82789])tse_base[0x82789]=scope->changed?scope->changed:1;
 if(!tse_base[0x82738])tse_base[0x82738]=scope->unsaved?scope->unsaved:1;
 return 1;
}
SF_EXPORT void save_feedback_note_denial(ES status) {
 if(!armed || retired || boot_services_ended || !FAILED(status))return;
 if(save_head && !save_head->first_denial)save_head->first_denial=status;
 if(action_head && !action_head->first_denial)action_head->first_denial=status;
}
static uint64_t EA save_wrapper(uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
 if(!prepared || retired || boot_services_ended || !native_save)return 0;
 if(!armed)return native_save(a,b,c,d);
 if(!writable_flags()) {ap_fault(&password_core);queue_notice(ERR(7));return 0;}
 if(save_depth>=16) {
  /* No additional tracking frame is needed: a live parent collects denial.
   * Keep the original call and make overflow visible as a failed attempt. */
  save_feedback_note_denial(ERR(15));ap_fault(&password_core);audit(73,save_depth);
  uint64_t result=native_save(a,b,c,d);return result&~UINT64_C(255);
 }
 SCOPE scope;snapshot(&scope);scope.previous=save_head;save_head=&scope;save_depth++;
 uint64_t result=native_save(a,b,c,d);
 save_head=scope.previous;save_depth--;
 if(scope.first_denial) {
  if(save_head && !save_head->first_denial)save_head->first_denial=scope.first_denial;
  preserve_changed(&scope);queue_notice(scope.first_denial);audit(70,scope.first_denial);
  result&=~UINT64_C(255);
 }
 return result;
}
static uint64_t EA stay_wrapper(uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
 if(!prepared || retired || boot_services_ended || !native_stay)return 0;
 if(!armed)return native_stay(a,b,c,d);
 if(!writable_flags()) {ap_fault(&password_core);queue_notice(ERR(7));return 0;}
 if(action_depth>=16) {
  save_feedback_note_denial(ERR(15));ap_fault(&password_core);audit(74,action_depth);
  return native_stay(a,b,c,d);
 }
 SCOPE scope;snapshot(&scope);scope.previous=action_head;action_head=&scope;action_depth++;
 uint64_t result=native_stay(a,b,c,d);
 action_head=scope.previous;action_depth--;
 if(scope.first_denial) {
  if(action_head && !action_head->first_denial)action_head->first_denial=scope.first_denial;
  preserve_changed(&scope);queue_notice(scope.first_denial);audit(71,scope.first_denial);
 }
 return result;
}
SF_EXPORT int save_feedback_prepare(uint8_t *tse,UN size,void *gateway,UN capacity,SAVE_FEEDBACK_PATCH patches[2]) {
 uint8_t *code=gateway;void *slot=0;
 uintptr_t image=(uintptr_t)tse,allocation=(uintptr_t)gateway;
 if(prepared || retired || boot_services_ended || !tse || !gateway || !patches ||
    size<0x92b10 || capacity<128 || !memory_present(tse,size,0) ||
    !memory_present(gateway,128,1) || !memory_present(patches,sizeof(owned),1) ||
    (image<=allocation?allocation-image<size:image-allocation<128) ||
    memcmp(tse+0x142ac,save_prefix,18) || memcmp(tse+0x440fc,stay_prefix,16) ||
    !memory_present(tse+0x82789,1,1) || !memory_present(tse+0x82738,1,1))return 0;
 memcpy(&slot,tse+0x6bb18,8);if(slot!=tse+0x440fc)return 0;
 /* SaveIterator: 18 position-independent instructions bytes + absolute tail. */
 memcpy(code,save_prefix,18);absolute_jump(code+18,tse+0x142be);
 /* SaveStay: relocate LEA and CALL explicitly; preserve the original stack
  * adjustment and return to 0x4410c only after the complete common save. */
 memcpy(code+64,stay_prefix,4);
 code[68]=0x48;code[69]=0xb9;slot=tse+0x6b510;memcpy(code+70,&slot,8);
 {static const uint8_t call[8]={0xff,0x15,2,0,0,0,0xeb,8};memcpy(code+78,call,8);}
 slot=tse+0x142ac;memcpy(code+86,&slot,8);absolute_jump(code+94,tse+0x4410c);
 owned[0].target=tse+0x142ac;owned[0].length=18;memcpy(owned[0].original,save_prefix,18);
 owned[1].target=tse+0x440fc;owned[1].length=16;memcpy(owned[1].original,stay_prefix,16);
 for(unsigned i=0;i<2;i++)memset(owned[i].replacement,0x90,sizeof(owned[i].replacement));
 absolute_jump(owned[0].replacement,(void *)save_wrapper);
 absolute_jump(owned[1].replacement,(void *)stay_wrapper);
 memcpy(patches,owned,sizeof(owned));
 native_save=(SAVE_FN)gateway;native_stay=(SAVE_FN)(void *)(code+64);
 tse_base=tse;epoch++;prepared=1;armed=0;notice_status=0;notice_token=0;
 return 1;
}
SF_EXPORT int save_feedback_commit(void) {
 if(!prepared || retired || boot_services_ended || !has_bytes(&owned[0],1) || !has_bytes(&owned[1],1))return 0;
 armed=1;return 1;
}
SF_EXPORT int save_feedback_cancel_unpublished(void) {
 if(!prepared || armed || save_head || action_head || !has_bytes(&owned[0],0) || !has_bytes(&owned[1],0))return 0;
 prepared=0;native_save=0;native_stay=0;tse_base=0;epoch++;notice_status=0;notice_token=0;return 1;
}
SF_EXPORT ES save_feedback_take_notice(void) {
 if(!notice_status)return 0;
 if(retired || boot_services_ended || !platform_session_owned() || password_core.session_token!=notice_token) {
  notice_status=0;notice_token=0;return 0;
 }
 if(password_core.busy)return 0;
 ES status=notice_status;notice_status=0;notice_token=0;return status;
}
SF_EXPORT void save_feedback_retire(void) {
 retired=1;armed=0;epoch++;notice_status=0;notice_token=0;
}
#ifdef AITWK_SAVE_FEEDBACK_TEST_EXPORT
/* Test-only observations of the real private state; absent in production. */
SF_EXPORT uint64_t save_feedback_test_query(unsigned field) {
 switch(field) {
 case 0:return (uintptr_t)save_head;
 case 1:return (uintptr_t)action_head;
 case 2:return save_depth;
 case 3:return action_depth;
 case 4:return (uint64_t)prepared;
 case 5:return (uint64_t)armed;
 case 6:return (uint64_t)retired;
 case 7:return notice_status;
 case 8:return notice_token;
 default:return UINT64_MAX;
 }
}
#endif
