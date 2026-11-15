/* UEFI/context doubles for the actual integrated04 save_feedback.c object. */
#include "save_feedback.h"
#define EX __declspec(dllexport)
AP_CORE password_core;
int boot_services_ended,platform_ready;
EX uint64_t fixture_status,fixture_save_entry,save_original,save_stay_original;
EX uint64_t save_top,save_action_top,fixture_dirty_82789,fixture_dirty_82738;
EX uint32_t save_depth,fixture_mark_denial,fixture_calls,fixture_guard_calls;
EX void *fixture_target_name;
EX uintptr_t fixture_memory_reject;
EX uint32_t fixture_faults,fixture_audits;
static int owner=1;
void *memcpy(void *d,const void *s,size_t n) {uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n) {uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n) {const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
int memory_present(const void *p,UN n,int write) {
 uintptr_t a=(uintptr_t)p;(void)write;
 if(!n || a<0x10000000 || a+n<a || a+n>0x70000000)return 0;
 return !fixture_memory_reject || fixture_memory_reject<a || fixture_memory_reject-a>=n;
}
int platform_session_owned(void) {return owner && password_core.active && !boot_services_ended;}
void ap_fault(AP_CORE *core) {core->mode=AP_MODE_FAULT;fixture_faults++;}
void audit(uint32_t code,uint64_t value) {(void)code;(void)value;fixture_audits++;}
EX void fixture_owner(uint64_t token,unsigned owned,unsigned busy) {
 password_core.session_token=token;password_core.active=1;password_core.busy=(uint8_t)busy;owner=(int)owned;
}
EX void fixture_ended(unsigned ended) {boot_services_ended=(int)ended;}
/* Constructor compatibility symbols are never executed by the production test;
 * it restores original entries and calls the real prepare/commit APIs. */
EX uint64_t save_wrapper(uint64_t a,uint64_t b,uint64_t c,uint64_t d) {(void)a;(void)b;(void)c;(void)d;return 0;}
EX uint64_t save_stay_wrapper(uint64_t a,uint64_t b,uint64_t c,uint64_t d) {(void)a;(void)b;(void)c;(void)d;return 0;}
EX ES EA fixture_set_variable(C16 *name,GUID *guid,uint32_t attributes,UN bytes,void *value) {
 (void)guid;(void)attributes;(void)bytes;(void)value;
 fixture_calls++;
 if(fixture_target_name && name!=fixture_target_name)return 0;
 fixture_guard_calls++;
 if(fixture_mark_denial)save_feedback_note_denial(fixture_status);
 return fixture_status;
}
