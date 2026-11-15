/* Emulator-only consumer: never included in an aggregate or firmware.
 * Its real CALL windows are registered by the fixture, not an owner boolean. */
#include "../native_observer04/observer.h"
extern int EA no_catalog_generation(uint64_t *);
typedef struct {uint64_t before_generation,after_generation,read_status;uint32_t entered,before_valid,after_valid,nested_entered,nested_old_valid;} RESULT;
static NO_TICKET *held;
static uintptr_t app;
static RESULT *report;
static C16 name[]={'G','e','n','e','r','a','t','i','o','n','0','8','L','a','b',0};
static GUID guid={0x865b5f3a,0xce38,0x4f4f,{0x89,0x75,0x09,0x15,0x55,0x44,0x23,0x88}};
__attribute__((noinline)) int EA og08_test_nested(void){
 NO_TICKET *attempt=0;if(!held||!report)return 0;
 report->nested_old_valid=no_scope_validate(held);
 report->nested_entered=no_scope_enter(NO_EFFECT,app,&attempt);
 if(report->nested_entered)no_scope_leave(attempt);
 return report->nested_entered;
}
__attribute__((noinline)) int EA og08_test_read(uintptr_t application,RESULT *out){
 if(held||!out)return 0;app=application;report=out;
 if(!no_catalog_generation(&out->before_generation))return 0;
 out->entered=no_scope_enter(NO_EFFECT,app,&held);if(!out->entered){held=0;return 0;}
 out->before_valid=no_scope_validate(held);
 uint32_t attrs=0;UN bytes=8;uint64_t value=0;
 out->read_status=no_read_variable(held,name,&guid,&attrs,&bytes,&value);
 no_catalog_generation(&out->after_generation);
 out->after_valid=no_scope_validate(held);no_scope_leave(held);held=0;report=0;return 1;
}
