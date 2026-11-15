#ifndef SAGE_NATIVE_PROVIDER_H
#define SAGE_NATIVE_PROVIDER_H
#include "efi.h"
#include "password_core.h"
#define PROVIDER_MAGIC 0x3430393152504741ULL
#define PROVIDER_READY 1u
#define PROVIDER_OWNED 2u
#define PROVIDER_GRANTED 4u
#define PROVIDER_DISABLED 8u
#define PROVIDER_BUSY 16u
#define PROVIDER_FAULT 32u
#define PROVIDER_ENDED 64u
#define PROVIDER_MAX_DEPTH 32u
#define LOCK_QID 0xffe0u
#define LOCK_CLEAR_QID 0xffe1u
typedef struct GATE_PROVIDER GATE_PROVIDER;
struct GATE_PROVIDER {
 uint64_t magic;uint32_t revision,size;
 ES(EA *begin)(GATE_PROVIDER *,uint64_t *);
 ES(EA *end)(GATE_PROVIDER *,uint64_t);
 uint32_t(EA *query)(GATE_PROVIDER *);
 ES(EA *request)(GATE_PROVIDER *);
 ES(EA *manage)(GATE_PROVIDER *,int);
};
OFF(GATE_PROVIDER,begin,16);OFF(GATE_PROVIDER,end,24);OFF(GATE_PROVIDER,query,32);
OFF(GATE_PROVIDER,request,40);OFF(GATE_PROVIDER,manage,48);
_Static_assert(sizeof(GATE_PROVIDER)==56,"Frozen provider ABI v1");
/* Operations1/2/3 are outer Begin, End and nested Begin. The adapter verifies the exact static guard
 * call sites; it never derives ownership from late HII notification state. */
typedef struct {
 int(EA *application_tpl)(void);
 int(EA *owner_caller)(void *,unsigned,uint64_t *,uint64_t,uint32_t);
 int(EA *owner_active)(uint64_t,uint32_t);
 int(EA *writable)(void *,UN);
 int(EA *prompt)(int); /* -1 unlock,0 set/change,1 clear */
} PROVIDER_HOST;
extern GATE_PROVIDER native_provider;
extern AP_CORE password_core;
extern ST *system_table;
extern int boot_services_ended;
extern HANDLE setup_hii;
AP_STATUS provider_initialize(const AP_ENV *,const PROVIDER_HOST *);
void provider_end_boot(void);
void provider_fault(void);
ES EA provider_begin(GATE_PROVIDER *,uint64_t *);
ES EA provider_end(GATE_PROVIDER *,uint64_t);
uint32_t EA provider_query(GATE_PROVIDER *);
ES EA provider_request(GATE_PROVIDER *);
ES EA provider_manage(GATE_PROVIDER *,int);
int platform_session_owned(void);
int platform_can_enter(void);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int memcmp(const void *,const void *,size_t);
size_t c16len(const C16 *);
void *alloc(UN);
void release(void *);
int memory_present(const void *,UN,int);
int cpu_entropy(uint8_t *,size_t);
int cpu_entropy_supported(void);
int ensure_unlocked(void);
int manage_password(int);
void audit(uint32_t,uint64_t);
int install_management(void);
int verify_owner_caller(void *,unsigned,uint64_t *,uint64_t,uint32_t);
int verify_owner_active(uint64_t,uint32_t);
int locate_bound_setup(uint8_t **,UN *);
int native_browser_state(void); /* 1 verified idle; 0 active; -1 unknown */
int policy_form(uint16_t);
int policy_question(uint16_t);
int policy_inert_ifr(const uint8_t *,UN);
int policy_ifr_insert(const uint8_t *,UN,uint16_t,uint16_t,uint16_t,uint16_t,uint8_t *,UN,UN *);
#endif
