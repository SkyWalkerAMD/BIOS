/* W890 provider component ABI v1. Native ownership binding is a separate
 * required component, not a caller supplied boolean in a release build. */
#ifndef W890_PROVIDER_H
#define W890_PROVIDER_H
#include "../w890_management.h"
#define EA __attribute__((ms_abi))
typedef uint64_t ES;
#define ERR(n) (0x8000000000000000ULL|(n))
#define W890_PROVIDER_MAGIC 0x3130305030393857ULL /* W890P001 */
#define W890_PROVIDER_READY 1u
#define W890_PROVIDER_OWNED 2u
#define W890_PROVIDER_GRANTED 4u
#define W890_PROVIDER_DISABLED 8u
#define W890_PROVIDER_BUSY 16u
#define W890_PROVIDER_FAULT 32u
#define W890_PROVIDER_ENDED 64u
#define W890_MAX_DEPTH 32u
typedef struct W890_PROVIDER W890_PROVIDER;
struct W890_PROVIDER {
 uint64_t magic;uint32_t revision,size;
 ES(EA *begin)(W890_PROVIDER *,uint64_t *);
 ES(EA *end)(W890_PROVIDER *,uint64_t);
 uint32_t(EA *query)(W890_PROVIDER *);
 ES(EA *request)(W890_PROVIDER *);
 ES(EA *manage)(W890_PROVIDER *,int);
};
_Static_assert(sizeof(W890_PROVIDER)==56,"W890 provider ABI v1");
_Static_assert(offsetof(W890_PROVIDER,begin)==16,"begin ABI");
_Static_assert(offsetof(W890_PROVIDER,end)==24,"end ABI");
_Static_assert(offsetof(W890_PROVIDER,query)==32,"query ABI");
_Static_assert(offsetof(W890_PROVIDER,request)==40,"request ABI");
_Static_assert(offsetof(W890_PROVIDER,manage)==48,"manage ABI");
typedef struct {
 uint32_t revision,size;
 int(EA *profile_bound)(void);
 int(EA *application_tpl)(void);
 /* operation 1=outer begin,2=end,3=nested begin. All original native CALL
  * sites and the entire owned frame chain must be verified by the adapter. */
 int(EA *owner_caller)(void *caller,unsigned operation,uint64_t *out_token,uint64_t token,uint32_t depth);
 int(EA *owner_active)(uint64_t token,uint32_t depth);
 int(EA *writable)(void *,size_t);
 /* A successful UI return alone never grants entry. AP_CORE state and the
  * same owned native frame/session must still validate afterward. */
 int(EA *prompt)(int operation); /* -1 unlock,0 set/change,1 clear */
 int(EA *authorize_operation)(void *caller,int operation,uint64_t token,uint32_t depth);
} W890_HOST;
typedef struct W890_CONFIG W890_CONFIG;
struct W890_CONFIG {
 void *extract;void *route;
 ES(EA *callback)(W890_CONFIG *,uint64_t action,uint16_t id,uint8_t type,void *value,uint64_t *request);
};
extern W890_PROVIDER w890_provider;
extern AP_CORE w890_password_core;
extern W890_CONFIG w890_management_config;
AP_STATUS w890_provider_initialize(const AP_ENV *,const W890_HOST *,const uint8_t setup_sha[32],const uint8_t tse_sha[32]);
void w890_provider_fault(void);
void w890_provider_end_boot(void);
int w890_session_owned(void);
int w890_session_can_enter(void);
ES EA w890_provider_begin(W890_PROVIDER *,uint64_t *);
ES EA w890_provider_end(W890_PROVIDER *,uint64_t);
uint32_t EA w890_provider_query(W890_PROVIDER *);
ES EA w890_provider_request(W890_PROVIDER *);
ES EA w890_provider_manage(W890_PROVIDER *,int);
ES EA w890_config_callback(W890_CONFIG *,uint64_t,uint16_t,uint8_t,void *,uint64_t *);
#endif
