#ifndef ACE_NV_GUARD_H
#define ACE_NV_GUARD_H
#include "lock.h"
enum {NV_ACTION_NONE=0,NV_ACTION_SET=1,NV_ACTION_CLEAR=2};
typedef struct {
 uint32_t phase,initialized,ready,armed,retired,fault,owned,present;
 uint32_t action,gate_busy,sealed,cleanup_complete;
 uint32_t attempts,commits,blocked,delete_attempts;
 uint64_t action_token,generation;
 ES last_set_status,last_get_status;
 uint32_t attributes;UN size;
 uint8_t hash[32];
} NV_STATUS;
/* No runtime API can initialize, activate or open an action. The dedicated
 * maintenance application calls these only around its isolated console UI. */
int nv_prepare(GETVAR,SETVAR,uint32_t,const uint8_t expected[32]);
int nv_activate(void);
int nv_begin_action(uint32_t);
void nv_end_action(void);
ES EA nv_guard_set(C16 *,GUID *,uint32_t,UN,void *);
int nv_cleanup_tombstone(void);
void nv_retire(void);
const NV_STATUS *nv_status(void);
#endif
