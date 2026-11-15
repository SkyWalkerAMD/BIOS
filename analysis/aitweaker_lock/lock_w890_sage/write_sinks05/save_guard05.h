#ifndef W890_SAVE_GUARD05_H
#define W890_SAVE_GUARD05_H
#include "../write_sinks04/policy04.h"
#include "../native_observer04/observer.h"
typedef struct {
 void *entry;uint32_t bytes,reserved;
} WS05_PATH;
typedef struct {
 uint32_t revision,size;
 W890_PROVIDER *provider;
 void *save_replay; uint32_t replay_bytes,reserved;
 WS05_PATH dispatch,defaults,load_defaults_save,profile,profile_policy;
 /* Exact reviewed integration helper CALL return; 32-byte window is pinned.
  * Optional only when the ConfigAccess profile adapter is not installed. */
 void *profile_bridge_return;
} WS05_BINDING;
enum {WS05_OK=0,WS05_OWNER=1,WS05_PROFILE=2,WS05_CACHE=3,WS05_VARIABLE=4,
      WS05_POLICY=5,WS05_STALE=6,WS05_PROVIDER=7,WS05_REENTRY=8};
typedef struct {uint32_t reason,protected_change,alias_change,prompted;uint64_t epoch;} WS05_REPORT;
/* Installation provision is not an authorization. no_scope_enter mints a
 * private native-session ticket for the exact compiled consumer call window.
 * This candidate has no firmware entry/installer. Notification/default/import
 * closure must be accepted by the integrating installer, not by an input bool. */
ES EA ws05_prepare(const WS05_BINDING *);
void EA ws05_end_boot(void);
int EA ws05_before_save(void);
int EA ws05_before_protected_action(void); /* not a generic FD6C replacement */
/* Call before the original Setup ConfigAccess.Callback for the exact native
 * profile QIDs. This does not read or modify Value or ActionRequest. Return 0
 * consumes the callback; the bridge returns EFI_ACCESS_DENIED in that case. */
int EA ws05_profile_callback_gate(CONFIG *,UN,uint16_t,uint8_t,void *,UN *,void *);
int EA ws05_last_report(WS05_REPORT *);
void EA ws05_native_dispatch(uint64_t,void *,void *,void *);
void EA ws05_native_defaults(void *,void *);
ES EA ws05_native_load_defaults_save(void *,UN);
ES EA ws05_native_profile(void *,UN,UN,uint16_t);
ES EA ws05_native_profile_policy(void *,UN,UN,uint16_t);
void ws05_save_mid_thunk(void);
ES EA ws05_provider_request_call(void);
void ws05_provider_request_return(void);
extern void *ws05_save_replay,*ws05_save_cancel;
#endif
