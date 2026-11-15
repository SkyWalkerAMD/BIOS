#ifndef W890_FIRST_FALLBACK_H
#define W890_FIRST_FALLBACK_H
#include <stdint.h>
#include <stddef.h>
#include "gate_adapter.h"
#define WF_ABI UINT64_C(0x3130304630393857)
enum {WF_CONTINUE=0,WF_MAIN_SELECTED=1,WF_CANNOT_RECOVER=2};
enum {WF_READ=1,WF_WRITE=2};
typedef struct WF_BINDING WF_BINDING;
/* These callbacks are integration boundaries, not boolean user permissions.
 * identity must bind the exact loaded W890 AMITSE/Setup and approved mutations;
 * session must prove the active outer native browser, not just a token value;
 * hii must resolve the opaque HII handle through the live HII database and the
 * SHA-bound Setup package/ConfigAccess owner. Never dereference an HII handle.
 */
struct WF_BINDING {
 uint64_t abi;
 uintptr_t native_base,application;
 uint64_t session_token;
 void *opaque,*provider,*gate;
 uint32_t (*query)(void *provider);
 uint64_t (*check_first)(WG_GATE *,uint32_t,uintptr_t,uintptr_t);
 int (*identity)(void *opaque,uintptr_t base,uintptr_t application);
 int (*session)(void *opaque,uint64_t token,uintptr_t application);
 int (*range)(void *opaque,uintptr_t address,size_t bytes,uint32_t access);
 int (*hii)(void *opaque,uintptr_t opaque_hii,uint8_t formset_guid[16],uint64_t *epoch);
 uint32_t busy,reserved;
};
WG_API uint32_t wf_main_fallback(WF_BINDING *binding);
WG_API uint32_t wf_first(WF_BINDING *binding);
WG_API size_t wf_binding_bytes(void);
#endif
