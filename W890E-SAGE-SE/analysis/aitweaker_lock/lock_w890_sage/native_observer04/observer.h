/* W890E-SAGE SE 0603. Compilable native authority, not an installer. */
#ifndef W890_NATIVE_OBSERVER04_H
#define W890_NATIVE_OBSERVER04_H
#include "../password_runtime02/source/efi.h"
#undef ERR
#include "../password/provider/provider.h"
#include "../navigation/gate_adapter.h"
#define NO_MAX_PATCHES 32u
#define NO_MAX_CALLS 48u
#define NO_MAX_DEPTH 32u
#define NO_REVISION 4u
#define NO_DENIED UINT64_C(0x800000000000000f)
#define NO_UNSUPPORTED UINT64_C(0x8000000000000003)
enum {NO_COLD=1,NO_LOOP=2,NO_SEND=3,NO_EFFECT=4,NO_MANAGE=5};
enum {NO_READ=1,NO_WRITE=2,NO_EXEC=4};
enum {NO_CALL_EFFECT=1,NO_CALL_MANAGE=2,NO_CALL_REQUEST=3,NO_CALL_SCOPE=4};
typedef struct NO_TICKET NO_TICKET; /* private storage; a copy cannot validate */
typedef struct {
 uint32_t module,rva,length,reserved; /* module 0=AMITSE, 1=Setup */
 uint8_t original[32],installed[32];
} NO_PATCH;
/* Reviewed consumers are actual compiled code bytes, not external approvals.
 * address is the return address; window covers [address-16,address+16).
 * Root's transaction must bind these to the reviewed component image hash. */
typedef struct {uintptr_t address;uint32_t kind,reserved;uint8_t window[32];} NO_CALL;
typedef ES (EA *NO_PUBLISH)(void *,uint64_t);
typedef struct {
 uint32_t revision,size;
 void *loop_trampoline,*send_trampoline,*entry_trampoline;
 W890_PROVIDER *provider;
 const NO_PATCH *patches;uint32_t patch_count,reserved;
 const NO_CALL *calls;uint32_t call_count,reserved2;
 CALLBACK management_bridge;
 NO_PUBLISH publish;void *publisher;
} NO_INSTALL;
typedef struct {
 ST *st;HII *database;HANDLE hii,setup_driver,tse_driver;CONFIG *config;
 uintptr_t setup_base,tse_base;UN setup_size,tse_size;
 uint64_t epoch;uint32_t loop_depth,send_depth,fault,ended;
} NO_IDENTITY;
/* ST is the EFI entry-supplied bootstrap trust anchor. No caller supplies a
 * module base, HII handle, native pointer, owner flag or valid-session bit. */
ES EA no_initialize(ST *);
ES EA no_prepare(const NO_INSTALL *); /* still no live permission */
int EA no_identity(NO_IDENTITY *);
ES EA no_shutdown(void); /* refuses active scopes; unregisters notifications */
void EA no_end_boot(EVENT,void *);

/* Actual native detour destinations. Only the checked original trampoline
 * is called. Loop direct callers are B8E1/37126; SendForm validates the real
 * protocol object and Setup handle/GUID arguments. Cancellation never jumps
 * to native cleanup/reset; it remains a separate first-page/Main decision. */
ES EA no_native_loop(void);
ES EA no_native_send_form(void *,HANDLE *,UN,GUID *,uint16_t,void *,UN *);
ES EA no_native_entry(HANDLE,ST *); /* firmware-load-only, not late retrofit */

/* Adapter/Runtime02 callbacks. Private wrappers mint session/token state. */
W890_HOST EA no_host(void);
int EA no_observe(void *,uint32_t,uintptr_t,uintptr_t,WG_SNAPSHOT *);
int EA no_publication_validate(void *,uint64_t);
int EA no_publication_finished(void *,uint64_t,const uint16_t[6],const uint8_t[32]);
int EA no_restoration_finished(void *,uint64_t);
int EA no_management_enter(void *,void *,CONFIG *,UN,uint16_t,uint8_t,void *,UN *,uint64_t *);
int EA no_management_valid(void *,uint64_t);
void EA no_management_leave(void *,uint64_t);

/* Effects receive a context-owned ticket only from an exact reviewed caller.
 * no_copy and no_read_variable revalidate owner before and after their work. */
int EA no_scope_enter(uint32_t,uintptr_t,NO_TICKET **);
int EA no_scope_validate(NO_TICKET *);
int EA no_scope_validate_cached(NO_TICKET *); /* no services; does not raise TPL */
void EA no_scope_leave(NO_TICKET *);
int EA no_copy(NO_TICKET *,uintptr_t,void *,UN);
ES EA no_read_variable(NO_TICKET *,C16 *,GUID *,uint32_t *,UN *,void *);

/* Lease must be minted at TPL_APPLICATION inside the cold entry wrapper.
 * validate_cached is bounded and service-free at TPL_NOTIFY: cached map,
 * pinned wrapper/epoch/frame and pointer bytes only. BSP callback exclusion
 * is NOT proof of AP or SMM quiescence. Root installer owns the transaction. */
int EA no_lease_begin(NO_TICKET **);
int EA no_lease_validate_cached(NO_TICKET *);
void EA no_lease_end(NO_TICKET *);
int EA no_range(uintptr_t,UN,uint32_t); /* current cached map, no services */
#endif
