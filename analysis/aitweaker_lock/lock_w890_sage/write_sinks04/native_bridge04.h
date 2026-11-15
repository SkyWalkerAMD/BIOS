#ifndef W890_WRITE_NATIVE04_H
#define W890_WRITE_NATIVE04_H
#include "policy04.h"
#include "../native_observer04/observer.h"
#define WS04_REVISION 4u
#define WS04_UNSUPPORTED UINT64_C(0x8000000000000003)
#define WS04_ACCESS_DENIED UINT64_C(0x800000000000000f)
enum {WS04_COMMIT=1,WS04_ROUTE=2,WS04_SAVE=3};
enum {WS04_POLICY=1,WS04_OWNER=2,WS04_NATIVE=3,WS04_VARIABLE=4,
      WS04_CAPACITY=5,WS04_CHANGED=6,WS04_EFFECTS_UNCLOSED=7,
      WS04_EXECUTION_LEASE_MISSING=8,WS04_PROVIDER=9};
typedef struct {
 uint32_t revision,size;
 W890_PROVIDER *provider;
} WS04_INSTALL;
typedef struct {
 uint32_t operation,reason,observed,checked;
 WS_RESULT policy;
 uint64_t epoch;
} WS04_REPORT;
/* Installer provision is not an authorization. All live reads require an
 * observer-minted private NO_TICKET and a native Loop/Send session. No native
 * module address, permission boolean, input diff, or variable ID is supplied.
 * The installer must bind this component and provider to immutable hashes. */
WS_API ES EA ws04_prepare(const WS04_INSTALL *);
WS_API void EA ws04_end_boot(void);
/* Real live preflight APIs. They perform no SetVariable, RouteConfig, original
 * callback or native trampoline calls. Reports are diagnostic observations,
 * never transferable write permits. Every success is invalid after return. */
WS_API int EA ws04_check_commit(uint32_t,void *,UN,WS04_REPORT *);
WS_API int EA ws04_check_route(CONFIG *,C16 *,WS04_REPORT *);
WS_API int EA ws04_check_save(WS04_REPORT *);
/* Native-compatible destinations remain closed until an independently
 * reviewed execution lease + complete side-effect path is implemented.
 * Current observer's cold installer lease must NOT be reused for effects. */
WS_API ES EA ws04_native_commit(uint32_t,void *,UN);
WS_API ES EA ws04_setup_route(CONFIG *,C16 *,C16 **);
WS_API uint8_t EA ws04_native_save(void);
WS_API int EA ws04_last_report(WS04_REPORT *);
#endif
