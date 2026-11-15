#ifndef W890_RESTRICTED_VISIT_PROFILE_H
#define W890_RESTRICTED_VISIT_PROFILE_H
#include "../../native_observer04/observer.h"
#undef NO_MAX_PATCHES
#define NO_MAX_PATCHES 64u
/* This is a link-time reviewed-code catalogue, never a run-time permission
 * argument. Zero/unresolved entries are mandatory closed boundaries. */
enum { NR_FIRST=1,NR_APP_INPUT,NR_FRAME_INPUT,NR_PAGE_RENDER,NR_PAGE_INPUT,
 NR_MENU,NR_NAVIGATION,NR_EXTRA_INPUT,NR_NATIVE_COMMIT,NR_ROUTE_CONFIG,
 NR_SAVE,NR_DEFAULT_API,NR_CONFIG_CALLBACK,NR_PENDING_HII,NR_ROLE_END };
typedef struct {
 uint32_t role,module,rva,patch_bytes;
 uintptr_t guard;uint32_t guard_bytes,reserved;
 uint8_t guard_sha256[32];
} NR_REQUIRED;
typedef struct {uint32_t revision,bytes,count,reserved;NR_REQUIRED required[NR_ROLE_END-1];} NR_CATALOG;
extern const NR_CATALOG nr05_catalog;
int EA no_native_visit_identity(uint64_t *visit,uint32_t *restricted);
int EA no_describe_form_callback(NO_TICKET *,uintptr_t,uintptr_t,WG_SNAPSHOT *);
#endif
