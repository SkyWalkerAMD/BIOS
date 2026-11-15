/* W890 0603 navigation boundary component, no installer or firmware entrypoint.
 * The trusted native observer must prove exact original/installed module bytes,
 * exclusive session ownership, pointer extents and HII/ConfigAccess provenance.
 * Merely filling a snapshot does NOT establish any of those facts.
 */
#ifndef W890_GATE_ADAPTER_H
#define W890_GATE_ADAPTER_H
#include <stdint.h>
#include <stddef.h>
#if defined(AITWK_TEST_EXPORT)
#define WG_API __declspec(dllexport)
#else
#define WG_API
#endif
#define WG_DENIED 0x800000000000000fULL
#define WG_ABI 0x3130304730393857ULL /* W890G001 */
enum {WG_FIRST=1,WG_RENDER,WG_PAGE_INPUT,WG_CONTROL_INPUT,WG_MENU,WG_FORM_OPEN,WG_NAVIGATION};
enum {WG_OWNER_UNKNOWN=0,WG_OWNER_SETUP=1,WG_OWNER_FOREIGN=2};
enum {WG_IDENTITY=1,WG_SESSION=2,WG_EXTENTS=4,WG_PAGE=8,WG_HII=16,
      WG_CONTROL=32,WG_FOREIGN_NO_SETUP=64};
typedef struct {
 uint64_t session,native_base,application,page,hii,control,history;
 uint32_t page_index,application_index,history_count,history_root,owner,proof,ifr_size;
 uint16_t form;
 uint8_t formset[16],ifr[127];
 uint64_t catalog_generation;int32_t classification;uint32_t reserved_scope;
} WG_SNAPSHOT;
typedef int (*WG_OBSERVE)(void *,uint32_t,uintptr_t,uintptr_t,WG_SNAPSHOT *);
typedef uint32_t (*WG_QUERY)(void *);
typedef uint64_t (*WG_REQUEST)(void *);
typedef struct {
 uint64_t abi;
 void *opaque,*provider;
 WG_OBSERVE observe;
 WG_QUERY query;
 WG_REQUEST request;
 uintptr_t native_base;
 uint32_t busy,reserved;
} WG_GATE;
typedef void (*WG_MENU_ORIGINAL)(void *,void *,void *);
WG_API uint64_t wg_check(WG_GATE *,uint32_t,uintptr_t,uintptr_t);
/* This wrapper must replace the verified native menu callback before input.
 * Native menu mutation/history free is never reached when checking fails. */
WG_API uint64_t wg_menu(WG_GATE *,void *,void *,void *);
/* Bound only by a future verified installer. NULL means deny. Never publish
 * the callback slot before every observer/provider/session dependency is live. */
WG_API extern WG_GATE *wg_binding;
WG_API void wg_native_menu_thunk(void *,void *,void *);
WG_API size_t wg_snapshot_bytes(void);
WG_API size_t wg_gate_bytes(void);
#endif
