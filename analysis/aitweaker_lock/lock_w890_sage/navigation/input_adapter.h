#ifndef W890_INPUT_ADAPTER_H
#define W890_INPUT_ADAPTER_H
#include "gate_adapter.h"
#define WI_ABI UINT64_C(0x3130304930393857)
typedef struct {uint64_t session,epoch,producer_root,list_root;uint32_t count,proof,classification,reserved;uint8_t digest[32];} WI_EFFECTS;
typedef struct {
 uint64_t abi;uintptr_t native_base;WG_GATE *gate;
 uint64_t (*check)(WG_GATE *,uint32_t,uintptr_t,uintptr_t);
 void *opaque;
 int (*range)(void *,uintptr_t,size_t,uint32_t);
 /* Must prove live native object/frame/event ownership and the exact module
  * overlay, independently of password authorization. False consumes input. */
 int (*scope)(void *,uintptr_t,uintptr_t,uint16_t,uintptr_t,uintptr_t);
 /* Includes producer-side state used by original helper3FED4, not only the
  * already-built pending list. All fields and digest must be stable. */
 int (*effects)(void *,WI_EFFECTS *);
 uintptr_t menu_callback;
 uint32_t busy,reserved;
} WI_BINDING;
WG_API extern WI_BINDING *wi_binding;
WG_API uint64_t wi_control(void *,void *);
WG_API uint64_t wi_pending(void *,void *,void *);
WG_API size_t wi_binding_bytes(void);
#endif
