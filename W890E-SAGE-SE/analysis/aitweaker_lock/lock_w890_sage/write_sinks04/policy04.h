#ifndef W890_WRITE_POLICY04_H
#define W890_WRITE_POLICY04_H
#include <stdint.h>
#include <stddef.h>
#define WS_MAX_VARIABLE_BYTES 65536u
#define WS_MAX_BATCH 256u
#define WS_MAX_CONFIG_UNITS 65536u
#define WS_DESCRIPTOR_BYTES 124u
#if defined(WS_TEST_EXPORT)
#define WS_API __declspec(dllexport)
#else
#define WS_API
#endif
enum {WS_SAFE=0,WS_DENIED=1,WS_UNKNOWN=2,WS_CHANGED=3,WS_INVALID=4};
enum {WS_SET_VARIABLE=1,WS_SETUP_ROUTE=2,WS_UNKNOWN_ROUTE=3};
typedef struct {
 uint8_t guid[16];uint16_t name[40];
 uint32_t attributes,old_attributes;uint32_t size,old_size;
 const uint8_t *before,*after;uint32_t route,reserved;
} WS_INTENT;
typedef struct {uint32_t result,first_rejected,changed,protected_changed;} WS_RESULT;
/* This pure function grants no authority and performs no writes. The native
 * bridge supplies provider state only after obtaining a private NO_TICKET. */
WS_API int ws04_preflight(const WS_INTENT *,size_t,uint32_t,WS_RESULT *);
WS_API int ws04_known(const uint8_t[16],const uint16_t[40],uint32_t,uint32_t);
/* Decodes exact original descriptor identity, independently of native index.
 * Source pointer must already be copied from an owner-validated native span. */
WS_API int ws04_descriptor(const uint8_t[WS_DESCRIPTOR_BYTES],WS_INTENT *);
/* One GUID/NAME/PATH header and one or more disjoint OFFSET/WIDTH/VALUE blocks.
 * Unknown extensions, duplicate/overlapping blocks and multi-GUID strings are
 * refused before the caller may write. input includes exactly one final NUL. */
WS_API int ws04_route_header(const uint16_t *,size_t,uint8_t[16],uint16_t[40],size_t *);
WS_API int ws04_route_apply(const uint16_t *,size_t,size_t,const uint8_t *,size_t,uint8_t *,size_t);
WS_API size_t ws04_intent_bytes(void);
#endif
