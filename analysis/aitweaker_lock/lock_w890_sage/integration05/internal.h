#include "management.h"
#include "../password_runtime02/source/runtime.h"
#ifndef ERR
#define ERR(n) (UINT64_C(0x8000000000000000)|(n))
#endif
int mp_live(MP_STATE *);
int mp_window(MP_STATE *,uint64_t);
int mp_identity(MP_STATE *,int bridge);
int mp_package(const uint8_t *,UN,const uint8_t **,UN *,uint16_t *);
int mp_original_forms(const uint8_t *,UN);
int mp_nonform_equal(const uint8_t *,UN,const uint8_t *,UN);
int mp_string_growth_only(const uint8_t *,UN,const uint8_t *,UN);
uint8_t *mp_export(MP_STATE *,uint64_t,UN *);
uint8_t *mp_alloc(MP_STATE *,uint64_t,UN);
void mp_free(MP_STATE *,void *);
uint32_t mp_u32(const uint8_t *);
void mp_put32(uint8_t *,uint32_t);
extern MP_STATE *mp_current;
