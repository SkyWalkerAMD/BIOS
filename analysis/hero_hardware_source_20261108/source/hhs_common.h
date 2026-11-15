#ifndef HHS_COMMON_H
#define HHS_COMMON_H
#include "efi_min.h"
/* Reuse the host firmware's existing freestanding common implementations.
 * common.c is supplied only for standalone tests, not mandatory duplicate IO. */
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int eq(const void *,const void *,size_t);
uint32_t probe_crc32(const void *,size_t);
#endif
