#ifndef HERO_TSE_AUDIT_H
#define HERO_TSE_AUDIT_H
#include "p1.h"
/* Read-only, exact-image diagnostic. No private TSE function is called. */
ES tse_snapshot(const char *,HANDLE,const uint8_t *,UN);
int tse_readable(const uint8_t *,size_t,size_t,uint64_t,uint64_t);
#endif
