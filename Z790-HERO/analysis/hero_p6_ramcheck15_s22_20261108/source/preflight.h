#ifndef P6_PREFLIGHT_H
#define P6_PREFLIGHT_H
#include "r2.h"
typedef struct {ES status;UN bytes;uint32_t attrs;uint8_t data[144];} VAR_SNAPSHOT;
typedef struct {VAR_SNAPSHOT settings,state;} PREFLIGHT;
ES preflight_read(PREFLIGHT *,const char *label);
int preflight_equal(const PREFLIGHT *,const PREFLIGHT *);
#endif
