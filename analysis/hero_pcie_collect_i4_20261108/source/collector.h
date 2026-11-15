#ifndef COLLECTOR_H
#define COLLECTOR_H
#include "efi_min.h"
#define SNAPSHOT_CAP 2097152U
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int eq(const void *,const void *,size_t);
uint32_t probe_crc32(const void *,size_t);
#define W(x) ((C16 *)L##x)
#endif
