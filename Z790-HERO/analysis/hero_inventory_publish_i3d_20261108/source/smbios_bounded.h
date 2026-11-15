#ifndef SMBIOS_BOUNDED_H
#define SMBIOS_BOUNDED_H
#include "r2.h"
#define TABLE_CAP 262144U
#define SNAPSHOT_CAP 786432U
typedef struct {
 uint64_t address;
 uint32_t bound,count,kind,length,major,minor,docrev;
} SM_ENTRY;
typedef struct {
 uint32_t used,count,end_offset,crc,types[256];
} SM_TABLE;
enum { SM_OK,SM_ARGUMENT,SM_ANCHOR,SM_LENGTH,SM_CHECKSUM,SM_ADDRESS,SM_TOO_LARGE,
 SM_HEADER,SM_STRING_END,SM_MISSING_END,SM_COUNT,SM_CHANGED };
int smbios_entry(const uint8_t *,size_t,unsigned,SM_ENTRY *);
int smbios_table(const uint8_t *,size_t,unsigned,SM_TABLE *);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int eq(const void *,const void *,size_t);
uint32_t probe_crc32(const void *,size_t);
#endif
