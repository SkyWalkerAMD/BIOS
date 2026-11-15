#ifndef P6_CHECK_COMMON_H
#define P6_CHECK_COMMON_H
#include "efi_min.h"
#define W(x) ((C16 *)L##x)
#define LOG_CAP 262144U
extern ST *gST;
extern char audit[LOG_CAP];extern UN audit_len;extern unsigned audit_bad;
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int eq(const void *,const void *,size_t);
int same(const char *,const char *);
void logtext(const char *);void loghex(uint64_t,unsigned);void logbytes(const uint8_t *,size_t);
void logn(const char *,size_t);
uint16_t u16(const uint8_t *);uint32_t u32(const uint8_t *);uint64_t u64(const uint8_t *);
uint32_t probe_crc32(const void *,size_t);
void say(const char *);void status(const char *,ES);
int memory_refresh(void);int memory_readable(const void *,UN);
ES identity_check(void);
#endif
