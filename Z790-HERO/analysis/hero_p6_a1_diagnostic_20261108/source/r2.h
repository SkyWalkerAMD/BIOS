#ifndef HERO_A1_COMMON_H
#define HERO_A1_COMMON_H
#include "efi_min.h"
#include "probe_core.h"
#define W(x) ((C16 *)L##x)
#define LOG_CAP 2097152U
typedef struct {
 char board[96],bios[96],result[160];
 uint32_t requests,acknowledged,targets,readable,records;
 uint32_t attempted,identity,version_valid,version_asserted,restore_ok,locked;
 uint32_t kcs_error,last_status;ES io_status;
} REPORT;
extern ST *gST;extern REPORT report;
extern char audit[LOG_CAP];extern UN audit_len;extern unsigned audit_bad;
void *memcpy(void *,const void *,size_t);void *memset(void *,int,size_t);
int eq(const void *,const void *,size_t);int same(const char *,const char *);
void strcopy(char *,size_t,const char *);
void logtext(const char *);void loghex(uint64_t,unsigned);void logbytes(const uint8_t *,size_t);
void logn(const char *,size_t);void say(const char *);void status(const char *,ES);
uint16_t u16(const uint8_t *);uint32_t u32(const uint8_t *);uint64_t u64(const uint8_t *);
uint32_t probe_crc32(const void *,size_t);
int memory_refresh(void);int memory_readable(const void *,UN);ES identity_check(void);
void detect_board(void);void result(const char *);
int a1_before(const char *,UN,UN,UN);void a1_after(const char *,ES,UN);
const char *a1_trace_summary(void);
ES p5_probe_same_value(void);
#endif
