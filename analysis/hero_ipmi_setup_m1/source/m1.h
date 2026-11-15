#ifndef HERO_M1_H
#define HERO_M1_H
#include "efi_min.h"
#include "probe_core.h"
#define W(x) ((C16 *)L##x)
#define CFG_MAGIC 0x31495048U
#define LOCK_MAGIC 0x314c5048U
#define CFG_GUID_INIT {0xc2614243,0xa877,0x4acf,{0xa4,0x58,0xce,0x29,0x04,0xec,0x3e,0x10}}
#define FORM_GUID_INIT {0x74390925,0x3be7,0x4cd0,{0xb0,0x50,0x7e,0xd8,0x81,0x29,0x6c,0x11}}
#define API_GUID_INIT {0x40823e46,0x8089,0x43f6,{0xaa,0x64,0xa6,0x33,0x42,0x12,0xbb,0x12}}
typedef struct { uint32_t magic; uint8_t enabled,version,reserved[2]; } CONFIG;
_Static_assert(sizeof(CONFIG)==8 && offsetof(CONFIG,enabled)==4,"M1 config ABI");
typedef struct {
    char board[96],bios[96],result[160];
    uint32_t requests,acknowledged,targets,readable,records;
    uint32_t attempted,identity,version_valid,version_asserted,restore_ok,locked;
    uint32_t kcs_error,last_status; ES io_status;
} REPORT;
typedef struct {
    uint32_t version,size;
    ES (EA *show)(void);
    const char *(EA *log)(UN *);
} M1_API;
extern ST *gST;
extern GUID config_guid,form_guid,api_guid;
extern REPORT report;
extern char audit[131072];
extern UN audit_len;
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int eq(const void *,const void *,size_t);
int same(const char *,const char *);
void strcopy(char *,size_t,const char *);
void logtext(const char *);
void loghex(uint64_t,unsigned);
void logbytes(const uint8_t *,size_t);
uint16_t u16(const uint8_t *);
uint32_t u32(const uint8_t *);
uint64_t u64(const uint8_t *);
ES config_read(CONFIG *);
ES config_write(const CONFIG *);
ES lock_read(void);
ES lock_write(int);
void detect_board(void);
ES EA engine_run(uint32_t initialize);
void result(const char *);
#endif
