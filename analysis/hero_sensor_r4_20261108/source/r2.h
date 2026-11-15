#ifndef HERO_R2_H
#define HERO_R2_H
#include "efi_min.h"
#include "probe_core.h"
#define W(x) ((C16 *)L##x)
#define CFG_MAGIC 0x31495048U
#define LOCK_MAGIC 0x314c5048U
#define CFG_GUID_INIT {0xc2614243,0xa877,0x4acf,{0xa4,0x58,0xce,0x29,0x04,0xec,0x3e,0x10}}
#define API_GUID_INIT {0x7e575405,0x66a3,0x420d,{0x88,0xda,0x8a,0xd7,0x0f,0xd9,0xe5,0x9b}}
#define MANUAL_MAGIC 0x324d5048U
typedef struct {uint32_t magic,size;} LOAD_OPTIONS;
typedef struct {uint32_t magic;uint8_t enabled,version,reserved[2];} CONFIG;
_Static_assert(sizeof(CONFIG)==8 && offsetof(CONFIG,enabled)==4,"persistent config ABI");
typedef struct {
 char board[96],bios[96],result[160];
 uint32_t requests,acknowledged,targets,readable,records;
 uint32_t attempted,identity,version_valid,version_asserted,restore_ok,locked;
 uint32_t kcs_error,last_status;ES io_status;
} REPORT;
typedef struct {
 uint32_t version,size;
 uint32_t manual_only,reserved;
 ES (EA *run)(uint32_t);
 const char *(EA *log)(UN *);
 ES (EA *status)(REPORT *);
 ES (EA *config)(CONFIG *,uint32_t *);
 ES (EA *enable)(uint32_t);
 ES (EA *unlock)(void);
} R2_API;
extern ST *gST;
extern GUID config_guid,api_guid;
extern REPORT report;
extern uint32_t config_source;
extern char audit[131072];extern UN audit_len;
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int eq(const void *,const void *,size_t);int same(const char *,const char *);
void strcopy(char *,size_t,const char *);
void logtext(const char *);void loghex(uint64_t,unsigned);void logbytes(const uint8_t *,size_t);
uint16_t u16(const uint8_t *);uint32_t u32(const uint8_t *);uint64_t u64(const uint8_t *);
ES config_read(CONFIG *);ES config_write(const CONFIG *);ES lock_read(void);ES lock_write(int);
void detect_board(void);ES EA engine_run(uint32_t);void result(const char *);

#define R3_API_GUID_INIT {0x61f3761c,0xa3a6,0x4fb5,{0x98,0xf9,0x46,0x36,0xc3,0x31,0xbc,0x39}}
#define R3_SENSORS 1U
#define R3_DASHBOARD 2U
#define R3_WRITE 0x100U
#define DMI_LOCK_MAGIC 0x33444c48U
/* R2 v2 API/layout remains byte-identical. R3 has a separate protocol. */
typedef struct {
 uint32_t version,size,requested,completed;
 ES sensor_status,dashboard_status,source_status;
 uint32_t dmi_attempted,dmi_written,dmi_matched,dmi_locked;
 uint32_t source_crc,source_bytes,ready_seen,reserved;
 char dashboard_result[160];
} R3_REPORT;
typedef struct {
 uint32_t version,size,manual_only,reserved;
 ES (EA *run)(uint32_t);
 const char *(EA *log)(UN *);
 ES (EA *status)(R3_REPORT *);
 ES (EA *unlock)(uint32_t);
} R3_API;
typedef struct {
 char bios[5],date[11],manufacturer[33],model[65],revision[33],serial[33];
 uint8_t bios_request[17],board_request[192];
 uint32_t bios_bytes,board_bytes,table_crc,table_bytes,dashboard_valid;
} LOCAL_IDENTITY;
extern GUID r3_api_guid;
extern R3_REPORT r3_report;
extern LOCAL_IDENTITY local_identity;
ES identity_read(void);
ES identity_parse(const uint8_t *,UN,LOCAL_IDENTITY *);
uint32_t identity_crc(const void *,size_t);
ES dmi_lock_read(void);ES dmi_lock_write(int);
ES EA engine_dashboard(uint32_t);
#endif
