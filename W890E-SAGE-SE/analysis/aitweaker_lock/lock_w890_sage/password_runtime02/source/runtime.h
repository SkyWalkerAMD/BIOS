#ifndef W890_RUNTIME02_H
#define W890_RUNTIME02_H
#include "efi.h"
#undef ERR
#include "../../password/provider/provider.h"
extern ST *w890_system_table;
extern int w890_runtime_ended;
extern GUID w890_credential_guid;
extern C16 w890_credential_name[];
AP_STATUS w890_runtime_bind(ST *,const W890_HOST *,const uint8_t setup_sha[32],const uint8_t tse_sha[32]);
void w890_runtime_end_boot(void);
int w890_runtime_alive(void);
int w890_runtime_active(void);
int w890_memory_present(const void *,UN,int);
AP_READ_RESULT w890_read_record(void *,uint8_t *,size_t,size_t *);
int w890_persist_record(void *,const uint8_t *,size_t);
int w890_entropy(void *,uint8_t *,size_t);
int w890_now_ms(void *,uint64_t *);
int EA w890_console_prompt(int);
int cpu_entropy(uint8_t *,size_t);
int cpu_entropy_supported(void);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int memcmp(const void *,const void *,size_t);
void *w890_alloc(UN);
void w890_release(void *);
typedef enum {W890_RECOVERY_OK=0,W890_RECOVERY_ABSENT=1,W890_RECOVERY_DENIED=2,W890_RECOVERY_INVALID=3,
 W890_RECOVERY_CHANGED=4,W890_RECOVERY_IO=5,W890_RECOVERY_UNCERTAIN=6} W890_RECOVERY_STATUS;
/* Separate original-boot recovery: only an enabled, exact-schema W890 private
 * record authenticated by its current password may be deleted. Disabled,
 * malformed, oversized, wrong-attribute and concurrently changed data remains. */
W890_RECOVERY_STATUS w890_recover_known_record(ST *,const uint8_t *,size_t);
#endif
