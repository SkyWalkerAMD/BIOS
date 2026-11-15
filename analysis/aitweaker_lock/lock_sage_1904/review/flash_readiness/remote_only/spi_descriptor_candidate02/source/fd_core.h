#ifndef FD_CORE_H
#define FD_CORE_H
#include "efi_min.h"
typedef struct {
 void *context;
 ES (EA *read32)(void *,uint32_t,uint32_t *);
 ES (EA *write32)(void *,uint32_t,uint32_t);
 ES (EA *stall)(void *,UN);
 int (EA *binding)(void *);
} FD_IO;
typedef struct {
 uint32_t reads,writes,go_attempts,blocks,passes;
 uint32_t failure_stage,failure_offset,final_transients_restored,protection_unchanged;
 uint32_t initial_hsfc,initial_faddr,last_status;
 uint32_t poll_observations,busy_fgo_observations;
 ES failure_status;
} FD_RESULT;
ES fd_capture(FD_IO *,uint8_t *,uint8_t *,FD_RESULT *);
#endif
