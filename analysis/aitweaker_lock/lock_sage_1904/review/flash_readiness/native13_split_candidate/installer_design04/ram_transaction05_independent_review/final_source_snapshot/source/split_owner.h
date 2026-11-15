#ifndef SAGE_SPLIT_OWNER_H
#define SAGE_SPLIT_OWNER_H
#include "provider.h"
#define SPLIT_CONTEXT_MAGIC 0x333150534e4f4350ULL
#define SPLIT_BINDING_MAGIC 0x3430393153504c47ULL
#define SPLIT_STATE_MAGIC 0x3331535441544547ULL
typedef struct {
 uint64_t magic;uint32_t revision,size;
 uint64_t module_base[2],module_size[2],guard_base[2],guard_size[2];
 uint64_t state_base,state_size;
} SPLIT_CONTEXT;
typedef struct {
 uint64_t magic;uint32_t revision,kind,self_offset,payload_size;
 uint64_t original_base,original_size,guard_base,state_base,state_size;
 uint64_t original_loop,original_frame,original_commit,original_defaults,original_save;
 uint64_t setup_base,setup_size,setup_callback,setup_route,setup_guard,setup_guard_size;
 uint32_t setup_guard_crc,reserved;
} SPLIT_BINDING;
typedef struct {void *ui_head,*save_head;uint64_t magic;volatile uint32_t phase;uint32_t reserved;} SPLIT_STATE;
_Static_assert(sizeof(SPLIT_CONTEXT)==96,"load options context");
_Static_assert(sizeof(SPLIT_BINDING)==160,"immutable split binding");
_Static_assert(sizeof(SPLIT_STATE)==32,"owned state");
int split_owner_bind(const SPLIT_CONTEXT *,uint8_t *,UN);
void split_owner_end(void);
int split_owner_ready(void);
extern HANDLE split_management_hii;
int install_split_management(HANDLE);
#endif
