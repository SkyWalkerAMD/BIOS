#ifndef DXE_STATE_PROBE_H
#define DXE_STATE_PROBE_H
#include "efi_min.h"
typedef void (*DX_APPEND)(void *,const char *,size_t);
typedef int (*DX_READ)(void *,uint64_t,void *,size_t,unsigned);
enum {DX_DATA=0,DX_CODE=1};
enum {DX_OK=0,DX_ARGUMENT,DX_IDENTITY,DX_RUNNING,DX_UNREADABLE,DX_BAD_LIST,DX_LIMIT,DX_CHANGED};
#define DX_MAX_NODES 1024U
#define DX_MAX_MATCHES 8U
typedef struct {
 uint64_t address;
 uint8_t raw[0x90],depex[256];
 uint32_t which,depex_bytes,depex_readable;
} DX_MATCH;
typedef struct {
 uint64_t core_base,list_head;
 uint32_t code_identity,running,complete,status,nodes,matches,target_count[2];
 uint32_t initialized,dependent,untrusted,scheduled,unrequested,depex_error;
 DX_MATCH match[DX_MAX_MATCHES];
 uint64_t visited[DX_MAX_NODES];
} DX_RESULT;
int dx_state_snapshot(DX_READ,void *,uint64_t,uint64_t,DX_RESULT *);
ES dxe_state_probe(ST *,DX_APPEND,void *);
int dx_range(const uint8_t *,size_t,size_t,uint64_t,size_t,unsigned);
#endif
