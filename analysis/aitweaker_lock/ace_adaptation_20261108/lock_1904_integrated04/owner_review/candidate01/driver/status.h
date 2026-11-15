#ifndef AITWK_STATUS_H
#define AITWK_STATUS_H
#include "efi.h"
#define STATUS_SIGNATURE 0x343039314b575441ULL
typedef struct {uint32_t version,build,board_matches,hooks_installed,credential_mode,session_active;} LOCK_STATUS;
typedef struct {uint64_t signature;ES (EA *query)(LOCK_STATUS *);} LOCK_STATUS_PROTOCOL;
#define STATUS_GUID {0x1930c80f,0x9a75,0x4a26,{0x98,0x8b,0x19,0x04,0xa1,0x2e,0x7c,0x01}}
#endif
