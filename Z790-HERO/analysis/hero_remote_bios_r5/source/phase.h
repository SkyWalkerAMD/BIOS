#ifndef HERO_PHASE_R5_H
#define HERO_PHASE_R5_H
#include "r2.h"
#include "settings.h"
#define PHASE_MAGIC 0x35465048U
#define PHASE_GUID_INIT {0xb5074b95,0x155f,0x422a,{0x8f,0x0a,0x93,0x14,0xd1,0x90,0x2c,0x6e}}
typedef struct { ES mailbox_status,boot_status;uint32_t mailbox_attrs,boot_attrs;UN mailbox_size,boot_size;uint64_t mailbox;uint8_t boot_phase;uint8_t pad[7]; } PHASE_STATE;
typedef struct {
 uint32_t magic,version,size,reserved; HANDLE image;
 ES (EA *sample)(void);
 ES (EA *snapshot)(char *,UN *);
 ES (EA *queue)(uint32_t,uint32_t);
 ES (EA *depart)(void);
 ES (EA *resume)(void);
 ES (EA *cancel)(void);
} PHASE_API;
void phase_read(PHASE_STATE *);
int phase_equal(const PHASE_STATE *,const PHASE_STATE *);
void phase_log(const PHASE_STATE *);
uint32_t probe_crc32(const void *,size_t);
#endif
