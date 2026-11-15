#ifndef W890_RECOVERY03_H
#define W890_RECOVERY03_H
#include "efi.h"
#include "password_core.h"
extern ST *rc_st;
extern int rc_ended;
extern GUID rc_guid;
extern C16 rc_name[];
typedef enum {RC_OK=0,RC_ABSENT=1,RC_DENIED=2,RC_INVALID=3,RC_CHANGED=4,RC_IO=5,
 RC_UNCERTAIN=6,RC_CANCELLED=7,RC_READ_ONLY=8,RC_EXIT=9} RC_RESULT;
/* Only a separately reviewed original-boot/writer-exclusion authority may
 * provide this callback. The actual carrier supplies NULL. It never trusts a
 * load option, variable, unsigned file or a UI confirmation as this proof. */
typedef int(EA *RC_BOOT_PROOF)(void *context,uint64_t epoch);
int rc_initialize(ST *,RC_BOOT_PROOF,void *,uint64_t);
void rc_shutdown(void);
int rc_alive(void);
int rc_present(const void *,UN,int);
void *rc_alloc(UN);
void rc_release(void *);
uint32_t rc_identity(void);
int rc_authorized(void);
RC_RESULT rc_read(uint8_t out[128]);
RC_RESULT rc_delete_known(const uint8_t *,size_t);
RC_RESULT rc_ui_attempt(void);
ES EA rc_application(HANDLE,ST *);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int memcmp(const void *,const void *,size_t);
#endif
