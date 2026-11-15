/* W8900603 live HII transaction. No entrypoint installs or publishes this. */
#ifndef W890_MANAGEMENT_LIVE04_H
#define W890_MANAGEMENT_LIVE04_H
#include "../password_runtime02/source/efi.h"
#undef ERR
#include "../password/provider/provider.h"
#define MP_REVISION 4U
#define MP_MAX_PACKAGE (8U*1024U*1024U)
#define MP_MAX_LANGUAGES 16U
#define MP_MAX_PATCHES 32U
typedef struct {uint32_t module,rva,length,reserved;uint8_t original[32],installed[32];} MP_PATCH;
typedef enum {MP_OK=0,MP_DENIED=1,MP_INVALID=2,MP_IO=3,MP_ROLLED_BACK=4,
 MP_DIRTY=5,MP_ENDED=6,MP_BUSY=7} MP_RESULT;
typedef enum {MP_EMPTY=0,MP_BOUND=1,MP_STRINGS=2,MP_PUBLISHED=3,MP_RECOVERY_REQUIRED=4,MP_RESTORED=5,MP_TERMINAL=6} MP_STAGE;
typedef struct {
 uint32_t revision,size;void *context;
 /* A ticket is minted only inside the verified cold native entry wrapper.
  * This callback must never manufacture permission from loop_depth==0 or a
  * generic compatibility/idle boolean. No HII service at raised TPL. */
 int(EA *window_valid)(void *,uint64_t);
 /* Independently recompute the fixed 45-byte insertion from official forms
  * and these six real string IDs; do not authorize an arbitrary supplied hash. */
 int(EA *publication_finished)(void *,uint64_t,const uint16_t[6],const uint8_t[32]);
 int(EA *restoration_finished)(void *,uint64_t);
 int(EA *management_enter)(void *,void *caller,CONFIG *,UN,uint16_t,uint8_t,void *,UN *,uint64_t *);
 int(EA *management_valid)(void *,uint64_t);
 void(EA *management_leave)(void *,uint64_t);
} MP_AUTHORITY;
typedef struct {
 ST *st;HII *database;STRINGS *strings;HANDLE hii,driver;CONFIG *config;
 void *setup_base;UN setup_size;HANDLE tse_driver;void *tse_base;UN tse_size;
 const MP_PATCH *patches;uint32_t patch_count,reserved;
} MP_BINDING;
typedef struct {
 uint32_t revision,stage;MP_BINDING binding;MP_AUTHORITY authority;
 CALLBACK original_callback;void *original_extract;ROUTE original_route;
 uint8_t *original_package,*published_package;UN original_size,published_size;
 uint16_t tokens[6];uint16_t previous_max_token;
 char languages[MP_MAX_LANGUAGES][32];uint32_t language_count;
 uint8_t published_forms_sha256[32];uint64_t active_window,management_ticket;
 void *management_caller;uint16_t management_qid;uint8_t dirty,busy,ended,management_busy;
 MP_PATCH patches[MP_MAX_PATCHES];uint32_t patch_count;uint8_t identity_busy;
 BS *pinned_bs;void *service_methods[10];
 uint8_t text_scratch[597466];
} MP_STATE;
/* Binding is read-only. Caller then uses an exact checked pointer transaction
 * to replace ONLY config->callback with mp_callback. Extract/Route stay intact. */
MP_RESULT mp_bind(MP_STATE *,const MP_BINDING *,const MP_AUTHORITY *);
MP_RESULT mp_publish(MP_STATE *,uint64_t publication_ticket);
/* NO_INSTALL.publish adapter. Positive MP_RESULT values are not EFI_STATUS. */
ES EA mp_native_publish(void *,uint64_t publication_ticket);
MP_RESULT mp_rollback(MP_STATE *,uint64_t publication_ticket);
/* Dispose is legal only after exact complete-package restoration, callback
 * restored by the external installer and a fresh publication window. */
MP_RESULT mp_dispose(MP_STATE *,uint64_t publication_ticket);
void mp_end_boot(MP_STATE *);
ES EA mp_callback(CONFIG *,UN,uint16_t,uint8_t,void *,UN *);
/* Runtime02 host.authorize_operation must additionally match its actual return
 * address to the reviewed callsite inside mp_callback. This accessor does not
 * itself authorize arbitrary caller addresses or OC-variable writes. */
int mp_management_scope(MP_STATE *,uint16_t *,uint64_t *,void **);
int mp_provider_caller(void *return_address);
#endif
