#ifndef W890_I04_TRANSACTION_H
#define W890_I04_TRANSACTION_H
#include "memory.h"
#define I04_MAGIC 0x3458544930393857ULL
typedef enum {I04_OK=0,I04_REFUSED=1,I04_BUSY=2,I04_ROLLED_BACK=3,I04_HOLD=4,I04_ENDED=5} I04_RESULT;
typedef enum {I04_EMPTY=0,I04_PREPARED=1,I04_INSTALLED=2,I04_RETIRED=3,I04_HELD=4} I04_PHASE;
typedef struct {
 /* Must validate a concrete loader/window lease, without UEFI services. It
  * is not inferred from app==NULL, a firmware phase or zero wrapper depth.
  * The deployable loader binding is deliberately absent from this component. */
 void *context;uint64_t ticket;int(EA *valid)(void *,uint64_t);
} I04_LEASE;
typedef struct {
 LOADED *tse,*setup;CONFIG *config;
 uint64_t targets[4]; /* entry, native loop, SendForm, management callback */
 uint64_t guard_base,guard_size; /* immutable linked wrapper .text */
 uint64_t tramp_base; /* one owned RO/X page; constructed by i04_trampolines */
 I04_LEASE lease;
} I04_PLAN;
typedef struct {
 uint64_t magic;I04_VM *vm;I04_PLAN plan;LOADED original_loaded[2];CONFIG original_config;
 UN(EA *raise)(UN);void(EA *restore)(UN);
 uint8_t *module_base[2];uint8_t header[2][4096];
 uint8_t guard_sha[32],tramp_sha[32],plan_sha[32];
 uint8_t replacement[4][24],original[4][24];uint64_t site[4];
 /* attempted means confirmed replacement sites, not all attempted writes.
  * touched/unknown_site retain partial-failure evidence even in HOLD. */
 uint32_t length[4],phase,busy,attempted,touched,unknown_site;volatile uint32_t ended;
 UN old_tpl;
} I04_TX;
/* Emits only three exact reviewed original prologues plus absolute resume
 * jumps into caller-owned writable storage. Does not publish any detour. */
int i04_trampolines(uint8_t page[4096],uint64_t tse_base);
I04_RESULT i04_prepare(I04_TX *,I04_VM *,const I04_PLAN *);
I04_RESULT i04_install(I04_TX *);
I04_RESULT i04_remove(I04_TX *);
void i04_end(I04_TX *);
int i04_validate(I04_TX *,uint32_t replacement_mask);
#endif
