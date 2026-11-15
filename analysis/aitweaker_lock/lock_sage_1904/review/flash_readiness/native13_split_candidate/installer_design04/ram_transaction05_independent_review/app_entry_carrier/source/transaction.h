#ifndef SAGE_RAM_TRANSACTION_H
#define SAGE_RAM_TRANSACTION_H
#include <stdint.h>
#include <stddef.h>
#define EA __attribute__((ms_abi))
#define TX_MAGIC 0x3331585447415341ULL
enum {TX_EMPTY=0,TX_PREPARED=1,TX_INSTALLED=2,TX_RETIRED=3,TX_HELD=4};
enum {TX_OK=0,TX_REFUSED=1,TX_ROLLED_BACK=2,TX_BUSY=3,TX_HOLD=4,TX_ENDED=5};
enum {TX_ORIGINAL=0,TX_PATCHED=1,TX_PERMISSIONS=2};
typedef struct TX_CONTEXT TX_CONTEXT;
typedef struct {
 uint64_t module_base[2],module_size[2],guard_base[2],guard_size[2],state_base,state_size;
} TX_PLAN;
typedef struct {
 uint64_t(EA *raise_tpl)(uint64_t);
 void(EA *restore_tpl)(uint64_t);
 int(EA *validate)(TX_CONTEXT *,uint32_t);
} TX_HOST;
struct TX_CONTEXT {
 uint64_t magic;
 uint32_t phase,busy;
 volatile uint32_t ended;
 uint32_t held,owned_state_valid,attempted;
 uint64_t saved_tpl;
 TX_PLAN plan;
 TX_HOST host;
 uint8_t original[12][24],replacement[12][24];
};
uint32_t EA tx_prepare(TX_CONTEXT *,const TX_PLAN *,const TX_HOST *);
uint32_t EA tx_install(TX_CONTEXT *);
uint32_t EA tx_remove(TX_CONTEXT *);
void EA tx_end(TX_CONTEXT *);
#endif
