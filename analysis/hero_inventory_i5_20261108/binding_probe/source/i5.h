#ifndef HERO_INVENTORY_I5_H
#define HERO_INVENTORY_I5_H
#include "network.h"
#include "hero_inventory_catalog.h"
#define I5_API_GUID_INIT {0x7e06fa9a,0x532e,0x44c6,{0x92,0x8a,0xcf,0x19,0xd2,0x71,0x8e,0x4b}}
#define I5_MAGIC 0x42354e49u
typedef struct {
 uint32_t magic,version,size,state;
 ES result;UN entry_tpl;
 const char *log;UN log_bytes;
 const HIC_CATALOG *catalog;
 ES (EA *connect_probe)(void);
 HANDLE binding_handle;
 uint32_t binding_starts,run_count;
} I5_API;
ES i5_capture_source(void);
int i5_source_valid(void);
const HIC_CATALOG *i5_catalog(void);
ES i5_prepare_network(HANDLE);
UN i5_current_tpl(void);
void i5_run_once(HANDLE);
int i5_observe_bmc_usb(HANDLE out[2]);
#endif
