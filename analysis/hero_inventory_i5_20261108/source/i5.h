#ifndef HERO_INVENTORY_I5_H
#define HERO_INVENTORY_I5_H
#include "network.h"
#include "hero_inventory_catalog.h"
#define I5_API_GUID_INIT {0xdfb7ec4e,0x5499,0x4812,{0xa2,0xb7,0xab,0x66,0x01,0xf4,0xe5,0x05}}
#define I5_MAGIC 0x41354e49u
typedef struct {
 uint32_t magic,version,size,state;
 ES result;UN entry_tpl;
 const char *log;UN log_bytes;
 const HIC_CATALOG *catalog;
} I5_API;
ES i5_capture_source(void);
int i5_source_valid(void);
const HIC_CATALOG *i5_catalog(void);
ES i5_prepare_network(HANDLE);
UN i5_current_tpl(void);
void i5_run_once(HANDLE);
#endif
