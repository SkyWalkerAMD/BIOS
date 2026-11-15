#ifndef HERO15_R5_PREFLIGHT_H
#define HERO15_R5_PREFLIGHT_H
#include "r2.h"
typedef struct {
 ES identity_status,pci_status,config_status,sensor_lock_status,dashboard_lock_status;
 uint32_t source_bytes,source_crc,config_attributes,config_bytes;
 UN segment,bus,device,function;
 uint8_t pci_config[64],bar1_descriptor[46],configuration[8];
} PREFLIGHT;
extern char preflight_audit[65536];
extern UN preflight_bytes;
extern unsigned preflight_bad;
extern uint32_t preflight_source_bytes,preflight_source_crc;
ES identity_check(void);
int memory_readable(const void *,UN);
void preflight_reset_log(void);
ES preflight_capture(PREFLIGHT *);
#endif
