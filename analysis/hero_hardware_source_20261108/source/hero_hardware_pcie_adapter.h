#ifndef HERO_HARDWARE_PCIE_ADAPTER_H
#define HERO_HARDWARE_PCIE_ADAPTER_H
#include "hero_hardware_source.h"
#include "hero_pcie_catalog.h"
typedef struct {HPC_PCI_RECORD *records;uint32_t capacity,used,rejected,reserved;} HHS_PCI_SINK;
int HeroHardwarePciSinkInit(HHS_PCI_SINK *,HPC_PCI_RECORD *,uint32_t capacity);
/* HHS visitor callback: ignores non-PCI records, copies only independently
 * checked PCI bytes. It does not create network operations or remove objects. */
int HeroHardwarePciVisit(void *,const HHS_RECORD *);
/* Leaves capture untouched on failure. Validates the PCI group independently
 * of optional BlockIo/DiskInfo results; never interprets an incomplete group
 * as an empty group. The resulting catalogue is still only a proposal. */
int HeroHardwarePciCapture(const HHS_PCI_SINK *,const HHS_RESULT *,HPC_CAPTURE *);
#endif
