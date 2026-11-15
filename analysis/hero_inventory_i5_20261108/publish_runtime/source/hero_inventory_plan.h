#ifndef HERO_INVENTORY_PLAN_H
#define HERO_INVENTORY_PLAN_H
#include "hero_inventory_publish.h"
#include "hero_inventory_catalog.h"
#include "hero_pcie_catalog.h"
#include "hero_sata_catalog.h"
/* Flatten only validated current-boot catalogues, keeping JSON owned by each
 * source catalogue. No fixed machine identity or frozen payload lives here.
 * Optional PCI/SATA catalogues may be NULL; never pass an invalid partial one.
 * The caller must retain all input buffers while the publisher is active.
 */
int HeroInventoryPlanBuild(const HIC_CATALOG *,const HPC_CATALOG *,const HSC_CATALOG *,
                           const char *system_uri,const char *chassis_uri,HIP_PLAN_DATA *);
#endif
