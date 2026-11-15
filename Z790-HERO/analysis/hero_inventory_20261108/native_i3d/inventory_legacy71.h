#ifndef HERO_INVENTORY_LEGACY71_H
#define HERO_INVENTORY_LEGACY71_H
#include "tls_client.h"
ES private_tls_inventory_exchange(unsigned,unsigned,const char *,UN,const char *,TLS_REPLY *);
int i3_inventory_source_valid(void);
uint64_t i3_inventory_source_epoch(void);
/* I3d continuation requires System and CPU from the prior verified I3b run.
 * Preflight reads every fixed member even if the collection is empty.
 * Step may POST only a currently missing DIMM after a fresh direct 404.
 * An acknowledged object readback and collection membership are distinct.
 */
ES inventory_legacy71_preflight(void);
ES inventory_legacy71_step(void);
ES inventory_legacy71_summary_step(void); /* separate explicit S/S action */
unsigned inventory_legacy71_state(void); /* 0=unprepared,1=ready,2=hold,
                                          3=direct+collections verified,
                                          4=direct verified,index incomplete */
unsigned inventory_legacy71_completed_mask(void); /* System+CPU+4 DIMMs */
unsigned inventory_legacy71_indexed_mask(void); /* CPU and DIMM collection bits */
unsigned inventory_legacy71_summary_state(void); /* 0=not done,1=verified,2=sent/unknown */
/* Optional transport-level exact-body guard. GET uses its normal read allowlist. */
int inventory_legacy71_write_allowed(unsigned,unsigned,const char *,UN);
#endif
