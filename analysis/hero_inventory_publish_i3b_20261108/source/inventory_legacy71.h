#ifndef HERO_INVENTORY_LEGACY71_H
#define HERO_INVENTORY_LEGACY71_H
#include "tls_client.h"
/* Implemented by I3b's pinned transport and exact current-SMBIOS source gate. */
ES private_tls_inventory_exchange(unsigned,unsigned,const char *,UN,const char *,TLS_REPLY *);
int i3_inventory_source_valid(void);
uint64_t i3_inventory_source_epoch(void);
/* I: all read-only checks. W/W: one pending request, then bounded readback.
 * Any sent request with uncertain/rejected result halts the publishing session.
 * Reset/reboot starts a new read-only preflight, never replays old state.
 */
ES inventory_legacy71_preflight(void);
ES inventory_legacy71_step(void);
unsigned inventory_legacy71_state(void); /* 0=unprepared,1=ready,2=hold,3=core verified */
unsigned inventory_legacy71_completed_mask(void);
#endif
