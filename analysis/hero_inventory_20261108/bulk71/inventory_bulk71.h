#ifndef HERO_INVENTORY_BULK71_H
#define HERO_INVENTORY_BULK71_H
#include "tls_client.h"
/* Independent future I3c adapter. Do not wire into I3b or call automatically.
 * Every request remains on .71's pinned internal USB transport. GET accepts only
 * inventory_bulk71_path_allowed() paths; methods1/2 only the InventoryData URI.
 * The adapter sends Content-Length in bytes, Connection: close, OData-Version4.0.
 */
ES private_tls_bulk71_exchange(unsigned method,const char *path,const char *content_type,
                               const char *body,UN bytes,TLS_REPLY *reply);
int i3_inventory_source_valid(void);
uint64_t i3_inventory_source_epoch(void);
int inventory_bulk71_path_allowed(const char *path);
ES inventory_bulk71_preflight(void); /* read-only; original core collections must be empty */
ES inventory_bulk71_post(void);      /* repeat census, POST once, never automatically finish */
ES inventory_bulk71_finish(void);    /* only after this boot's explicit positive POST ack */
ES inventory_bulk71_verify(void);    /* GET only; cannot release a failed/unknown session */
/* 0 idle;1 prepared;2 POST ack;3 finish ack;4 core verified;5 held;6 core+warnings */
unsigned inventory_bulk71_state(void);
#endif
