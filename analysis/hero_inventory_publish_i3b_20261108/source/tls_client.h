#ifndef HERO_I3_TLS_CLIENT_H
#define HERO_I3_TLS_CLIENT_H
#include "network.h"
typedef struct {unsigned status;const char *body;UN length;} TLS_REPLY;
ES private_tls_get_pinned(void);
ES private_tls_read_inventory(void);
ES private_tls_resource(unsigned,TLS_REPLY *);
/* Fixed inventory-only paths; method 0 GET, 1 POST(collection), 2 PATCH(System). */
ES private_tls_inventory_exchange(unsigned,unsigned,const char *,UN,const char *,TLS_REPLY *);
ES private_tls_cleanup(void);
int private_tls_active(void);
#endif
