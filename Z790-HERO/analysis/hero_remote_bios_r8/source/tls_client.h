#ifndef HERO_TLS_CLIENT_H
#define HERO_TLS_CLIENT_H
#include "network.h"
ES private_tls_get(void);
ES private_tls_get_pinned(void);
ES private_tls_read_bios(void);
ES private_tls_cleanup(void);
int private_tls_active(void);
typedef struct {unsigned status;const char *body;UN length;} TLS_REPLY;
/* Fixed resource table. Write bodies are supplied only by the publisher. */
ES private_tls_resource(unsigned,const char *,UN,TLS_REPLY *);
#endif
