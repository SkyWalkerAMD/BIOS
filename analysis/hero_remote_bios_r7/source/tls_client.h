#ifndef HERO_TLS_CLIENT_H
#define HERO_TLS_CLIENT_H
#include "network.h"
ES private_tls_get(void);
ES private_tls_get_pinned(void);
ES private_tls_read_bios(void);
ES private_tls_cleanup(void);
int private_tls_active(void);
#endif
