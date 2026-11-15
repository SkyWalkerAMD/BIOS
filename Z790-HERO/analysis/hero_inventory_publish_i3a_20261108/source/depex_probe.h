#ifndef HERO_DEPEX_PROBE_H
#define HERO_DEPEX_PROBE_H
#include "efi_min.h"
typedef void (*DP_APPEND)(void *,const char *,size_t);
/* Only LocateProtocol (five known GUIDs) and one GetVariable. No method calls,
 * installs, driver start, allocation, variable writes or network I/O. */
ES depex_probe(ST *,DP_APPEND,void *);
#endif
