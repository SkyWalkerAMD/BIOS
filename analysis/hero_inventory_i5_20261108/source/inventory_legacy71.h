/* I5-A has no publication entry: all mutation requests are denied. */
#ifndef I5_READONLY_TRANSPORT_GUARD_H
#define I5_READONLY_TRANSPORT_GUARD_H
#include "network.h"
static int inventory_legacy71_write_allowed(unsigned method,unsigned id,const char *body,UN bytes){
 (void)method;(void)id;(void)body;(void)bytes;return 0;
}
#endif
