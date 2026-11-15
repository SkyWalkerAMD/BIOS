#include "p1.h"
_Static_assert(V_COUNT==41,"String ABI changed");
_Static_assert(sizeof(values[0])==160,"Value capacity changed");
_Static_assert(V_CONFIG_STATUS-V_SEL0==16,"SEL record count changed");
