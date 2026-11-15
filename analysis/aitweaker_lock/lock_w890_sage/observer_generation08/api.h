#ifndef W890_OBSERVER_GENERATION08_API_H
#define W890_OBSERVER_GENERATION08_API_H
#include "../native_observer04/observer.h"
/* Requires an existing private native visit. Read-only; creates no authority.
 * Consumers must compare before/after around HII export and native snapshots. */
int EA no_catalog_generation(uint64_t *out);
#endif
