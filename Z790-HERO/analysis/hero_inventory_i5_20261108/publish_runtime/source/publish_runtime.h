#ifndef I5_PUBLISH_RUNTIME_H
#define I5_PUBLISH_RUNTIME_H
#include "i5.h"
#include "hero_inventory_publish.h"
/* Context-owned callbacks; transport accepts no arbitrary endpoint/body. */
ES i5_publish_current_host(void);
ES i5_publish_authorize(const HIP_REQUEST *);
int i5_publish_budget_ok(void);
uint32_t i5_publish_elapsed_ms(void);
ES private_tls_publish_exchange(const HIP_REQUEST *,HIP_RESPONSE *);
ES i5_hardware_capture(void);
int i5_hardware_source_valid(void);
#endif
