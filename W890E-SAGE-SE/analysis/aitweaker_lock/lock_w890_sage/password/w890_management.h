/* Pure action backend; the native adapter must establish AP_CORE ownership. */
#ifndef W890_MANAGEMENT_H
#define W890_MANAGEMENT_H
#include "w890_policy.h"
AP_API AP_STATUS w890_management_action(AP_CORE *,uint64_t session,uint16_t question,
 const uint8_t *current,size_t current_length,
 const uint8_t *replacement,size_t replacement_length,
 const uint8_t *confirmation,size_t confirmation_length);
#endif
