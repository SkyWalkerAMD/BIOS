#include "w890_management.h"
AP_API AP_STATUS w890_management_action(AP_CORE *core,uint64_t token,uint16_t question,
 const uint8_t *current,size_t current_len,const uint8_t *replacement,size_t replacement_len,
 const uint8_t *confirmation,size_t confirmation_len){
 if(!core)return AP_BAD_ARGUMENT;
 if(question==W890_SET_QID){
  if(!replacement||!confirmation||replacement_len<AP_PASSWORD_MIN||replacement_len>AP_PASSWORD_MAX||
     confirmation_len!=replacement_len||!ap_constant_equal(replacement,confirmation,replacement_len))return AP_BAD_ARGUMENT;
  return ap_set_password(core,token,current,current_len,replacement,replacement_len);
 }
 if(replacement_len||confirmation_len)return AP_BAD_ARGUMENT;
 if(question==W890_CLEAR_QID)return ap_clear_password(core,token,current,current_len);
 if(question==W890_VERIFY_QID)return ap_unlock(core,token,current,current_len);
 return AP_BAD_ARGUMENT;
}
