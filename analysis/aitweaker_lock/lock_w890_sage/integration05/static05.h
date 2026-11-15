#ifndef W890_STATIC_INTEGRATION05_H
#define W890_STATIC_INTEGRATION05_H
#include "observer_static05.h"
#include "management.h"
#ifndef ERR
#define ERR(n) (UINT64_C(0x8000000000000000)|(n))
#endif
#define NO_PREPARSE 6u
ES EA i05_entry(HANDLE,ST *);
ES EA i05_services(void);
ES EA i05_preparse(void);
ES EA i05_loop(void);
ES EA i05_send(void *,HANDLE *,UN,GUID *,uint16_t,void *,UN *);
int i05_parser_caller(uintptr_t);
__attribute__((noreturn)) void EA i05_failure(void);
int i05_image_range(uintptr_t,UN);
MP_STATE *i05_management_state(void);
#endif
