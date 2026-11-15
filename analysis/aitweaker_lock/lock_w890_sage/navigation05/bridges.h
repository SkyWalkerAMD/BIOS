#ifndef W890_NAVIGATION05_BRIDGES_H
#define W890_NAVIGATION05_BRIDGES_H
#include "navigation.h"
ES EA n05_bridges_bind(void);
ES EA n05_native_render(void *);
ES EA n05_native_page_input(void *,void *,void *);
ES EA n05_native_frame_input(void *,void *);
ES EA n05_native_control_input(void *,void *);
ES EA n05_native_app_input(void *,void *);
ES EA n05_native_extra_input(void *,void *);
ES EA n05_native_alt_input(void *,void *);
ES EA n05_native_form_open(void *,UN,uint32_t *);
ES EA n05_native_pending(void *,void *,void *);
void EA n05_native_first(void);
void EA n05_first_dispatch(void *);
uint32_t EA n05_recovery_poll(void *);
void EA n05_recovery_terminal(void);
extern uintptr_t n05_first_resume,n05_form_open_trampoline;
#endif
