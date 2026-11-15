#ifndef W890_NAVIGATION05_H
#define W890_NAVIGATION05_H
#include "../native_observer04/observer.h"
enum {N05_UNKNOWN=0,N05_CONTINUE=1,N05_MAIN=2,N05_DENIED=3,N05_RETRY=4};
/* No external identity/permission callback. All native facts come from the
 * actual linked observer04; only its private active Loop creates authority. */
ES EA n05_bind(void);
void *EA n05_history_allocate(void *,UN);
void *EA n05_history_reallocate(void *,UN,UN);
void EA n05_forget_history(void *); /* exact free-stub callsites only */
uint32_t EA n05_fallback_main(void);
ES EA n05_check(uint32_t,uintptr_t,uintptr_t);
uint32_t EA n05_first(void); /* 1=keep current, 2=Main, 0=unproved owner/recovery */
ES EA n05_menu(void *,void *,void *);
/* Used only by installed per-free-site assembly stubs; root binds these to
 * actual module globals/resume addresses and checks immutable installed bytes. */
extern uintptr_t n05_history_global,n05_menu_free_resume,n05_loop_free_resume;
void EA n05_menu_free_stub(void);
void EA n05_loop_free_stub(void);
#endif
