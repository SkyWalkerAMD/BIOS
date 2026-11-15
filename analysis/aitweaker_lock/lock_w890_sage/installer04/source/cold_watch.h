#ifndef W890_I04_COLD_WATCH_H
#define W890_I04_COLD_WATCH_H
#include "memory.h"
typedef struct CW_TICKET CW_TICKET;
typedef int(EA *CW_CONSUMER)(const CW_TICKET *);
/* These are timing/identity observations only. No hook is installed by this
 * component. A ticket is valid only synchronously inside the load notification.
 * Register before the original AMITSE image exists; late boot is refused. */
ES cw_arm(ST *,CW_CONSUMER);
int cw_valid(const CW_TICKET *,HANDLE *,LOADED **);
ES cw_close(void);
uint32_t cw_state(void);
void EA cw_end(EVENT,void *);
enum {CW_EMPTY=0,CW_ARMING=1,CW_ARMED=2,CW_WINDOW=3,CW_OBSERVED=4,CW_FAULT=5,CW_ENDED=6,CW_CLOSED=7};
#endif
