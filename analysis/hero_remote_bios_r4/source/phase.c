#include "phase.h"
/* These are non-secret protection-state variables, verified in HERO's own
 * NVRAM module. This component has no SetVariable or private SMM calls. */
static GUID mailbox_guid={0x504af431,0x3025,0x4d32,{0x9f,0xbf,0xe9,0xf3,0x18,0x55,0x55,0x1d}};
static GUID boot_guid={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
void phase_read(PHASE_STATE *p){
 memset(p,0,sizeof(*p));p->mailbox_size=sizeof(p->mailbox);p->boot_size=sizeof(p->boot_phase);
 p->mailbox_status=gST->rt->get_variable(W("NvLockMailbox"),&mailbox_guid,&p->mailbox_attrs,&p->mailbox_size,&p->mailbox);
 p->boot_status=gST->rt->get_variable(W("AuthVarPreBootPhase"),&boot_guid,&p->boot_attrs,&p->boot_size,&p->boot_phase);
}
int phase_equal(const PHASE_STATE *a,const PHASE_STATE *b){return eq(a,b,sizeof(*a));}
void phase_log(const PHASE_STATE *p){
 logtext("NVLOCK status=");loghex(p->mailbox_status,16);logtext(" attrs=");loghex(p->mailbox_attrs,8);logtext(" size=");loghex(p->mailbox_size,4);logtext(" value=");loghex(p->mailbox,16);logtext("\r\n");
 logtext("AUTH_PREBOOT status=");loghex(p->boot_status,16);logtext(" attrs=");loghex(p->boot_attrs,8);logtext(" size=");loghex(p->boot_size,4);logtext(" value=");loghex(p->boot_phase,2);logtext("\r\n");
}
