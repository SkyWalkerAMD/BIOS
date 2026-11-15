/* Synchronous, scoped log sink. Never retained across an exported call.
 * No event/callback can later call unloaded USB launcher code. */
#include "m1.h"
static TRACE active;
static ES failure;
static UN flushed;
ES trace_bind(const TRACE *t){
    if(active.emit)return ERR(20);
    if(!t || t->magic!=TRACE_MAGIC || t->version!=1 || t->size!=sizeof(*t) || !t->emit)return ERR(2);
    active=*t;failure=0;return 0;
}
void trace_unbind(void){memset(&active,0,sizeof(active));}
ES trace_status(void){return failure;}
ES checkpoint(const char *stage,ES status){
    if(FAILED(failure))return failure;
    if(audit_len>sizeof(audit)-256)return failure=ERR(9);
    logtext("STAGE ");logtext(stage);logtext(" status=");loghex(status,16);logtext("\r\n");
    if(!active.emit)return 0; /* RAM only during UnloadImage after scope ended. */
    if(flushed>audit_len)return failure=ERR(33);
    failure=active.emit(active.context,audit+flushed,audit_len-flushed);
    if(!FAILED(failure))flushed=audit_len;
    return failure;
}
