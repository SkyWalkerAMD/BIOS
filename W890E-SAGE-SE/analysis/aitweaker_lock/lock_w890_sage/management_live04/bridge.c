#include "internal.h"
/* Kept out of line so the host can bind its one precise, disassembled return
 * address. A dynamic argument containing an alleged caller is never sufficient. */
__attribute__((noinline)) static ES call_provider(UN action,uint16_t question,uint8_t type,void*value,UN*request){
 ES status=w890_config_callback(&w890_management_config,action,question,type,value,request);
 __asm__ volatile("":::"memory");return status;
}
int mp_provider_caller(void*address){
 uintptr_t a=(uintptr_t)address,begin=(uintptr_t)call_provider;
 if(a<begin+5||a>=begin+128||!w890_memory_present((void*)(a-5),5,0))return 0;
 const uint8_t*p=(void*)(a-5);if(p[0]!=0xe8)return 0;
 int32_t relative=(int32_t)mp_u32(p+1);
 return a+(intptr_t)relative==(uintptr_t)w890_config_callback;
}
int mp_management_scope(MP_STATE*s,uint16_t*qid,uint64_t*ticket,void**caller){
 if(!mp_live(s)||!s->management_busy||s->busy||s->stage!=MP_PUBLISHED||!s->management_ticket||
  !s->authority.management_valid(s->authority.context,s->management_ticket)||!mp_live(s))return 0;
 if(qid){if(!w890_memory_present(qid,sizeof(*qid),1))return 0;*qid=s->management_qid;}
 if(ticket){if(!w890_memory_present(ticket,sizeof(*ticket),1))return 0;*ticket=s->management_ticket;}
 if(caller){if(!w890_memory_present(caller,sizeof(*caller),1))return 0;*caller=s->management_caller;}return 1;
}
ES EA mp_callback(CONFIG*this,UN action,uint16_t question,uint8_t type,void*value,UN*request){
 MP_STATE*s=mp_current;void*caller=__builtin_return_address(0);
 if(!mp_live(s)||this!=s->binding.config||s->busy||s->management_busy||!mp_identity(s,1))return ERR(15);
 if(question<W890_SET_QID||question>W890_VERIFY_QID){
  /* Preserve all arguments and the original OUT storage. No OC write authority
   * follows from reaching the original callback; write guards remain separate. */
  return s->original_callback(this,action,question,type,value,request);
 }
 if(s->stage!=MP_PUBLISHED||s->dirty!=1)return ERR(15);
 uint64_t ticket=0;
 if(action>1||type!=10)return ERR(3);
 if(!s->authority.management_enter(s->authority.context,caller,this,action,question,type,value,request,&ticket)||!mp_live(s)||!ticket)return ERR(15);
 s->management_busy=1;s->management_ticket=ticket;s->management_caller=caller;s->management_qid=question;
 ES status=ERR(15);
 if(s->authority.management_valid(s->authority.context,ticket)&&mp_live(s)&&mp_identity(s,1))status=call_provider(action,question,type,value,request);
 int still_valid=mp_live(s)&&s->authority.management_valid(s->authority.context,ticket)&&mp_live(s)&&mp_identity(s,1);
 if(mp_live(s))s->authority.management_leave(s->authority.context,ticket);
 s->management_ticket=0;s->management_caller=0;s->management_qid=0;s->management_busy=0;
 return still_valid?status:ERR(15);
}
