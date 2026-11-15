#include "recovery.h"
ST *rc_st;int rc_ended;
GUID rc_guid={0x7aa1505b,0xef11,0x4c41,{0x90,0x02,0x42,0x7f,0x82,0x69,0x03,0xe6}};
C16 rc_name[]=L"AiTweakerPasswordW890V1";
static RT *original_rt;static BS *original_bs;static GETVAR get;static SETVAR set;
static EVENT event;static RC_BOOT_PROOF boot_proof;static void *proof_context;static uint64_t proof_epoch;static int busy,initialized;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
#include "memory.inc"
static void EA end_boot(EVENT e,void *c){(void)e;(void)c;rc_ended=1;boot_proof=0;}
int rc_alive(void){
 return initialized&&!rc_ended&&rc_present(rc_st,sizeof(*rc_st),0)&&rc_st->rt==original_rt&&rc_st->bs==original_bs&&
  rc_present(original_rt,sizeof(*original_rt),0)&&rc_present(original_bs,sizeof(*original_bs),0)&&
  original_rt->get_variable==get&&original_rt->set_variable==set;
}
int rc_initialize(ST *st,RC_BOOT_PROOF proof,void *context,uint64_t epoch){
 if(initialized||rc_ended||!rc_present(st,sizeof(*st),0)||!rc_present(st->rt,sizeof(RT),0)||!rc_present(st->bs,sizeof(BS),0))return 0;
 if(!st->rt->get_variable||!st->rt->set_variable||!st->bs->create_event||!st->bs->close_event||
    !st->bs->allocate_pool||!st->bs->free_pool||!st->bs->locate_protocol||!st->bs->stall||
    !st->bs->locate_handles||!st->bs->handle_protocol)return 0;
 rc_st=st;original_rt=st->rt;original_bs=st->bs;get=st->rt->get_variable;set=st->rt->set_variable;
 boot_proof=proof;proof_context=context;proof_epoch=epoch;initialized=1;
 ES result=st->bs->create_event(0x201,8,end_boot,0,&event);
 if(!rc_alive()||FAILED(result)||!event){rc_ended=1;boot_proof=0;return 0;}return 1;
}
void rc_shutdown(void){
 if(event&&rc_alive()){ES s=rc_st->bs->close_event(event);if(!rc_ended&&!FAILED(s))event=0;}
 rc_ended=1;boot_proof=0;
}
void *rc_alloc(UN n){void *p=0;if(rc_alive()&&n&&n<=32*1024*1024&&!FAILED(rc_st->bs->allocate_pool(4,n,&p))&&rc_alive())return p;return 0;}
void rc_release(void *p){if(p&&rc_alive())rc_st->bs->free_pool(p);}
int rc_authorized(void){
 if(!rc_alive()||rc_identity()!=3||!rc_alive()||!boot_proof||!proof_epoch||!rc_present((void *)boot_proof,1,0))return 0;
 return boot_proof(proof_context,proof_epoch)&&rc_alive();
}
RC_RESULT rc_read(uint8_t out[128]){
 if(!out||!rc_alive())return RC_IO;UN n=128;uint32_t attr=0;ES s=get(rc_name,&rc_guid,&attr,&n,out);
 if(!rc_alive()){ap_secure_zero(out,128);return RC_IO;}
 if(s==ERR(14)){ap_secure_zero(out,128);return RC_ABSENT;}
 if(FAILED(s)||n!=128||attr!=3||!ap_record_valid(out,n)){ap_secure_zero(out,128);return RC_INVALID;}
 return RC_OK;
}
RC_RESULT rc_delete_known(const uint8_t *password,size_t length){
 uint8_t first[128],second[128],derived[32];RC_RESULT result=RC_READ_ONLY;
 if(busy||!password||length<AP_PASSWORD_MIN||length>AP_PASSWORD_MAX)return RC_INVALID;
 busy=1;if(!rc_authorized())goto done;
 result=rc_read(first);if(result!=RC_OK)goto done;
 if(first[12]!=1){result=RC_DENIED;goto done;}
 uint32_t iterations=(uint32_t)first[20]|((uint32_t)first[21]<<8)|((uint32_t)first[22]<<16)|((uint32_t)first[23]<<24);
 if(ap_pbkdf2_sha256(password,length,first+32,32,iterations,derived)||!ap_constant_equal(derived,first+64,32)){result=RC_DENIED;goto done;}
 ap_secure_zero(derived,32);
 if(!rc_authorized()){result=RC_READ_ONLY;goto done;}
 result=rc_read(second);if(result!=RC_OK||!ap_constant_equal(first,second,128)){result=RC_CHANGED;goto done;}
 /* The last identity/proof check precedes the final exact record read. Do not
  * insert more externally reentrant services between that read and deletion.
  * The authority must exclude concurrent writes; UEFI has no compare-delete. */
 if(!rc_alive()){result=RC_READ_ONLY;goto done;}
 ES s=set(rc_name,&rc_guid,0,0,0);if(!rc_alive()){result=RC_UNCERTAIN;goto done;}
 result=rc_read(second);
 if(!FAILED(s)&&result==RC_ABSENT)result=RC_OK;
 else if(FAILED(s)&&result==RC_OK&&ap_constant_equal(first,second,128))result=RC_IO;
 else result=RC_UNCERTAIN;
done:ap_secure_zero(first,128);ap_secure_zero(second,128);ap_secure_zero(derived,32);busy=0;return result;
}
