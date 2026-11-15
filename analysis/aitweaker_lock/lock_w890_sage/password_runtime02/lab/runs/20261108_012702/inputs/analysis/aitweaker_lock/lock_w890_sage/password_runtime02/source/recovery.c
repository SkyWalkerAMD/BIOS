#include "runtime.h"
/* Separate recovery backend. No namespace enumeration or caller-supplied
 * variable names. Run exclusively on an original boot with no lock writer
 * resident. UEFI provides no compare-and-delete primitive: the second read
 * detects observed changes, not an adversarial concurrent firmware writer. */
static int recovery_busy;
typedef struct {ST *st;GETVAR get;SETVAR set;EVENT event;volatile int ended;} RECOVERY;
static RECOVERY recovery_context;
static void EA recovery_end(EVENT event,void *context){(void)event;((RECOVERY *)context)->ended=1;}
static AP_READ_RESULT read_one(RECOVERY *c,uint8_t data[128],uint32_t *attributes,size_t *size){
 *size=0;*attributes=0;if(c->ended)return AP_READ_ERROR;UN n=128;
 ES s=c->get(w890_credential_name,&w890_credential_guid,attributes,&n,data);
 if(c->ended){ap_secure_zero(data,128);return AP_READ_ERROR;}
 if(s==ERR(14)){ap_secure_zero(data,128);return AP_READ_NOT_FOUND;}
 *size=n;
 if(FAILED(s)||n!=128||*attributes!=3){ap_secure_zero(data,128);return AP_READ_ERROR;}
 return AP_READ_OK;
}
W890_RECOVERY_STATUS w890_recover_known_record(ST *st,const uint8_t *password,size_t length){
 W890_RECOVERY_STATUS result=W890_RECOVERY_INVALID;RECOVERY *c=&recovery_context;
 uint8_t first[128],second[128],derived[32];size_t first_n=0,second_n=0;uint32_t first_attr=0,second_attr=0;
 if(recovery_busy||c->event||c->ended||!password||length<AP_PASSWORD_MIN||length>AP_PASSWORD_MAX||!st||!st->rt||!st->bs||
    !st->rt->get_variable||!st->rt->set_variable||!st->bs->create_event||!st->bs->close_event)return result;
 recovery_busy=1;c->st=st;c->get=st->rt->get_variable;c->set=st->rt->set_variable;
 ES s=st->bs->create_event(0x201,8,recovery_end,c,&c->event);
 if(c->ended||FAILED(s)||!c->event){result=W890_RECOVERY_IO;goto done;}
 AP_READ_RESULT read=read_one(c,first,&first_attr,&first_n);
 if(read==AP_READ_NOT_FOUND){result=W890_RECOVERY_ABSENT;goto done;}
 if(read!=AP_READ_OK||!ap_record_valid(first,first_n)){result=W890_RECOVERY_INVALID;goto done;}
 if(first[12]!=1){result=W890_RECOVERY_DENIED;goto done;}
 uint32_t iterations=(uint32_t)first[20]|((uint32_t)first[21]<<8)|((uint32_t)first[22]<<16)|((uint32_t)first[23]<<24);
 if(ap_pbkdf2_sha256(password,length,first+32,32,iterations,derived)||!ap_constant_equal(derived,first+64,32)){result=W890_RECOVERY_DENIED;goto done;}
 ap_secure_zero(derived,sizeof(derived));
 read=read_one(c,second,&second_attr,&second_n);
 if(read!=AP_READ_OK||second_n!=first_n||second_attr!=first_attr||!ap_constant_equal(first,second,first_n)){result=W890_RECOVERY_CHANGED;goto done;}
 if(c->ended){result=W890_RECOVERY_IO;goto done;}
 s=c->set(w890_credential_name,&w890_credential_guid,0,0,0);
 if(c->ended){result=W890_RECOVERY_UNCERTAIN;goto done;}
 read=read_one(c,second,&second_attr,&second_n);
 if(!FAILED(s)&&read==AP_READ_NOT_FOUND)result=W890_RECOVERY_OK;
 else if(FAILED(s)&&read==AP_READ_OK&&second_n==first_n&&second_attr==first_attr&&ap_constant_equal(first,second,first_n))result=W890_RECOVERY_IO;
 else result=W890_RECOVERY_UNCERTAIN;
done:
 ap_secure_zero(first,sizeof(first));ap_secure_zero(second,sizeof(second));ap_secure_zero(derived,sizeof(derived));
 if(c->event&&!c->ended){if(!FAILED(c->st->bs->close_event(c->event)))c->event=0;else result=W890_RECOVERY_IO;}
 if(!c->event&&!c->ended)ap_secure_zero(c,sizeof(*c));recovery_busy=0;return result;
}
