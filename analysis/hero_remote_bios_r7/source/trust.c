/* Temporary public trust for the verified HERO test. Never overwrite an
 * existing store. The variable is BS-only (no NV/runtime access). HttpDxe's
 * normal verification is unchanged. Its TLS cache can persist until reset. */
#include "network.h"
#include "certificate.h"
static GUID ca_guid={0xfd2340d0,0x3dab,0x4349,{0xa6,0xc7,0x3b,0x4f,0x12,0xb4,0x8e,0xae}};
static int owned;
static uint8_t check[sizeof(hero_cert_esl)];
static ES read_trust(uint32_t *attrs,UN *n){
 *attrs=0;*n=sizeof(check);
 return gST->rt->get_variable(W("TlsCaCertificate"),&ca_guid,attrs,n,check);
}
int trust_is_owned(void){return owned;}
ES trust_cleanup(void){
 if(!owned)return 0;
 uint32_t attrs;UN n;ES e=read_trust(&attrs,&n);status("TEMP_CA_CLEANUP_READ",e);
 if(e==ERR(14)){owned=0;return 0;}
 if(FAILED(e))return e;
 if(attrs!=2||n!=sizeof(hero_cert_esl)||!eq(check,hero_cert_esl,n)){
  logtext("TEMP_CA_CHANGED_EXTERNALLY_NOT_DELETED\r\n");return ERR(26);
 }
 e=gST->rt->set_variable(W("TlsCaCertificate"),&ca_guid,0,0,0);status("TEMP_CA_DELETE",e);
 if(FAILED(e))return e;
 e=read_trust(&attrs,&n);status("TEMP_CA_ABSENCE_VERIFY",e);
 if(e!=ERR(14))return FAILED(e)?e:ERR(7);
 owned=0;return 0;
}
ES trust_begin(void){
 if(!network_candidate()||owned||tcp_is_active())return ERR(15);
 uint32_t attrs;UN n;ES e=read_trust(&attrs,&n);status("TEMP_CA_INITIAL_READ",e);
 if(e!=ERR(14)){logtext("EXISTING_CA_STORE_NOT_MODIFIED\r\n");return ERR(15);}
 e=gST->rt->set_variable(W("TlsCaCertificate"),&ca_guid,2,sizeof(hero_cert_esl),(void *)hero_cert_esl);
 status("TEMP_CA_BS_ONLY_CREATE",e);if(FAILED(e))return e;
 owned=1;e=read_trust(&attrs,&n);status("TEMP_CA_READBACK",e);
 if(FAILED(e))return e;
 if(attrs!=2||n!=sizeof(hero_cert_esl)||!eq(check,hero_cert_esl,n))return ERR(26);
 logtext("TEMP_CA_EXACT_READBACK_OK; TLS_NATIVE_VERIFY_UNCHANGED\r\n");return 0;
}
