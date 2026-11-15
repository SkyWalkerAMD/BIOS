#include "w890_policy.h"
#include "w890_policy_data.h"
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
static uint16_t u16(const uint8_t *p){return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static int equal(const void *a,const void *b,size_t n){return ap_constant_equal(a,b,n);}
static int member(const uint16_t *values,size_t count,uint16_t value){
 size_t lo=0,hi=count;while(lo<hi){size_t mid=lo+(hi-lo)/2;if(values[mid]<value)lo=mid+1;else hi=mid;}
 return lo<count&&values[lo]==value;
}
static int is_question(uint8_t op){return op==5||op==6||op==7||op==8||op==12||op==15||op==26||op==27||op==28||op==35;}
AP_API int w890_profile_matches(const uint8_t setup[32],const uint8_t tse[32]){
 return setup&&tse&&equal(setup,w890_setup_sha256,32)&&equal(tse,w890_tse_sha256,32);
}
AP_API int w890_form(uint16_t id){return member(w890_protected_forms,COUNT(w890_protected_forms),id);}
AP_API int w890_question(uint16_t id){return member(w890_protected_questions,COUNT(w890_protected_questions),id);}
AP_API int w890_inert_ifr(const uint8_t *ifr,size_t n){
 if(!ifr||n!=17)return 0;
 for(size_t i=0;i<COUNT(w890_inert_exit);i++)if(equal(ifr,w890_inert_exit[i],17))return 1;
 return 0;
}
AP_API W890_POLICY w890_classify_form(const uint8_t formset[16],uint16_t form){
 if(!formset||!equal(formset,w890_setup_formset,16)||!member(w890_known_forms,COUNT(w890_known_forms),form))return W890_UNKNOWN;
 return w890_form(form)?W890_PROTECTED:W890_UNPROTECTED;
}
AP_API W890_POLICY w890_classify_control(const uint8_t formset[16],uint16_t form,const uint8_t *ifr,size_t n){
 W890_POLICY page=w890_classify_form(formset,form);
 if(page==W890_UNKNOWN||!ifr||n<2||n>127||(ifr[1]&127)!=n)return W890_UNKNOWN;
 if(page==W890_PROTECTED)return W890_PROTECTED;
 if(!is_question(ifr[0]))return W890_UNKNOWN;
 if(n<13)return W890_UNKNOWN;
 /* An exact descriptor has an exception only under the bound original Exit
  * identity. It cannot be moved to a different form to gain an exception. */
 if(form==0x271a&&w890_inert_ifr(ifr,n))return W890_UNPROTECTED;
 uint16_t q=u16(ifr+6),store=u16(ifr+8),offset=u16(ifr+10);
 if(w890_question(q)||store==35)return W890_PROTECTED;
 if(store==40){
  size_t width;
  if(ifr[0]==5||ifr[0]==7){if(n<14)return W890_UNKNOWN;width=(size_t)1<<(ifr[13]&3);if(n!=14+3*width)return W890_UNKNOWN;}
  else if(ifr[0]==6){if(n!=14)return W890_UNKNOWN;width=1;}
  else return W890_UNKNOWN;
  if(offset>=W890_MEMORY_BYTES||width>W890_MEMORY_BYTES-offset)return W890_UNKNOWN;
  for(size_t i=0;i<COUNT(w890_memory_offsets);i++)
   if(w890_memory_offsets[i]>=offset&&w890_memory_offsets[i]-offset<width)return W890_PROTECTED;
 }
 if(ifr[0]==15){
  if(n<15)return W890_UNKNOWN;
  if(n>=33&&!equal(ifr+17,w890_setup_formset,16))return W890_UNKNOWN;
  uint16_t target=u16(ifr+13);
  if(!target)return W890_UNKNOWN; /* Dynamic reference requires native evidence. */
  return w890_classify_form(formset,target);
 }
 return W890_UNPROTECTED;
}
static int named(const uint16_t *name,size_t n,const uint16_t *want,size_t count){
 return n==count&&equal(name,want,n*2);
}
AP_API W890_POLICY w890_variable_kind(const uint16_t *name,size_t n,const uint8_t guid[16]){
 if(!name||!guid||!n||n>256)return W890_UNKNOWN;
 if(equal(guid,w890_credential_guid,16)&&named(name,n,w890_credential_name,COUNT(w890_credential_name)))return W890_CREDENTIAL;
 if(equal(guid,w890_oc_guid,16)&&named(name,n,w890_oc_name,COUNT(w890_oc_name)))return W890_PROTECTED;
 if(equal(guid,w890_memory_guid,16)&&named(name,n,w890_memory_name,COUNT(w890_memory_name)))return W890_PROTECTED;
 return W890_UNPROTECTED;
}
AP_API W890_POLICY w890_variable_change(const uint16_t *name,size_t n,const uint8_t guid[16],
 uint32_t old_attributes,const uint8_t *before,size_t old_size,
 uint32_t new_attributes,const uint8_t *after,size_t new_size){
 W890_POLICY kind=w890_variable_kind(name,n,guid);
 if(kind!=W890_PROTECTED)return kind;
 if(!before||!after||old_attributes!=7||new_attributes!=7)return W890_UNKNOWN;
 if(equal(guid,w890_oc_guid,16)){
  if(old_size!=W890_OC_BYTES||new_size!=W890_OC_BYTES)return W890_UNKNOWN;
  return equal(before,after,W890_OC_BYTES)?W890_UNPROTECTED:W890_PROTECTED;
 }
 if(old_size!=W890_MEMORY_BYTES||new_size!=W890_MEMORY_BYTES)return W890_UNKNOWN;
 for(size_t i=0;i<COUNT(w890_memory_offsets);i++)if(before[w890_memory_offsets[i]]!=after[w890_memory_offsets[i]])return W890_PROTECTED;
 return W890_UNPROTECTED;
}
static void copy(uint8_t *dst,const uint8_t *src,size_t n){while(n--)*dst++=*src++;}
static void action(uint8_t *p,uint16_t prompt,uint16_t help,uint16_t qid){
 const uint8_t base[15]={12,15,0,0,0,0,0,0,0,0,255,255,4,0,0};
 copy(p,base,15);put16(p+2,prompt);put16(p+4,help);put16(p+6,qid);
}
AP_API int w890_security_insert(const uint8_t *src,size_t n,const uint16_t tokens[6],
 uint8_t *dst,size_t capacity,size_t *written){
 if(written)*written=0;
 if(!src||!tokens||!dst||!written||n!=W890_ORIGINAL_FORMS_BYTES||capacity<n+45)return 0;
 uintptr_t sa=(uintptr_t)src,da=(uintptr_t)dst;
 if(sa>UINTPTR_MAX-n||da>UINTPTR_MAX-capacity||(sa<da+capacity&&da<sa+n))return 0;
 uint16_t saved_tokens[6];for(unsigned i=0;i<6;i++){if(!tokens[i])return 0;saved_tokens[i]=tokens[i];}
 uint8_t hash[32];ap_sha256(src,n,hash);int exact=equal(hash,w890_forms_sha256,32);ap_secure_zero(hash,32);
 if(!exact)return 0;
 const size_t at=W890_SECURITY_INSERT;
 copy(dst,src,at);
 action(dst+at,saved_tokens[0],saved_tokens[1],W890_SET_QID);
 action(dst+at+15,saved_tokens[2],saved_tokens[3],W890_CLEAR_QID);
 action(dst+at+30,saved_tokens[4],saved_tokens[5],W890_VERIFY_QID);
 copy(dst+at+45,src+at,n-at);
 size_t length=n+45;dst[0]=(uint8_t)length;dst[1]=(uint8_t)(length>>8);dst[2]=(uint8_t)(length>>16);
 *written=length;return 1;
}
