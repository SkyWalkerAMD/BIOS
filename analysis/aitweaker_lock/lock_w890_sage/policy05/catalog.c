#include "catalog.h"
typedef struct {uint32_t offset;uint16_t form,formset;uint8_t length;int8_t risk;uint16_t flags;} FH05_CONTROL;
typedef struct {uint32_t offset;uint16_t form,formset;int16_t risk;uint16_t flags;} FH05_FORM;
typedef struct {uint8_t hash[32];uint32_t bytes;const uint8_t (*formsets)[16];uint32_t formset_count;
                const FH05_CONTROL *controls;uint32_t control_count;
                const FH05_FORM *forms;uint32_t form_count;} FH05_PACKAGE;
#include "catalog_data.h"

AP_API int fh05_describe(const uint8_t *forms,size_t bytes,const uint8_t formset[16],
                        uint16_t form,uint32_t offset,unsigned is_control,FH05_DESCRIPTION *out){
 if(!out)return 0;
 out->storage_risk=-1;out->review_flags=FH05_LIVE_IDENTITY_REQUIRED;
 if(!forms||!formset||bytes<4||bytes>0xffffffu||is_control>1)return 0;
 if(forms[3]!=2||((size_t)forms[0]|((size_t)forms[1]<<8)|((size_t)forms[2]<<16))!=bytes)return 0;
 unsigned lengths=0;
 for(size_t i=0;i<sizeof(packages)/sizeof(packages[0]);i++)if(packages[i].bytes==bytes)lengths++;
 if(!lengths)return 0;
 uint8_t hash[32];ap_sha256(forms,bytes,hash);const FH05_PACKAGE *p=0;
 for(size_t i=0;i<sizeof(packages)/sizeof(packages[0]);i++){
  if(packages[i].bytes==bytes&&ap_constant_equal(hash,packages[i].hash,32)){
   if(p){ap_secure_zero(hash,sizeof(hash));return 0;}p=&packages[i];
  }
 }
 ap_secure_zero(hash,sizeof(hash));if(!p)return 0;
 unsigned fs=p->formset_count;
 for(unsigned i=0;i<p->formset_count;i++)if(ap_constant_equal(formset,p->formsets[i],16)){
  if(fs!=p->formset_count)return 0;fs=i;
 }
 if(fs==p->formset_count)return 0;
 if(is_control){
  size_t lo=0,hi=p->control_count;
  while(lo<hi){size_t mid=lo+(hi-lo)/2;if(p->controls[mid].offset<offset)lo=mid+1;else hi=mid;}
  if(lo==p->control_count)return 0;
  const FH05_CONTROL *q=&p->controls[lo];
  if(q->offset!=offset||q->form!=form||q->formset!=fs||offset>=bytes||q->length>bytes-offset)return 0;
  out->storage_risk=q->risk;out->review_flags=q->flags;return 1;
 }
 for(unsigned i=0;i<p->form_count;i++){
  const FH05_FORM *f=&p->forms[i];
  if(f->form==form&&f->formset==fs&&f->offset==offset){out->storage_risk=f->risk;out->review_flags=f->flags;return 1;}
 }
 return 0;
}
