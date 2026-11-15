/* Pure bounded stores to an already extent-checked owned DIAG09_REGION.
 * Callers establish RAM ownership/read-write mapping and live state first.
 * No service, pointer chase, blocking lock, allocation or policy decision.
 */
#ifndef SAGE_DIAGNOSTIC_STORE_H
#define SAGE_DIAGNOSTIC_STORE_H
#include "diagnostic09.h"
typedef struct {
 DIAG09_RECORD first,request;
 uint64_t request_count,prompt_count,ack_count;
 uint32_t flags,first_valid,request_valid;
} DIAG09_VIEW;
static inline uint32_t d09_crc(const void *data,size_t n){
 const uint8_t *p=data;uint32_t c=~0u;
 while(n--){c^=*p++;for(unsigned i=0;i<8;i++)c=(c>>1)^(0xedb88320u&(0u-(c&1)));}return~c;
}
static inline int d09_header(const DIAG09_REGION *r){
 return r&&r->magic==DIAG09_MAGIC&&r->revision==DIAG09_REVISION&&r->bytes==sizeof(*r)&&
  !(__atomic_load_n(&r->flags,__ATOMIC_ACQUIRE)&~(DIAG09_FLAG_OVERFLOW|DIAG09_FLAG_DROPPED_WRITER|DIAG09_FLAG_REQUEST_PENDING|DIAG09_FLAG_INCOMPLETE));
}
static inline int d09_take(DIAG09_REGION *r){
 if(!d09_header(r))return 0;
 uint32_t expected=0;
 if(!__atomic_compare_exchange_n(&r->writer_lock,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED)){
  __atomic_fetch_or(&r->flags,DIAG09_FLAG_DROPPED_WRITER,__ATOMIC_RELAXED);return 0;
 }
 return 1;
}
static inline void d09_leave(DIAG09_REGION *r){__atomic_store_n(&r->writer_lock,0,__ATOMIC_RELEASE);}
static inline int d09_record_ok(const DIAG09_RECORD *r){
 DIAG09_RECORD c=*r;uint32_t expected=c.crc32;c.crc32=0;
 return !c.reserved32&&!c.reserved64&&!(c.valid&~DIAG09_VALID_MASK)&&expected==d09_crc(&c,sizeof(c));
}
static inline void d09_finish_record(DIAG09_RECORD *r,uint64_t serial){
 r->request_serial=serial;r->reserved32=0;r->reserved64=0;r->crc32=0;r->crc32=d09_crc(r,sizeof(*r));
}
static inline void d09_first(DIAG09_REGION *r,const DIAG09_RECORD *source){
 if(!source||!source->reason||source->classification==0||!d09_take(r))return;
 if(!r->first_commit){
  DIAG09_RECORD copy=*source;d09_finish_record(&copy,0);
  __atomic_store_n(&r->first_commit,1,__ATOMIC_RELEASE);
  r->first=copy;__atomic_store_n(&r->first_commit,2,__ATOMIC_RELEASE);
 }
 d09_leave(r);
}
static inline uint64_t d09_request(DIAG09_REGION *r,const DIAG09_RECORD *source){
 if(!source||!source->reason||!d09_take(r))return 0;
 uint64_t serial=0;
 if(__atomic_load_n(&r->flags,__ATOMIC_ACQUIRE)&DIAG09_FLAG_REQUEST_PENDING){__atomic_fetch_or(&r->flags,DIAG09_FLAG_DROPPED_WRITER,__ATOMIC_RELAXED);goto done;}
 if(r->request_count==UINT64_MAX||r->request_commit>UINT64_MAX-2||r->request_commit&1){
  __atomic_fetch_or(&r->flags,DIAG09_FLAG_OVERFLOW|DIAG09_FLAG_INCOMPLETE,__ATOMIC_RELAXED);goto done;
 }
 serial=r->request_count+1;DIAG09_RECORD copy=*source;d09_finish_record(&copy,serial);
 uint64_t previous=r->request_commit;__atomic_store_n(&r->request_commit,previous+1,__ATOMIC_RELEASE);
 r->request=copy;r->request_count=serial;
 __atomic_store_n(&r->request_commit,previous+2,__ATOMIC_RELEASE);
 __atomic_fetch_or(&r->flags,DIAG09_FLAG_REQUEST_PENDING,__ATOMIC_RELAXED);
done:d09_leave(r);return serial;
}
static inline void d09_complete(DIAG09_REGION *r,uint64_t serial){
 if(!serial||!d09_take(r))return;
 if((__atomic_load_n(&r->flags,__ATOMIC_ACQUIRE)&DIAG09_FLAG_REQUEST_PENDING)&&r->request.request_serial==serial&&
    r->request_commit&&!(r->request_commit&1)&&d09_record_ok(&r->request))
  __atomic_fetch_and(&r->flags,~DIAG09_FLAG_REQUEST_PENDING,__ATOMIC_RELAXED);
 d09_leave(r);
}
static inline int d09_prompt(DIAG09_REGION *r,DIAG09_VIEW *view){
 if(!view)return 0;memset(view,0,sizeof(*view));if(!d09_take(r))return 0;
 if(r->prompt_count!=UINT64_MAX)r->prompt_count++;else __atomic_fetch_or(&r->flags,DIAG09_FLAG_OVERFLOW,__ATOMIC_RELAXED);
 view->request_count=r->request_count;view->prompt_count=r->prompt_count;view->ack_count=r->ack_count;view->flags=__atomic_load_n(&r->flags,__ATOMIC_ACQUIRE);
 if(r->first_commit&&!(r->first_commit&1)&&d09_record_ok(&r->first)){view->first=r->first;view->first_valid=1;}
 if((__atomic_load_n(&r->flags,__ATOMIC_ACQUIRE)&DIAG09_FLAG_REQUEST_PENDING)&&r->request_commit&&!(r->request_commit&1)&&d09_record_ok(&r->request)){
  view->request=r->request;view->request_valid=1;
 }
 d09_leave(r);return 1;
}
static inline void d09_ack(DIAG09_REGION *r){
 if(!d09_take(r))return;
 if(r->ack_count!=UINT64_MAX)r->ack_count++;else __atomic_fetch_or(&r->flags,DIAG09_FLAG_OVERFLOW,__ATOMIC_RELAXED);
 d09_leave(r);
}
#endif
