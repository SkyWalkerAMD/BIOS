#ifndef P1_NATIVE_H
#define P1_NATIVE_H
#include "p1.h"
#include "hii_abi.h"
typedef struct NDB NDB;
struct NDB {
 void *new_packages,*remove_packages;
 ES (EA *update)(NDB *,HANDLE,const void *);
 ES (EA *list)(NDB *,uint8_t,const GUID *,UN *,HANDLE *);
 ES (EA *export)(NDB *,HANDLE,UN *,void *);
};
typedef struct NSTR NSTR;
struct NSTR {
 ES (EA *new_string)(NSTR *,HANDLE,uint16_t *,const char *,const C16 *,const C16 *,const void *);
 void *get;
 ES (EA *set)(NSTR *,HANDLE,uint16_t,const char *,const C16 *,const void *);
};
OFF(NDB,update,16);OFF(NDB,list,24);OFF(NDB,export,32);
OFF(NSTR,new_string,0);OFF(NSTR,set,16);
ES native_attach(void);
ES native_detach(void);
ES native_publish(void);
int native_is_attached(void);
/* Pure checked IFR splice, exercised against official bytes and malformed data. */
int native_form_bounds(const uint8_t *,size_t,size_t *,size_t *);
int native_splice(const uint8_t *,size_t,const uint8_t *,size_t,uint16_t,uint16_t,uint8_t *,size_t,size_t *);
#endif
