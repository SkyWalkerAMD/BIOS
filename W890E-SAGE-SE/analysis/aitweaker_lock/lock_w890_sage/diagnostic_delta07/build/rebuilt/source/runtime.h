#ifndef W890_HII06_RUNTIME_H
#define W890_HII06_RUNTIME_H
#include "efi_min.h"
int h6_begin(ST *,void (*)(const char *));
int h6_refresh(void);
int h6_range(const void *,size_t);
int h6_code(const void *);
int h6_known(const GUID *);
void h6_loaded_bad(HANDLE,const char *);
void h6_module(HANDLE,const LOADED *,const GUID *);
void h6_forms(HANDLE,const void *,size_t);
int h6_null_driver(HANDLE,const GUID *);
unsigned h6_end(void);
#endif
