#ifndef M1_HII_ABI_H
#define M1_HII_ABI_H
#include "efi_min.h"
typedef struct HDB HDB;
struct HDB {
    ES (EA *new_packages)(HDB *,const void *,HANDLE,HANDLE *);
    ES (EA *remove_packages)(HDB *,HANDLE);
};
typedef struct HSTR HSTR;
struct HSTR {
    void *new_string,*get_string;
    ES (EA *set_string)(HSTR *,HANDLE,uint16_t,const char *,C16 *,const void *);
};
typedef struct ROUTING ROUTING;
struct ROUTING {
    void *extract,*export_config,*route;
    ES (EA *block_to_config)(ROUTING *,const C16 *,const uint8_t *,UN,C16 **,C16 **);
    ES (EA *config_to_block)(ROUTING *,const C16 *,uint8_t *,UN *,C16 **);
};
typedef struct ACCESS ACCESS;
struct ACCESS {
    ES (EA *extract)(ACCESS *,const C16 *,C16 **,C16 **);
    ES (EA *route)(ACCESS *,const C16 *,C16 **);
    ES (EA *callback)(ACCESS *,UN,uint16_t,uint8_t,void *,UN *);
};
typedef struct BROWSER BROWSER;
struct BROWSER {
    ES (EA *send_form)(BROWSER *,HANDLE *,UN,GUID *,uint16_t,void *,UN *);
    void *browser_callback;
};
OFF(HSTR,set_string,16);OFF(ROUTING,block_to_config,24);OFF(ROUTING,config_to_block,32);
#endif
