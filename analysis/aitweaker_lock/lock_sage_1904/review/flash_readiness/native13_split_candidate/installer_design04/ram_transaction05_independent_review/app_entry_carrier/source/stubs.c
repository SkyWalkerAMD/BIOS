#include "app.h"
int platform_inventory(void){return 0;}
int platform_prepare(RAM_SESSION *s,unsigned m){(void)s;(void)m;return 0;}
uint32_t platform_install(RAM_SESSION *s){(void)s;return TX_REFUSED;}
int platform_start_provider(RAM_SESSION *s){(void)s;return 0;}
uint32_t platform_remove(RAM_SESSION *s){(void)s;return TX_REFUSED;}
int ui_capture_initial(void){return 0;}
int ui_open_management(RAM_SESSION *s){(void)s;return 0;}
int ui_open_original_setup(RAM_SESSION *s){(void)s;return 0;}
int ui_restore_credential(RAM_SESSION *s){(void)s;return 0;}
int ui_compare_original_stores(void){return 0;}
ES kvm_present(ST *st,const char *p,size_t n,unsigned w){(void)st;(void)p;(void)n;(void)w;return 0;}
