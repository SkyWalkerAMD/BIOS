#ifndef LC01_CORE_H
#define LC01_CORE_H
#include <stdint.h>
#include <stddef.h>
#ifndef LC_USB_VID
#define LC_USB_VID 0x046b
#define LC_USB_PID 0xff31
#define LC_PCI_VID 0x8086
#define LC_VARIANT "PRODUCTION"
#endif
int lc_identity(unsigned vid,unsigned pid,unsigned number,unsigned alt,unsigned eps,unsigned cls,unsigned sub,unsigned proto);
int lc_exact_line(const char *value,size_t n,const char *expected);
int lc_response(int call_result,unsigned status,unsigned masked,unsigned msg,unsigned host,unsigned driver,unsigned sense,int resid,unsigned info,int guards);
int lc_retry_ua(int ret,unsigned status,unsigned masked,unsigned msg,unsigned host,unsigned driver,int resid,unsigned info,int guards,const uint8_t data[8],const uint8_t sense[32],unsigned sense_len);
int lc_capacity(const uint8_t data[8],uint32_t *last,uint32_t *block);
uint32_t lc_crc32(const void *data,size_t n);
size_t lc_frame(const void *data,size_t n,void *out,size_t cap);
int lc_display(const char *log,size_t n,const char *phase);
#endif
