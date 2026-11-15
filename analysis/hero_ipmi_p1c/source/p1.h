#ifndef HERO_P1_H
#define HERO_P1_H
#include "r2.h"
#define P1_API_GUID {0x4c8dd4ac,0x6827,0x4431,{0xb9,0xc7,0x0a,0xd4,0x1e,0x87,0x1d,0xb1}}
#define P1_FORM_GUID {0x491ef9f7,0x625c,0x48dc,{0xb1,0x40,0x2c,0x85,0x77,0xba,0x47,0xf1}}
enum { V_RESULT,V_SELFTEST,V_DEVICE,V_REVISION,V_FIRMWARE,V_IPMI,V_MFG,V_PRODUCT,
 V_WDT_RUNNING,V_WDT_USE,V_WDT_POLICY,V_WDT_INITIAL,V_WDT_REMAINING,
 V_SEL_COUNT,V_SEL_FREE,V_SEL_OVERFLOW,V_SEL_LOGGING,V_SEL_RANGE,
 V_CHANNEL,V_SOURCE,V_IP,V_MASK,V_GATEWAY,V_MAC,V_SEL0,V_COUNT=V_SEL0+16 };
extern char values[V_COUNT][160];
extern ES last_refresh;
typedef struct {
 uint32_t version,size;
 ES (EA *refresh)(void);
 const char *(EA *log)(UN *);
 const char *(EA *value)(unsigned);
 ES (EA *native_link)(void);
 HANDLE driver_image;
} P1_API;
ES p1_collect(void);
void value_text(unsigned,const char *);
void value_hex(unsigned,uint64_t,unsigned);
void value_dec(unsigned,uint32_t);
void value_ip(unsigned,const uint8_t *);
int p1_read_allowed(uint8_t,uint8_t,const uint8_t *,size_t);
#endif
