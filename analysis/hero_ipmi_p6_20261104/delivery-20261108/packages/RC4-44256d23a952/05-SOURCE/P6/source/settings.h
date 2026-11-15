#ifndef HERO_IPMI_SETTINGS_H
#define HERO_IPMI_SETTINGS_H
#include "p5.h"
#define P6_CFG_GUID {0xbef09fe1,0x8540,0x4be1,{0x90,0x82,0xe6,0x62,0x43,0x28,0xf4,0x35}}
typedef struct {
 uint8_t source,channel,wdt_enabled,wdt_minutes,wdt_action,sel_logging,sel_erase,sel_full;
 uint8_t ip[4],mask[4],gateway[4];
 uint8_t retry;
 uint8_t reserved[11];
} P6_SETTINGS;
_Static_assert(sizeof(P6_SETTINGS)==32,"Native variable ABI");
_Static_assert(offsetof(P6_SETTINGS,ip)==8 && offsetof(P6_SETTINGS,retry)==20,"Native IFR offsets");
enum { P6_PHASE_IDLE=0,P6_PHASE_LAN=1,P6_PHASE_LOGGING=2,P6_PHASE_ERASE=3,
 P6_PHASE_FULL=4,P6_PHASE_WDT_CONFIG=5,P6_PHASE_WDT_START=6,P6_PHASE_WDT_STOP=7 };
ES p6_seed_settings(void);
void p6_load_saved_result(void);
unsigned p6_selected_lan(void);
void p6_apply_settings(void);
void p6_start_os_watchdog(void);
void p6_stop_os_watchdog(void);
ES p6_transport_open(void);
ES p6_transport_close(void);
int p6_exchange(void *,uint8_t,uint8_t,const uint8_t *,size_t,uint8_t *,size_t *);
int p6_delay(void *,unsigned);
extern unsigned p6_write_armed;
#endif
