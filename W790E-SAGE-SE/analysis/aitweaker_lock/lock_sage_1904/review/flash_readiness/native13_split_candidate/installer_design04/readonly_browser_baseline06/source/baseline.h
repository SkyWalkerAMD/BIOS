#ifndef SAGE_BROWSER_BASELINE06_H
#define SAGE_BROWSER_BASELINE06_H
#include "efi.h"
typedef struct{UN rsp,rbp,rbx,rsi,rdi,r12,r13,r14,r15,image,st;}ENTRY_CAPTURE;
extern ENTRY_CAPTURE captured_entry;
extern ST *app_st;extern HANDLE app_image,app_setup_hii;extern void *app_browser;
extern volatile int app_ended;extern volatile uint32_t app_hold_reason;
void *memcpy(void *,const void *,size_t);void *memset(void *,int,size_t);int memcmp(const void *,const void *,size_t);
void ap_secure_zero(void *,size_t);int ap_constant_equal(const void *,const void *,size_t);void ap_sha256(const uint8_t *,size_t,uint8_t[32]);
void app_log(const char *);void app_number(const char *,uint64_t);void app_result(const char *,int);
void app_require_services(void);__attribute__((noreturn))void app_hold(uint32_t);
void baseline_tpl(void);
int baseline_inventory(void);int baseline_original_unchanged(void);void baseline_globals(const char *);
int baseline_map(void);int baseline_access(const void *,UN,int);
int browser_capture(void);int browser_publish(void);int browser_invoke(void);
#endif
