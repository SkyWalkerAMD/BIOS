#ifndef SAGE_RAM_APP_H
#define SAGE_RAM_APP_H
#include "split_owner.h"
#include "transaction.h"
typedef struct {UN rsp,rbp,rbx,rsi,rdi,r12,r13,r14,r15,image,st;} ENTRY_CAPTURE;
extern ENTRY_CAPTURE captured_entry;
typedef struct {
 TX_CONTEXT tx;
 SPLIT_CONTEXT provider_context;
 HANDLE provider_image;
 GATE_PROVIDER *provider;
 uint32_t mode,prepared,published,provider_started,finished,failed;
} RAM_SESSION;
extern ST *app_st;
extern HANDLE app_image,app_setup_hii;
extern void *app_browser;
extern volatile int app_ended;
extern RAM_SESSION app_sessions[2];
/* These helpers only append bounded diagnostic text/numbers in preallocated
 * application RAM. No firmware, file or variable call is performed. Never
 * pass password/record buffers or any printable credential material. */
void app_log(const char *);
void app_number(const char *,uint64_t);
void app_result(const char *,int);
/* On ending/held state this never returns and invokes no firmware service.
 * Call before and immediately after each firmware boundary in UI code. */
void app_require_services(void);
__attribute__((noreturn)) void app_hold(uint32_t);
int platform_inventory(void);
/* Observations only; these values never establish that a browser is idle. */
int platform_native_globals(const char *label);
int platform_prepare(RAM_SESSION *,unsigned);
uint32_t platform_install(RAM_SESSION *);
int platform_start_provider(RAM_SESSION *);
uint32_t platform_remove(RAM_SESSION *);
/* session_ui.c is independently owned by uefi_lab. No global variable-table
 * interception. Initial unknown/preexisting private credential must refuse
 * modification; only the exact private record observed during this test may
 * be restored/deleted, and never printed. OC/MEM are read-only observations. */
int ui_capture_initial(void);
int ui_open_management(RAM_SESSION *);
int ui_open_original_setup(RAM_SESSION *);
int ui_restore_credential(RAM_SESSION *);
int ui_compare_original_stores(void);
#endif
