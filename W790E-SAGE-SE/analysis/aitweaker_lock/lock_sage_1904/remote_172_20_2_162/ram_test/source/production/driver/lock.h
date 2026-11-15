#ifndef AITWK_LOCK_H
#define AITWK_LOCK_H
#include "efi.h"
#include "../core/password_core.h"
#define LOCK_QID 0xffe0u
#define LOCK_CLEAR_QID 0xffe1u
extern ST *system_table;
extern AP_CORE password_core;
extern GUID credential_guid,oc_guid,memory_guid;
extern C16 credential_name[];
extern SETVAR original_set_variable;
extern int platform_ready,boot_services_ended;
extern HANDLE setup_hii;
int initialize_services(void);
int cpu_entropy_supported(void);
int cpu_entropy(uint8_t *,size_t);
int install_variable_guard(void);
int memory_present(const void *,UN,int);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int memcmp(const void *,const void *,size_t);
size_t c16len(const C16 *);
int c16equal(const C16 *,const C16 *);
void *alloc(UN);
void release(void *);
int ensure_unlocked(void);
int manage_password(int clear);
int patch_memory(void *,const void *,UN);
void audit(uint32_t,uint64_t);
int attach_platform(uint8_t *,UN,uint8_t *,UN);
int install_hii_management(uint8_t *,UN);
void end_platform(void);
int protection_for_variable(C16 *,GUID *);
int protected_change(int,uint32_t,UN,const void *);
int policy_form(uint16_t);
int policy_question(uint16_t);
int policy_inert_ifr(const uint8_t *,UN);
int policy_ifr_insert(const uint8_t *,UN,uint16_t,uint16_t,uint16_t,uint16_t,
                      uint8_t *,UN,UN *);
#endif
