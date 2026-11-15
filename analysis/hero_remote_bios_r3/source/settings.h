#ifndef HERO_SETTINGS_H
#define HERO_SETTINGS_H
#include "r2.h"
#define SETUP_SIZE 3398U
#define TX_MAGIC 0x33524248U
typedef struct {
 uint32_t magic,version,size,setting,before_crc,after_crc,attrs,setup_size;
 uint8_t old_value,new_value,reserved[26];
 uint32_t checksum;
} TRANSACTION;
_Static_assert(sizeof(TRANSACTION)==64,"transaction format");
typedef struct {const char *name;uint32_t offset,maximum;} SETTING;
extern const SETTING settings[3];
uint32_t probe_crc32(const void *,size_t);
int setting_valid(uint32_t,uint32_t);
int transaction_valid(const TRANSACTION *);
int prepare_update(const uint8_t *,size_t,uint32_t,uint32_t,uint32_t,uint8_t *,TRANSACTION *);
int prepare_restore(const uint8_t *,size_t,const TRANSACTION *,uint8_t *);
#endif
