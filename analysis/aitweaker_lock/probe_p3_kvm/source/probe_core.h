#ifndef PROBE_CORE_H
#define PROBE_CORE_H
#include <stdint.h>
#include <stddef.h>
typedef struct { uint32_t text_rva,text_size,entry,image_size,text_crc; } IMAGE_INFO;
typedef struct { uint32_t packages,formsets,forms,password_questions,form_2714,form_2713; } HII_INFO;
uint32_t probe_crc32(const void *,size_t);
int probe_image(const void *,size_t,IMAGE_INFO *);
int probe_hii(const void *,size_t,HII_INFO *);
#endif
