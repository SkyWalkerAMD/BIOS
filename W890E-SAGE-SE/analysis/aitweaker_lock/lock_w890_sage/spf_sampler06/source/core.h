#ifndef W890_HII06_CORE_H
#define W890_HII06_CORE_H
#include <stdint.h>
#include <stddef.h>
#define H6_MAX_TEXT (2U*1024U*1024U)
#define H6_MAX_RELOC (128U*1024U)
typedef int (*H6_COPY)(void *,uint64_t,void *,size_t);
typedef void *(*H6_ALLOC)(void *,size_t);
typedef int (*H6_FREE)(void *,void *);
typedef struct {void *context;H6_COPY copy;H6_ALLOC alloc;H6_FREE free;} H6_HOST;
typedef struct {uint32_t rva,type;uint64_t original;} H6_RELOC;
typedef struct {
 uint8_t guid[16];const char *name;uint64_t preferred;
 uint32_t image_size,entry,text_rva,text_size,reloc_rva,reloc_size,count;
 uint8_t text_sha[32],reloc_sha[32];H6_RELOC fixups[8];
} H6_PROFILE;
enum {H6_OK=0,H6_HEADER=1,H6_RANGE=2,H6_ALLOC_FAILED=3,H6_LAYOUT=4,
 H6_RELOC_RANGE=5,H6_RELOC_TABLE=6,H6_RELOC_VALUE=7,H6_TEXT_MISMATCH=8,H6_UNKNOWN=9,H6_FREE_FAILED=10,H6_CHANGED=11};
typedef struct {
 uint32_t status,raw_valid,normalized_valid,entry,image_size,text_rva,text_size,reloc_rva,reloc_size;
 uint8_t raw[32],normalized[32];
} H6_RESULT;
#ifdef H6_EXPORT
#define H6_API __declspec(dllexport)
#else
#define H6_API
#endif
H6_API int h6_probe(const H6_HOST *,uint64_t,uint64_t,const H6_PROFILE *,H6_RESULT *);
H6_API const H6_PROFILE *h6_profile(const uint8_t *);
H6_API size_t h6_profile_count(void);
H6_API const H6_PROFILE *h6_profile_at(size_t);
H6_API const char *h6_status(unsigned);
#endif
