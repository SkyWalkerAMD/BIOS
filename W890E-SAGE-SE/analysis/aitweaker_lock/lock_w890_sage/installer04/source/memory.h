/* W890 installer: read-only observation of the current firmware address space. */
#ifndef W890_I04_MEMORY_H
#define W890_I04_MEMORY_H
#include "../../password_runtime02/source/efi.h"
#define I04_MAP_BYTES (128U*1024U)
typedef struct {uint32_t type,pad;uint64_t start,virtual_start,pages,attrs;} I04_MD;
typedef struct {uint64_t cr0,cr3,cr4,efer,pat;uint32_t physical_bits,reserved;} I04_CPU;
typedef struct {uint64_t physical,leaf_bytes;uint32_t rw,nx,user,pat;} I04_PAGE;
typedef struct {
 uint8_t map[I04_MAP_BYTES];UN bytes,stride,key;I04_CPU cpu;
 ST *st;BS *bs;ES(EA *get_map)(UN *,void *,UN *,UN *,uint32_t *);
 uint32_t valid;volatile uint32_t ended;
} I04_VM;
int i04_cpu(I04_CPU *);
int i04_capture(I04_VM *,ST *);
int i04_vm_current(const I04_VM *);
int i04_readable(const I04_VM *,uint64_t,UN);
int i04_walk(const I04_VM *,uint64_t,I04_PAGE *);
int i04_access(const I04_VM *,uint64_t,UN,int writable,int executable);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int memcmp(const void *,const void *,size_t);
#endif
