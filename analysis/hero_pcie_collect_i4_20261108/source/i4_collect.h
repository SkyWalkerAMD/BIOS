#ifndef I4_COLLECT_H
#define I4_COLLECT_H
#include "efi_min.h"
#define I4_PCI_LIMIT 128U
#define I4_BLOCK_LIMIT 128U
#define I4_DISK_LIMIT 64U
#define I4_PATH_CAP 1024U
#define I4_IDENTIFY_CAP 4096U
#define I4_MAP_CAP 262144U
#define I4_MAP_ENTRIES 4096U
typedef int (*I4_APPEND)(void *,const char *,size_t);
/* Appends bounded structured text. Return is collection integrity, not a claim
 * that every optional protocol or device identification was available. */
ES pcie_storage_collect(ST *,I4_APPEND,void *);

typedef struct {uint32_t type,pad;uint64_t physical,virtual_address,pages,attributes;} I4_MD;
typedef struct {const uint8_t *data;size_t bytes,descriptor_bytes;} I4_MAP;
typedef struct {
 uint32_t media_id;uint8_t removable,present,partition,read_only,write_cache;
 uint32_t block_size,io_align;uint64_t last_block,lowest_lba;
 uint32_t logical_per_physical,optimal_transfer;
} I4_MEDIA;
typedef struct {
 uint64_t revision;I4_MEDIA *media;void *reset,*read_blocks,*write_blocks,*flush;
} I4_BLOCK;
typedef struct I4_DISK I4_DISK;
struct I4_DISK {
 GUID interface;void *inquiry;
 ES (EA *identify)(I4_DISK *,void *,uint32_t *);
 void *sense,*which_ide;
};
OFF(I4_MD,physical,8);OFF(I4_MD,pages,24);OFF(I4_MD,attributes,32);
OFF(I4_MEDIA,block_size,12);OFF(I4_MEDIA,io_align,16);OFF(I4_MEDIA,last_block,24);
OFF(I4_MEDIA,lowest_lba,32);OFF(I4_MEDIA,logical_per_physical,40);OFF(I4_MEDIA,optimal_transfer,44);
OFF(I4_BLOCK,media,8);OFF(I4_BLOCK,reset,16);OFF(I4_BLOCK,read_blocks,24);OFF(I4_BLOCK,write_blocks,32);OFF(I4_BLOCK,flush,40);
OFF(I4_DISK,identify,24);OFF(I4_DISK,sense,32);OFF(I4_DISK,which_ide,40);
_Static_assert(sizeof(I4_MEDIA)==48&&sizeof(I4_DISK)==48&&sizeof(I4_BLOCK)==48,"I4 official x64 protocol sizes");
OFF(BS,get_memory_map,0x38);
/* Host-testable borrowed-memory helpers. Do not allocate or access hardware. */
int i4_range_readable(const I4_MAP *,const void *,size_t);
ES i4_path_copy(const I4_MAP *,const uint8_t *,uint8_t *,size_t *);
size_t i4_media_bytes(uint64_t);
int i4_media_fields_equal(uint64_t,const uint8_t *,const uint8_t *);
#endif
