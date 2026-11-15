/* Current-boot read-only hardware source. No publication and no UI/network IO.
 * All record views are borrowed until visitor return. Visitor MUST stage data,
 * then check the corresponding completed group before constructing inventory.
 * Missing/unsupported/truncated data never authorizes deletion of inventory. */
#ifndef HERO_HARDWARE_SOURCE_H
#define HERO_HARDWARE_SOURCE_H
#include <stdint.h>
#include <stddef.h>
#define HHS_VERSION 1U
#define HHS_PCI_LIMIT 128U
#define HHS_BLOCK_LIMIT 128U
#define HHS_DISK_LIMIT 64U
#define HHS_PATH_LIMIT 1024U
#define HHS_IDENTIFY_LIMIT 4096U
#define HHS_MEMORY_MAP_LIMIT 262144U
enum HHS_KIND {HHS_PCI=1,HHS_BLOCK=2,HHS_DISK=3};
enum HHS_ISSUE {
 HHS_ENUMERATION=1U,HHS_LIMIT=2U,HHS_MEMORY_MAP=4U,HHS_PROTOCOL=8U,
 HHS_LOCATION=16U,HHS_CONFIG=32U,HHS_PATH=64U,HHS_PATH_CHANGED=128U,
 HHS_MEDIA=256U,HHS_MEDIA_CHANGED=512U,HHS_IDENTIFY=1024U,HHS_BUFFER=2048U,
 HHS_VISITOR_ABORTED=4096U,HHS_CLEANUP=8192U
};
enum HHS_DISK_SKIP {HHS_DISK_CALLED=0,HHS_DISK_UNSUPPORTED=1,HHS_DISK_GETTER_UNAVAILABLE=2};
#define HHS_PCI_LOCATION_VALID 1U
#define HHS_PCI_CONFIG_VALID 2U
#define HHS_PCI_PATH_VALID 4U
#define HHS_PCI_VALID 7U
typedef struct {
 uint64_t protocol_status,pointer,first_status,second_status;
 uint32_t first_bytes,second_bytes,first_crc32,second_crc32,valid,stable;
 const uint8_t *first,*second;
} HHS_PATH_VIEW;
typedef struct {
 uint64_t location_status,config_status,segment,bus,device,function;
 uint32_t flags,config_bytes,config_crc32,reserved;
 const uint8_t *config;
} HHS_PCI_VIEW;
typedef struct {
 uint64_t revision,media_pointer,revision_after,media_pointer_after;
 uint32_t media_bytes,readable,stable,reserved;
 const uint8_t *first,*second;
} HHS_BLOCK_VIEW;
typedef struct {
 uint8_t interface_guid_le[16];
 uint64_t identify_status;
 uint32_t expected_bytes,returned_bytes,captured_bytes,crc32;
 uint32_t allowlisted,skip,buffer_guards_ok,format_size_match;
 const uint8_t *identify;
} HHS_DISK_VIEW;
typedef struct {
 uint32_t version,bytes,kind,source_index;
 uint64_t source_handle,protocol_status,protocol_pointer;
 uint32_t protocol_readable,valid,incomplete,issues;
 HHS_PATH_VIEW path;
 union {HHS_PCI_VIEW pci;HHS_BLOCK_VIEW block;HHS_DISK_VIEW disk;} data;
} HHS_RECORD;
typedef struct {
 uint32_t kind,limit,captured,valid_records;
 uint32_t complete,stable,truncated,incomplete_records;
 uint64_t enum_status,declared,cleanup_status;
 uint64_t memory_map_status,memory_map_bytes,descriptor_bytes;
 uint32_t memory_map_version,reserved_map;
 uint32_t issues,reserved;
 uint64_t source_bytes;
 uint32_t source_crc32,reserved2;
} HHS_GROUP;
typedef struct {
 uint32_t version,bytes,complete,incomplete;
 uint32_t visitor_calls,visitor_aborted,reserved[2];
 uint64_t status;
 HHS_GROUP groups[3]; /* PCI, BlockIo, DiskInfo; independently gated. */
} HHS_RESULT;
typedef struct {
 uint32_t version,bytes;
 void *user;
 /* 0=record accepted, any other value=abort. This is intentionally different
  * from I4's historical text append success convention. No view may be kept. */
 int (*visit)(void *,const HHS_RECORD *);
} HHS_VISITOR;
/* Caller allocates a 16-byte-aligned workspace using WorkspaceSize(), calls
 * Init once, and keeps it separate from Visitor and Result. No pool allocation
 * is performed by these helpers; Collect only frees firmware-owned handle
 * enumeration arrays obtained from LocateHandleBuffer. Workspace contains all
 * large buffers, record views and copied protocol samples. */
size_t HeroHardwareSourceWorkspaceSize(void);
int HeroHardwareSourceInit(void *workspace,size_t bytes);
/* UEFI x64 EFI_STATUS. Success=all three groups complete; EFI_NOT_READY=source
 * incomplete; EFI_ABORTED=visitor rejection; cleanup error has priority over
 * ordinary source incompleteness. Per-group complete remains independently
 * available, including after another optional group fails. */
uint64_t HeroHardwareSourceCollect(void *system_table,void *workspace,size_t bytes,
                                  const HHS_VISITOR *,HHS_RESULT *);
#endif
