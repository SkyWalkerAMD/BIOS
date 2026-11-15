/* Pure offline/current-boot PCI catalogue. No UEFI, network or filesystem IO.
 * Produces proposed resources and MERGE-ONLY link additions, not permission
 * to publish. The caller still binds this capture to the current host/BMC. */
#ifndef HERO_PCIE_CATALOG_H
#define HERO_PCIE_CATALOG_H
#include <stdint.h>
#include <stddef.h>
#define HPC_PCI_MAX 128U
#define HPC_DEVICE_MAX 64U
#define HPC_STORAGE_MAX 32U
#define HPC_ITEM_MAX (HPC_PCI_MAX+HPC_DEVICE_MAX+HPC_STORAGE_MAX)
#define HPC_LINK_MAX 512U
#define HPC_PATH_MAX 1024U
#define HPC_URI_MAX 192U
#define HPC_JSON_MAX 131072U
#define HPC_OBJECT_MAX 8192U
#define HPC_CAPTURE_MAX 2097152U
enum HPC_ERROR {HPC_OK,HPC_ARGUMENT,HPC_OVERLAP,HPC_BOUND,HPC_CRC,HPC_FORMAT,HPC_INCOMPLETE,HPC_DUPLICATE,HPC_PATH,HPC_CONFIG,HPC_ROUTE,HPC_CAPACITY};
enum HPC_KIND {HPC_DEVICE=1,HPC_FUNCTION=2,HPC_STORAGE=3};
enum HPC_METHOD {HPC_POST_INSTANCE=1,HPC_POST_COLLECTION=2};
enum HPC_LINK_KIND {HPC_SYSTEM_DEVICE=1,HPC_SYSTEM_FUNCTION=2,HPC_DEVICE_FUNCTION=3,HPC_DEVICE_CHASSIS=4};
#define HPC_LINK_MERGE_REQUIRED 1U
#define HPC_CAPTURE_VALID 7U /* successful location/config + stable path */
typedef struct {
 uint32_t source_index,flags,config_crc32,path_crc32,path_bytes,reserved;
 uint64_t source_handle;
 uint16_t segment;uint8_t bus,device,function,pad[3];
 uint8_t config[256],path[HPC_PATH_MAX];
} HPC_PCI_RECORD;
typedef struct {
 const char *system_uri,*chassis_uri;uint32_t system_bytes,chassis_bytes;
} HPC_ROUTES;
typedef struct {
 uint32_t version,pci_declared,pci_captured,pci_complete,pci_truncated,reserved;
 uint64_t pci_status,cleanup_status;
 uint32_t source_crc32,source_bytes;
} HPC_CAPTURE;
typedef struct {
 uint32_t kind,method,source_index,device_index,config_crc32,path_crc32;
 uint32_t json_offset,json_bytes;
 uint16_t segment;uint8_t bus,device,function,reserved[3];
 char collection_uri[HPC_URI_MAX],member_uri[HPC_URI_MAX];
} HPC_ITEM;
typedef struct {
 uint32_t kind,flags,source_item,reserved;
 char parent_uri[HPC_URI_MAX],member_uri[HPC_URI_MAX];
} HPC_LINK_ADDITION;
typedef struct {
 uint32_t version,valid,result,error_index,source_crc32,source_bytes;
 uint32_t item_count,device_count,function_count,storage_count,link_count,json_bytes;
 uint32_t warnings,reserved;
 HPC_ITEM items[HPC_ITEM_MAX];HPC_LINK_ADDITION links[HPC_LINK_MAX];
 char json[HPC_JSON_MAX];
} HPC_CATALOG;
typedef struct {
 uint32_t order[HPC_PCI_MAX],device_of[HPC_PCI_MAX],device_first[HPC_DEVICE_MAX];
 uint32_t function_item[HPC_PCI_MAX],device_item[HPC_DEVICE_MAX];
} HPC_SCRATCH;
/* Buffers must be disjoint; argument/overlap failures leave output untouched.
 * Other failures invalidate output and no partial resources may be published.
 * Input records have a successful, complete PCI enumeration; CRC protects the
 * captured bytes, not trust/authenticity. Storage here describes controllers
 * only; no drive, namespace or media capacity is promoted to physical storage.
 */
int HeroPcieCatalogBuild(const HPC_PCI_RECORD *,uint32_t,const HPC_ROUTES *,
                        const HPC_CAPTURE *,HPC_CATALOG *,HPC_SCRATCH *);
uint32_t HeroPcieCrc32(const void *,size_t);
uint32_t HeroPcieCatalogSize(void);uint32_t HeroPcieScratchSize(void);uint32_t HeroPcieRecordSize(void);
/* I4 text fixture conversion is host-only. Firmware uses the separately
 * bounded typed collector/visitor and must populate HPC_CAPTURE explicitly. */
#endif
