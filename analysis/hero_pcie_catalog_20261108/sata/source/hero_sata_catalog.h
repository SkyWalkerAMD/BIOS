/* Pure current-boot SATA catalogue. No IO, network or permission to publish.
 * All storage views are copied before the HHS visitor returns. Incomplete
 * groups fail closed; absent/unsupported devices never authorize deletions. */
#ifndef HERO_SATA_CATALOG_H
#define HERO_SATA_CATALOG_H
#include "hero_pcie_catalog.h"
#include "hero_hardware_source.h"
#define HSC_DRIVE_MAX 32U
#define HSC_JSON_MAX 32768U
#define HSC_OBJECT_MAX 1024U
enum HSC_ERROR {HSC_OK,HSC_ARGUMENT,HSC_OVERLAP,HSC_BOUND,HSC_CRC,HSC_FORMAT,HSC_INCOMPLETE,HSC_DUPLICATE,HSC_PATH,HSC_IDENTIFY,HSC_ROUTE,HSC_CAPACITY,HSC_ASSOCIATION,HSC_MEDIA,HSC_PCI};
/* Exact field locations: 1 Storage.Drives (TOP LEVEL), 2 Function.Links.Drives,
 * 3 Function.Links.StorageControllers. The controller member uses the source
 * handler's URI fragment #/StorageControllers/0, not a guessed child path. */
enum HSC_LINK_KIND {HSC_STORAGE_DRIVE=1,HSC_FUNCTION_DRIVE=2,HSC_FUNCTION_CONTROLLER=3};
typedef struct {
 uint32_t source_index,path_bytes,path_crc32,media_bytes,media_crc32,reserved;
 uint64_t source_handle,revision;
 uint8_t path[HPC_PATH_MAX],media[48];
} HSC_BLOCK;
typedef struct {
 uint32_t source_index,path_bytes,path_crc32,identify_crc32;
 uint64_t source_handle;
 uint8_t path[HPC_PATH_MAX],identify[512];
} HSC_DISK;
typedef struct {
 uint32_t version,rejected,block_seen,disk_seen,ata_count,reserved[3];
 HSC_BLOCK blocks[HHS_BLOCK_LIMIT];HSC_DISK ata[HHS_DISK_LIMIT];
} HSC_SOURCE;
typedef struct {
 uint32_t method,disk_index,block_index,pci_index,path_crc32,identify_crc32;
 uint32_t logical_sector_bytes,json_offset,json_bytes,reserved;
 uint64_t capacity_bytes,source_handle;
 uint16_t segment,port,pmp,lun;uint8_t bus,device,function,pad;
 char collection_uri[HPC_URI_MAX],member_uri[HPC_URI_MAX];
} HSC_ITEM;
typedef struct {
 uint32_t kind,flags,item_index,reserved;
 char parent_uri[HPC_URI_MAX],member_uri[HPC_URI_MAX];
} HSC_LINK;
typedef struct {
 uint32_t version,valid,result,error_index,item_count,link_count,json_bytes,skipped;
 uint32_t source_crc32[3],reserved;
 HSC_ITEM items[HSC_DRIVE_MAX];HSC_LINK links[HSC_DRIVE_MAX*3];
 char json[HSC_JSON_MAX];
} HSC_CATALOG;
int HeroSataSourceInit(HSC_SOURCE *);
/* HHS visitor convention: 0 accepted; nonzero abort. Ignores PCI, retains all
 * valid BlockIo records and AHCI Identify-512 only. NVMe Namespace/USB metadata
 * can be observed but is never decoded as a physical controller/drive. */
int HeroSataVisit(void *,const HHS_RECORD *);
/* Requires a previously validated HPC catalogue from the same current HHS
 * PCI group. Output links are additions requiring fresh GET/merge; this never
 * generates a replacement array PATCH. Buffers must be disjoint. */
int HeroSataCatalogBuild(const HSC_SOURCE *,const HHS_RESULT *,
                        const HPC_PCI_RECORD *,uint32_t,const HPC_CATALOG *,
                        const HPC_ROUTES *,HSC_CATALOG *);
uint32_t HeroSataSourceSize(void);uint32_t HeroSataCatalogSize(void);
uint32_t HeroSataCrc32(const void *,size_t);
#endif
