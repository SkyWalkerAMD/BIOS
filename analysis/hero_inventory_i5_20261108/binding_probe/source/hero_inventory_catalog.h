/* Offline, freestanding SMBIOS -> legacy inventory JSON catalogue.
 * No UEFI, network, BMC, filesystem, heap or persistent-variable operations.
 * The caller must gate the platform, capture a valid SMBIOS entry/table,
 * and bind publication to this same boot, hardware identity and BMC peer.
 */
#ifndef HERO_INVENTORY_CATALOG_H
#define HERO_INVENTORY_CATALOG_H
#include <stdint.h>
#include <stddef.h>

#define HIC_MAX_TABLE 262144u
#define HIC_MAX_RECORDS 1024u
#define HIC_MAX_CPUS 8u
#define HIC_MAX_DIMMS 32u
#define HIC_MAX_ITEMS (1u + HIC_MAX_CPUS + HIC_MAX_DIMMS)
#define HIC_MAX_STRING 255u
#define HIC_JSON_BYTES 32768u

enum HIC_RESULT {
 HIC_OK=0, HIC_ARGUMENT=1, HIC_TABLE_BOUND=2, HIC_STRUCTURE=3,
 HIC_STRING_ENCODING=4, HIC_STRING_INDEX=5, HIC_LIMIT=6,
 HIC_DUPLICATE_HANDLE=7, HIC_MISSING_TYPE=8, HIC_AMBIGUOUS_TYPE=9,
 HIC_UUID_UNAVAILABLE=10, HIC_IDENTITY_UNAVAILABLE=11,
 HIC_JSON_OVERFLOW=12, HIC_BAD_VALUE=13, HIC_BAD_VERSION=14
};
enum HIC_KIND { HIC_SYSTEM_PATCH=1, HIC_CPU_POST=2, HIC_MEMORY_POST=3 };
enum HIC_WARNING {
 HIC_UNKNOWN_CAPACITY=1, HIC_UNKNOWN_SPEED=2, HIC_UNKNOWN_CPU_COUNT=4,
 HIC_FRACTIONAL_MIB_OMITTED=8, HIC_PLACEHOLDER_OMITTED=16
};
typedef struct {
 uint32_t kind, index, json_offset, json_bytes, source_offset;
 uint16_t source_handle, reserved;
} HIC_ITEM;
typedef struct {
 uint32_t version, valid, result, error_offset, warnings;
 uint32_t item_count, cpu_count, dimm_count, json_bytes, table_bytes, table_crc32;
 uint8_t smbios_major, smbios_minor, reserved[2];
 char uuid[37], bios_version[256], board_model[256], board_manufacturer[256];
 HIC_ITEM items[HIC_MAX_ITEMS];
 char json[HIC_JSON_BYTES];
} HIC_CATALOG;
typedef struct {
 uint32_t offset, strings_begin, strings_end;
 uint16_t handle;
 uint8_t type, length;
} HIC_RECORD;
typedef struct {
 uint8_t handles[8192];
 HIC_RECORD bios, system, board, cpus[HIC_MAX_CPUS], dimms[HIC_MAX_DIMMS];
 uint32_t bios_count, system_count, board_count, cpu_count, dimm_count, record_count;
} HIC_SCRATCH;

/* Input table ends exactly after Type127 double NUL, not its maximum bound.
 * All three buffers must be disjoint. ALWAYS check the return value first:
 * argument/overlap errors leave buffers untouched; other errors invalidate out.
 * UTF-8 strings are validated and JSON emitted as ASCII with Unicode escapes.
 * JSON bodies are individually NUL-terminated; json_bytes excludes each NUL.
 * Only Type0/1/2 identity, Type4 CPU and Type17 DIMMs are emitted.
 */
int HeroInventoryBuild(const uint8_t *table,uint32_t bytes,uint8_t major,uint8_t minor,
                       HIC_CATALOG *catalog,HIC_SCRATCH *scratch);
uint32_t HeroInventoryCatalogSize(void);
uint32_t HeroInventoryScratchSize(void);
#endif
