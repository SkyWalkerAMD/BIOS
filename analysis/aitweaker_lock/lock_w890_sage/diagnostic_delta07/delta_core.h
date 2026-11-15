#ifndef W890_DELTA07_CORE_H
#define W890_DELTA07_CORE_H
#include <stddef.h>
#include <stdint.h>
#define D7_HEADER_BYTES 224U
#define D7_KIND_CPU_DELTA 1U
#define D7_KIND_UNKNOWN_RAW 2U
#define D7_KIND_FIXED_DELTA 3U
#define D7_DIAGNOSTIC_ONLY 1U
#define D7_CPU_TEXT_SHAPE 2U
#define D7_UNKNOWN_CONTENT 4U
enum {D7_OK=0,D7_FORMAT=1,D7_TARGET=2,D7_FINGERPRINT=3,D7_BASELINE=4,D7_NEED_SPACE=5,D7_OVERFLOW=6};
typedef struct {
 uint32_t kind,artifact_id,package_index,expected_length,observed_instances,instance_index;
 uint64_t current_hii;
 uint8_t package_guid[16],source_log_sha[32],selection_sha[32],expected_sha[32];
} D7_META;
typedef struct {uint32_t required,body_bytes,prefix,suffix,flags,body_crc;uint8_t packet_sha[32];} D7_RESULT;
typedef struct {uint32_t offset,bytes,form_count;uint8_t sha[32];} D7_FORMS;
#ifdef D7_EXPORT
#define D7_API __declspec(dllexport)
#else
#define D7_API
#endif
/* PackageList input is an owned ExportPackageLists snapshot. String package
 * bodies are skipped, never interpreted, hashed or exported by this routine. */
D7_API int d7_select_forms(const uint8_t *,size_t,const uint8_t guid[16],uint32_t,D7_FORMS *);
/* No capacities are selected here: the caller supplies its reviewed budget.
 * An insufficient/null output writes no packet bytes and reports required. */
D7_API int d7_packet(const D7_META *,const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *,size_t,D7_RESULT *);
D7_API size_t d7_b64_size(size_t);
D7_API int d7_base64(const uint8_t *,size_t,char *,size_t);
#endif
