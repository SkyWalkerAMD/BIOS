#ifndef W890_SPF_SAMPLER06_H
#define W890_SPF_SAMPLER06_H
#include "core.h"
/* Observation flags only. No value here authorizes native execution. */
enum {
 S7_VALID_MASK=0x00000fffU, S7_CODE_MATCH=1U<<12,
 S7_HEADER_MATCH=1U<<13, S7_POINTERS_MATCH=1U<<14,
 S7_COUNTS_MATCH=1U<<15, S7_READS_COMPLETE=1U<<16,
 S7_CANDIDATE_ZERO=1U<<17, S7_CANDIDATE_NONZERO=1U<<18,
 S7_UNSTABLE=1U<<19, S7_PROFILE_MISMATCH=1U<<20,
 S7_UNREADABLE=1U<<21, S7_INVALID_POINTER=1U<<22,
 S7_PROBE_FAILURE=1U<<23
};
#pragma pack(push,1)
typedef struct {
 uint64_t source,source_pages,source_guids,current_blob,current_pages;
 uint32_t declared_size,source_page_count,first_page_offset;
 uint64_t source_page0_hii;
 uint16_t header_parent_field,header_guid_index,header_form_id;
 uint32_t status_mask;
} S7_SNAPSHOT;
typedef struct {S7_SNAPSHOT a,b;} S7_PAIR;
#pragma pack(pop)
#ifdef S7_EXPORT
#define S7_API __declspec(dllexport)
#else
#define S7_API
#endif
/* h->copy must validate current mapping/readability and copy without invoking
 * native Setup/variable services. The fixed AMITSE text profile is measured by
 * h6_probe for each snapshot; no caller-provided MATCH flag is accepted.
 * Return 1 = two complete equal diagnostic observations, never authority.
 * A mapped/self-declared range is NOT proof of an allocator-owned extent. */
S7_API int s7_capture_pair(const H6_HOST *,uint64_t,uint64_t,S7_PAIR *);
#endif
