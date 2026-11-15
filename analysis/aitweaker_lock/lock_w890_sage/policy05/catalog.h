/* Static IFR description only. A match NEVER grants native execution or write
 * permission. Caller must separately establish live HII/producer/object identity,
 * callback effects, current visit and password authorization. */
#ifndef W890_FOREIGN_CATALOG05_H
#define W890_FOREIGN_CATALOG05_H
#include "../password/core/password_core.h"

enum { FH05_CALLBACK_REVIEW=1, FH05_EXTENSION=2, FH05_REF_UNRESOLVED=4,
       FH05_STORAGE_LAYOUT=8, FH05_LIVE_IDENTITY_REQUIRED=16, FH05_DYNAMIC_TARGET=32 };
typedef struct {int32_t storage_risk;uint32_t review_flags;} FH05_DESCRIPTION;
/* forms is the complete FORMS package, including its four-byte header.
 * offset is a byte offset within that package. is_control: 0=FORM, 1=question.
 * Return 1 means a catalog record matched, not that execution is allowed.
 * storage_risk -1/0/1 = unknown / no known protected storage / protected.
 * review_flags is nonzero for EVERY valid result. No cached caller-supplied
 * digest or boolean is accepted in place of hashing the actual input bytes.
 * Buffers and output must be valid readable/writable extents supplied by a
 * separately verified caller. This pure function cannot establish that owner. */
AP_API int fh05_describe(const uint8_t *forms,size_t bytes,const uint8_t formset[16],
                        uint16_t form,uint32_t offset,unsigned is_control,FH05_DESCRIPTION *out);
#endif
