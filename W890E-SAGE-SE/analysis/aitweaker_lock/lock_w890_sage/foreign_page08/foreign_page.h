/* UI scope observation only. No callbacks, password operations or write grants. */
#ifndef W890_FOREIGN_PAGE08_H
#define W890_FOREIGN_PAGE08_H
#include "../integration05/observer.h"
#define FP08_REVISION 1u
enum {FP08_UNKNOWN=-1,FP08_ORDINARY=0,FP08_PROTECTED=1};
typedef struct {
 uint32_t revision,size;
 uint64_t visit,epoch,catalog_generation;
 uintptr_t native_base,application,page,raw_page,hii,control;
 uint32_t page_index,application_index,owner;
 int32_t classification;
 uint32_t review_flags,form_offset,ifr_offset,ifr_size;
 uint16_t form,native_type;
 uint8_t formset[16],package_list_guid[16],forms_sha256[32],ifr[127];
} FP08_VIEW;
/* These obtain private roots from the existing observer, never caller owner,
 * HII, formset, native base, digest or permission booleans. index must be the
 * exact member index in the original App page array. control must belong to
 * the current page, its frame array and canonical raw descriptor list.
 * Return1 proves bounded identity+classification; classification=-1 remains
 * unknown. It never authorizes code execution or protected settings writes. */
int EA fp08_describe_page(uintptr_t page,uint32_t index,FP08_VIEW *out);
int EA fp08_describe_control(uintptr_t page,uintptr_t control,FP08_VIEW *out);
size_t EA fp08_view_bytes(void);
/* Integrator-provided private observation APIs; TESTONLY fixture implements
 * explicit simulated anchors. no_catalog_generation grants no permission. */
int EA no_native_visit_identity(uint64_t *,uint32_t *);
int EA no_catalog_generation(uint64_t *);
#endif
