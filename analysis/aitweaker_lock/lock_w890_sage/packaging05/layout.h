#ifndef W890_STATIC_LAYOUT05_H
#define W890_STATIC_LAYOUT05_H
#include <stdint.h>
#include <stddef.h>
#define I05_LAYOUT_REVISION 5u
#define I05_MAX_SECTIONS 16u
#define I05_MAX_PATCHES 64u
#define I05_MAX_SPANS 256u
#define I05_MAX_FIXUPS 256u
#define I05_MAX_SYMBOLS 192u
#pragma pack(push,1)
typedef struct {char name[8];uint32_t rva,virtual_bytes,raw_bytes,file_offset,characteristics;} I05_SECTION;
typedef struct {uint32_t module,rva,length,target_rva,mode;uint8_t original[32],installed[32];} I05_PATCH;
typedef struct {uint32_t rva,length;uint8_t sha256[32];} I05_SPAN;
typedef struct {uint32_t rva,reserved;uint64_t preferred_value;} I05_FIXUP;
typedef struct {char name[40];uint32_t rva,kind;} I05_SYMBOL; /* 0=export, 1=trampoline */
typedef struct {
 char magic[8];
 uint32_t revision,size,image_size,entry_rva,original_entry_rva,extension_rva,extension_image_size;
 uint32_t section_count,patch_count,span_count,fixup_count,export_count,trampoline_count,slot_rva,header_bytes,reserved;
 uint8_t header_sha256[32];
 I05_SECTION sections[I05_MAX_SECTIONS];
 I05_PATCH patches[I05_MAX_PATCHES];
 I05_SPAN spans[I05_MAX_SPANS];
 I05_FIXUP fixups[I05_MAX_FIXUPS];
 I05_SYMBOL symbols[I05_MAX_SYMBOLS];
} I05_LAYOUT;
#pragma pack(pop)
/* Separate translation unit; never LTO/constant-fold the post-link slot. */
__declspec(dllexport) extern const I05_LAYOUT i05_static_layout;
const I05_LAYOUT *i05_layout_get(void);
uint32_t i05_layout_symbol(const char *name,uint32_t kind);
/* Caller must first prove the exact LoadedImage range readable via its genuine
 * EFI entry SystemTable, i04_capture/i04_access, or established no_range.
 * This function checks identity, never grants session/owner authorization.
 * It does not call UEFI or write to firmware/code/variables. */
int i05_layout_live(uintptr_t base,uint64_t size);
#endif
