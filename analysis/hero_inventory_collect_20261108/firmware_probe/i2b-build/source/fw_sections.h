#ifndef HERO_FW_SECTIONS_H
#define HERO_FW_SECTIONS_H
#include <stdint.h>
#include <stddef.h>
typedef struct {uint32_t offset,size,payload,payload_size,type;} FP_SECTION;
typedef struct {uint32_t count,pe_count,encapsulated;FP_SECTION items[64];} FP_SECTIONS;
enum {FP_SECT_OK,FP_SECT_ARGUMENT,FP_SECT_HEADER,FP_SECT_LENGTH,FP_SECT_LIMIT,FP_SECT_PADDING};
/* Input is EFI_FV2 ReadFile body, without the 24/32-byte FFS header.
 * Parse top-level sections only; no decompression, extraction protocol or execution. */
int fp_sections_parse(const uint8_t *,size_t,FP_SECTIONS *);
#endif
