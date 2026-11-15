#ifndef HERO_SEL_DECODE_H
#define HERO_SEL_DECODE_H
#include <stddef.h>
#include <stdint.h>

/* Pure formatting only. The production value buffer is 160 ASCII bytes.
 * Complete 16-byte input remains at the end as 32 hexadecimal digits. */
enum { SEL_FORMAT_OK=0, SEL_FORMAT_INVALID=1, SEL_FORMAT_TRUNCATED=2 };
int sel_format_record(char *out,size_t cap,const uint8_t *record,size_t length);
#endif
