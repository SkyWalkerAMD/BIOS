#ifndef HERO_FIRMWARE_PROBE_H
#define HERO_FIRMWARE_PROBE_H
#include "collector.h"
#define FP_MAP_CAP 131072U
#define FP_PATH_CAP 4096U
#define FP_FILE_CAP 1048576U
#define FP_IMAGE_CAP 2097152U
#define FP_HANDLE_CAP 1024U
#define FP_FV_CAP 64U
#define FP_CRC_BUDGET 8388608U
/* Callback must copy bytes synchronously; no retained pointers into this module. */
typedef void (*FP_APPEND)(void *,const char *,size_t);
/* All counts/statuses, including incomplete views, are written to append. */
ES firmware_probe(ST *,FP_APPEND,void *);
/* Pure parsers exposed for host testing. */
int fp_range_readable(const uint8_t *,size_t,size_t,uint64_t,size_t);
int fp_path_targets(const uint8_t *,size_t,unsigned *);
#endif
