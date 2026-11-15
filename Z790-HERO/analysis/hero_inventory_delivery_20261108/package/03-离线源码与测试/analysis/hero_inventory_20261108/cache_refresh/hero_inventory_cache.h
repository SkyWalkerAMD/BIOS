/* Offline-tested cache repair engine. The adapter owns TLS, firmware/source
 * identity, timeouts and logging. No arbitrary URI, key or DELETE is exposed.
 * This is not a resource deletion or inventory publication engine.
 */
#ifndef HERO_INVENTORY_CACHE_H
#define HERO_INVENTORY_CACHE_H
#include <stdint.h>
#include "../dynamic_catalog/hero_inventory_catalog.h"

enum HICR_TARGET { HICR_CPU=1, HICR_MEMORY=2 };
enum HICR_METHOD { HICR_GET=0, HICR_DELETE_CACHE=3 };
enum HICR_RESOURCE {
 HICR_GLOBAL_TABLES=0, HICR_SYSTEM=1, HICR_CPUS=2, HICR_DIMMS=3,
 HICR_CPU_ITEM=4, HICR_DIMM_ITEM=5
};
enum HICR_RESULT {
 HICR_READY=0, HICR_COMPLETE=1, HICR_REFRESHED=2,
 HICR_ARGUMENT=10, HICR_CATALOG=11, HICR_SOURCE=12, HICR_BUDGET=13,
 HICR_TRANSPORT=14, HICR_HTTP=15, HICR_JSON=16, HICR_IDENTITY=17,
 HICR_MEMBER=18, HICR_COLLECTION=19, HICR_NO_CACHE=20, HICR_ETAG=21,
 HICR_REPLAY_BLOCKED=22, HICR_RESPONSE_UNCONFIRMED=23,
 HICR_INDEX_INCOMPLETE=24, HICR_HELD=25
};
enum HICR_PHASE {
 HICR_IDLE=0, HICR_BASELINE=1, HICR_CAPABILITY=2,
 HICR_ATTEMPTED=3, HICR_READBACK=4, HICR_FINISHED=5
};
typedef struct {
 uint32_t status;
 const char *body;
 uint32_t bytes;
 /* Optional HTTP ETag: if present, it must agree with the body's fresh tag.
  * Body @odata.etag is sufficient for the already observed AMI responses. */
 const char *etag;
 uint32_t etag_bytes;
} HICR_REPLY;
typedef struct {
 void *user;
 /* Must check this boot, exact current SMBIOS, supported HERO/BIOS/BMC and
  * all existing transport safety gates. Called before EVERY exchange. */
 int (*source_valid)(void *,uint64_t,const HIC_CATALOG *);
 /* Reserve log space/time for the stated maximum number of exchanges. */
 int (*reserve)(void *,uint32_t);
 /* All resources are enums, not strings supplied by a remote response.
  * Return 0 only if a complete HTTP response was received. Bound each call.
  * Never retry DELETE inside this adapter, including a TLS/network retry. */
 int (*exchange)(void *,uint32_t,uint32_t,uint32_t,const char *,uint32_t,
                 const char *,uint32_t,HICR_REPLY *);
} HICR_OPS;
typedef struct {
 uint32_t version,last_result,phase,target,attempted_mask,acknowledged_mask;
 uint32_t verified_mask,hold,last_http_status,exchanges;
 uint32_t delete_transport_failed,delete_http_status,delete_target;
} HICR_STATE;

/* Allocate this many bytes in pool/heap, aligned to 8; do not use UEFI stack.
 * Initialize ONCE per application boot. Do not reset it to retry a write. */
uint32_t HeroInventoryCacheContextSize(void);
int HeroInventoryCacheInit(void *,uint32_t,uint64_t source_epoch);
int HeroInventoryCacheState(const void *,HICR_STATE *);
/* Inspect is always read-only, including after a failed/uncertain DELETE. */
int HeroInventoryCacheInspect(void *,uint32_t,const HIC_CATALOG *,const HICR_OPS *);
/* Explicitly invoked repair. Fresh preflight, at most one DELETE of the
 * selected exact SRK key, then one complete readback. No automatic retry.
 * A missing collection member alone NEVER authorizes resource creation. */
int HeroInventoryCacheRefresh(void *,uint32_t,const HIC_CATALOG *,const HICR_OPS *);
/* Adapter-level allowlist and fixed path construction. No Patterns, broad
 * prefixes, collection DELETE, redirects or URI from JSON may be forwarded. */
int HeroInventoryCacheWriteAllowed(uint32_t,uint32_t,uint32_t,const char *,uint32_t,
                                  const char *,uint32_t);
int HeroInventoryCachePath(uint32_t,uint32_t,char *,uint32_t);
#endif
