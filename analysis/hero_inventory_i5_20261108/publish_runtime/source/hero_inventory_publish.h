/* Bounded request/response inventory coordinator. No UEFI, I/O or wait loops.
 * The adapter must execute exactly the returned request on the already pinned
 * internal peer, and provide a fresh current-host source check before Next.
 * A request is consumed once: timeouts never cause an automatic resend.
 */
#ifndef HERO_INVENTORY_PUBLISH_H
#define HERO_INVENTORY_PUBLISH_H
#include <stdint.h>
#define HIP_RESOURCE_MAX 320u
#define HIP_LINK_MAX 640u
#define HIP_URI_MAX 192u
#define HIP_BODY_MAX 32768u
#define HIP_NONE 0xffffffffu
enum HIP_METHOD {HIP_GET=0,HIP_POST=1,HIP_PATCH=2,HIP_DELETE_EXACT_CACHE=3};
enum HIP_KIND {HIP_SYSTEM=1,HIP_CPU=2,HIP_MEMORY=3,HIP_PCIE_DEVICE=4,HIP_PCIE_FUNCTION=5,HIP_STORAGE=6,HIP_DRIVE=7};
enum HIP_LINK_FIELD {HIP_SYSTEM_DEVICES=1,HIP_SYSTEM_FUNCTIONS=2,HIP_DEVICE_CHASSIS=3,HIP_DEVICE_FUNCTIONS=4,HIP_STORAGE_DRIVES=5,HIP_FUNCTION_DRIVES=6,HIP_FUNCTION_CONTROLLERS=7};
enum HIP_RESULT {HIP_READY=0,HIP_WAIT=1,HIP_COMPLETE=2,HIP_ARGUMENT=10,HIP_PLAN=11,HIP_SOURCE=12,HIP_BUDGET=13,HIP_TRANSPORT=14,HIP_HTTP=15,HIP_JSON=16,HIP_IDENTITY=17,HIP_CONFLICT=18,HIP_ETAG=19,HIP_UNCONFIRMED=20,HIP_INDEX_PENDING=21,HIP_REPLAY=22,HIP_OVERFLOW=23};
typedef struct {
 uint32_t kind,parent_index,post_to_collection,reserved;
 char member_uri[HIP_URI_MAX],collection_uri[HIP_URI_MAX];
 const char *body;uint32_t body_bytes,body_crc32;
} HIP_RESOURCE;
typedef struct {uint32_t field,parent_index;char member_uri[HIP_URI_MAX];} HIP_LINK;
typedef struct {
 uint32_t version,resource_count,link_count,source_crc32,hardware_crc32;
 char system_uri[HIP_URI_MAX],chassis_uri[HIP_URI_MAX];
 HIP_RESOURCE resources[HIP_RESOURCE_MAX];HIP_LINK links[HIP_LINK_MAX];
} HIP_PLAN_DATA;
typedef struct {
 uint32_t sequence,method,resource_index,body_bytes;
 const char *uri,*body,*if_match;uint32_t if_match_bytes;
} HIP_REQUEST;
typedef struct {
 uint32_t sequence,transport_result,http_status,body_bytes;
 const char *body,*etag,*location;uint32_t etag_bytes,location_bytes;
} HIP_RESPONSE;
typedef struct {
 uint32_t version,result,phase,inflight,requests,writes,verified,indexed;
 uint32_t current_resource,current_link_group,last_http,unknown_write;
 uint32_t resource_count,link_count,extra_collection_members,reserved;
} HIP_STATE;
uint32_t HeroInventoryPublishContextSize(void);
/* Caller owns immutable plan and bodies until completion. Context requires
 * 8-byte alignment. Init ONCE per boot; never reinitialize to replay a write.
 * System is resources[0]. Paths must match the proven AMI legacy hierarchy.
 * max_ms bounds the whole session; the adapter separately bounds each I/O.
 */
int HeroInventoryPublishInit(void *,uint32_t,const HIP_PLAN_DATA *,uint64_t epoch,
                             uint32_t max_requests,uint32_t max_ms);
int HeroInventoryPublishState(const void *,HIP_STATE *);
/* source_ok is 1 only after exact live source/peer checks, not a cached flag.
 * elapsed_ms is monotonic since Init. Changing epoch or plan is fatal.
 * Returned request remains stable while inflight, but Next returns WAIT
 * without returning it again. No writes occur in either library function.
 */
int HeroInventoryPublishNext(void *,uint64_t epoch,int source_ok,uint32_t elapsed_ms,HIP_REQUEST *);
/* Recheck the exact pending request after TLS and immediately before HTTP.
 * This never issues/repeats a request. A nonzero result forbids sending it. */
int HeroInventoryPublishAuthorize(void *,const HIP_REQUEST *,uint64_t epoch,int source_ok,uint32_t elapsed_ms);
int HeroInventoryPublishAccept(void *,const HIP_RESPONSE *);
#endif
