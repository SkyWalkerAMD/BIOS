/* Proposed private diagnostic09 schema. No public provider ABI change.
 * This header is a reviewed design input, not a deployable implementation.
 * The only storage is state_base+[0x40,0x280), inside the already-owned4KiB.
 * Never place credentials, record bytes, salts/verifiers or their hashes here.
 */
#ifndef SAGE_DIAGNOSTIC09_H
#define SAGE_DIAGNOSTIC09_H
#include <stdint.h>
#include <stddef.h>
#define DIAG09_MAGIC 0x3930474149444753ULL
#define DIAG09_REVISION 1u
#define DIAG09_STATE_OFFSET 0x40u
#define DIAG09_REGION_BYTES 0x240u
#define DIAG09_FLAG_OVERFLOW 1u
#define DIAG09_FLAG_DROPPED_WRITER 2u
#define DIAG09_FLAG_REQUEST_PENDING 4u
#define DIAG09_FLAG_INCOMPLETE 8u
enum DIAG09_HOOK {
 D09_HOOK_NONE=0,D09_RENDER=1,D09_PAGE_INPUT=2,D09_APP_INPUT=3,
 D09_FRAME_INPUT=4,D09_POLL=5,D09_NAVIGATION=6,D09_DEFAULTS=7,
 D09_SETUP_CALLBACK=8,D09_INDEPENDENT_VERIFY=9
};
enum DIAG09_REASON {
 D09_NONE=0,D09_PAGE_MEMORY=1,D09_PAGE_FORM_GLOBALS=2,D09_PAGE_FORM_TABLE=3,
 D09_PAGE_FORM_INDEX=4,D09_PAGE_FORM_RECORD=5,D09_PAGE_OWNER=6,
 D09_PAGE_FRAMES=7,D09_FRAME_MEMORY=8,D09_FRAME_ARRAY=9,
 D09_CONTROL_MEMORY=10,D09_CONTROL_OWNER=11,D09_IFR_MEMORY=12,
 D09_IFR_LENGTH=13,D09_PROTECTED_FORM=14,D09_PROTECTED_QUESTION=15,
 D09_CHROME_KIND=16,D09_CHROME_FRAME=17,D09_CHROME_CONTROL=18,
 D09_CHROME_OBJECT_FIELDS=19,D09_CHROME_DESCRIPTOR=20,D09_CHROME_IFR=21,
 D09_CHROME_LOCATION=22,D09_CHROME_IMAGE=23,D09_CHROME_METHOD=24,
 D09_CHROME_DETOUR=25,D09_CHROME_CRC=26,D09_CHROME_HII=27,
 D09_F5=28,D09_DEFAULTS_EVENT=29,D09_NAVIGATION_FORM=30,
 D09_CALLBACK_QUESTION=31,D09_INDEPENDENT_VERIFY_ACTION=32,
 D09_NO_FRESH_REQUEST_TRACE=33
};
enum DIAG09_VALID {
 D09_V_STAGE=1ull<<0,D09_V_APP=1ull<<1,D09_V_PAGE=1ull<<2,
 D09_V_FORM=1ull<<3,D09_V_PAGE_OWNER=1ull<<4,D09_V_FRAME=1ull<<5,
 D09_V_CONTROL=1ull<<6,D09_V_CONTROL_OWNER=1ull<<7,D09_V_IFR=1ull<<8,
 D09_V_CALLBACK=1ull<<9,D09_V_NATIVE_HII=1ull<<10,
 D09_V_CALLER=1ull<<11,D09_V_PROVIDER=1ull<<12,D09_V_REDIRECT=1ull<<13,
 D09_V_EVENT=1ull<<14,D09_V_OWNER_DETAIL=1ull<<15
};
typedef struct {
 uint32_t hook,reason;                 /* 0 */
 int32_t classification;uint32_t detail;/* 8: -1 unknown,0 safe,1 protected; valid by reason */
 uint64_t valid,stage;                 /* 16,24 */
 uint32_t app_index,app_count;         /* 32 */
 uint32_t page_index,form_id;          /* 40 */
 uint64_t page_hii;                   /* 48: opaque handle, never followed by diagnostics */
 int32_t page_owner;uint32_t owner_reason; /* 56 */
 uint64_t owner_status;               /* 64: only an already returned EFI status */
 uint32_t canonical_count,target_seen;/* 72 */
 uint32_t frame_index,frame_kind,frame_count,frame_vtable_rva; /* 80 */
 uint32_t control_index,control_vtable_rva,control_type;int32_t chrome_result; /* 96 */
 uint64_t control_hii;                /* 112 */
 int32_t control_owner;uint32_t hii_class; /* 120 */
 uint32_t opcode,opcode_length,varstore_id,question_id; /* 128 */
 uint32_t varstore_offset,descriptor_flags,callback_bits,callback_module; /* 144 */
 uint64_t callback_rva;               /* 160: only if it lies inside a pinned module */
 uint32_t method_slot,descriptor_byte,source_hii_class,ifr_pointer_class; /* 168 */
 uint32_t frame_vtable_class,code_range_index; /* 184 */
 uint64_t native_strings_hii,request_return_rva; /* 192 */
 uint32_t request_return_module,provider_flags,depth;int32_t redirect_result; /* 208 */
 uint32_t event_arg,event_action,crc32,reserved32; /* 224 */
 uint64_t request_serial,reserved64;   /* 240 */
} DIAG09_RECORD;
typedef struct {
 uint64_t magic;uint32_t revision,bytes; /* 0 */
 uint64_t first_commit,request_commit;  /* 16: even sequence,0 unavailable */
 uint64_t request_count,prompt_count,ack_count; /* 32 */
 volatile uint32_t writer_lock,flags;  /* 56: nonblocking atomic claim */
 DIAG09_RECORD first;                 /* 64: first committed denial, immutable */
 DIAG09_RECORD request;               /* 320: exact current request, replaced atomically */
} DIAG09_REGION;
_Static_assert(sizeof(DIAG09_RECORD)==256,"record256");
_Static_assert(offsetof(DIAG09_RECORD,control_hii)==112,"controlHII112");
_Static_assert(offsetof(DIAG09_RECORD,crc32)==232,"crc232");
_Static_assert(offsetof(DIAG09_RECORD,request_serial)==240,"serial240");
_Static_assert(sizeof(DIAG09_REGION)==DIAG09_REGION_BYTES,"region576");
_Static_assert(offsetof(DIAG09_REGION,first)==64,"first64");
_Static_assert(offsetof(DIAG09_REGION,request)==320,"request320");
_Static_assert(DIAG09_STATE_OFFSET>=32,"preserve public state prefix");
_Static_assert(DIAG09_STATE_OFFSET+DIAG09_REGION_BYTES<=4096,"stay in owned page");
#endif
