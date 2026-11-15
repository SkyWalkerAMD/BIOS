/* Transport-free, freestanding inventory write gate. No BMC/UEFI calls.
 * The adapter owns identity parsing, JSON, HTTPS, journaling and deadlines.
 * A new instance is used only after a complete fresh preflight; never resume
 * a persisted write intent by replaying its request after reset/connection loss.
 */
#ifndef HERO_INVENTORY_PUBLISH_GATE_H
#define HERO_INVENTORY_PUBLISH_GATE_H

typedef unsigned int HERO_INV_U32;
typedef unsigned long long HERO_INV_U64;

enum HERO_INV_MODE { HERO_INV_LEGACY = 1, HERO_INV_BULK = 2 };
enum HERO_INV_KIND {
    HERO_INV_SYSTEM_PATCH = 1, HERO_INV_RESOURCE_POST = 2,
    HERO_INV_BULK_POST = 3, HERO_INV_BULK_FINISH = 4
};
enum HERO_INV_PHASE {
    HERO_INV_READY = 1, HERO_INV_WAIT_RESULT = 2, HERO_INV_VERIFY = 3,
    HERO_INV_UNKNOWN_VERIFY = 4, HERO_INV_REJECTED_VERIFY = 5,
    HERO_INV_ALL_WRITES_VERIFIED = 6, HERO_INV_HOLD_RECONCILED = 7,
    HERO_INV_HOLD_UNVERIFIED = 8, HERO_INV_CORE_VERIFIED = 9,
    HERO_INV_CORE_VERIFIED_WARNINGS = 10
};
enum HERO_INV_CHECKS {
    HERO_INV_SAME_BOOT = 1, HERO_INV_LOCAL_IDENTITY_MATCH = 2,
    HERO_INV_INTERNAL_USB_MATCH = 4, HERO_INV_PEER_PIN_MATCH = 8,
    HERO_INV_SAME_SERVICE_PATH = 16, HERO_INV_FRESH_BASELINE = 32,
    HERO_INV_INTENT_DURABLY_RECORDED = 64, HERO_INV_EXACT_BODY_HASH = 128,
    HERO_INV_REQUIRED_CHECKS = 255
};
typedef struct {
    HERO_INV_U32 Version, Mode, Phase, Count, Index, Readbacks, ActiveKind, BulkPostAcknowledged;
    HERO_INV_U64 LastSequence;
} HERO_INV_GATE;

HERO_INV_U32 HeroInvGateSize(void);
int HeroInvInit(HERO_INV_GATE *g, HERO_INV_U32 mode, HERO_INV_U32 operations);
/* Call only AFTER persisting this exact intent (method/path/body hash/boot).
 * Required checks refer to the current request, not the previous operation.
 */
int HeroInvBegin(HERO_INV_GATE *g, HERO_INV_U32 kind, HERO_INV_U64 sequence, HERO_INV_U32 checks);
/* HTTP status 0 or transport_error means outcome unknown, never auto-replay. */
int HeroInvAcknowledge(HERO_INV_GATE *g, HERO_INV_U32 http_status,
                       int transport_error, HERO_INV_U64 sequence);
/* matches means fresh GET of EVERY expected field, correct type and member ID.
 * For bulk-finish it also requires InventoryData.Status == Completed.
 */
int HeroInvReadback(HERO_INV_GATE *g, int query_ok, int matches, HERO_INV_U64 sequence);
int HeroInvFinalReadback(HERO_INV_GATE *g, int query_ok, int matches, int warnings,
                        HERO_INV_U64 sequence);
#endif
