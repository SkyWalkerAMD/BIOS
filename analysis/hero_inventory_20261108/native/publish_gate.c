#include "publish_gate.h"

_Static_assert(sizeof(HERO_INV_U32) == 4, "32-bit integer required");
_Static_assert(sizeof(HERO_INV_U64) == 8, "64-bit integer required");

static int valid(const HERO_INV_GATE *g) {
    return g && g->Version == 1 && (g->Mode == HERO_INV_LEGACY || g->Mode == HERO_INV_BULK)
        && g->Index <= g->Count && g->Count <= 321;
}

HERO_INV_U32 HeroInvGateSize(void) { return (HERO_INV_U32)sizeof(HERO_INV_GATE); }

int HeroInvInit(HERO_INV_GATE *g, HERO_INV_U32 mode, HERO_INV_U32 operations) {
    if (!g || (mode != HERO_INV_LEGACY && mode != HERO_INV_BULK) || operations > 321
        || (mode == HERO_INV_BULK && operations != 2)) return 0;
    g->Version = 1; g->Mode = mode; g->Count = operations; g->Index = 0;
    g->Phase = operations ? HERO_INV_READY : HERO_INV_ALL_WRITES_VERIFIED;
    g->Readbacks = 0; g->ActiveKind = 0; g->BulkPostAcknowledged = 0; g->LastSequence = 0;
    return 1;
}

int HeroInvBegin(HERO_INV_GATE *g, HERO_INV_U32 kind, HERO_INV_U64 sequence, HERO_INV_U32 checks) {
    if (!valid(g) || g->Phase != HERO_INV_READY || g->Index >= g->Count
        || sequence <= g->LastSequence || (checks & HERO_INV_REQUIRED_CHECKS) != HERO_INV_REQUIRED_CHECKS) return 0;
    if (g->Mode == HERO_INV_LEGACY) {
        if (kind != HERO_INV_SYSTEM_PATCH && kind != HERO_INV_RESOURCE_POST) return 0;
    } else {
        if (g->Index == 0 && kind != HERO_INV_BULK_POST) return 0;
        if (g->Index == 1 && (kind != HERO_INV_BULK_FINISH || !g->BulkPostAcknowledged)) return 0;
    }
    g->ActiveKind = kind; g->Readbacks = 0; g->LastSequence = sequence;
    g->Phase = HERO_INV_WAIT_RESULT;
    return 1;
}

int HeroInvAcknowledge(HERO_INV_GATE *g, HERO_INV_U32 http_status, int transport_error, HERO_INV_U64 sequence) {
    if (!valid(g) || g->Phase != HERO_INV_WAIT_RESULT || sequence <= g->LastSequence) return 0;
    g->LastSequence = sequence;
    if (transport_error || http_status == 0) g->Phase = HERO_INV_UNKNOWN_VERIFY;
    else if (http_status != 200 && http_status != 201 && http_status != 204) g->Phase = HERO_INV_REJECTED_VERIFY;
    else if (g->ActiveKind == HERO_INV_BULK_POST) {
        g->BulkPostAcknowledged = 1; g->Index = 1; g->Phase = HERO_INV_READY;
    } else g->Phase = HERO_INV_VERIFY;
    return 1;
}

int HeroInvReadback(HERO_INV_GATE *g, int query_ok, int matches, HERO_INV_U64 sequence) {
    if (!valid(g) || sequence <= g->LastSequence
        || (g->Phase != HERO_INV_VERIFY && g->Phase != HERO_INV_UNKNOWN_VERIFY
            && g->Phase != HERO_INV_REJECTED_VERIFY)) return 0;
    g->LastSequence = sequence; ++g->Readbacks;
    if (query_ok && matches) {
        if (g->Phase == HERO_INV_VERIFY) {
            ++g->Index;
            g->Phase = g->Index < g->Count ? HERO_INV_READY : HERO_INV_ALL_WRITES_VERIFIED;
        } else g->Phase = HERO_INV_HOLD_RECONCILED;
    } else if (g->Readbacks >= 3) g->Phase = HERO_INV_HOLD_UNVERIFIED;
    return 1;
}

int HeroInvFinalReadback(HERO_INV_GATE *g, int query_ok, int matches, int warnings, HERO_INV_U64 sequence) {
    if (!valid(g) || g->Phase != HERO_INV_ALL_WRITES_VERIFIED || sequence <= g->LastSequence) return 0;
    g->LastSequence = sequence;
    if (query_ok && matches) g->Phase = warnings ? HERO_INV_CORE_VERIFIED_WARNINGS : HERO_INV_CORE_VERIFIED;
    else g->Phase = HERO_INV_HOLD_UNVERIFIED;
    return 1;
}
