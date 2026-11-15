#ifndef AITWK_SAVE_FEEDBACK_H
#define AITWK_SAVE_FEEDBACK_H
#include "lock.h"

/* This module aggregates deliberate guard denials; it grants no access and
 * never treats an absent browser session as a reason to skip native startup.
 */
typedef struct {
 uint8_t *target;
 UN length;
 uint8_t original[18],replacement[18];
} SAVE_FEEDBACK_PATCH;

/* Caller must have validated the complete ACE1904 AMITSE identity before any
 * original text mutation. Gateway is at least 128 writable executable bytes,
 * retained for the full lifetime of every published entry/cached caller.
 * prepare changes only that owned gateway and private state, never AMITSE. */
int save_feedback_prepare(uint8_t *,UN,void *,UN,SAVE_FEEDBACK_PATCH [2]);
/* Called after both prepared entry patches pass exact readback. */
int save_feedback_commit(void);
/* Only after reverse rollback proves both original entries restored. */
int save_feedback_cancel_unpublished(void);
/* Existing policy calls this only for a rejection it actually returns. */
void save_feedback_note_denial(ES);
/* Called from an owned browser poll; returns one status for the current token.
 * The caller decides the safe UI message. No vendor-initialization popup. */
ES save_feedback_take_notice(void);
/* Retires data/notice writes. Platform owns actual code restoration; do not
 * free gateways on a foreign/partial ownership conflict. */
void save_feedback_retire(void);
#endif
