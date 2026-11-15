/* W890E-SAGE SE 0603 pure policy. No firmware entrypoint or hardware writes. */
#ifndef W890_POLICY_H
#define W890_POLICY_H
#include <stddef.h>
#include <stdint.h>
#include "core/password_core.h"

#define W890_SET_QID 0xffd0u
#define W890_CLEAR_QID 0xffd1u
#define W890_VERIFY_QID 0xffd2u
#define W890_CREDENTIAL_BYTES 128u
#define W890_OC_BYTES 22955u
#define W890_MEMORY_BYTES 1219u

typedef enum {
 W890_UNKNOWN = -1, W890_UNPROTECTED = 0, W890_PROTECTED = 1,
 W890_CREDENTIAL = 2
} W890_POLICY;

/* These functions take verified buffers, not arbitrary firmware pointers.
 * Caller must bind the official module/profile, validate pointer extents and
 * preserve the native session/caller identity before granting anything. */
AP_API int w890_profile_matches(const uint8_t setup_digest[32], const uint8_t tse_digest[32]);
AP_API int w890_form(uint16_t id);
AP_API int w890_question(uint16_t id);
AP_API int w890_inert_ifr(const uint8_t *, size_t);
AP_API W890_POLICY w890_classify_form(const uint8_t formset[16], uint16_t form);
AP_API W890_POLICY w890_classify_control(const uint8_t formset[16], uint16_t form,
                                        const uint8_t *ifr, size_t length);
/* name_length excludes terminator and is measured in UTF-16 code units. */
AP_API W890_POLICY w890_variable_kind(const uint16_t *name, size_t name_length,
                                     const uint8_t guid[16]);
/* Checks protected bytes without changing either buffer. Unknown/malformed
 * protected-variable requests return UNKNOWN and must be denied by callers.
 * Attribute changes, deletion and append cannot be classed unprotected. */
AP_API W890_POLICY w890_variable_change(const uint16_t *name, size_t name_length,
 const uint8_t guid[16], uint32_t old_attributes, const uint8_t *old_value, size_t old_size,
 uint32_t new_attributes, const uint8_t *new_value, size_t new_size);
/* Add three callback actions to the exact original Security form. Input is
 * the original FORMS package (not an entire package list). Original package
 * SHA-256 is verified; no other build is accepted. No partial output on error.
 * tokens: set prompt/help, clear prompt/help, verify prompt/help. */
AP_API int w890_security_insert(const uint8_t *, size_t, const uint16_t tokens[6],
                                uint8_t *, size_t, size_t *written);
#endif
