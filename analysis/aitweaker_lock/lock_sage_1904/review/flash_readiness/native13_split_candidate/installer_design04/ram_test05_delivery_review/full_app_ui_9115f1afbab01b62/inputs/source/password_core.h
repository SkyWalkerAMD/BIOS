/* Independent password verifier/state core. Freestanding C11; no firmware I/O.
 * All multibyte persistent fields are explicitly little-endian. This is not
 * a variable-authentication scheme: the storage adapter owns write authority.
 */
#ifndef AITWK_PASSWORD_CORE_H
#define AITWK_PASSWORD_CORE_H
#include <stddef.h>
#include <stdint.h>

#if defined(AITWK_TEST_EXPORT)
#define AP_API __declspec(dllexport)
#else
#define AP_API
#endif

#define AP_RECORD_BYTES 128u
#define AP_SALT_BYTES 32u
#define AP_VERIFIER_BYTES 32u
#define AP_PASSWORD_MIN 8u
#define AP_PASSWORD_MAX 128u
#define AP_ITERATIONS 600000u
#define AP_ITERATIONS_MAX 2000000u
#define AP_RETRY_DELAY_MS 5000u

typedef enum {
    AP_OK=0, AP_DENIED=1, AP_BAD_ARGUMENT=2, AP_OUTSIDE_SESSION=3,
    AP_STALE_SESSION=4, AP_CREDENTIAL_ERROR=5, AP_UNCONFIGURED=6,
    AP_RATE_LIMITED=7, AP_STORAGE_FAILED=8, AP_ENTROPY_FAILED=9,
    AP_CLOCK_FAILED=10, AP_BUSY=11, AP_CANCELLED=12, AP_COUNTER_EXHAUSTED=13
} AP_STATUS;
typedef enum { AP_MODE_UNCONFIGURED=0, AP_MODE_ENABLED=1,
               AP_MODE_DISABLED=2, AP_MODE_FAULT=3 } AP_MODE;
typedef enum { AP_READ_OK=0, AP_READ_NOT_FOUND=1, AP_READ_ERROR=2 } AP_READ_RESULT;

/* Read returns the exact size, including a too-large size when capacity is
 * insufficient. Only READ_NOT_FOUND with size 0 denotes an absent variable.
 * Persist must be atomic: 0 means the exact 128 bytes committed; nonzero means
 * old persistent bytes are unchanged. An adapter unable to make that guarantee
 * must invalidate the core with ap_fault(), not report a clean failure.
 * Entropy must come from a cryptographically secure provider; no clock fallback.
 * now_ms must be monotonic for this boot, and return 0 on success.
 * Call serially at application level. Callbacks may signal a session boundary,
 * but must not concurrently modify this object from another CPU/thread.
 */
typedef AP_READ_RESULT (*AP_READ)(void *, uint8_t *, size_t, size_t *);
typedef int (*AP_PERSIST)(void *, const uint8_t *, size_t);
typedef int (*AP_ENTROPY)(void *, uint8_t *, size_t);
typedef int (*AP_NOW_MS)(void *, uint64_t *);
typedef struct {
    void *opaque;
    AP_READ read;
    AP_PERSIST persist;
    AP_ENTROPY entropy;
    AP_NOW_MS now_ms;
} AP_ENV;

typedef struct {
    AP_ENV env;
    uint8_t record[AP_RECORD_BYTES];
    uint64_t session_token;
    uint64_t last_now_ms;
    uint64_t retry_after_ms;
    uint32_t failed_attempts;
    uint32_t mode;
    uint8_t active;
    uint8_t unlocked;
    uint8_t busy;
    uint8_t clock_valid;
} AP_CORE;

/* Initialize once per resident driver instance. Missing storage denies access
 * until explicit enrollment. Clear writes DISABLED; it never deletes storage.
 * Initial enrollment authority is a responsibility of the BIOS management UI.
 */
AP_API AP_STATUS ap_init(AP_CORE *, const AP_ENV *);
AP_API void ap_fault(AP_CORE *);
AP_API uint64_t ap_session_begin(AP_CORE *);
AP_API void ap_session_end(AP_CORE *);
AP_API int ap_can_enter(const AP_CORE *);
AP_API AP_STATUS ap_unlock(AP_CORE *, uint64_t expected_session,
                           const uint8_t *password, size_t password_len);
AP_API AP_STATUS ap_set_password(AP_CORE *, uint64_t expected_session,
                                 const uint8_t *current, size_t current_len,
                                 const uint8_t *replacement, size_t replacement_len);
AP_API AP_STATUS ap_clear_password(AP_CORE *, uint64_t expected_session,
                                   const uint8_t *current, size_t current_len);
AP_API AP_STATUS ap_cancel(AP_CORE *, uint64_t expected_session);
AP_API uint64_t ap_retry_remaining_ms(AP_CORE *);
AP_API int ap_record_valid(const uint8_t *, size_t);
AP_API void ap_secure_zero(void *, size_t);
AP_API int ap_constant_equal(const void *, const void *, size_t);

/* Actual crypto primitives, also exposed for independent known-answer tests.
 * PBKDF2 derives exactly 32 bytes. Raw primitive accepts low iteration counts
 * for standards vectors; persistent credentials always require >= AP_ITERATIONS.
 * Output and input must not overlap. Caller owns and must wipe password inputs.
 */
AP_API void ap_sha256(const uint8_t *, size_t, uint8_t output[32]);
AP_API void ap_hmac_sha256(const uint8_t *, size_t, const uint8_t *, size_t,
                           uint8_t output[32]);
AP_API int ap_pbkdf2_sha256(const uint8_t *, size_t, const uint8_t *, size_t,
                           uint32_t iterations, uint8_t output[32]);
#endif
