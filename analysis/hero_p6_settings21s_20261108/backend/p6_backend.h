#ifndef HERO_P6_BACKEND_H
#define HERO_P6_BACKEND_H
#include <stddef.h>
#include <stdint.h>

/* Portable, synchronous, non-reentrant per hardware interface. Caller owns all
 * identity checks, serialization, deadlines, PCI changes, NVRAM and UI policy.
 * exchange: 0 = transport success; response includes netfn/LUN, cmd, CC.
 * response_len is capacity on entry, actual length on success. No retry here.
 * delay_ms: 0 = completed; nonzero = stop. Both callbacks must be bounded.
 */
typedef int (*P6_EXCHANGE)(void *, uint8_t, uint8_t, const uint8_t *, size_t,
                         uint8_t *, size_t *);
typedef int (*P6_DELAY)(void *, uint32_t);
typedef struct { void *context; P6_EXCHANGE exchange; P6_DELAY delay_ms; } P6_IO;

typedef enum {
    P6_OK = 0, P6_ARGUMENT = 1, P6_TRANSPORT = 2, P6_PROTOCOL = 3,
    P6_COMPLETION = 4, P6_BUSY = 5, P6_UNSUPPORTED = 6, P6_VERIFY = 7,
    P6_UNCERTAIN = 8, P6_FOREIGN_OWNER = 9, P6_TIMEOUT = 10
} P6_STATUS;
typedef enum {
    P6_STAGE_NONE = 0, P6_STAGE_CHANNEL = 1, P6_STAGE_SNAPSHOT = 2,
    P6_STAGE_ACQUIRE = 3, P6_STAGE_WRITE = 4, P6_STAGE_COMMIT = 5,
    P6_STAGE_COMPLETE = 6, P6_STAGE_VERIFY = 7, P6_STAGE_ROLLBACK = 8,
    P6_STAGE_RESERVE = 9, P6_STAGE_POLL = 10, P6_STAGE_START = 11
} P6_STAGE;
typedef enum {
    P6_RECOVERY_NONE = 0,
    P6_RECOVERY_RESTORED = 1, /* requested settings verified; not DHCP lease */
    P6_RECOVERY_STOPPED = 2,  /* owned timer stopped; no countdown restoration */
    P6_RECOVERY_UNCONFIRMED = 3
} P6_RECOVERY;
enum { P6_FLAG_NO_CHANGE = 1, P6_FLAG_DHCP_LEASE_DYNAMIC = 2,
       P6_FLAG_ERASE_COMPLETED = 4, P6_FLAG_RECORD_DELETED = 8 };
typedef struct {
    uint32_t status;       /* returned P6_STATUS */
    uint32_t cause;        /* initial failure, preserved across recovery */
    uint32_t stage;        /* stage of initial failure or last success */
    uint32_t completion;   /* failing CC, 0 when no CC failure */
    uint32_t requests;     /* all exchange attempts */
    uint32_t writes;       /* config/destructive attempts, excludes reservation */
    uint32_t recovery;     /* P6_RECOVERY */
    uint32_t recovery_cause;
    uint32_t recovery_completion;
    uint32_t channel;      /* selected LAN channel */
    uint32_t polls;
    uint32_t record_id;    /* actual oldest SEL ID, never 0/FFFF */
    uint32_t entries_after;
    uint32_t flags;
} P6_RESULT;

typedef struct {
    uint8_t channel; /* 0 = require exactly one LAN channel in 1..11 */
    uint8_t source;  /* 0 = no operation; 1 = static; 2 = BMC DHCP */
    uint8_t address[4];
    uint8_t mask[4];
    uint8_t gateway[4]; /* 0.0.0.0 = no gateway */
} P6_LAN;
typedef struct {
    uint32_t entries, free_bytes, last_add, last_erase, operations, version;
} P6_SEL_INFO;

/* All public operations initialize result. Result must be non-NULL. On any
 * malformed response or transport failure there are NO more exchanges during
 * that call, including recovery. The caller must not automatically replay a
 * failed operation. A LAN SIP flag is advisory, not an exclusive lock.
 */
int p6_validate_ipv4(const uint8_t address[4], const uint8_t mask[4],
                     const uint8_t gateway[4]);
int p6_lan_apply(const P6_IO *, const P6_LAN *, P6_RESULT *);
/* configure(enabled=1) prepares a STOPPED OS Load timer; never arms it.
 * configure(enabled=0) stops only use=3, preserves its action/count/settings.
 * start validates the prepared timer, then arms it, with a separate readback.
 * Timeout unit is MINUTES, range 1..30. Action: 0 none, 1 reset, 2 down, 3 cycle.
 */
int p6_watchdog_configure(const P6_IO *, int enabled, unsigned minutes,
                         unsigned action, P6_RESULT *);
int p6_watchdog_start(const P6_IO *, unsigned minutes, unsigned action,
                     P6_RESULT *);
/* Recovery only: stop an already-running OS Load timer if its complete
 * programmed use/action/pretimeout/count match our prior start request.
 * Never prepare, reset, take over another use, or change a stopped timer. */
int p6_watchdog_recover_stop(const P6_IO *, unsigned minutes, unsigned action,
                            P6_RESULT *);
int p6_sel_get_info(const P6_IO *, P6_SEL_INFO *, P6_RESULT *);
/* Erase is initiated only once. Polls max 30 with 1 second bounded delays.
 * New records may arrive after a completed erase: see entries_after.
 */
int p6_sel_clear(const P6_IO *, P6_RESULT *);
int p6_sel_delete_oldest(const P6_IO *, P6_RESULT *);
/* BMC-global bit3, NOT Creator's BIOS SEL Components / progress-code policy. */
int p6_sel_logging(const P6_IO *, int enabled, P6_RESULT *);

#endif
