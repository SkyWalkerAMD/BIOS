#ifndef PROBE_CORE_H
#define PROBE_CORE_H
#include <stdint.h>
#include <stddef.h>
typedef struct {
    void *ctx;
    int (*read)(void *,int,uint8_t *); /* reg 0=data, 1=status */
    int (*write)(void *,int,uint8_t);  /* reg 0=data, 1=command */
    void (*delay_ms)(void *);
    unsigned budget;
    uint8_t last_status;
    unsigned candidate_armed, candidate_next;
    unsigned fan_armed, fan_next;
    uint8_t fan_rpm[15], fan_pwm[15], fan_type[15];
    unsigned dmi_armed,dmi_length;
    uint8_t dmi_request[192];
} KCS;
enum { K_OK, K_IO, K_TIMEOUT, K_BUSY, K_STATE, K_OVERFLOW, K_RESPONSE, K_DENIED, K_FAN_VERIFY, K_ALL_FF };
int kcs_query(KCS *,uint8_t,uint8_t,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
typedef struct { uint8_t command, length, data[32]; } CANDIDATE_STEP;
const CANDIDATE_STEP *candidate_step(unsigned);
void candidate_arm(KCS *);
void candidate_disarm(KCS *);
int candidate_query(KCS *,unsigned,uint8_t *,size_t,size_t *);
int dashboard_read(KCS *,uint8_t,uint8_t *,size_t,size_t *);
int dashboard_arm(KCS *,const uint8_t *,size_t);
void dashboard_disarm(KCS *);
int dashboard_write(KCS *,uint8_t *,size_t,size_t *);
void fan_arm(KCS *);
void fan_disarm(KCS *);
int fan_packet(KCS *,unsigned,CANDIDATE_STEP *);
int fan_query(KCS *,unsigned,uint8_t *,size_t,size_t *);
int probe_bmc_identity(const uint8_t *,size_t);
const char *kcs_error(int);
int probe_pci_gate(const uint8_t config[64]);
int probe_pci_layout(const uint8_t config[64]);
int probe_board_gate(const char *,const char *);
/* Decode the common fields of full/compact sensor records, bounds checked.
 * Does not interpret OEM SDR records or claim temperature units. */
typedef struct {
    uint8_t owner,lun,number,type,event_type,share_count;
    char name[33];
} SENSOR;
int probe_sensor(const uint8_t *,size_t,SENSOR *);
#endif
