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
} KCS;
enum { K_OK, K_IO, K_TIMEOUT, K_BUSY, K_STATE, K_OVERFLOW, K_RESPONSE, K_DENIED };
int kcs_query(KCS *,uint8_t,uint8_t,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
const char *kcs_error(int);
int probe_pci_gate(const uint8_t config[64]);
int probe_pci_layout(const uint8_t config[64]);
int probe_board_gate(const char *,const char *);
/* Decode the common fields of full/compact sensor records, bounds checked.
 * Does not interpret OEM SDR records or claim temperature units. */
typedef struct {
    uint8_t owner,lun,number,type,share_count;
    char name[33];
} SENSOR;
int probe_sensor(const uint8_t *,size_t,SENSOR *);
#endif
