#ifndef CAPACITY_ABI_H
#define CAPACITY_ABI_H
#include "efi_min.h"
/* UEFI 2.11 section 15.4: exact field order independently read by parent.
 * x64 offsets below are derived using natural alignment and asserted here.
 * Provenance and the local library cross-check are in abi_review.json. */
typedef struct {
 uint64_t timeout;
 void *in_data,*out_data,*sense,*cdb;
 uint32_t in_length,out_length;
 uint8_t cdb_length,direction,host_status,target_status,sense_length;
} SCSI_PACKET;
typedef struct SCSI_IO SCSI_IO;
struct SCSI_IO {
 ES(EA *get_type)(SCSI_IO *,uint8_t *);
 ES(EA *get_location)(SCSI_IO *,uint8_t **,uint64_t *);
 void *reset_bus,*reset_device;
 ES(EA *execute)(SCSI_IO *,SCSI_PACKET *,void *);
 uint32_t io_align;
};
OFF(SCSI_PACKET,timeout,0);OFF(SCSI_PACKET,in_data,8);OFF(SCSI_PACKET,out_data,16);
OFF(SCSI_PACKET,sense,24);OFF(SCSI_PACKET,cdb,32);OFF(SCSI_PACKET,in_length,40);
OFF(SCSI_PACKET,out_length,44);OFF(SCSI_PACKET,cdb_length,48);OFF(SCSI_PACKET,direction,49);
OFF(SCSI_PACKET,host_status,50);OFF(SCSI_PACKET,target_status,51);OFF(SCSI_PACKET,sense_length,52);
_Static_assert(sizeof(SCSI_PACKET)==56,"SCSI packet ABI");
OFF(SCSI_IO,get_type,0);OFF(SCSI_IO,get_location,8);OFF(SCSI_IO,execute,32);
OFF(SCSI_IO,io_align,40);_Static_assert(sizeof(SCSI_IO)==48,"SCSI protocol ABI");
typedef struct {uint32_t id;uint8_t removable,present,partition,readonly,cache;uint8_t pad[3];uint32_t block,align,pad2;uint64_t last;} MEDIA;
typedef struct {uint64_t revision;MEDIA *media;void *reset,*read,*write,*flush;} BIO;
typedef struct USBIO USBIO;
struct USBIO {void *transfer[6];ES(EA *device)(USBIO *,uint8_t *);void *config;ES(EA *interface)(USBIO *,uint8_t *);};
OFF(MEDIA,block,12);OFF(MEDIA,last,24);OFF(BIO,media,8);
OFF(USBIO,device,0x30);OFF(USBIO,interface,0x40);
#endif
