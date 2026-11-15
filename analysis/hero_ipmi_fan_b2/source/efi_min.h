/* Minimal x64 UEFI ABI declarations. Layout checked against EDK II
 * edk2-stable202502 headers listed in reference/sources.json. */
#ifndef EFI_MIN_H
#define EFI_MIN_H
#include <stdint.h>
#include <stddef.h>
typedef uint64_t ES;
typedef uint64_t UN;
typedef uint16_t C16;
typedef void *HANDLE;
#define EA __attribute__((ms_abi))
#define ERR(n) (0x8000000000000000ULL | (n))
#define FAILED(s) (((ES)(s) >> 63) != 0)
typedef struct { uint32_t a; uint16_t b,c; uint8_t d[8]; } GUID;
typedef struct { uint64_t sig; uint32_t rev,size,crc,reserved; } HDR;
typedef struct { uint16_t scan,unicode; } KEY;
typedef struct TEXTIN TEXTIN;
struct TEXTIN { void *reset; ES (EA *read)(TEXTIN *,KEY *); HANDLE wait; };
typedef struct TEXTOUT TEXTOUT;
struct TEXTOUT { void *reset; ES (EA *out)(TEXTOUT *,C16 *); };
typedef struct {
    HDR hdr;
    void *raise_tpl,*restore_tpl,*allocate_pages,*free_pages,*get_memory_map;
    ES (EA *allocate_pool)(uint32_t,UN,void **);
    ES (EA *free_pool)(void *);
    void *create_event,*set_timer;
    ES (EA *wait_for_event)(UN,HANDLE *,UN *);
    void *signal_event,*close_event,*check_event;
    void *install_protocol,*reinstall_protocol,*uninstall_protocol;
    ES (EA *handle_protocol)(HANDLE,GUID *,void **);
    void *reserved,*register_notify,*locate_handle,*locate_device_path,*install_table;
    void *load_image,*start_image,*exit,*unload_image,*exit_boot_services;
    void *get_monotonic;
    ES (EA *stall)(UN);
    ES (EA *set_watchdog)(UN,uint64_t,UN,C16 *);
    void *connect,*disconnect,*open_protocol,*close_protocol,*protocol_info,*protocols_per_handle;
    ES (EA *locate_handles)(uint32_t,GUID *,void *,UN *,HANDLE **);
    ES (EA *locate_protocol)(GUID *,void *,void **);
    void *install_multiple,*uninstall_multiple,*crc32,*copy_mem,*set_mem,*create_event_ex;
} BS;
typedef struct {
    uint16_t year; uint8_t month,day,hour,minute,second,pad1;
    uint32_t nanosecond; int16_t timezone; uint8_t daylight,pad2;
} ETIME;
typedef struct {
    HDR hdr;
    ES (EA *get_time)(ETIME *,void *);
    void *set_time,*get_wakeup,*set_wakeup,*set_virtual,*convert_pointer;
    ES (EA *get_variable)(C16 *,GUID *,uint32_t *,UN *,void *);
} RT;
typedef struct { GUID guid; void *table; } CT;
typedef struct {
    HDR hdr; C16 *vendor; uint32_t fwrev;
    HANDLE in_handle; TEXTIN *in; HANDLE out_handle; TEXTOUT *out;
    HANDLE err_handle; TEXTOUT *err; RT *rt; BS *bs; UN table_count; CT *tables;
} ST;
typedef struct PCI PCI;
typedef ES (EA *MEM_ACCESS)(PCI *,uint32_t,uint8_t,uint64_t,UN,void *);
typedef ES (EA *CFG_ACCESS)(PCI *,uint32_t,uint32_t,UN,void *);
struct PCI {
    void *poll_mem,*poll_io;
    struct { MEM_ACCESS read,write; } mem,io;
    struct { CFG_ACCESS read,write; } pci;
    void *copy_mem,*map,*unmap,*alloc_buffer,*free_buffer,*flush;
    ES (EA *location)(PCI *,UN *,UN *,UN *,UN *);
    void *attributes;
    ES (EA *bar_attributes)(PCI *,uint8_t,uint64_t *,void **);
    void *set_bar_attributes; uint64_t romsize; void *romimage;
};
typedef struct FILEP FILEP;
struct FILEP {
    uint64_t revision;
    ES (EA *open)(FILEP *,FILEP **,C16 *,uint64_t,uint64_t);
    ES (EA *close)(FILEP *);
    void *delete_file;
    ES (EA *read)(FILEP *,UN *,void *);
    ES (EA *write)(FILEP *,UN *,void *);
    void *get_position,*set_position,*get_info,*set_info;
    ES (EA *flush)(FILEP *);
};
typedef struct FS FS;
struct FS { uint64_t revision; ES (EA *open_volume)(FS *,FILEP **); };
typedef struct {
    uint32_t revision; HANDLE parent; ST *st; HANDLE device; void *filepath,*reserved;
    uint32_t options_size; void *options,*image_base; uint64_t image_size;
    uint32_t code_type,data_type; void *unload;
} LOADED;
#define OFF(t,m,v) _Static_assert(offsetof(t,m)==(v),"UEFI ABI offset: " #t "." #m)
OFF(ST,bs,0x60); OFF(ST,rt,0x58); OFF(ST,tables,0x70);
OFF(BS,handle_protocol,0x98); OFF(BS,locate_handles,0x138);
OFF(BS,locate_protocol,0x140); OFF(BS,stall,0xf8); OFF(BS,set_watchdog,0x100);
OFF(RT,get_variable,0x48); OFF(PCI,mem,0x10); OFF(PCI,pci,0x30);
OFF(PCI,location,0x70); OFF(PCI,bar_attributes,0x80);
OFF(FILEP,write,0x28); OFF(FILEP,flush,0x50); OFF(LOADED,device,0x18);
_Static_assert(sizeof(GUID)==16 && sizeof(ETIME)==16 && sizeof(void *)==8,"x64 ABI");
#endif
