/* Minimal x64 UEFI ABI. Reference: EDK II edk2-stable202502. */
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
typedef struct TEXTOUT TEXTOUT;
struct TEXTOUT { void *reset; ES (EA *out)(TEXTOUT *,C16 *); };
typedef struct {
    HDR hdr;
    void *raise_tpl,*restore_tpl,*allocate_pages,*free_pages,*get_memory_map;
    ES (EA *allocate_pool)(uint32_t,UN,void **);
    ES (EA *free_pool)(void *);
    void *create_event,*set_timer,*wait_for_event,*signal_event,*close_event,*check_event;
    void *install_protocol,*reinstall_protocol,*uninstall_protocol;
    ES (EA *handle_protocol)(HANDLE,GUID *,void **);
    void *reserved,*register_notify,*locate_handle,*locate_device_path,*install_table;
    void *load_image,*start_image,*exit,*unload_image,*exit_boot_services,*get_monotonic;
    ES (EA *stall)(UN);
    void *set_watchdog,*connect,*disconnect,*open_protocol,*close_protocol,*protocol_info,*protocols_per_handle;
    ES (EA *locate_handles)(uint32_t,GUID *,void *,UN *,HANDLE **);
    ES (EA *locate_protocol)(GUID *,void *,void **);
    void *install_multiple,*uninstall_multiple,*crc32,*copy_mem,*set_mem,*create_event_ex;
} BS;
typedef struct { GUID guid; void *table; } CT;
typedef struct {
    HDR hdr; C16 *vendor; uint32_t fwrev;
    HANDLE in_handle; void *in; HANDLE out_handle; TEXTOUT *out;
    HANDLE err_handle; TEXTOUT *err; void *rt; BS *bs; UN table_count; CT *tables;
} ST;
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
typedef struct HII HII;
struct HII {
    void *new_list,*remove_list,*update_list;
    ES (EA *list)(HII *,uint8_t,GUID *,UN *,HANDLE *);
    ES (EA *export_list)(HII *,HANDLE,UN *,void *);
    void *register_notify,*unregister_notify,*find_layout,*get_layout,*set_layout;
    ES (EA *get_driver)(HII *,HANDLE,HANDLE *);
};
typedef struct { void *send_form,*browser_callback; } BROWSER;
typedef struct { void *extract,*route,*callback; } CONFIG;
#define OFF(t,m,v) _Static_assert(offsetof(t,m)==(v),"UEFI ABI: " #t "." #m)
OFF(ST,bs,0x60); OFF(ST,rt,0x58);
OFF(BS,handle_protocol,0x98); OFF(BS,locate_handles,0x138); OFF(BS,locate_protocol,0x140);
OFF(BS,allocate_pool,0x40); OFF(BS,free_pool,0x48); OFF(BS,stall,0xf8);
OFF(FILEP,write,0x28); OFF(FILEP,flush,0x50);
OFF(LOADED,device,0x18); OFF(LOADED,image_base,0x40); OFF(LOADED,image_size,0x48);
OFF(HII,list,0x18); OFF(HII,export_list,0x20); OFF(HII,get_driver,0x50);
OFF(CONFIG,callback,0x10);
_Static_assert(sizeof(GUID)==16 && sizeof(void *)==8,"x64 ABI");
#endif
