/* Minimal x64 UEFI declarations used by this driver. Field layouts follow

 * UEFI 2.11 and the EDK II public protocol headers; no private AMI ABI here. */

#ifndef AITWK_EFI_H

#define AITWK_EFI_H

#include <stdint.h>

#include <stddef.h>

typedef uint64_t ES;

typedef uint64_t UN;

typedef uint16_t C16;

typedef void *HANDLE;

typedef void *EVENT;

#define EA __attribute__((ms_abi))

#define ERR(n) (0x8000000000000000ULL | (n))

#define FAILED(s) (((ES)(s) >> 63) != 0)

#define U(s) ((C16 *)L##s)

typedef struct { uint32_t a; uint16_t b,c; uint8_t d[8]; } GUID;

typedef struct { uint64_t sig; uint32_t rev,size,crc,reserved; } HDR;

typedef struct { uint16_t scan; C16 ch; } KEY;

typedef struct INPUT INPUT;

struct INPUT { void *reset; ES (EA *read)(INPUT *,KEY *); EVENT wait; };

typedef struct { int32_t max,mode,attribute,column,row; uint8_t cursor; } OUTMODE;

typedef struct TEXTOUT TEXTOUT;

struct TEXTOUT {

 void *reset; ES (EA *out)(TEXTOUT *,C16 *); void *test;

 ES (EA *query)(TEXTOUT *,UN,UN *,UN *); void *set_mode;

 ES (EA *attribute)(TEXTOUT *,UN); ES (EA *clear)(TEXTOUT *);

 ES (EA *cursor)(TEXTOUT *,UN,UN); ES (EA *enable_cursor)(TEXTOUT *,uint8_t);

 OUTMODE *mode;

};

typedef void (EA *NOTIFY)(EVENT,void *);

typedef struct {

 HDR hdr;

 UN (EA *raise_tpl)(UN); void (EA *restore_tpl)(UN);

 ES (EA *allocate_pages)(uint32_t,uint32_t,UN,uint64_t *); void *free_pages;

 ES (EA *memory_map)(UN *,void *,UN *,UN *,uint32_t *);

 ES (EA *allocate_pool)(uint32_t,UN,void **); ES (EA *free_pool)(void *);

 ES (EA *create_event)(uint32_t,UN,NOTIFY,void *,EVENT *);

 ES (EA *set_timer)(EVENT,uint32_t,uint64_t);

 ES (EA *wait)(UN,EVENT *,UN *); ES (EA *signal)(EVENT);

 ES (EA *close_event)(EVENT); ES (EA *check_event)(EVENT);

 ES (EA *install_protocol)(HANDLE *,GUID *,uint32_t,void *);

 void *reinstall_protocol,*uninstall_protocol;

 ES (EA *handle_protocol)(HANDLE,GUID *,void **);

 void *reserved; ES (EA *register_notify)(GUID *,EVENT,void **);

 void *locate_handle,*locate_device_path,*install_table;

 ES (EA *load_image)(uint8_t,HANDLE,void *,void *,UN,HANDLE *);

 ES (EA *start_image)(HANDLE,UN *,C16 **);

 void *exit; ES (EA *unload_image)(HANDLE);

 void *exit_boot_services,*get_monotonic;

 ES (EA *stall)(UN); ES (EA *set_watchdog)(UN,uint64_t,UN,C16 *);

 void *connect,*disconnect,*open_protocol,*close_protocol,*protocol_info,*protocols_per_handle;

 ES (EA *locate_handles)(uint32_t,GUID *,void *,UN *,HANDLE **);

 ES (EA *locate_protocol)(GUID *,void *,void **);

 void *install_multiple,*uninstall_multiple;

 ES (EA *crc32)(void *,UN,uint32_t *);

 void *copy_mem,*set_mem;

 ES (EA *create_event_ex)(uint32_t,UN,NOTIFY,void *,GUID *,EVENT *);

} BS;

typedef ES (EA *GETVAR)(C16 *,GUID *,uint32_t *,UN *,void *);

/* No variable-write callable type in this baseline. */

typedef struct {

 HDR hdr; void *get_time,*set_time,*get_wakeup,*set_wakeup;

 void *virtual_map,*convert_pointer; GETVAR get_variable;

 void *next_variable; void *set_variable;

 void *monotonic,*reset,*update_capsule,*query_capsule,*query_variable;

} RT;

typedef struct { GUID guid; void *table; } CT;

typedef struct {

 HDR hdr; C16 *vendor; uint32_t fwrev;

 HANDLE in_handle; INPUT *in; HANDLE out_handle; TEXTOUT *out;

 HANDLE err_handle; TEXTOUT *err; RT *rt; BS *bs; UN table_count; CT *tables;

} ST;

typedef struct {

 uint32_t revision; HANDLE parent; ST *st; HANDLE device; void *filepath,*reserved;

 uint32_t options_size; void *options,*image_base; uint64_t image_size;

 uint32_t code_type,data_type; void *unload;

} LOADED;

typedef struct HII HII;

struct HII {

 void *new_list,*remove_list;

 ES (EA *update_list)(HII *,HANDLE,void *);

 ES (EA *list)(HII *,uint8_t,GUID *,UN *,HANDLE *);

 ES (EA *export_list)(HII *,HANDLE,UN *,void *);

 void *register_notify,*unregister_notify,*find_layout,*get_layout,*set_layout;

 ES (EA *get_driver)(HII *,HANDLE,HANDLE *);

};

typedef struct STRINGS STRINGS;

struct STRINGS {

 ES (EA *new_string)(STRINGS *,HANDLE,uint16_t *,char *,C16 *,C16 *,void *);

 void *get_string;

 ES (EA *set_string)(STRINGS *,HANDLE,uint16_t,char *,C16 *,void *);

 ES (EA *languages)(STRINGS *,HANDLE,char *,UN *);

 void *secondary_languages;

};

typedef struct CONFIG CONFIG;

typedef ES (EA *ROUTE)(CONFIG *,C16 *,C16 **);

/* EFI_BROWSER_ACTION_REQUEST is UINTN, including the OUT storage width. */

typedef UN BROWSER_ACTION_REQUEST;

typedef ES (EA *CALLBACK)(CONFIG *,UN,uint16_t,uint8_t,void *,BROWSER_ACTION_REQUEST *);

struct CONFIG { void *extract; ROUTE route; CALLBACK callback; };

typedef struct RNG RNG;

struct RNG { void *info; ES (EA *get)(RNG *,GUID *,UN,uint8_t *); };

typedef struct CPU CPU;

struct CPU {void *flush,*enable,*disable,*interrupt_state,*init,*register_interrupt;

 ES (EA *timer)(CPU *,uint32_t,uint64_t *,uint64_t *);void *set_attributes;uint32_t timer_count,dma_alignment;};

typedef struct MEMATTR MEMATTR;

struct MEMATTR {

 ES (EA *get)(MEMATTR *,uint64_t,uint64_t,uint64_t *);

 ES (EA *set)(MEMATTR *,uint64_t,uint64_t,uint64_t);

 ES (EA *clear)(MEMATTR *,uint64_t,uint64_t,uint64_t);

};

typedef struct { uint8_t b,g,r,a; } PIXEL;

enum {BLT_VIDEO_FILL=0,BLT_VIDEO_TO_BUFFER=1,BLT_BUFFER_TO_VIDEO=2,BLT_VIDEO_TO_VIDEO=3};

typedef struct { uint32_t version,width,height,format; uint32_t masks[4]; uint32_t scanline; } GOPINFO;

typedef struct { uint32_t max,mode; GOPINFO *info; UN info_size; uint64_t base; UN size; } GOPMODE;

typedef struct GOP GOP;

struct GOP { void *query,*set;

 ES (EA *blt)(GOP *,PIXEL *,uint32_t,UN,UN,UN,UN,UN,UN,UN); GOPMODE *mode; };

#define OFF(t,m,v) _Static_assert(offsetof(t,m)==(v),"ABI " #t "." #m)

OFF(ST,rt,0x58); OFF(ST,bs,0x60); OFF(RT,get_variable,0x48); OFF(RT,set_variable,0x58);

OFF(BS,create_event,0x50); OFF(BS,handle_protocol,0x98); OFF(BS,crc32,0x158);

OFF(BS,locate_handles,0x138); OFF(BS,create_event_ex,0x170);

OFF(LOADED,image_base,0x40); OFF(LOADED,image_size,0x48);

OFF(HII,get_driver,0x50); OFF(CONFIG,callback,0x10); OFF(TEXTOUT,mode,0x48);

OFF(CPU,timer,0x30); OFF(CPU,timer_count,0x40);

_Static_assert(sizeof(GUID)==16 && sizeof(void *)==8,"x64 only");

#endif

