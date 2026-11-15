#ifndef SAGE_NATIVE_GATE_H
#define SAGE_NATIVE_GATE_H
#include "efi.h"
#define GATE_BINDING_MAGIC 0x3430393145544147ULL
#define PROVIDER_MAGIC 0x3430393152504741ULL
#define PROVIDER_READY 1u
#define PROVIDER_OWNED 2u
#define PROVIDER_GRANTED 4u
#define PROVIDER_DISABLED 8u
#define PROVIDER_BUSY 16u
#define PROVIDER_FAULT 32u
#define PROVIDER_ENDED 64u
typedef struct {
 uint64_t magic;
 uint32_t revision,kind,self_rva,image_size;
 uint32_t original_loop_rva,original_frame_rva;
 uint32_t setup_callback_rva,setup_route_rva,setup_gate_rva,setup_gate_size;
 uint32_t setup_gate_crc,context_rva;
 uint32_t original_commit_rva,original_defaults_rva;
 uint32_t original_save_rva,reserved;
} GATE_BINDING;
typedef struct GATE_PROVIDER GATE_PROVIDER;
struct GATE_PROVIDER {
 uint64_t magic; uint32_t revision,size;
 ES (EA *begin)(GATE_PROVIDER *,uint64_t *);
 ES (EA *end)(GATE_PROVIDER *,uint64_t);
 uint32_t (EA *query)(GATE_PROVIDER *);
 ES (EA *request)(GATE_PROVIDER *);
 ES (EA *manage)(GATE_PROVIDER *,int);
};
#define GATE_FRAME_MAGIC 0x343039314d524647ULL
#define GATE_FRAME_OPEN 1u
typedef struct GATE_FRAME GATE_FRAME;
struct GATE_FRAME {
 uint64_t magic;uint32_t revision,size;
 GATE_FRAME *previous;GATE_PROVIDER *provider;uint64_t token;
 uint32_t depth,flags;
};
extern const volatile GATE_BINDING gate_binding;
int gate_memory(const void *,UN,int);
uint8_t *gate_base(void);
ES EA gate_render(void *);
ES EA gate_page_input(void *,void *);
ES EA gate_app_input(void *,void *);
ES EA gate_frame_input(void *,void *);
ES EA gate_navigation(GUID *,uint16_t *,GUID *,uint16_t *);
void EA gate_poll(void);
uint64_t EA gate_loop(void);
ES EA gate_callback(CONFIG *,UN,uint16_t,uint8_t,void *,BROWSER_ACTION_REQUEST *);
ES EA gate_route(CONFIG *,C16 *,C16 **);
ES EA gate_variable_commit(uint32_t,void *,UN);
uint64_t EA gate_save(void *);
uint64_t EA gate_defaults(uint64_t,void *,void *,void *);
int gate_owner(HANDLE,uint8_t **);
int gate_redirect(void);
void *memcpy(void *,const void *,size_t);
void *memset(void *,int,size_t);
int memcmp(const void *,const void *,size_t);
OFF(GATE_PROVIDER,begin,16);OFF(GATE_PROVIDER,query,32);
_Static_assert(sizeof(GATE_BINDING)==72,"binding layout");
_Static_assert(sizeof(GATE_FRAME)==48,"frame layout");
#endif
