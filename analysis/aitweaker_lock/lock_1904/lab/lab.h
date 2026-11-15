/* VM fixture ABI. This private protocol is NOT the password lock protocol. */
#ifndef LAB_H
#define LAB_H
#include "efi_min.h"
typedef struct {
 HDR hdr; void *get_time,*set_time,*get_wakeup,*set_wakeup,*set_virtual,*convert;
 ES(EA *get_variable)(C16 *,GUID *,uint32_t *,UN *,void *);
 void *next_variable;
 ES(EA *set_variable)(C16 *,GUID *,uint32_t,UN,void *);
 void *next_high,*reset_system,*update_capsule,*query_capsule,*query_variable;
} RT;
OFF(RT,get_variable,0x48); OFF(RT,set_variable,0x58);
typedef ES(EA *LOAD_IMAGE)(uint8_t,HANDLE,void *,void *,UN,HANDLE *);
typedef ES(EA *START_IMAGE)(HANDLE,UN *,C16 **);
typedef ES(EA *INSTALL)(HANDLE *,GUID *,unsigned,void *);
typedef struct LAB_PROTOCOL LAB_PROTOCOL;
struct LAB_PROTOCOL {
 uint64_t signature; HANDLE owner; uint64_t boot_counter,unlocked,calls;
 ES(EA *operation)(LAB_PROTOCOL *,unsigned);
};
#define LAB_SIGNATURE 0x3130393142414c55ULL
static GUID lab_guid={0x7c506d83,0xf153,0x40e7,{0xaa,0x60,0x17,0x3f,0x42,0x3a,0x60,0x90}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x9576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static inline int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354U&&c==0x43544743U&&d==0x47435447U;}
static inline void trace(const char*s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static inline void number(uint64_t n){char h[]="0123456789abcdef";for(unsigned i=0;i<16;i++){char b[]={h[(n>>((15-i)*4))&15],0};trace(b);}}
static inline void event(const char*s,uint64_t n){trace(s);trace("=");number(n);trace("\n");}
static inline void finish(unsigned ok){trace(ok?"LAB_PASS\n":"LAB_FAIL\n");__asm__ volatile("outl %0,%1"::"a"(ok?0x10U:0x11U),"Nd"((uint16_t)0xf4));}
static inline ES read_u64(ST*st,C16*name,uint64_t*v){UN n=sizeof(*v);uint32_t attr=0;ES s=((RT*)st->rt)->get_variable(name,&lab_guid,&attr,&n,v);if(!s&&(n!=8||attr!=3))return ERR(33);return s;}
static inline ES write_u64(ST*st,C16*name,uint64_t v){return ((RT*)st->rt)->set_variable(name,&lab_guid,3,sizeof(v),&v);}
ES start_file(ST*,HANDLE,C16*,HANDLE*);
void *memset(void*,int,size_t);
void *memcpy(void*,const void*,size_t);
#endif
