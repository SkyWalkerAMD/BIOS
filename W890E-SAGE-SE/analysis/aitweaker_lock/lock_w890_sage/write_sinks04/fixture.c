/* HOST TEST FIXTURE ONLY. This file is never linked into DENYONLY component.
 * It explicitly models the observer, firmware variables and memory validity.
 * It does NOT demonstrate real owner acquisition, native dispatch or NVRAM.
 */
#include "native_bridge04.h"
struct NO_TICKET {uint64_t generation;};
typedef struct {GUID guid;C16 name[40];void *value;UN size;uint32_t attrs;} VARIABLE;
static struct {NO_IDENTITY id;struct NO_TICKET ticket;VARIABLE vars[256];uint32_t n,owner,flags,reads,copies,enters,leaves,active,fail_read,fail_copy;uintptr_t mutate;uint32_t mutate_read;uint8_t mutate_value;} f;
static void cp(void *a,const void *b,UN n){uint8_t*x=a;const uint8_t*y=b;while(n--)*x++=*y++;}
static int eq(const void*a,const void*b,UN n){const uint8_t*x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static void zero(void*a,UN n){uint8_t*x=a;while(n--)*x++=0;}
static uint32_t EA query(W890_PROVIDER *p){(void)p;return f.flags;}
static W890_PROVIDER provider={W890_PROVIDER_MAGIC,1,sizeof(W890_PROVIDER),0,0,query,0,0};
__declspec(dllexport) void EA fixture_reset(const NO_IDENTITY *id,uint32_t flags){zero(&f,sizeof f);f.id=*id;f.flags=flags;f.owner=1;f.ticket.generation=1;}
__declspec(dllexport) W890_PROVIDER *EA fixture_provider(void){return &provider;}
__declspec(dllexport) void EA fixture_flags(uint32_t flags){f.flags=flags;}
__declspec(dllexport) void EA fixture_owner(uint32_t active){f.owner=active;}
__declspec(dllexport) int EA fixture_add(const uint8_t*g,const uint16_t*n,void*p,UN size,uint32_t attrs){
 if(f.n==256||size>WS_MAX_VARIABLE_BYTES)return 0;VARIABLE*v=&f.vars[f.n++];cp(&v->guid,g,16);cp(v->name,n,80);v->value=p;v->size=size;v->attrs=attrs;return 1;
}
__declspec(dllexport) void EA fixture_fail(uint32_t read,uint32_t copy){f.fail_read=read;f.fail_copy=copy;}
__declspec(dllexport) void EA fixture_mutate(uintptr_t address,uint32_t read,uint8_t value){f.mutate=address;f.mutate_read=read;f.mutate_value=value;}
__declspec(dllexport) uint64_t EA fixture_counts(void){return f.reads|((uint64_t)f.copies<<16)|((uint64_t)f.enters<<32)|((uint64_t)f.leaves<<48);}
int EA no_identity(NO_IDENTITY *id){if(!f.owner)return 0;*id=f.id;return 1;}
int EA no_range(uintptr_t p,UN n,uint32_t perm){(void)perm;return p>=4096&&n&&n<=UINTPTR_MAX-p;}
int EA no_scope_enter(uint32_t kind,uintptr_t object,NO_TICKET **out){(void)object;f.enters++;if(!f.owner||kind!=NO_EFFECT||f.active)return 0;f.active=1;*out=&f.ticket;return 1;}
int EA no_scope_validate(NO_TICKET*t){return f.owner&&f.active&&t==&f.ticket;}
void EA no_scope_leave(NO_TICKET*t){if(t==&f.ticket){f.active=0;f.leaves++;}}
int EA no_copy(NO_TICKET*t,uintptr_t p,void*out,UN n){f.copies++;if(!no_scope_validate(t)||f.copies==f.fail_copy||!no_range(p,n,NO_READ))return 0;cp(out,(void*)p,n);return no_scope_validate(t);}
ES EA no_read_variable(NO_TICKET*t,C16*name,GUID*g,uint32_t*attrs,UN*size,void*out){
 f.reads++;if(!no_scope_validate(t)||f.reads==f.fail_read)return WS04_ACCESS_DENIED;
 if(f.mutate&&f.reads==f.mutate_read)*(uint8_t*)f.mutate=f.mutate_value;
 for(uint32_t i=0;i<f.n;i++){VARIABLE*v=&f.vars[i];if(eq(&v->guid,g,16)&&eq(v->name,name,80)){
  UN cap=*size;*size=v->size;*attrs=v->attrs;if(cap<v->size)return UINT64_C(0x8000000000000005);cp(out,v->value,v->size);return 0;}}
 return UINT64_C(0x800000000000000e);
}
