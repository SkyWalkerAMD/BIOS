/* Emulation-only service fixture. No hardware services are called by this PE. */
#include "app.h"
ST *app_st;
HANDLE app_image,app_setup_hii;
void *app_browser;
volatile int app_ended;
RAM_SESSION app_sessions[2];
ENTRY_CAPTURE captured_entry;
ST fixture_st;BS fixture_bs;RT fixture_rt;HII fixture_hii;
struct {void *send_form,*callback;} fixture_browser;
GATE_PROVIDER fixture_provider;
__attribute__((aligned(4096))) uint8_t fixture_state[4096];
uint32_t fixture_provider_flags=1,fixture_hold_reason;
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
void app_log(const char *s){(void)s;}
void app_number(const char *s,uint64_t n){(void)s;(void)n;}
void app_result(const char *s,int n){(void)s;(void)n;}
__attribute__((noreturn,noinline)) void app_hold(uint32_t n){fixture_hold_reason=n;for(;;)__asm__ volatile("ud2");}
void app_require_services(void){if(app_ended||app_sessions[0].tx.held||app_sessions[1].tx.held)app_hold(0xe0000001u);}
ES EA fixture_get(C16 *n,GUID *g,uint32_t *a,UN *z,void *p){(void)n;(void)g;(void)a;(void)z;(void)p;return ERR(3);}
ES EA fixture_set(C16 *n,GUID *g,uint32_t a,UN z,void *p){(void)n;(void)g;(void)a;(void)z;(void)p;return ERR(3);}
UN EA fixture_raise(UN n){(void)n;return 4;}
void EA fixture_restore(UN n){(void)n;}
ES EA fixture_locate(GUID *g,void *r,void **p){(void)g;(void)r;(void)p;return ERR(3);}
ES EA fixture_list(HII *h,uint8_t t,GUID *g,UN *n,HANDLE *p){(void)h;(void)t;(void)g;(void)n;(void)p;return ERR(3);}
ES EA fixture_export(HII *h,HANDLE a,UN *n,void *p){(void)h;(void)a;(void)n;(void)p;return ERR(3);}
ES EA fixture_send(void *b,HANDLE *h,UN n,GUID *g,uint16_t f,void *s,BROWSER_ACTION_REQUEST *a){(void)b;(void)h;(void)n;(void)g;(void)f;(void)s;(void)a;return ERR(3);}
uint32_t EA fixture_query(GATE_PROVIDER *p){(void)p;return fixture_provider_flags;}
void test_setup(void){
 app_st=&fixture_st;app_image=(HANDLE)0x1111;app_setup_hii=(HANDLE)0x7777;app_browser=&fixture_browser;
 fixture_st.bs=&fixture_bs;fixture_st.rt=&fixture_rt;
 fixture_bs.raise_tpl=fixture_raise;fixture_bs.restore_tpl=fixture_restore;fixture_bs.locate_protocol=fixture_locate;
 fixture_rt.hdr.size=sizeof(RT);fixture_rt.hdr.crc=0x11223344;
 fixture_rt.get_variable=fixture_get;fixture_rt.set_variable=fixture_set;
 fixture_hii.list=fixture_list;fixture_hii.export_list=fixture_export;
 fixture_browser.send_form=fixture_send;
 fixture_provider.magic=PROVIDER_MAGIC;fixture_provider.revision=1;fixture_provider.size=sizeof(fixture_provider);fixture_provider.query=fixture_query;
 RAM_SESSION *s=&app_sessions[1];s->mode=2;s->tx.magic=TX_MAGIC;s->tx.phase=TX_INSTALLED;
 s->provider_context.magic=SPLIT_CONTEXT_MAGIC;s->provider_context.revision=1;s->provider_context.size=sizeof(SPLIT_CONTEXT);
 s->provider_context.state_base=(uintptr_t)fixture_state;s->provider_context.state_size=4096;
 s->tx.plan.state_base=(uintptr_t)fixture_state;s->tx.plan.state_size=4096;
 SPLIT_STATE *state=(void *)fixture_state;state->magic=SPLIT_STATE_MAGIC;state->phase=1;
 s->provider_started=1;s->provider_image=(HANDLE)0x3333;s->provider=&fixture_provider;
}
uint64_t test_session(void){return (uintptr_t)&app_sessions[1];}
void test_condition(unsigned condition){
 RAM_SESSION *s=&app_sessions[1];SPLIT_STATE *state=(void *)fixture_state;
 if(condition==1)s->mode=1;
 if(condition==2)s->tx.phase=TX_PREPARED;
 if(condition==3)s->provider_started=0;
 if(condition==4)s->tx.phase=TX_RETIRED,state->phase=2;
 if(condition==5)state->ui_head=(void *)1;
 if(condition==6)state->save_head=(void *)1;
 if(condition==7)state->magic=0;
 if(condition==8)fixture_rt.hdr.crc^=1;
 if(condition==9)fixture_browser.send_form=0;
 if(condition==10)app_ended=1;
 if(condition==11)s->tx.held=1;
 if(condition==12)s->tx.busy=1;
 if(condition==13)s->provider_context.state_base+=8;
 if(condition==14)s->provider_context.state_size=8192;
}
