#include "source/trust.c"
ST *gST;static ST st;static RT rt;
static int checks,failure,target_ok,present,creates,deletes,corrupt,keep_after_delete;
static ES read_error,create_error,delete_error;static uint32_t stored_attrs;
static uint8_t stored[sizeof(hero_cert_esl)];
#define CK(x) do{checks++;if(!(x)&&!failure)failure=__LINE__;}while(0)
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
void *memcpy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;return d;}
void logtext(const char *s){(void)s;}void status(const char *s,ES e){(void)s;(void)e;}
HANDLE network_candidate(void){return target_ok?(HANDLE)1:0;}int tcp_is_active(void){return 0;}
static void check_name(C16 *name,GUID *g){CK(eq(g,&ca_guid,16));CK(eq(name,W("TlsCaCertificate"),34));}
static ES EA get(C16 *name,GUID *g,uint32_t *a,UN *n,void *data){
 check_name(name,g);if(read_error)return read_error;if(!present)return ERR(14);
 *a=stored_attrs;if(*n<sizeof(stored)){*n=sizeof(stored);return ERR(5);}
 *n=sizeof(stored);memcpy(data,stored,sizeof(stored));if(corrupt)((uint8_t *)data)[80]^=1;return 0;
}
static ES EA set(C16 *name,GUID *g,uint32_t a,UN n,void *data){
 check_name(name,g);if(n){creates++;CK(a==2&&n==sizeof(stored)&&eq(data,hero_cert_esl,n));if(create_error)return create_error;stored_attrs=a;present=1;memcpy(stored,data,n);return 0;}
 deletes++;CK(a==0&&data==0);if(delete_error)return delete_error;if(!keep_after_delete)present=0;return 0;
}
static void reset(void){gST=&st;st.rt=&rt;rt.get_variable=get;rt.set_variable=set;owned=present=creates=deletes=corrupt=keep_after_delete=0;target_ok=1;read_error=create_error=delete_error=0;stored_attrs=2;memcpy(stored,hero_cert_esl,sizeof(stored));}
int run_tests(void){
 reset();target_ok=0;CK(trust_begin()==ERR(15)&&!creates&&!owned);
 reset();present=1;CK(trust_begin()==ERR(15)&&!creates&&!deletes&&!owned);
 reset();read_error=ERR(7);CK(trust_begin()==ERR(15)&&!creates&&!owned);
 reset();create_error=ERR(15);CK(trust_begin()==ERR(15)&&creates==1&&!owned);
 reset();CK(!trust_begin()&&present&&owned&&creates==1);CK(trust_begin()==ERR(15)&&creates==1);CK(!trust_cleanup()&&!present&&!owned&&deletes==1);CK(!trust_cleanup()&&deletes==1);
 reset();CK(!trust_begin());delete_error=ERR(7);CK(trust_cleanup()==ERR(7)&&owned&&present);CK(trust_begin()==ERR(15));delete_error=0;CK(!trust_cleanup()&&!owned&&!present);
 reset();corrupt=1;CK(trust_begin()==ERR(26)&&owned);CK(trust_cleanup()==ERR(26)&&!deletes&&owned);corrupt=0;CK(!trust_cleanup()&&!owned);
 reset();CK(!trust_begin());stored_attrs=7;CK(trust_cleanup()==ERR(26)&&!deletes&&owned);stored_attrs=2;CK(!trust_cleanup());
 reset();CK(!trust_begin());read_error=ERR(7);CK(trust_cleanup()==ERR(7)&&owned&&!deletes);read_error=0;CK(!trust_cleanup());
 reset();CK(!trust_begin());present=0;CK(!trust_cleanup()&&!owned&&!deletes);
 reset();CK(!trust_begin());keep_after_delete=1;CK(trust_cleanup()==ERR(7)&&owned);keep_after_delete=0;CK(!trust_cleanup()&&!owned);
 return failure;
}
int get_checks(void){return checks;}
