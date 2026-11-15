/* Test-only mocked platform. No socket, USB, TLS, filesystem or BMC calls. */
#include "inventory_legacy71.c"
typedef ES (EA *TEST_HANDLER)(unsigned,unsigned,const char *,UN,const char *,TLS_REPLY *);
static TEST_HANDLER handler;
static ST test_st;static BS test_bs;
ST *gST;
static int test_source_good,test_tls_active;
static uint64_t test_epoch;
void *memcpy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;return d;}
void *memset(void *d,int ch,size_t n){uint8_t *x=d;while(n--)*x++=(uint8_t)ch;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int same(const char *a,const char *b){while(*a&&*b)if(*a++!=*b++)return 0;return *a==*b;}
void logtext(const char *s){(void)s;}void status(const char *s,ES e){(void)s;(void)e;}
int i3_inventory_source_valid(void){return test_source_good;}
uint64_t i3_inventory_source_epoch(void){return test_epoch;}
int private_tls_active(void){return test_tls_active;}
static ES EA fake_stall(UN n){return n==1000000?0:ERR(2);}
ES private_tls_inventory_exchange(unsigned method,unsigned id,const char *body,UN bytes,const char *etag,TLS_REPLY *r){
 if(!handler)return ERR(2);return handler(method,id,body,bytes,etag,r);
}
void i71_test_reset(TEST_HANDLER callback){
 stage=0;done_mask=0;attempted_mask=0;source_epoch=0;indexed_mask=0;summary_attempted=0;summary_verified=0;
 memset(&test_st,0,sizeof(test_st));memset(&test_bs,0,sizeof(test_bs));test_st.bs=&test_bs;test_bs.stall=fake_stall;gST=&test_st;
 test_source_good=1;test_tls_active=0;test_epoch=12345;handler=callback;
}
void i71_test_source(int good,uint64_t epoch){test_source_good=good;test_epoch=epoch;}
void i71_test_tls_active(int active){test_tls_active=active;}
int i71_test_matches(unsigned item,const char *body,UN length){
 if(item>5)return 0;TLS_REPLY r={200,body,length};return parse_reply(&r,inv71_items[item].get_id)&&item_matches(item);
}
unsigned i71_test_token_count(const char *body,UN length){return jparse(&actual,body,length)?actual.count:0;}
