/* Exercise the exact TCP implementation without sockets or hardware. */
#include "source/tcp.c"
ST *gST;static ST st;static BS bs;static RT rt;static SB sb;static TCP mock;
static int checks,failure,eligible,create_error,open_error,config_error,event_error,queue_error,timeout,reset_error,destroy_error,close_error,connects,polls,closures;
static ES completion;
#define CK(x) do{checks++;if(!(x)&&!failure)failure=__LINE__;}while(0)
void *memset(void *d,int c,size_t n){uint8_t *p=d;while(n--)*p++=(uint8_t)c;return d;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
void status(const char *s,ES e){(void)s;(void)e;}void say(const char *s){(void)s;}void logtext(const char *s){(void)s;}
HANDLE network_candidate(void){return eligible?(HANDLE)1:0;}
static ES EA hp(HANDLE h,GUID *g,void **p){
 *p=0;if(equal(g,&tcp_sb_guid,16)){CK(h==(HANDLE)1);*p=&sb;return 0;}
 CK(equal(g,&tcp_guid,16)&&h==(HANDLE)2);if(open_error)return ERR(14);*p=&mock;return 0;
}
static ES EA create(SB *s,HANDLE *h){CK(s==&sb);if(create_error)return ERR(9);*h=(HANDLE)2;return 0;}
static ES EA destroy(SB *s,HANDLE h){CK(s==&sb&&h==(HANDLE)2);return destroy_error?ERR(7):0;}
static ES EA cfg(TCP *t,TCP_CONFIG *c){CK(t==&mock);if(!c)return reset_error?ERR(7):0;CK(c->tos==0&&c->ttl==64&&!c->options&&!c->access.use_default&&c->access.active);const uint8_t local[]={169,254,0,18},remote[]={169,254,0,17},mask[]={255,255,0,0};CK(equal(c->access.station,local,4)&&equal(c->access.remote,remote,4)&&equal(c->access.mask,mask,4)&&c->access.remote_port==443&&c->access.station_port==0);return config_error?ERR(2):0;}
static ES EA event(uint32_t type,UN tpl,void(EA *fn)(HANDLE,void *),void *ctx,HANDLE *h){CK(type==0x200&&tpl==8&&fn==tcp_notify&&!ctx);if(event_error)return ERR(9);*h=(HANDLE)3;return 0;}
static ES EA close_event(HANDLE h){CK(h==(HANDLE)3);closures++;return close_error?ERR(7):0;}
static ES EA connect(TCP *t,TCP_TOKEN *token){CK(t==&mock&&token==&tcp_token&&token->status==ERR(6));connects++;return queue_error?ERR(7):0;}
static ES EA poll(TCP *t){CK(t==&mock);polls++;if(!timeout){tcp_token.status=completion;tcp_notify(0,0);}return ERR(6);}
static ES EA cancel(TCP *t,TCP_TOKEN *token){CK(t==&mock);if(token){CK(token==&tcp_token);token->status=ERR(21);tcp_notify(0,0);}return 0;}
static ES EA stall(UN n){CK(n==10000);return 0;}
static ES EA locate(GUID *g,void *r,void **p){CK(equal(g,&tls_sb_guid,16)&&!r);*p=0;return ERR(14);}
static ES EA getvar(C16 *name,GUID *g,uint32_t *attrs,UN *size,void *data){const C16 *exp=W("TlsCaCertificate");UN i=0;while(exp[i]){CK(name[i]==exp[i]);i++;}CK(name[i]==0&&equal(g,&tls_ca_guid,16)&&attrs&&*size==0&&!data);return ERR(14);}
static void reset(void){
 memset(&st,0,sizeof(st));memset(&bs,0,sizeof(bs));memset(&rt,0,sizeof(rt));memset(&mock,0,sizeof(mock));memset(&tcp_token,0,sizeof(tcp_token));
 eligible=1;create_error=open_error=config_error=event_error=queue_error=timeout=reset_error=destroy_error=close_error=0;connects=polls=closures=0;completion=0;
 tcp_child=0;tcp_binding=0;tcp=0;tcp_done=0;st.bs=&bs;st.rt=&rt;gST=&st;
 bs.handle_protocol=hp;bs.create_event=event;bs.close_event=close_event;bs.stall=stall;bs.locate_protocol=locate;rt.get_variable=getvar;
 sb.create=create;sb.destroy=destroy;mock.configure=cfg;mock.connect=connect;mock.cancel=cancel;mock.poll=poll;
 /* transmit/receive are NULL: any accidental application data operation fails. */
}
int run_tests(void){
 reset();eligible=0;CK(tcp_connect_probe()==ERR(15)&&connects==0);
 reset();CK(tcp_connect_probe()==0&&!tcp_is_active()&&connects==1&&polls==1&&closures==1);
 reset();create_error=1;CK(tcp_connect_probe()==ERR(9)&&connects==0&&!tcp_is_active());
 reset();open_error=1;CK(tcp_connect_probe()==ERR(14)&&connects==0&&!tcp_is_active());
 reset();config_error=1;CK(tcp_connect_probe()==ERR(2)&&connects==0&&!tcp_is_active());
 reset();event_error=1;CK(tcp_connect_probe()==ERR(9)&&connects==0&&!tcp_is_active());
 reset();queue_error=1;CK(tcp_connect_probe()==ERR(7)&&!tcp_is_active());
 reset();completion=ERR(104);CK(tcp_connect_probe()==completion&&!tcp_is_active());
 reset();timeout=1;CK(tcp_connect_probe()==ERR(18)&&polls==1000&&!tcp_is_active());
 reset();reset_error=1;CK(tcp_connect_probe()==ERR(7)&&tcp_is_active()&&closures==0);CK(tcp_connect_probe()==ERR(20)&&connects==1);reset_error=0;CK(tcp_cleanup()==0&&!tcp_is_active());
 reset();destroy_error=1;CK(tcp_connect_probe()==ERR(7)&&tcp_is_active()&&closures==0);destroy_error=0;CK(tcp_cleanup()==0&&!tcp_is_active());
 reset();close_error=1;CK(tcp_connect_probe()==ERR(7)&&tcp_is_active());close_error=0;CK(tcp_cleanup()==0&&!tcp_is_active());
 reset();tls_inventory();return failure;
}
int get_checks(void){return checks;}
