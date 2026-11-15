/* Bounded TCP reachability on the verified internal USB interface only.
 * Connect to 169.254.0.17:443, send no application data, then reset/destroy
 * this private TCP instance. No certificate or platform policy is changed. */
#include "network.h"
static GUID tcp_sb_guid={0x00720665,0x67eb,0x4a99,{0xba,0xf7,0xd3,0xc3,0x3a,0x1c,0x7c,0xc9}};
static GUID tcp_guid={0x65530bc7,0xa359,0x410f,{0xb0,0x10,0x5a,0xad,0xc7,0xec,0x2b,0x62}};
static GUID tls_sb_guid={0x952cb795,0xff36,0x48cf,{0xa2,0x49,0x4d,0xf4,0x86,0xd6,0xab,0x8d}};
static GUID tls_ca_guid={0xfd2340d0,0x3dab,0x4349,{0xa6,0xc7,0x3b,0x4f,0x12,0xb4,0x8e,0xae}};
typedef struct {uint8_t use_default,station[4],mask[4];uint16_t station_port;uint8_t remote[4];uint16_t remote_port;uint8_t active;} TCP_ACCESS;
typedef struct {uint8_t tos,ttl;TCP_ACCESS access;void *options;} TCP_CONFIG;
typedef struct {HANDLE event;ES status;} TCP_TOKEN;
typedef struct TCP TCP;
struct TCP {void *mode;ES (EA *configure)(TCP *,TCP_CONFIG *);void *routes;ES (EA *connect)(TCP *,TCP_TOKEN *);void *accept,*transmit,*receive,*close;ES (EA *cancel)(TCP *,TCP_TOKEN *);ES (EA *poll)(TCP *);};
OFF(TCP_ACCESS,station_port,10);OFF(TCP_ACCESS,remote,12);OFF(TCP_ACCESS,remote_port,16);OFF(TCP_CONFIG,access,2);OFF(TCP_CONFIG,options,24);
OFF(TCP,connect,24);OFF(TCP,cancel,64);OFF(TCP,poll,72);
_Static_assert(sizeof(TCP_ACCESS)==20&&sizeof(TCP_CONFIG)==32&&sizeof(TCP_TOKEN)==16,"TCP ABI sizes");
static HANDLE tcp_child;static SB *tcp_binding;static TCP *tcp;
static TCP_TOKEN tcp_token;static volatile uint32_t tcp_done;
static void EA tcp_notify(HANDLE event,void *context){(void)event;(void)context;tcp_done=1;}
void tls_inventory(void){
 void *p=0;status("TLS_SERVICE_BINDING",gST->bs->locate_protocol(&tls_sb_guid,0,&p));
 UN n=0;uint32_t attrs=0;ES e=gST->rt->get_variable(W("TlsCaCertificate"),&tls_ca_guid,&attrs,&n,0);
 status("TLS_CA_VARIABLE_SIZE_QUERY",e);status("TLS_CA_VARIABLE_BYTES",n);if(e==ERR(5))status("TLS_CA_VARIABLE_ATTRS",attrs);
 /* Size query only; no trust-store bytes or credentials are exported. */
}
ES tcp_cleanup(void){
 if(tcp_child&&tcp_binding){
  if(tcp){tcp->cancel(tcp,0);ES e=tcp->configure(tcp,0);status("TCP_RESET_INSTANCE",e);if(FAILED(e))return e;}
  ES e=tcp_binding->destroy(tcp_binding,tcp_child);status("TCP_DESTROY",e);if(FAILED(e))return e;
  tcp_child=0;tcp=0;tcp_binding=0;
 }
 if(tcp_token.event){ES e=gST->bs->close_event(tcp_token.event);if(FAILED(e))return e;tcp_token.event=0;}
 return 0;
}
int tcp_is_active(void){return tcp_child||tcp_token.event;}
ES tcp_connect_probe(void){
 HANDLE h=network_candidate();if(!h)return ERR(15);if(tcp_is_active())return ERR(20);
 ES e=gST->bs->handle_protocol(h,&tcp_sb_guid,(void **)&tcp_binding);status("TCP_SERVICE_BINDING",e);if(FAILED(e)||!tcp_binding)return FAILED(e)?e:ERR(14);
 e=tcp_binding->create(tcp_binding,&tcp_child);status("TCP_CREATE",e);if(FAILED(e))return e;
 e=gST->bs->handle_protocol(tcp_child,&tcp_guid,(void **)&tcp);status("TCP_OPEN",e);if(FAILED(e)||!tcp){if(!FAILED(e))e=ERR(14);goto end;}
 TCP_CONFIG c={0,64,{0,{169,254,0,18},{255,255,0,0},0,{169,254,0,17},443,1},0};
 e=tcp->configure(tcp,&c);status("TCP_CONFIGURE",e);if(FAILED(e))goto end;
 memset(&tcp_token,0,sizeof(tcp_token));tcp_done=0;
 e=gST->bs->create_event(0x200,8,tcp_notify,0,&tcp_token.event);if(FAILED(e))goto end;
 tcp_token.status=ERR(6);logtext("TCP_CONNECT_ONLY=169.254.0.17:443; APPLICATION_BYTES=0\r\n");
 say("Connect internal BMC TCP 443 only; no application data. Up to 10 seconds.\r\n");
 e=tcp->connect(tcp,&tcp_token);status("TCP_CONNECT_QUEUE",e);if(FAILED(e))goto end;
 for(unsigned i=0;i<1000&&!tcp_done;i++){ES p=tcp->poll(tcp);if(FAILED(p)&&p!=ERR(6)&&p!=ERR(18)){status("TCP_POLL",p);break;}gST->bs->stall(10000);}
 if(tcp_done)e=tcp_token.status;else{
  status("TCP_CANCEL",tcp->cancel(tcp,&tcp_token));for(unsigned i=0;i<100&&!tcp_done;i++){tcp->poll(tcp);gST->bs->stall(10000);}e=ERR(18);
 }
 status("TCP_CONNECT_DONE",e);
 if(!FAILED(e)&&tcp_done)logtext("TCP_443_REACHABLE_NO_APPLICATION_DATA\r\n");
end:{ES cleanup=tcp_cleanup();return FAILED(cleanup)?cleanup:e;}
}
