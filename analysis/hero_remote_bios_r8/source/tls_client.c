/* R8: private native TLS + TCP on the verified BMC USB path. No SetVariable,
 * credentials or redirects. Publication uses exact pinned certificate auth.
 * TLS implementations may cache a CA in RAM until a host reset.
 * All asynchronous I/O buffers and tokens outlive failed cleanup attempts. */
#include "tls_client.h"
#include "certificate.h"
#include "pin.h"
#include "http_frame.h"
#include "gzip.h"
typedef struct {uint8_t def,ip[4],mask[4];uint16_t port;uint8_t peer[4];uint16_t peer_port;uint8_t active;} ACCESS;
typedef struct {uint8_t tos,ttl;ACCESS access;void *options;} PTCP_CONFIG;
typedef struct {uint32_t length;void *buffer;} FRAGMENT;
typedef struct {uint8_t flags[4];uint32_t length,count;FRAGMENT fragment;} DATA;
typedef struct {HANDLE event;ES status;DATA *data;} TOKEN;
typedef struct STREAM STREAM;
struct STREAM {void *mode;ES (EA *configure)(STREAM *,PTCP_CONFIG *);void *routes;ES (EA *connect)(STREAM *,TOKEN *);void *accept;ES (EA *transmit)(STREAM *,TOKEN *);ES (EA *receive)(STREAM *,TOKEN *);void *close;ES (EA *cancel)(STREAM *,TOKEN *);ES (EA *poll)(STREAM *);};
typedef struct TLS TLS;
struct TLS {ES (EA *set)(TLS *,uint32_t,void *,UN);ES (EA *get)(TLS *,uint32_t,void *,UN *);ES (EA *build)(TLS *,uint8_t *,UN,uint8_t *,UN *);ES (EA *process)(TLS *,FRAGMENT **,uint32_t *,uint32_t);};
typedef struct TC TC;struct TC {ES (EA *set)(TC *,uint32_t,void *,UN);void *get;};
typedef struct __attribute__((packed)) {uint32_t flags;char *host;} VERIFY_HOST;
OFF(PTCP_CONFIG,access,2);OFF(PTCP_CONFIG,options,24);OFF(ACCESS,peer_port,16);
OFF(DATA,fragment,16);OFF(TOKEN,data,16);OFF(STREAM,transmit,40);OFF(STREAM,receive,48);OFF(STREAM,poll,72);
_Static_assert(sizeof(VERIFY_HOST)==12&&sizeof(FRAGMENT)==16&&sizeof(DATA)==32,"private TLS ABI");
static GUID stream_sb={0x00720665,0x67eb,0x4a99,{0xba,0xf7,0xd3,0xc3,0x3a,0x1c,0x7c,0xc9}};
static GUID stream_guid={0x65530bc7,0xa359,0x410f,{0xb0,0x10,0x5a,0xad,0xc7,0xec,0x2b,0x62}};
static GUID tls_sb={0x952cb795,0xff36,0x48cf,{0xa2,0x49,0x4d,0xf4,0x86,0xd6,0xab,0x8d}};
static GUID tls_guid={0x00ca959f,0x6cfa,0x4db1,{0x95,0xbc,0xe4,0x6c,0x47,0x51,0x43,0x90}};
static GUID ptls_config_guid={0x1682fe44,0xbd7a,0x4407,{0xb7,0xc7,0xdc,0xa3,0x7c,0xa3,0x92,0x2d}};
static SB *sb,*tsb;static HANDLE sc,tc;static STREAM *stream;static TLS *tls;
static TOKEN io;static DATA packet;static volatile uint32_t complete;
static unsigned ticks;static int use_pin;static uint8_t rx[18437],tx[32768],plain[18437];
static char response_text[32768];static UN response_size;
static TLS_REPLY last_reply;
static char decoded_body[32769];
static char request_buffer[8192];static const char *active_request;
static const char *get_requests[]={
 "GET /redfish/v1/ HTTP/1.1\r\nHost: 169.254.0.17\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
 "GET /redfish/v1/Systems/Self HTTP/1.1\r\nHost: 169.254.0.17\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
 "GET /redfish/v1/Systems/Self/Bios HTTP/1.1\r\nHost: 169.254.0.17\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"};
static unsigned resource;
static UN request_length(void){UN n=0;while(active_request[n])n++;return n;}
static void EA notified(HANDLE event,void *context){(void)event;(void)context;complete=1;}
int private_tls_active(void){return sc||tc||io.event;}
ES private_tls_cleanup(void){
 if(sc&&sb){
  if(stream){stream->cancel(stream,0);ES e=stream->configure(stream,0);status("PTLS_TCP_RESET",e);if(FAILED(e))return e;}
  ES e=sb->destroy(sb,sc);status("PTLS_TCP_DESTROY",e);if(FAILED(e))return e;sc=0;stream=0;sb=0;
 }
 if(io.event){ES e=gST->bs->close_event(io.event);if(FAILED(e))return e;io.event=0;}
 if(tc&&tsb){ES e=tsb->destroy(tsb,tc);status("PTLS_TLS_DESTROY",e);if(FAILED(e))return e;tc=0;tls=0;tsb=0;}
 return 0;
}
static ES wait_io(void){
 for(unsigned i=0;i<1000&&!complete&&ticks<3000;i++,ticks++){
  ES e=stream->poll(stream);if(FAILED(e)&&e!=ERR(6)&&e!=ERR(18))break;
  if(!complete)gST->bs->stall(10000);
 }
 if(complete)return io.status;
 status("PTLS_TCP_CANCEL",stream->cancel(stream,&io));
 for(unsigned i=0;i<100&&!complete;i++){stream->poll(stream);gST->bs->stall(10000);}
 return ERR(18);
}
static ES transfer(int send,uint8_t *buffer,UN n,UN *actual){
 if(!n||n>sizeof(tx))return ERR(2);
 memset(&packet,0,sizeof(packet));packet.flags[0]=send?1:0;packet.length=(uint32_t)n;packet.count=1;packet.fragment=(FRAGMENT){(uint32_t)n,buffer};
 io.data=&packet;io.status=ERR(6);complete=0;
 ES e=send?stream->transmit(stream,&io):stream->receive(stream,&io);if(FAILED(e))return e;
 e=wait_io();if(FAILED(e))return e;
 if(packet.length>n||packet.fragment.length>n||packet.count!=1||packet.fragment.buffer!=buffer||packet.length!=packet.fragment.length)return ERR(24);
 if(!packet.length)return ERR(24);*actual=packet.length;
 return send&&packet.length!=n?ERR(24):0;
}
static ES send_bytes(UN n){UN actual=0;return n?transfer(1,tx,n,&actual):0;}
static ES receive_exact(UN offset,UN n){
 if(offset>sizeof(rx)||n>sizeof(rx)-offset)return ERR(2);
 UN used=0;
 while(used<n){UN actual=0;ES e=transfer(0,rx+offset+used,n-used,&actual);if(FAILED(e))return e;used+=actual;}
 return 0;
}
static ES receive_record(UN *n){
 ES e=receive_exact(0,5);if(FAILED(e))return e;
 if(rx[0]<20||rx[0]>23||rx[1]!=3||rx[2]<1||rx[2]>3)return ERR(24);
 UN body=(UN)rx[3]*256+rx[4];if(body>sizeof(rx)-5)return ERR(4);
 *n=body+5;return body?receive_exact(5,body):0;
}
static ES state(uint32_t *s){UN n=4;*s=0;ES e=tls->get(tls,7,s,&n);return !FAILED(e)&&n!=4?ERR(24):e;}
static ES handshake(void){
 UN n=sizeof(tx);ES e=tls->build(tls,0,0,tx,&n);status("PTLS_CLIENT_HELLO",e);
 if(FAILED(e)||n>sizeof(tx))return FAILED(e)?e:ERR(4);
 e=send_bytes(n);if(FAILED(e))return e;
 for(unsigned i=0;i<32;i++){
  uint32_t s;e=state(&s);if(FAILED(e))return e;
  if(s==2){
   if(!pin.hello_seen||(use_pin&&!pin.seen))return ERR(26);
   uint8_t ver[2]={0};UN size=2;e=tls->get(tls,0,ver,&size);if(FAILED(e)||size!=2||ver[0]!=3||ver[1]!=3)return ERR(26);
   logtext(use_pin?"PTLS_HANDSHAKE_EXACT_PIN_AUTHENTICATED\r\n":"PTLS_HANDSHAKE_VERIFIED\r\n");return 0;
  }
  if(s!=1)return ERR(21);
  UN in=0;e=receive_record(&in);if(FAILED(e))return e;
  if(rx[0]==23)return ERR(24);
  ES pin_status=pin_record(rx,in);if(FAILED(pin_status)){status("PTLS_PEER_POLICY_CHECK",pin_status);return pin_status;}
  status("PTLS_HANDSHAKE_RECORD",rx[0]);n=sizeof(tx);e=tls->build(tls,rx,in,tx,&n);status("PTLS_HANDSHAKE_STEP",e);
  if(FAILED(e)){
   /* Retrieve only the native TLS public alert (never key material). */
   uint32_t error_state=4;ES set=tls->set(tls,7,&error_state,4);UN alert_size=sizeof(tx);
   if(!FAILED(set)&&!FAILED(tls->build(tls,0,0,tx,&alert_size))&&alert_size>=7&&alert_size<=sizeof(tx)&&tx[0]==21&&tx[3]==0&&tx[4]==2){status("PTLS_ALERT_LEVEL",tx[5]);status("PTLS_ALERT_DESCRIPTION",tx[6]);}
   return e;
  }
  if(n>sizeof(tx))return ERR(4);
  e=send_bytes(n);if(FAILED(e))return e;
 }
 return ERR(18);
}
/* ProcessPacket returns allocated fragments; copy into static buffers before
 * TCP sees them. Do not free the original caller-owned fragment/buffer. */
static ES crypt(uint8_t *input,UN n,uint8_t *output,UN capacity,UN *used,int decrypt){
 FRAGMENT original={(uint32_t)n,input},*f=&original;uint32_t count=1;
 ES e=tls->process(tls,&f,&count,decrypt?1:0);*used=0;
 if(FAILED(e)){if(f!=&original&&f)gST->bs->free_pool(f);return e;}
 if(!f||count>64){if(f&&f!=&original)gST->bs->free_pool(f);return ERR(24);}
 for(uint32_t i=0;i<count;i++){
  if(!f[i].buffer||f[i].length>capacity-*used)e=ERR(4);
  else if(!FAILED(e)){memcpy(output+*used,f[i].buffer,f[i].length);*used+=f[i].length;}
  if(f[i].buffer&&f[i].buffer!=input)gST->bs->free_pool(f[i].buffer);
 }
 if(f!=&original)gST->bs->free_pool(f);return e;
}
static ES fetch_root(void){
 UN len=request_length(),n=0;
 plain[0]=23;plain[1]=3;plain[2]=3;plain[3]=(uint8_t)len;plain[4]=(uint8_t)(len>>8);memcpy(plain+5,active_request,len);
 ES e=crypt(plain,len+5,tx,sizeof(tx),&n,0);status("PTLS_ENCRYPT_GET",e);if(FAILED(e))return e;
 e=send_bytes(n);status("PTLS_GET_SENT",e);if(FAILED(e))return e;
 for(unsigned i=0;i<64;i++){
  UN in=0;e=receive_record(&in);
  if(FAILED(e))return e;
  if(rx[0]==21){UN out=sizeof(tx);e=tls->build(tls,rx,in,tx,&out);status("PTLS_PEER_CLOSE",e);return !response_size?ERR(24):e;}
  if(rx[0]!=23)return ERR(24);
  e=crypt(rx,in,plain,sizeof(plain),&n,1);if(FAILED(e))return e;
  /* Native EFI TLS plaintext record lengths use host byte order. */
  UN off=0;while(off<n){
   if(n-off<5||plain[off]!=23)return ERR(24);
   UN bytes=u16(plain+off+3);if(bytes>n-off-5||bytes>=sizeof(response_text)-response_size)return ERR(4);
   memcpy(response_text+response_size,plain+off+5,bytes);response_size+=bytes;off+=bytes+5;
  }
  /* Root GET requests Connection: close. Keep raw HTTP for strict parsing in
   * a later stage; this probe never treats a partial body as applied state. */
 }
 return ERR(18);
}
static ES exchange_with_policy(int pinned,unsigned id,const char *request){
 HANDLE nic=network_candidate();if(!nic||private_tls_active()||tcp_is_active())return ERR(15);
 ES e;TC *config=0;ticks=0;response_size=0;use_pin=pinned;resource=id;active_request=request;memset(&last_reply,0,sizeof(last_reply));memset(&pin,0,sizeof(pin));memset(&io,0,sizeof(io));memset(response_text,0,sizeof(response_text));
 status("PTLS_RESOURCE_ID",resource);logtext(active_request);
 logtext(use_pin?"TLS_AUTH_POLICY=EXACT_PROVISIONED_LEAF_PIN\r\n":"TLS_AUTH_POLICY=NATIVE_CA_AND_HOST\r\n");
 e=gST->bs->locate_protocol(&tls_sb,0,(void **)&tsb);status("PTLS_SERVICE",e);if(FAILED(e)||!tsb)return FAILED(e)?e:ERR(14);
 e=tsb->create(tsb,&tc);status("PTLS_CREATE",e);if(FAILED(e))goto end;
 e=gST->bs->handle_protocol(tc,&tls_guid,(void **)&tls);status("PTLS_OPEN",e);if(FAILED(e)||!tls){if(!FAILED(e))e=ERR(14);goto end;}
 e=gST->bs->handle_protocol(tc,&ptls_config_guid,(void **)&config);status("PTLS_CONFIG_OPEN",e);if(FAILED(e)||!config){if(!FAILED(e))e=ERR(14);goto end;}
 uint8_t version[2]={3,3};uint32_t client=0,verify=use_pin?0:1;VERIFY_HOST host={2,"169.254.0.17"};
 e=tls->set(tls,0,version,2);status("PTLS_VERSION_12",e);if(FAILED(e))goto end;
 e=tls->set(tls,1,&client,4);if(FAILED(e))goto end;
 /* HERO rejects EfiTlsCipherList for c02f. Inspect and allowlist the actual
  * ServerHello instead; unsupported suites are rejected before HTTP. */
 e=tls->set(tls,5,&verify,4);status("PTLS_AUTH_METHOD_SET",e);if(FAILED(e))goto end;
 if(!use_pin){
  e=tls->set(tls,11,&host,sizeof(host));status("PTLS_VERIFY_HOST",e);if(FAILED(e))goto end;
  e=config->set(config,2,(void *)(hero_cert_esl+44),sizeof(hero_cert_esl)-44);status("PTLS_CA_CONFIG",e);if(FAILED(e))goto end;
 }
 UN vn=4;verify=0xff;e=tls->get(tls,5,&verify,&vn);status("PTLS_VERIFY_READBACK",e);if(FAILED(e)||vn!=4||verify!=(use_pin?0u:1u)){if(!FAILED(e))e=ERR(26);goto end;}
 e=gST->bs->handle_protocol(nic,&stream_sb,(void **)&sb);if(FAILED(e)||!sb){if(!FAILED(e))e=ERR(14);goto end;}
 e=sb->create(sb,&sc);status("PTLS_TCP_CREATE",e);if(FAILED(e))goto end;
 e=gST->bs->handle_protocol(sc,&stream_guid,(void **)&stream);if(FAILED(e)||!stream){if(!FAILED(e))e=ERR(14);goto end;}
 PTCP_CONFIG c={0,64,{0,{169,254,0,18},{255,255,0,0},0,{169,254,0,17},443,1},0};
 e=stream->configure(stream,&c);status("PTLS_TCP_CONFIG",e);if(FAILED(e))goto end;
 e=gST->bs->create_event(0x200,8,notified,0,&io.event);if(FAILED(e))goto end;
 complete=0;io.status=ERR(6);e=stream->connect(stream,&io);if(!FAILED(e))e=wait_io();status("PTLS_TCP_CONNECT",e);if(FAILED(e))goto end;
 e=handshake();status("PTLS_HANDSHAKE_RESULT",e);if(FAILED(e))goto end;
 say("TLS handshake succeeded. Reading selected resource.\r\n");e=fetch_root();status("PTLS_FETCH_RESULT",e);
 if(response_size){
  unsigned code,encoding;UN body_off,body_len;ES framing=http_frame(response_text,response_size,&code,&body_off,&body_len,&encoding);
  status("PTLS_HTTP_FRAMING",framing);status("PTLS_HTTP_STATUS",code);status("PTLS_HTTP_BODY_BYTES",body_len);
  if(!FAILED(e)&&FAILED(framing))e=framing;
  if(!FAILED(e)&&encoding){
   UN n=0;e=gzip_decode((const uint8_t *)response_text+body_off,body_len,decoded_body,32768,&n);status("PTLS_GZIP_DECODE",e);
   if(!FAILED(e)){decoded_body[n]=0;last_reply=(TLS_REPLY){code,decoded_body,n};status("PTLS_DECODED_BYTES",n);logtext("PTLS_DECODED_BEGIN\r\n");logtext(decoded_body);logtext("\r\nPTLS_DECODED_END\r\n");say(decoded_body);say("\r\n");}
  }else if(!FAILED(e))last_reply=(TLS_REPLY){code,response_text+body_off,body_len};
  /* Log printable HTTP/JSON only, not TLS secrets or encrypted records. */
  UN printable=encoding?body_off:response_size;
  for(UN i=0;i<printable;i++)if((uint8_t)response_text[i]<32&&response_text[i]!='\r'&&response_text[i]!='\n'&&response_text[i]!='\t')response_text[i]='?';
  response_text[printable]=0;status("PTLS_HTTP_BYTES",response_size);logtext("PTLS_HTTP_BEGIN\r\n");logtext(response_text);logtext("\r\nPTLS_HTTP_END\r\n");say(response_text);say("\r\n");
 }
end:{ES cleanup=private_tls_cleanup();if(FAILED(cleanup)||FAILED(e))memset(&last_reply,0,sizeof(last_reply));return FAILED(cleanup)?cleanup:e;}
}
static ES get_with_policy(int pinned,unsigned id){if(id>=3)return ERR(2);return exchange_with_policy(pinned,id,get_requests[id]);}
ES private_tls_get(void){return get_with_policy(0,0);}
ES private_tls_get_pinned(void){return get_with_policy(1,0);}
ES private_tls_read_bios(void){ES e=get_with_policy(1,1);return FAILED(e)?e:get_with_policy(1,2);}
/* No pending-settings endpoint, credentials, arbitrary method or arbitrary URL. */
static const struct {const char *method,*path,*type;int body;} resources[]={
 {"GET","/redfish/v1/",0,0},
 {"GET","/redfish/v1/Systems/Self",0,0},
 {"GET","/redfish/v1/Systems/Self/Bios",0,0},
 {"GET","/redfish/v1/Registries",0,0},
 {"POST","/redfish/v1/Registries","application/json",1},
 {"PATCH","/redfish/v1/Systems/Self/Bios","application/json",1},
 {"POST","/redfish/v1/BiosStaticFiles","multipart/form-data; boundary=HERO_R8_STATIC_46F2C920",1},
 {"GET","/redfish/v1/BiosStaticFiles/SetupData.xml",0,0},
 {"GET","/redfish/v1/Registries/BiosAttributeRegistryHERO3107.0.8.0.json",0,0},
 {"GET","/bios/SetupData.xml",0,0}};
static int append_request(UN *n,const char *s,UN length){if(length>=sizeof(request_buffer)-*n)return 0;memcpy(request_buffer+*n,s,length);*n+=length;request_buffer[*n]=0;return 1;}
static int append_text(UN *n,const char *s){UN z=0;while(s[z])z++;return append_request(n,s,z);}
static ES make_request(unsigned id,const char *body,UN length){
 if(id>=sizeof(resources)/sizeof(resources[0])||length>4096||(!body&&length)||resources[id].body!=(length!=0))return ERR(2);
 for(UN i=0;i<length;i++)if(!body[i])return ERR(2);
 UN n=0;request_buffer[0]=0;
 if(!append_text(&n,resources[id].method)||!append_text(&n," ")||!append_text(&n,resources[id].path)||!append_text(&n," HTTP/1.1\r\nHost: 169.254.0.17\r\nAccept: application/json, application/xml\r\nAccept-Encoding: identity\r\nConnection: close\r\n"))return ERR(4);
 if(length){
  char decimal[16];UN z=0,v=length;do{decimal[z++]=(char)('0'+v%10);v/=10;}while(v);
  for(UN i=0;i<z/2;i++){char c=decimal[i];decimal[i]=decimal[z-1-i];decimal[z-1-i]=c;}
  if(!append_text(&n,"Content-Type: ")||!append_text(&n,resources[id].type)||!append_text(&n,"\r\nContent-Length: ")||!append_request(&n,decimal,z)||!append_text(&n,"\r\n"))return ERR(4);
 }
 if(!append_text(&n,"\r\n")||(length&&!append_request(&n,body,length)))return ERR(4);
 return 0;
}
ES private_tls_resource(unsigned id,const char *body,UN length,TLS_REPLY *reply){
 if(!reply)return ERR(2);memset(reply,0,sizeof(*reply));
 if(private_tls_active())return ERR(15);ES e=make_request(id,body,length);if(FAILED(e))return e;
 e=exchange_with_policy(1,id,request_buffer);if(!FAILED(e))*reply=last_reply;return e;
}
