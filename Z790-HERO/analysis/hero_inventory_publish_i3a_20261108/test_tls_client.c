/* Execute the exact private TLS transport against deterministic protocol mocks.
 * Test data is synthetic; no network or real TLS secrets are involved. */
#include "source/tls_client.c"
ST *gST;char audit[131072];UN audit_len;static ST st;static BS bs;static SB mock_sb,mock_tsb;static STREAM mock_stream;static TLS mock_tls;static TC mock_tc;
static int failure,checks,good,app_sends,creates,fail_stage,handshake_reject,timeout,fail_reset,fail_destroy,tls_destroy_fail,read_bad,allocs,frees,configured_verify;
static uint32_t mock_state;static UN wire_size,wire_pos;static uint8_t wire[4096],outbuf[4096];static FRAGMENT outfrag;
#define CK(x) do{checks++;if(!(x)&&!failure)failure=__LINE__;}while(0)
void *memcpy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *x=d;while(n--)*x++=(uint8_t)c;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
uint16_t u16(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
uint32_t u32(const uint8_t *p){return u16(p)|(uint32_t)u16(p+2)<<16;}
void logtext(const char *s){(void)s;}void status(const char *s,ES e){(void)s;(void)e;}void say(const char *s){(void)s;}
HANDLE network_candidate(void){return good?(HANDLE)1:0;}int tcp_is_active(void){return 0;}
static ES EA freepool(void *p){CK(p==&outfrag||p==outbuf);frees++;return 0;}
static ES EA create(SB *p,HANDLE *h){creates++;if(fail_stage==(p==&mock_tsb?2:8))return ERR(9);*h=p==&mock_tsb?(HANDLE)2:(HANDLE)3;return 0;}
static ES EA destroy(SB *p,HANDLE h){CK(h==(p==&mock_tsb?(HANDLE)2:(HANDLE)3));return (p==&mock_tsb?tls_destroy_fail:fail_destroy)?ERR(7):0;}
static ES EA locate(GUID *g,void *registration,void **p){CK(eq(g,&tls_sb,16)&&!registration);*p=0;if(fail_stage==1)return ERR(14);*p=&mock_tsb;return 0;}
static ES EA handle(HANDLE h,GUID *g,void **p){
 *p=0;if(eq(g,&tls_guid,16)){CK(h==(HANDLE)2);if(fail_stage==3)return ERR(14);*p=&mock_tls;}
 else if(eq(g,&ptls_config_guid,16)){CK(h==(HANDLE)2);*p=&mock_tc;}
 else if(eq(g,&stream_sb,16)){CK(h==(HANDLE)1);if(fail_stage==7)return ERR(14);*p=&mock_sb;}
 else if(eq(g,&stream_guid,16)){CK(h==(HANDLE)3);if(fail_stage==9)return ERR(14);*p=&mock_stream;}else CK(0);return 0;
}
static ES EA tls_set(TLS *t,uint32_t type,void *data,UN n){
 CK(t==&mock_tls);
 if(type==0){CK(n==2&&eq(data,"\3\3",2));if(fail_stage==4)return ERR(3);}
 else if(type==1)CK(n==4&&*(uint32_t *)data==0);
 else if(type==2)CK(n==2&&eq(data,"\300\57",2));
 else if(type==5){CK(n==4&&*(uint32_t *)data==(use_pin?0u:1u));configured_verify=*(uint32_t *)data;}
 else if(type==7){CK(n==4&&*(uint32_t *)data==4);mock_state=4;}
 else if(type==11){VERIFY_HOST *h=data;CK(n==12&&h->flags==2&&eq(h->host,"169.254.0.17",13));if(fail_stage==5)return ERR(3);}
 else CK(0);return 0;
}
static ES EA tls_get(TLS *t,uint32_t type,void *data,UN *n){CK(t==&mock_tls);if(type==0){CK(*n==2);memcpy(data,"\3\3",2);}else {CK(*n==4);if(type==5)*(uint32_t *)data=configured_verify;else if(type==7)*(uint32_t *)data=mock_state;else CK(0);}return 0;}
static ES EA ca(TC *t,uint32_t type,void *data,UN n){CK(t==&mock_tc&&type==2&&n==sizeof(hero_cert_esl)-44&&eq(data,hero_cert_esl+44,n));return fail_stage==6?ERR(21):0;}
static ES EA tls_build(TLS *t,uint8_t *in,UN n,uint8_t *out,UN *size){
 CK(t==&mock_tls&&*size>=5);
 if(!in){if(mock_state==4){memcpy(out,"\25\3\3\0\2\2\55",7);*size=7;return 0;}CK(!n&&mock_state==0);mock_state=1;memcpy(out,"\26\3\3\0\1\1",6);*size=6;return 0;}
 if(in[0]==21){*size=0;mock_state=3;return 0;}
 CK(n>=6&&in[0]==22);*size=0;if(in[5]==2){mock_state=1;return 0;}if(handshake_reject)return ERR(26);mock_state=2;return 0;
}
static ES EA process(TLS *t,FRAGMENT **fr,uint32_t *count,uint32_t decrypt){
 CK(t==&mock_tls&&mock_state==2&&*count==1);
 FRAGMENT *f=*fr;CK(f->length<sizeof(outbuf));memcpy(outbuf,f->buffer,f->length);
 if(!decrypt){CK(u16(outbuf+3)==request_length()&&eq(outbuf+5,active_request,request_length()));}
 uint8_t b=outbuf[3];outbuf[3]=outbuf[4];outbuf[4]=b;outfrag=(FRAGMENT){f->length,outbuf};*fr=&outfrag;allocs+=2;return 0;
}
static ES EA configure(STREAM *s,PTCP_CONFIG *c){
 CK(s==&mock_stream);if(!c)return fail_reset?ERR(7):0;
 CK(c->ttl==64&&!c->access.def&&eq(c->access.ip,"\251\376\0\22",4)&&eq(c->access.peer,"\251\376\0\21",4)&&c->access.peer_port==443&&c->access.active==1);return fail_stage==10?ERR(15):0;
}
static ES EA event(uint32_t ty,UN tpl,void (EA *f)(HANDLE,void *),void *ctx,HANDLE *h){CK(ty==0x200&&tpl==8&&f==notified&&!ctx);if(fail_stage==11)return ERR(9);*h=(HANDLE)4;return 0;}
static ES EA close_event(HANDLE h){CK(h==(HANDLE)4);return 0;}
static ES EA connect(STREAM *s,TOKEN *t){CK(s==&mock_stream&&t==&io);if(fail_stage==12)return ERR(15);t->status=0;if(!timeout)notified(t->event,0);return 0;}
static ES EA transmit(STREAM *s,TOKEN *t){CK(s==&mock_stream&&t==&io&&t->data->count==1&&t->data->flags[0]==1);if(mock_state==2)app_sends++;t->status=0;notified(t->event,0);return 0;}
static ES EA receive(STREAM *s,TOKEN *t){CK(s==&mock_stream&&t==&io&&t->data->count==1);UN n=t->data->length;if(n>wire_size-wire_pos)n=wire_size-wire_pos;if(n>2)n=2;/* short TCP reads */
 if(!n){t->status=ERR(104);notified(t->event,0);return 0;}
 memcpy(t->data->fragment.buffer,wire+wire_pos,n);wire_pos+=n;t->data->length=(uint32_t)n;t->data->fragment.length=(uint32_t)n;t->status=0;notified(t->event,0);return 0;
}
static ES EA poll(STREAM *s){CK(s==&mock_stream);return 0;}
static ES EA cancel(STREAM *s,TOKEN *t){CK(s==&mock_stream);if(t){t->status=ERR(21);notified(t->event,0);}return 0;}
static ES EA stall(UN n){CK(n==10000);return 0;}
static void wire_record(uint8_t type,const char *s,UN n){wire[wire_size++]=type;wire[wire_size++]=3;wire[wire_size++]=3;wire[wire_size++]=(uint8_t)(n>>8);wire[wire_size++]=(uint8_t)n;memcpy(wire+wire_size,s,n);wire_size+=n;}
static void server_hello(void){uint8_t hello[42]={2,0,0,38,3,3};hello[39]=0;hello[40]=0x9c;hello[41]=0;wire_record(22,(const char *)hello,sizeof(hello));}
static void pinned_wire(void);
static void reset(void){
 audit_len=0;memset(&st,0,sizeof(st));memset(&bs,0,sizeof(bs));gST=&st;st.bs=&bs;
 bs.handle_protocol=handle;bs.locate_protocol=locate;bs.free_pool=freepool;bs.create_event=event;bs.close_event=close_event;bs.stall=stall;
 mock_sb.create=mock_tsb.create=create;mock_sb.destroy=mock_tsb.destroy=destroy;
 mock_tls=(TLS){tls_set,tls_get,tls_build,process};mock_tc.set=ca;
 mock_stream=(STREAM){0,configure,0,connect,0,transmit,receive,0,cancel,poll};
 sc=tc=0;sb=tsb=0;stream=0;tls=0;memset(&io,0,sizeof(io));
 good=1;app_sends=creates=fail_stage=handshake_reject=timeout=fail_reset=fail_destroy=tls_destroy_fail=read_bad=allocs=frees=configured_verify=0;mock_state=0;wire_size=wire_pos=0;
 pinned_wire();
}
static void beput(uint8_t *p,UN n){p[0]=(uint8_t)(n>>16);p[1]=(uint8_t)(n>>8);p[2]=(uint8_t)n;}
static uint8_t cert_handshake[sizeof(pinned_leaf)+10];
static void make_certificate(void){cert_handshake[0]=11;beput(cert_handshake+1,sizeof(pinned_leaf)+6);beput(cert_handshake+4,sizeof(pinned_leaf)+3);beput(cert_handshake+7,sizeof(pinned_leaf));memcpy(cert_handshake+10,pinned_leaf,sizeof(pinned_leaf));}
static void pinned_wire(void){wire_size=wire_pos=0;server_hello();make_certificate();wire_record(22,(const char *)cert_handshake,sizeof(cert_handshake));const char text[]="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";wire_record(23,text,sizeof(text)-1);wire_record(21,"\1\0",2);}
static void check_pin_fragments(void){
 make_certificate();uint8_t part[sizeof(cert_handshake)+5];
 for(UN split=0;split<=sizeof(cert_handshake);split++){
  memset(&pin,0,sizeof(pin));memset(part,0,5);part[0]=22;memcpy(part+5,cert_handshake,split);CK(!pin_record(part,split+5));
  memcpy(part+5,cert_handshake+split,sizeof(cert_handshake)-split);CK(!pin_record(part,sizeof(cert_handshake)-split+5)&&pin.seen);
 }
 memset(&pin,0,sizeof(pin));uint8_t ccs[]={20,3,3,0,1,1};CK(pin_record(ccs,6)==ERR(26));
 memset(&pin,0,sizeof(pin));CK(!pin_certificate(cert_handshake+4,sizeof(cert_handshake)-4));CK(pin_certificate(cert_handshake+4,sizeof(cert_handshake)-4)==ERR(26));
 memset(&pin,0,sizeof(pin));cert_handshake[10]^=1;CK(pin_certificate(cert_handshake+4,sizeof(cert_handshake)-4)==ERR(26));make_certificate();
 memset(&pin,0,sizeof(pin));beput(cert_handshake+4,1);CK(pin_certificate(cert_handshake+4,sizeof(cert_handshake)-4)==ERR(26));make_certificate();
 memset(&pin,0,sizeof(pin));uint8_t huge[]={22,3,3,0,4,11,1,0,0};CK(pin_record(huge,sizeof(huge))==ERR(4));
}
static void check_http(void){
 const char good_response[]="HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}";
 unsigned code,encoding;UN off,n;CK(!http_frame(good_response,sizeof(good_response)-1,&code,&off,&n,&encoding)&&code==200&&n==2&&eq(good_response+off,"{}",2));
 for(UN i=0;i<sizeof(good_response)-1;i++)CK(FAILED(http_frame(good_response,i,&code,&off,&n,&encoding)));
 const char *bad[]={"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}","HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\n{}","HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999\r\n\r\n{}","HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n","HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Encoding: br\r\n\r\n{}","HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}","HTTP/1.1 000 BAD\r\nContent-Length: 0\r\n\r\n"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){UN size=0;while(bad[i][size])size++;CK(FAILED(http_frame(bad[i],size,&code,&off,&n,&encoding)));}
 const char missing[]="HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\n\r\n{}";CK(!http_frame(missing,sizeof(missing)-1,&code,&off,&n,&encoding)&&code==404&&n==2);
}
int run_tests(void){
 reset();good=0;CK(private_tls_get_pinned()==ERR(15)&&!creates&&!app_sends);
 reset();CK(!private_tls_get_pinned()&&!private_tls_active()&&app_sends==1&&response_size>30&&allocs==frees);
 for(int i=1;i<=12;i++){if(i==5||i==6)continue;reset();fail_stage=i;CK(FAILED(private_tls_get_pinned())&&!private_tls_active()&&!app_sends);}
 reset();handshake_reject=1;CK(private_tls_get_pinned()==ERR(26)&&!app_sends&&!private_tls_active());
 reset();timeout=1;CK(private_tls_get_pinned()==ERR(18)&&!app_sends&&!private_tls_active()&&ticks==1000);
 reset();wire[0]=0;CK(private_tls_get_pinned()==ERR(24)&&!app_sends&&!private_tls_active());
 reset();wire[3]=0xff;CK(private_tls_get_pinned()==ERR(4)&&!app_sends&&!private_tls_active());
 reset();fail_reset=1;CK(private_tls_get_pinned()==ERR(7)&&private_tls_active());int c=creates;CK(private_tls_get_pinned()==ERR(15)&&creates==c);fail_reset=0;CK(!private_tls_cleanup()&&!private_tls_active());
 reset();fail_destroy=1;CK(private_tls_get_pinned()==ERR(7)&&private_tls_active());fail_destroy=0;CK(!private_tls_cleanup()&&!private_tls_active());
 reset();tls_destroy_fail=1;CK(private_tls_get_pinned()==ERR(7)&&private_tls_active());tls_destroy_fail=0;CK(!private_tls_cleanup()&&!private_tls_active());
 reset();pinned_wire();CK(!private_tls_get_pinned()&&pin.seen&&app_sends==1&&!private_tls_active()&&allocs==frees);
 reset();pinned_wire();wire[67]^=1;CK(private_tls_get_pinned()==ERR(26)&&!app_sends&&!private_tls_active());
 reset();wire_size=wire_pos=0;server_hello();wire_record(22,"\1\0\0\0",4);CK(private_tls_get_pinned()==ERR(26)&&!app_sends&&!private_tls_active());
 reset();wire[45]=0;CK(private_tls_get_pinned()==ERR(26)&&!app_sends&&!private_tls_active());
 reset();pinned_wire();handshake_reject=1;CK(private_tls_get_pinned()==ERR(26)&&!app_sends&&!private_tls_active());
 check_pin_fragments();
 check_http();
 TLS_REPLY r;
 for(unsigned i=0;i<7;i++){
  reset();CK(!private_tls_resource(i,&r)&&r.status==200&&r.length==2&&eq(r.body,"{}",2)&&app_sends==1&&!private_tls_active());
  CK(eq(active_request,"GET ",4));
  UN length=request_length();CK(length>4&&eq(active_request+length-4,"\r\n\r\n",4));
 }
 for(unsigned i=7;i<24;i++){reset();CK(private_tls_resource(i,&r)==ERR(2)&&!creates&&!app_sends);}
 reset();CK(private_tls_resource(0,0)==ERR(2)&&!creates&&!app_sends);
 reset();CK(exchange_with_policy(0,0,"GET /bad")==ERR(15)&&!creates&&!app_sends);
 reset();audit_len=sizeof(audit)-39999;CK(private_tls_resource(0,&r)==ERR(4)&&!creates&&!app_sends);
 reset();CK(!make_request(4));active_request=request_buffer;
 const char expected[]="GET /redfish/v1/Oem/Ami/InventoryData HTTP/1.1\r\nHost: 169.254.0.17\r\nAccept: application/json;charset=utf-8\r\nOData-Version: 4.0\r\nAccept-Encoding: identity\r\nConnection: close\r\nBiosRedfishVersion: 1.8.0\r\nBiosRtpVersion: 1.8.a\r\n\r\n";
 CK(request_length()==sizeof(expected)-1&&eq(active_request,expected,sizeof(expected)-1));
 reset();handshake_reject=1;CK(private_tls_resource(4,&r)==ERR(26)&&!app_sends&&!r.status);
 reset();tls_destroy_fail=1;CK(private_tls_resource(4,&r)==ERR(7)&&private_tls_active()&&!r.status);tls_destroy_fail=0;CK(!private_tls_cleanup());
 uint8_t gz[]={31,139,8,0,0,0,0,0,2,255,171,174,5,0,67,191,166,163,2,0,0,0};
 for(unsigned corrupt=0;corrupt<2;corrupt++){
  reset();wire_size=wire_pos=0;server_hello();make_certificate();wire_record(22,(const char *)cert_handshake,sizeof(cert_handshake));
  const char header[]="HTTP/1.1 200 OK\r\nContent-Length: 22\r\nContent-Encoding: gzip\r\n\r\n";
  char response[256];memcpy(response,header,sizeof(header)-1);if(corrupt)gz[sizeof(gz)-8]^=1;memcpy(response+sizeof(header)-1,gz,sizeof(gz));
  wire_record(23,response,sizeof(header)-1+sizeof(gz));wire_record(21,"\1\0",2);
  ES e=private_tls_resource(2,&r);
  if(corrupt)CK(FAILED(e)&&!r.status);else CK(!e&&r.status==200&&r.length==2&&eq(r.body,"{}",2));
 }
 return failure;
}
int get_checks(void){return checks;}
