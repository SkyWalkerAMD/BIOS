/* R6 first-stage host-interface transport probe. GET service root only.
 * Never GET Bios/SD: that operation consumes the queue on this BMC.
 * No persistent IP configuration, password, NVRAM or BIOS writes.
 */
#include "network.h"
static GUID snp_guid={0xa19832b9,0xac25,0x11d3,{0x9a,0x2d,0,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID http_sb_guid={0xbdc8e6af,0xd9bc,0x4379,{0xa7,0x2a,0xe0,0xc4,0xe7,0x5d,0xae,0x1c}};
static GUID http_guid={0x7a59b29b,0x910b,0x4171,{0x82,0x42,0xa8,0x5a,0x0d,0xf2,0x5b,0x5b}};
static GUID ip4_guid={0x5b446ed1,0xe30b,0x4faa,{0x87,0x1a,0x36,0x54,0xec,0xa3,0x60,0x80}};
static GUID usb_guid={0x2b2f68d6,0x0cd2,0x44cf,{0x8e,0x8b,0xbb,0xa2,0x0b,0x1b,0x5b,0x75}};
typedef struct USB USB;
struct USB {void *control,*bulk,*async_interrupt,*interrupt,*iso,*async_iso;ES (EA *device)(USB *,void *);void *config;ES (EA *interface)(USB *,void *);};
OFF(USB,device,48);OFF(USB,interface,64);
static HANDLE candidate,child;static SB *binding;static HTTP *http;
static volatile uint32_t done;static HTTP_TOKEN token;static HTTP_MESSAGE message;
static HTTP_REQUEST request;static HTTP_RESPONSE response;
static HTTP_HEADER headers[]={{"Host","169.254.0.17"},{"Accept","application/json"},{"Connection","close"}};
static char body[8192];static int active;
static void EA notify(HANDLE event,void *context){(void)event;(void)context;done=1;}
static int target(void){detect_board();return same(report.board,"ROG MAXIMUS Z790 HERO")&&same(report.bios,"3107");}
/* Firmware device paths are protocol-owned. Bound traversal and never follow
 * unknown node layouts; a USB node is required before using this transport. */
static int path_info(HANDLE h){
 uint8_t *p=0;ES e=gST->bs->handle_protocol(h,&dp_guid,(void **)&p);status("DEVICE_PATH",e);if(FAILED(e)||!p)return 0;
 int usb=0;UN total=0;
 for(unsigned nodes=0;nodes<64&&total<2048;nodes++){
  unsigned n=u16(p+2);if(n<4||n>256||n>2048-total){logtext("BAD_DEVICE_PATH\r\n");return 0;}
  logtext("DP=");logbytes(p,n);
  if(p[0]==0x7f)return p[1]==0xff&&n==4?usb:0;
  if(p[0]==3&&(p[1]==5||p[1]==15||p[1]==16))usb=1;
  total+=n;p+=n;
 }return 0;
}
static void inventory_protocol(const char *name,GUID *guid){
 HANDLE *hs=0;UN count=0;ES e=gST->bs->locate_handles(2,guid,0,&count,&hs);status(name,FAILED(e)?e:count);
 if(!FAILED(e)&&count<=32)for(UN i=0;i<count;i++){logtext("HANDLE=");loghex((UN)hs[i],16);logtext("\r\n");path_info(hs[i]);}
 if(hs)gST->bs->free_pool(hs);
}
void usb_inventory(void){
 HANDLE *hs=0;UN count=0;ES e=gST->bs->locate_handles(2,&usb_guid,0,&count,&hs);status("USB_IO_COUNT",FAILED(e)?e:count);
 if(!FAILED(e)&&count<=128)for(UN i=0;i<count;i++){
  USB *u=0;uint8_t dev[18]={0},intf[9]={0};e=gST->bs->handle_protocol(hs[i],&usb_guid,(void **)&u);if(FAILED(e)||!u)continue;
  status("USB_INDEX",i);e=u->device(u,dev);status("USB_DEVICE_DESCRIPTOR",e);if(!FAILED(e)){logtext("USB_DEVICE=");logbytes(dev,sizeof(dev));}
  e=u->interface(u,intf);status("USB_INTERFACE_DESCRIPTOR",e);if(!FAILED(e)){logtext("USB_INTERFACE=");logbytes(intf,sizeof(intf));}
  path_info(hs[i]);
 }
 if(hs)gST->bs->free_pool(hs);
}
int usb_target_handles(HANDLE out[2]){
 out[0]=out[1]=0;if(!target())return 0;
 HANDLE *hs=0;UN count=0;unsigned controls=0,data=0;ES e=gST->bs->locate_handles(2,&usb_guid,0,&count,&hs);
 if(!FAILED(e)&&count<=128)for(UN i=0;i<count;i++){
  USB *u=0;uint8_t dev[18]={0},in[9]={0};
  if(FAILED(gST->bs->handle_protocol(hs[i],&usb_guid,(void **)&u))||!u)continue;
  if(FAILED(u->device(u,dev))||FAILED(u->interface(u,in)))continue;
  if(dev[0]!=18||dev[1]!=1||u16(dev+8)!=0x046b||u16(dev+10)!=0xffb0||in[0]!=9||in[1]!=4)continue;
  if(in[2]==0&&in[5]==2&&in[6]==2&&in[7]==255){out[0]=hs[i];controls++;}
  if(in[2]==1&&in[5]==10&&in[6]==0&&in[7]==0){out[1]=hs[i];data++;}
 }
 if(hs)gST->bs->free_pool(hs);
 if(controls!=1||data!=1){out[0]=out[1]=0;return 0;}return 1;
}
/* IPv4/IPv6 child handles expose the same SNP interface as their parent.
 * Select the physical MAC handle on the verified BMC control-interface path;
 * do not count those children as extra NICs or select another USB adapter. */
static UN path_length(const uint8_t *p){
 UN total=0;if(!p)return 0;
 for(unsigned i=0;i<64&&total<2048;i++){
  unsigned n=u16(p+total+2);if(n<4||n>256||n>2048-total)return 0;
  if(p[total]==0x7f)return p[total+1]==0xff&&n==4?total+4:0;
  total+=n;
 }return 0;
}
static int bmc_physical_snp(HANDLE h,HANDLE control){
 uint8_t *p=0,*u=0;
 if(!control||FAILED(gST->bs->handle_protocol(h,&dp_guid,(void **)&p))||FAILED(gST->bs->handle_protocol(control,&dp_guid,(void **)&u)))return 0;
 UN un=path_length(u),pn=path_length(p);if(un<4||pn!=un+37)return 0;
 UN prefix=un-4;
 return eq(p,u,prefix)&&p[prefix]==3&&p[prefix+1]==11&&u16(p+prefix+2)==37;
}
void network_inventory(void){
 candidate=0;unsigned matches=0;HANDLE *hs=0;UN count=0;HANDLE usb_handles[2];
 int verified=usb_target_handles(usb_handles);status("BMC_USB_TARGET_VERIFIED",verified);
 ES e=gST->bs->locate_handles(2,&snp_guid,0,&count,&hs);status("SNP_COUNT",FAILED(e)?e:count);
 if(!FAILED(e)&&count<=32)for(UN i=0;i<count;i++){
  SNP *s=0;status("SNP_INDEX",i);e=gST->bs->handle_protocol(hs[i],&snp_guid,(void **)&s);status("SNP_OPEN",e);
  int usb=path_info(hs[i]);status("SNP_USB_PATH",usb);
  if(FAILED(e)||!s||!s->mode)continue;SNP_MODE *m=s->mode;
  status("SNP_STATE",m->state);status("SNP_MEDIA",m->present);status("SNP_HW_SIZE",m->hw_size);status("SNP_IFTYPE",m->iftype);
  if(m->hw_size==6){logtext("SNP_MAC=");logbytes(m->current,6);}
  void *b=0;status("SNP_HTTP_BINDING",gST->bs->handle_protocol(hs[i],&http_sb_guid,&b));
  int base=usb&&verified&&bmc_physical_snp(hs[i],usb_handles[0]);status("SNP_BMC_PHYSICAL_PATH",base);
  if(base&&m->hw_size==6&&(m->iftype==0||m->iftype==1)){candidate=hs[i];matches++;}
 }
 if(hs)gST->bs->free_pool(hs);if(matches!=1)candidate=0;
 status("UNIQUE_USB_NETWORK",candidate?1:0);
 inventory_protocol("HTTP_BINDING_COUNT",&http_sb_guid);inventory_protocol("IP4_CONFIG_COUNT",&ip4_guid);
 say("Inventory complete. C=QR / V=text to capture details.\r\n");
}
ES network_connect(void){
 if(!target()||!candidate||active)return ERR(15);
 ES (EA *connect)(HANDLE,HANDLE *,void *,uint8_t)=(void *)gST->bs->connect;
 if(!connect)return ERR(3);logtext("CONNECT_ONLY_UNIQUE_USB_SNP\r\n");
 return connect(candidate,0,0,1);
}
HANDLE network_candidate(void){return target()&&!active?candidate:0;}
static ES wait_token(void){
 for(unsigned n=0;n<1000&&!done;n++){ES e=http->poll(http);if(FAILED(e)&&e!=ERR(6)){status("HTTP_POLL",e);break;}gST->bs->stall(10000);}
 if(done)return token.status;
 ES e=http->cancel(http,&token);status("HTTP_CANCEL",e);
 for(unsigned n=0;n<100&&!done;n++){http->poll(http);gST->bs->stall(10000);}
 return ERR(18);
}
ES network_cleanup(void){
 ES tc=tcp_cleanup();if(FAILED(tc))return tc;
 if(child&&binding){if(http)http->cancel(http,0);ES e=binding->destroy(binding,child);status("HTTP_DESTROY",e);if(FAILED(e))return e;child=0;http=0;active=0;}
 if(token.event){ES e=gST->bs->close_event(token.event);if(FAILED(e))return e;token.event=0;}
 /* EFI_HTTP headers are one driver-allocated block. */
 if(message.headers&&message.headers!=headers){gST->bs->free_pool(message.headers);message.headers=0;}
 binding=0;return 0;
}
ES network_get(void){
 if(!target()||!candidate||active||tcp_is_active())return ERR(15);ES e;
 binding=0;e=gST->bs->handle_protocol(candidate,&http_sb_guid,(void **)&binding);status("HTTP_BINDING",e);if(FAILED(e)||!binding)return FAILED(e)?e:ERR(14);
 e=binding->create(binding,&child);status("HTTP_CREATE",e);if(FAILED(e))return e;active=1;
 e=gST->bs->handle_protocol(child,&http_guid,(void **)&http);status("HTTP_OPEN",e);if(FAILED(e)||!http)goto end;
 HTTP4 ip={0,{169,254,0,18},{255,255,0,0},0};HTTP_CONFIG config={1,10000,0,&ip};
 e=http->configure(http,&config);status("HTTP_CONFIGURE",e);if(FAILED(e))goto end;
 memset(&token,0,sizeof(token));e=gST->bs->create_event(0x200,8,notify,0,&token.event);if(FAILED(e))goto end;
 request.method=0;request.url=W("https://169.254.0.17/redfish/v1/");
 message=(HTTP_MESSAGE){&request,3,headers,0,0};token.message=&message;token.status=ERR(6);done=0;
 say("GET internal BMC service root; up to 10 seconds per stage.\r\n");logtext("GET https://169.254.0.17/redfish/v1/\r\n");
 e=http->request(http,&token);status("HTTP_REQUEST_QUEUE",e);if(FAILED(e))goto end;
 e=wait_token();status("HTTP_REQUEST_DONE",e);if(FAILED(e))goto end;
 memset(body,0,sizeof(body));response.status=0;message=(HTTP_MESSAGE){&response,0,0,sizeof(body)-1,body};token.status=ERR(6);done=0;
 e=http->response(http,&token);status("HTTP_RESPONSE_QUEUE",e);if(FAILED(e))goto end;
 e=wait_token();status("HTTP_RESPONSE_DONE",e);status("HTTP_STATUS_ENUM",response.status);status("HTTP_BODY_BYTES",message.length);
 if((!FAILED(e)||e==ERR(35))&&done&&message.length<sizeof(body)){body[message.length]=0;logtext("HTTP_BODY_BEGIN\r\n");logtext(body);logtext("\r\nHTTP_BODY_END\r\n");say(body);say("\r\n");}
end:{ES cleanup=network_cleanup();return FAILED(cleanup)?cleanup:e;}
}
