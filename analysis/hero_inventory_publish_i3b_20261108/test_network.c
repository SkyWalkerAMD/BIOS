/* Host mocks include the exact transport source. No real network or UEFI I/O. */
#include "source/network.c"
ST *gST;REPORT report;char audit[2097152];UN audit_len;
ES tcp_cleanup(void){return 0;}int tcp_is_active(void){return 0;}
static ST st;static BS bs;static SNP snp;static SNP_MODE sm;static SB sb;static HTTP hp;
static HANDLE handles[3]={(HANDLE)1,(HANDLE)2,(HANDLE)5};
static HANDLE usb_handles_mock[2]={(HANDLE)8,(HANDLE)9};
static uint8_t usbpath[]={3,5,6,0,0,0,0x7f,0xff,4,0};
static uint8_t nicpath[47],ip4path[74],ip6path[107];
static uint8_t endpath[]={0x7f,0xff,4,0};
static int good_target,nics,usb_present,fail_destroy,timeout_stage,stage,checks,failure,requests,responses,connections;
static ES configure_status;
static int children,wrong_prefix;
static USB usb_mock[2];static int usb_count,usb_wrong_id,usb_wrong_class;
#define CK(x) do{checks++;if(!(x)&&!failure)failure=__LINE__;}while(0)
void *memcpy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *x=d;while(n--)*x++=(uint8_t)c;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int same(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
void strcopy(char *d,size_t n,const char *s){if(!n)return;while(--n&&*s)*d++=*s++;*d=0;}
void logtext(const char *s){(void)s;}void loghex(uint64_t n,unsigned d){(void)n;(void)d;}void logbytes(const uint8_t *s,size_t n){(void)s;(void)n;}
void say(const char *s){(void)s;}void status(const char *s,ES e){(void)s;(void)e;}
uint16_t u16(const uint8_t *s){return s[0]|(uint16_t)s[1]<<8;}
int i3_target_valid(void){return good_target;}
void detect_board(void){strcopy(report.board,sizeof(report.board),good_target?"ROG MAXIMUS Z790 HERO":"Other");strcopy(report.bios,sizeof(report.bios),"3107");}
static ES EA locate(uint32_t type,GUID *guid,void *key,UN *n,HANDLE **h){(void)type;(void)key;*h=0;*n=0;if(eq(guid,&usb_guid,16)){if(!usb_count)return ERR(14);*n=usb_count;*h=usb_handles_mock;return 0;}if(!eq(guid,&snp_guid,16)||!nics)return ERR(14);*n=nics;*h=handles;return 0;}
static ES EA handle(HANDLE h,GUID *guid,void **p){
 *p=0;
 if(eq(guid,&usb_guid,16))*p=&usb_mock[h==(HANDLE)8?0:1];
 else if(eq(guid,&snp_guid,16))*p=&snp;
 else if(eq(guid,&dp_guid,16)){
  if(h==(HANDLE)8||h==(HANDLE)9)*p=usbpath;
  else if(!usb_present)*p=endpath;
  else if(children&&h==(HANDLE)2)*p=ip4path;
  else if(children&&h==(HANDLE)5)*p=ip6path;
  else *p=nicpath;
 }else if(eq(guid,&http_sb_guid,16))*p=&sb;else if(eq(guid,&http_guid,16))*p=&hp;return *p?0:ERR(14);
}
static ES EA usb_device(USB *u,void *buffer){(void)u;uint8_t d[18]={18,1,0,2,2,0,0,64,0x6b,4,0xb0,0xff,0,1,1,2,3,2};if(usb_wrong_id)d[8]^=1;memcpy(buffer,d,18);return 0;}
static ES EA usb_interface(USB *u,void *buffer){uint8_t d[9]={9,4,0,0,1,2,2,255,6};if(u==&usb_mock[1]){d[2]=1;d[4]=2;d[5]=10;d[6]=d[7]=0;}if(usb_wrong_class)d[5]=3;memcpy(buffer,d,9);return 0;}
static ES EA freepool(void *p){(void)p;return 0;}
static ES EA create(SB *s,HANDLE *h){(void)s;*h=(HANDLE)3;return 0;}
static ES EA destroy(SB *s,HANDLE h){(void)s;(void)h;return fail_destroy?ERR(7):0;}
static ES EA configure(HTTP *h,HTTP_CONFIG *c){(void)h;CK(c->version==1&&c->timeout==10000&&!c->ipv6);CK(c->access->default_address==0&&c->access->address[0]==169&&c->access->address[3]==18);return configure_status;}
static ES EA event(uint32_t type,UN tpl,void (EA *f)(HANDLE,void *),void *ctx,HANDLE *h){CK(type==0x200&&tpl==8&&f==notify&&!ctx);*h=(HANDLE)4;return 0;}
static ES EA closeevent(HANDLE h){CK(h==(HANDLE)4);return 0;}
static ES EA stall(UN n){(void)n;return 0;}
static ES EA connect(HANDLE h,HANDLE *drivers,void *dp,uint8_t recurse){CK(h==(HANDLE)1&&!drivers&&!dp&&recurse);connections++;return 0;}
static ES EA req(HTTP *h,HTTP_TOKEN *t){(void)h;requests++;stage=1;HTTP_REQUEST *r=t->message->data;CK(r->method==0);const C16 *expect=W("https://169.254.0.17/redfish/v1/");UN i=0;while(expect[i]){CK(r->url[i]==expect[i]);i++;}CK(r->url[i]==0&&t->message->count==3&&t->message->length==0);return 0;}
static ES EA resp(HTTP *h,HTTP_TOKEN *t){(void)h;responses++;stage=2;CK(t->message->length==8191);strcopy(t->message->body,8191,"{\"RedfishVersion\":\"1.6.0\"}");t->message->length=26;((HTTP_RESPONSE *)t->message->data)->status=3;return 0;}
static ES EA poll(HTTP *h){(void)h;if(timeout_stage!=stage){token.status=0;notify(0,0);}return 0;}
static ES EA cancel(HTTP *h,HTTP_TOKEN *t){(void)h;if(t){t->status=ERR(21);notify(0,0);}return 0;}
static void reset(void){
 memset(&st,0,sizeof(st));memset(&bs,0,sizeof(bs));memset(&sm,0,sizeof(sm));memset(&token,0,sizeof(token));memset(&message,0,sizeof(message));
 candidate=child=0;binding=0;http=0;active=0;done=0;requests=responses=connections=0;fail_destroy=timeout_stage=stage=0;configure_status=0;good_target=nics=usb_present=1;
 usb_count=2;usb_wrong_id=usb_wrong_class=children=wrong_prefix=0;for(unsigned i=0;i<2;i++){usb_mock[i].device=usb_device;usb_mock[i].interface=usb_interface;}
 memset(nicpath,0,sizeof(nicpath));memcpy(nicpath,usbpath,6);nicpath[6]=3;nicpath[7]=11;nicpath[8]=37;memcpy(nicpath+43,endpath,4);
 memset(ip4path,0,sizeof(ip4path));memcpy(ip4path,nicpath,43);ip4path[43]=3;ip4path[44]=12;ip4path[45]=27;memcpy(ip4path+70,endpath,4);
 memset(ip6path,0,sizeof(ip6path));memcpy(ip6path,nicpath,43);ip6path[43]=3;ip6path[44]=13;ip6path[45]=60;memcpy(ip6path+103,endpath,4);
 st.bs=&bs;gST=&st;bs.handle_protocol=handle;bs.locate_handles=locate;bs.free_pool=freepool;bs.create_event=event;bs.close_event=closeevent;bs.stall=stall;bs.connect=(void *)connect;
 sm.hw_size=6;sm.iftype=1;snp.mode=&sm;sb.create=create;sb.destroy=destroy;hp.configure=configure;hp.request=req;hp.response=resp;hp.poll=poll;hp.cancel=cancel;
}
int run_tests(void){
 HANDLE usb_handles[2];reset();usb_count=0;CK(!usb_target_handles(usb_handles));usb_count=1;CK(!usb_target_handles(usb_handles));usb_count=2;CK(usb_target_handles(usb_handles)&&usb_handles[0]==(HANDLE)8&&usb_handles[1]==(HANDLE)9);usb_wrong_id=1;CK(!usb_target_handles(usb_handles));usb_wrong_id=0;usb_wrong_class=1;CK(!usb_target_handles(usb_handles));usb_wrong_class=0;good_target=0;CK(!usb_target_handles(usb_handles));
 reset();CK(network_get()==ERR(15)&&requests==0);network_inventory();CK(candidate==(HANDLE)1);CK(network_connect()==0&&connections==1);CK(network_get()==0&&requests==1&&responses==1&&!active&&!child&&!token.event);
 reset();good_target=0;network_inventory();CK(network_get()==ERR(15)&&network_connect()==ERR(15)&&requests==0&&connections==0);
 reset();nics=0;network_inventory();CK(!candidate&&network_get()==ERR(15));
 reset();nics=2;network_inventory();CK(!candidate&&network_get()==ERR(15));
 reset();nics=3;children=1;network_inventory();CK(candidate==(HANDLE)1);CK(network_get()==0&&requests==1);
 reset();nicpath[4]=1;network_inventory();CK(!candidate);
 reset();usb_count=0;network_inventory();CK(!candidate);
 reset();sm.iftype=0;network_inventory();CK(candidate==(HANDLE)1);
 reset();sm.iftype=6;network_inventory();CK(!candidate);
 reset();usb_present=0;network_inventory();CK(!candidate&&network_connect()==ERR(15));
 reset();sm.hw_size=32;network_inventory();CK(!candidate);
 reset();usbpath[2]=0;network_inventory();CK(!candidate);usbpath[2]=6;
 reset();network_inventory();configure_status=ERR(15);CK(network_get()==ERR(15)&&!requests&&!child&&!active);
 reset();network_inventory();timeout_stage=1;CK(network_get()==ERR(18)&&requests==1&&responses==0&&!active&&!token.event);
 reset();network_inventory();timeout_stage=2;CK(network_get()==ERR(18)&&requests==1&&responses==1&&!active&&!token.event);
 reset();network_inventory();fail_destroy=1;CK(network_get()==ERR(7)&&active&&child&&token.event);CK(network_get()==ERR(15));fail_destroy=0;CK(network_cleanup()==0&&!active&&!child&&!token.event);
 return failure;
}
int get_checks(void){return checks;}
