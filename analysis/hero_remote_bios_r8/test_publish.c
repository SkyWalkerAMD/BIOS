#include "source/publish.c"
ST *gST;REPORT report;static ST st;static BS bs;static RT rt;
static int failure,checks,calls,reads,fail_call,fail_read,mutate_read,foreign_registry,existing_bios,bad_registry,bad_layout,uncertain_patch;
static unsigned sequence[20];
static int legacy_layout,keep_legacy_layout,bad_current,upload_status;
#define CK(x) do{checks++;if(!(x)&&!failure)failure=__LINE__;}while(0)
void *memcpy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *x=d;while(n--)*x++=(uint8_t)c;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int same(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
void logtext(const char *s){(void)s;}void status(const char *s,ES e){(void)s;(void)e;}
static UN length(const char *s){UN n=0;while(s[n])n++;return n;}
static ES EA getvar(C16 *name,GUID *guid,uint32_t *attrs,UN *n,void *data){
 CK(eq(name,W("Setup"),12)&&eq(guid,&setup_guid,16)&&*n==3398);reads++;
 if(reads==fail_read)return ERR(7);*attrs=7;*n=3398;memset(data,0,*n);uint8_t *b=data;b[0]=reads==mutate_read?0:1;b[3291]=5;return 0;
}
static ES EA stall(UN n){CK(n==1000000);return 0;}
static void reply(TLS_REPLY *r,unsigned status,const char *body){*r=(TLS_REPLY){status,body,length(body)};}
ES private_tls_resource(unsigned id,const char *body,UN n,TLS_REPLY *r){
 CK(calls<20);sequence[calls++]=id;if(calls==fail_call)return ERR(18);
 CK(id!=7&&id<=9); /* No pending-queue resource exists. */
 if(id==2){if(existing_bios||calls>2)reply(r,200,bad_current?"{}":current);else reply(r,404,"{}");}
 else if(id==3)reply(r,200,foreign_registry?"{\"Members\":[{\"@odata.id\":\"/redfish/v1/Registries/BiosAttributeRegistryOTHER.1.2.3\"}]}":"{\"Members\":[{\"@odata.id\":\"/redfish/v1/Registries/Base.1.5.0\"}]}");
 else if(id==4){CK(n==sizeof(hero_registry_json)-1&&eq(body,hero_registry_json,n));reply(r,201,"");}
 else if(id==8)reply(r,200,bad_registry?"{}":hero_registry_json);
 else if(id==6){CK(n==sizeof(hero_layout_upload)-1&&eq(body,hero_layout_upload,n));reply(r,upload_status?upload_status:201,"");if(!keep_legacy_layout)legacy_layout=0;}
 else if(id==9)reply(r,200,bad_layout?"<html>not published</html>":legacy_layout?hero_legacy_layout_xml:hero_layout_xml);
 else if(id==5){CK(n==length(current)&&eq(body,current,n));reply(r,uncertain_patch?500:204,"");}
 else CK(0);
 return 0;
}
static void reset(void){
 memset(&st,0,sizeof(st));memset(&bs,0,sizeof(bs));memset(&rt,0,sizeof(rt));gST=&st;st.bs=&bs;st.rt=&rt;rt.get_variable=getvar;bs.stall=stall;
 memset(&report,0,sizeof(report));memcpy(report.board,"ROG MAXIMUS Z790 HERO",21);memcpy(report.bios,"3107",5);
 calls=reads=fail_call=fail_read=mutate_read=foreign_registry=existing_bios=bad_registry=bad_layout=uncertain_patch=attempted=0;memset(sequence,0,sizeof(sequence));
 legacy_layout=keep_legacy_layout=bad_current=upload_status=0;
}
static void refresh_reset(void){reset();existing_bios=legacy_layout=1;}
static void refresh_checks(void){
 refresh_reset();CK(!publish_refresh_layout()&&calls==7&&reads==3&&attempted);
 unsigned want[]={2,3,8,9,6,9,2};CK(eq(sequence,want,sizeof(want)));CK(publish_refresh_layout()==ERR(15)&&calls==7);
 for(int i=1;i<=7;i++){refresh_reset();fail_call=i;CK(publish_refresh_layout()==ERR(18)&&calls==i);}
 for(int i=1;i<=3;i++){refresh_reset();fail_read=i;CK(publish_refresh_layout()==ERR(7)&&calls==(i<=2?0:4)&&!attempted);}
 refresh_reset();mutate_read=2;CK(publish_refresh_layout()==ERR(15)&&!calls&&!attempted);
 refresh_reset();mutate_read=3;CK(publish_refresh_layout()==ERR(15)&&calls==4&&!attempted);
 refresh_reset();existing_bios=0;CK(publish_refresh_layout()==ERR(15)&&calls==1&&!attempted);
 refresh_reset();bad_current=1;CK(publish_refresh_layout()==ERR(15)&&calls==1&&!attempted);
 refresh_reset();foreign_registry=1;CK(publish_refresh_layout()==ERR(15)&&calls==2&&!attempted);
 refresh_reset();bad_registry=1;CK(publish_refresh_layout()==ERR(15)&&calls==3&&!attempted);
 refresh_reset();bad_layout=1;CK(publish_refresh_layout()==ERR(15)&&calls==4&&!attempted);
 refresh_reset();legacy_layout=0;CK(!publish_refresh_layout()&&calls==4&&!attempted);
 refresh_reset();upload_status=500;CK(publish_refresh_layout()==ERR(7)&&calls==5&&attempted);
 refresh_reset();keep_legacy_layout=1;CK(publish_refresh_layout()==ERR(18)&&calls==10&&attempted);
 for(int i=0;i<calls;i++)CK(sequence[i]!=4&&sequence[i]!=5); /* No registry/current writes. */
 refresh_reset();report.bios[3]='6';CK(publish_refresh_layout()==ERR(15)&&!calls&&!reads);
 refresh_reset();report.board[0]='X';CK(publish_refresh_layout()==ERR(15)&&!calls&&!reads);
}
static int parse(const char *s){return jparse(&json,s,length(s));}
static void json_checks(void){
 const char *bad[]={"", " ","{}{}","{\"a\":1,\"a\":2}","{\"a\":1,\"\\u0061\":2}","{\"x\":}","[1,]","{\"a\":1,}","{\"a\" 1}","\"unterminated","\"bad\\x\"","[01]","[-]","[1.]","[1e]","[+1]","[NaN]","truex","[tru]","[fals]","[nul]","[\"\1\"]","[\"\\u8000\"]"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++)CK(!parse(bad[i]));
 CK(parse("{\"a\": [1,-1.25e+1,true,false,null,{},[],\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0061\"]}"));
 CK(parse("{\"\\u0049d\":\"abc\"}")&&jeq(&json,jfind(&json,0,"Id"),"abc"));
 for(UN n=0;n<sizeof(hero_registry_json)-1;n++)CK(!jparse(&json,hero_registry_json,n));
 CK(jparse(&json,hero_registry_json,sizeof(hero_registry_json)-1));
 char deep[64];for(unsigned i=0;i<30;i++)deep[i]='[';for(unsigned i=30;i<60;i++)deep[i]=']';deep[60]=0;CK(!parse(deep));
 TLS_REPLY r;reply(&r,200,"{\"Members\":[{\"@odata.id\":\"/redfish/v1/Registries/\\u0042iosAttributeRegistryOTHER.1.2.3\"}]}");CK(!registry_collection_safe(&r));
 reply(&r,200,"{\"Members\":[{\"@odata.id\":\"/redfish/v1/Registries/" HERO_REGISTRY "\"}]}");CK(registry_collection_safe(&r));
 reply(&r,200,"{\"Members\":[{\"@odata.id\":\"https://example.invalid/\"}]}");CK(!registry_collection_safe(&r));
 reply(&r,200,hero_registry_json);CK(registry_readback(&r));
 reply(&r,200,current);CK(current_readback(&r));
}
int run_tests(void){
 reset();CK(!publish_snapshot()&&calls==8&&reads==4&&attempted);unsigned want[]={2,3,4,8,6,9,5,2};CK(eq(sequence,want,sizeof(want)));CK(publish_snapshot()==ERR(15)&&calls==8);
 for(int i=1;i<=8;i++){reset();fail_call=i;CK(publish_snapshot()==ERR(18)&&calls==i);}
 for(int i=1;i<=4;i++){reset();fail_read=i;CK(publish_snapshot()==ERR(7));CK(calls==(i<=2?0:i==3?2:6));}
 reset();mutate_read=2;CK(publish_snapshot()==ERR(15)&&!calls&&!attempted);
 reset();mutate_read=3;CK(publish_snapshot()==ERR(15)&&calls==2&&!attempted);
 reset();mutate_read=4;CK(publish_snapshot()==ERR(15)&&calls==6&&attempted);
 reset();report.bios[3]='6';CK(publish_snapshot()==ERR(15)&&!calls&&!reads);
 reset();report.board[0]='X';CK(publish_snapshot()==ERR(15)&&!calls&&!reads);
 reset();foreign_registry=1;CK(publish_snapshot()==ERR(15)&&calls==2&&!attempted);
 reset();existing_bios=1;CK(publish_snapshot()==ERR(15)&&calls==1&&!attempted);
 reset();bad_registry=1;CK(publish_snapshot()==ERR(33)&&calls==4&&attempted);
 reset();bad_layout=1;CK(publish_snapshot()==ERR(18)&&calls==10&&attempted);for(int i=0;i<calls;i++)CK(sequence[i]!=5);
 reset();uncertain_patch=1;CK(publish_snapshot()==ERR(7)&&calls==7&&attempted);
 reset();CK(!read_observed());UN n;CK(!make_current(&n));json_checks();
 refresh_checks();
 return failure;
}
int get_checks(void){return checks;}
