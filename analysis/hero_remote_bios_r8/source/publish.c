/* Publish only observed current values and an entirely read-only registry.
 * Never read /Bios/SD, POST current settings, or write a UEFI variable. */
#include "publish.h"
#include "catalog.h"
#include "json_small.h"
static GUID setup_guid={0xec87d643,0xeba4,0x4bb5,{0xa1,0xe5,0x3f,0x3e,0x36,0xb2,0x0d,0xa9}};
static uint8_t setup[3398],check_setup[3398];static JSON json;
static const char *names[]={"BootupNumLockState","WaitForF1IfError","POSTDelayTime"};
static const char *values[3];static char current[512];static int attempted;
static ES read_setup(uint8_t *data){UN n=3398;uint32_t a=0;ES e=gST->rt->get_variable(W("Setup"),&setup_guid,&a,&n,data);return FAILED(e)?e:n==3398&&a==7?0:ERR(33);}
static ES read_observed(void){
 if(!same(report.board,"ROG MAXIMUS Z790 HERO")||!same(report.bios,"3107"))return ERR(15);
 ES e=read_setup(setup);if(FAILED(e))return e;e=read_setup(check_setup);if(FAILED(e)||!eq(setup,check_setup,sizeof(setup)))return FAILED(e)?e:ERR(15);
 if(setup[0]>1||setup[3293]>1||setup[3291]>10)return ERR(33);
 static const char *delay[]={"0 sec","1 sec","2 sec","3 sec","4 sec","5 sec","6 sec","7 sec","8 sec","9 sec","10 sec"};
 values[0]=setup[0]?"On":"Off";values[1]=setup[3293]?"Enabled":"Disabled";values[2]=delay[setup[3291]];
 status("SNAPSHOT_NUMLOCK",setup[0]);status("SNAPSHOT_F1",setup[3293]);status("SNAPSHOT_POST_DELAY",setup[3291]);
 return 0;
}
static int add_current(UN *n,const char *s){UN z=0;while(s[z])z++;if(z>=sizeof(current)-*n)return 0;memcpy(current+*n,s,z);*n+=z;current[*n]=0;return 1;}
static ES make_current(UN *n){
 *n=0;if(!add_current(n,"{\"AttributeRegistry\":\"" HERO_REGISTRY "\",\"Attributes\":{"))return ERR(4);
 for(unsigned i=0;i<3;i++)if(!add_current(n,i?",\"":"\"")||!add_current(n,names[i])||!add_current(n,"\":\"")||!add_current(n,values[i])||!add_current(n,"\""))return ERR(4);
 return add_current(n,"}}")?0:ERR(4);
}
static int registry_collection_safe(const TLS_REPLY *r){
 if(r->status!=200||!jparse(&json,r->body,r->length))return 0;
 unsigned a=jfind(&json,0,"Members");if(a>=json.count||json.t[a].type!='[')return 0;
 for(unsigned t=a+1;t<json.t[a].after;t=json.t[t].after){
  unsigned id=jfind(&json,t,"@odata.id");if(id>=json.count||json.t[id].type!='s')return 0;
  char name[160];UN p=json.t[id].start,n=0;while(p<json.t[id].end){int c=jchar(json.s,json.t[id].end,&p);if(c<32||n>=159)return 0;name[n++]=(char)c;}name[n]=0;
  const char prefix[]="/redfish/v1/Registries/";if(n<sizeof(prefix)-1||!eq(name,prefix,sizeof(prefix)-1))return 0;
  const char *idname=name+sizeof(prefix)-1;
  if(n>=sizeof(prefix)-1+21&&eq(idname,"BiosAttributeRegistry",21)&&!same(idname,HERO_REGISTRY))return 0;
 }
 return 1;
}
static int registry_readback(const TLS_REPLY *r){
 if(r->status!=200||!jparse(&json,r->body,r->length)||!jeq(&json,jfind(&json,0,"Id"),HERO_REGISTRY))return 0;
 unsigned entries=jfind(&json,0,"RegistryEntries"),a=jfind(&json,entries,"Attributes");
 if(a>=json.count||json.t[a].type!='[')return 0;unsigned count=0,mask=0;
 for(unsigned t=a+1;t<json.t[a].after;t=json.t[t].after){
  unsigned name=jfind(&json,t,"AttributeName"),ro=jfind(&json,t,"ReadOnly");
  if(ro>=json.count||json.t[ro].type!='t')return 0;unsigned bit=0;
  for(unsigned i=0;i<3;i++)if(jeq(&json,name,names[i]))bit=1u<<i;
  if(!bit||(mask&bit))return 0;mask|=bit;count++;
 }return count==3&&mask==7;
}
static int current_readback(const TLS_REPLY *r){
 if(r->status!=200||!jparse(&json,r->body,r->length)||!jeq(&json,jfind(&json,0,"AttributeRegistry"),HERO_REGISTRY))return 0;
 unsigned attrs=jfind(&json,0,"Attributes");if(attrs>=json.count||json.t[attrs].type!='{')return 0;unsigned count=0;
 for(unsigned t=attrs+1;t<json.t[attrs].after;t=json.t[t+1].after)count++;
 if(count!=3)return 0;for(unsigned i=0;i<3;i++)if(!jeq(&json,jfind(&json,attrs,names[i]),values[i]))return 0;return 1;
}
static ES exchange(unsigned id,const char *data,UN n,TLS_REPLY *r){ES e=private_tls_resource(id,data,n,r);status("PUBLISH_TRANSPORT",e);if(!FAILED(e))status("PUBLISH_HTTP_STATUS",r->status);return e;}
ES publish_snapshot(void){
 TLS_REPLY r;UN size;ES e;if(attempted)return ERR(15);
 e=read_observed();if(FAILED(e))return e;e=make_current(&size);if(FAILED(e))return e;
 e=exchange(2,0,0,&r);if(FAILED(e))return e;
 /* This release creates missing state only; never overwrites existing BIOS. */
 if(r.status!=404)return ERR(15);
 e=exchange(3,0,0,&r);if(FAILED(e))return e;if(!registry_collection_safe(&r))return ERR(15);
 e=read_setup(check_setup);if(FAILED(e)||!eq(setup,check_setup,sizeof(setup)))return FAILED(e)?e:ERR(15);
 attempted=1;logtext("PUBLISH_FIRST_MUTATION_READ_ONLY_CATALOG\r\n");
 e=exchange(4,hero_registry_json,sizeof(hero_registry_json)-1,&r);if(FAILED(e))return e;if(r.status!=201)return ERR(7);
 int ready=0;for(unsigned i=0;i<5;i++){
  e=exchange(8,0,0,&r);if(FAILED(e))return e;if(registry_readback(&r)){ready=1;break;}if(r.status!=404)return ERR(33);gST->bs->stall(1000000);
 }if(!ready)return ERR(18);logtext("PUBLISH_REGISTRY_READONLY_VERIFIED\r\n");
 e=exchange(6,hero_layout_upload,sizeof(hero_layout_upload)-1,&r);if(FAILED(e))return e;if(r.status!=201)return ERR(7);
 ready=0;for(unsigned i=0;i<5;i++){
  e=exchange(9,0,0,&r);if(FAILED(e))return e;
  if(r.status==200&&r.length==sizeof(hero_layout_xml)-1&&eq(r.body,hero_layout_xml,r.length)){ready=1;break;}gST->bs->stall(1000000);
 }if(!ready)return ERR(18);logtext("PUBLISH_LAYOUT_EXACT_READBACK\r\n");
 e=read_setup(check_setup);if(FAILED(e)||!eq(setup,check_setup,sizeof(setup)))return FAILED(e)?e:ERR(15);
 e=exchange(5,current,size,&r);if(FAILED(e))return e;if(r.status!=204)return ERR(7);
 e=exchange(2,0,0,&r);if(FAILED(e))return e;if(!current_readback(&r))return ERR(33);
 logtext("PUBLISH_CURRENT_VALUES_VERIFIED\r\nREAD_ONLY_SNAPSHOT_PUBLISHED\r\n");return 0;
}
/* R8b -> R8c menu-only update. Require our own exact legacy layout, read-only
 * registry, and current settings equal to this machine before any mutation.
 * Never refresh current BIOS values or registry through this path. */
ES publish_refresh_layout(void){
 TLS_REPLY r;UN size;ES e;if(attempted)return ERR(15);
 e=read_observed();if(FAILED(e))return e;e=make_current(&size);if(FAILED(e))return e;
 e=exchange(2,0,0,&r);if(FAILED(e))return e;if(!current_readback(&r))return ERR(15);
 e=exchange(3,0,0,&r);if(FAILED(e))return e;if(!registry_collection_safe(&r))return ERR(15);
 e=exchange(8,0,0,&r);if(FAILED(e))return e;if(!registry_readback(&r))return ERR(15);
 e=exchange(9,0,0,&r);if(FAILED(e))return e;
 if(r.status==200&&r.length==sizeof(hero_layout_xml)-1&&eq(r.body,hero_layout_xml,r.length)){
  logtext("READ_ONLY_LAYOUT_ALREADY_CURRENT\r\n");return 0;
 }
 if(r.status!=200||r.length!=sizeof(hero_legacy_layout_xml)-1||!eq(r.body,hero_legacy_layout_xml,r.length))return ERR(15);
 e=read_setup(check_setup);if(FAILED(e)||!eq(setup,check_setup,sizeof(setup)))return FAILED(e)?e:ERR(15);
 attempted=1;logtext("UPDATE_OWN_READ_ONLY_LAYOUT_ONLY\r\n");
 e=exchange(6,hero_layout_upload,sizeof(hero_layout_upload)-1,&r);if(FAILED(e))return e;if(r.status!=201)return ERR(7);
 int ready=0;for(unsigned i=0;i<5;i++){
  e=exchange(9,0,0,&r);if(FAILED(e))return e;
  if(r.status==200&&r.length==sizeof(hero_layout_xml)-1&&eq(r.body,hero_layout_xml,r.length)){ready=1;break;}gST->bs->stall(1000000);
 }if(!ready)return ERR(18);
 e=exchange(2,0,0,&r);if(FAILED(e))return e;if(!current_readback(&r))return ERR(33);
 logtext("READ_ONLY_LAYOUT_UPDATED_CURRENT_VALUES_UNCHANGED\r\n");return 0;
}
