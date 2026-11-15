/* Independent, NOT integrated I3c candidate. Exact .71 data, one POST and one
 * acknowledged completion only. No legacy fallbacks, DELETE or CRC mutations.
 * Original direct serializers omit Thermal/Power; their live sensor identities
 * are retained as collateral-readback checks, not sent as invented inventory.
 */
#include "inventory_bulk71.h"
#include "bulk71_json.h"
#include "core71_catalog.h"
#include "bulk71_catalog.h"
#define JNONE 2048U
#define MAX_GUARDS 16U

static JSON actual,expected;
static unsigned phase,post_attempted,finish_attempted,guard_count;
static uint64_t epoch;
static char guards[MAX_GUARDS][160];
static unsigned guard_kind[MAX_GUARDS];
static uint64_t thermal_before,power_before;
static int has_thermal,has_power,baseline_saved;
static const char *root_path="/redfish/v1/";
static const char *systems_path="/redfish/v1/Systems";
static const char *system_path="/redfish/v1/Systems/Self";
static const char *chassis_path="/redfish/v1/Chassis/Self";
static const char *inventory_path="/redfish/v1/Oem/Ami/InventoryData";
static const char *status_path="/redfish/v1/Oem/Ami/InventoryData/Status";
static const char *core_paths[]={"/redfish/v1/Systems/Self",
 "/redfish/v1/Systems/Self/Processors/DevType1_CPU0",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM0",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM1",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM2",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM3"};
static const char *collection_paths[]={"/redfish/v1/Systems/Self/Processors","/redfish/v1/Systems/Self/Memory"};
/* Only these already-disclosed relation families may be followed. No Actions,
 * Bios/SD, management NICs, registries, credentials or endpoint enumeration. */
static const char *optional_paths[]={
 "/redfish/v1/Systems/Self/MemoryDomains","/redfish/v1/Systems/Self/Storage",
 "/redfish/v1/Systems/Self/SimpleStorage","/redfish/v1/Systems/Self/NetworkInterfaces",
 "/redfish/v1/Systems/Self/EthernetInterfaces","/redfish/v1/Chassis/Self/NetworkAdapters",
 "/redfish/v1/Systems/Self/PCIeDevices","/redfish/v1/Systems/Self/PCIeFunctions",
 "/redfish/v1/Chassis/Self/PCIeDevices","/redfish/v1/Chassis/Self/PCIeSlots",
 "/redfish/v1/Chassis/Self/Assembly","/redfish/v1/Chassis/Self/Thermal",
 "/redfish/v1/Chassis/Self/Power"};

int inventory_bulk71_path_allowed(const char *path){
 if(!path)return 0;
 if(same(path,root_path)||same(path,systems_path)||same(path,chassis_path)||same(path,inventory_path)||same(path,status_path))return 1;
 for(unsigned i=0;i<6;i++)if(same(path,core_paths[i]))return 1;
 for(unsigned i=0;i<2;i++)if(same(path,collection_paths[i]))return 1;
 for(unsigned i=0;i<sizeof(optional_paths)/sizeof(optional_paths[0]);i++)if(same(path,optional_paths[i]))return 1;
 return 0;
}
static int copy_text(JSON *j,unsigned t,char *out,UN cap){
 if(t>=j->count||j->t[t].type!='s'||!cap)return 0;UN p=j->t[t].start,n=0;
 while(p<j->t[t].end){int ch=jchar(j->s,j->t[t].end,&p);if(ch<32||ch>=127||n+1>=cap)return 0;out[n++]=(char)ch;}out[n]=0;return 1;
}
static int strings_match(JSON *a,unsigned x,JSON *b,unsigned y,int fold){
 if(x>=a->count||y>=b->count||a->t[x].type!='s'||b->t[y].type!='s')return 0;UN p=a->t[x].start,q=b->t[y].start;
 while(p<a->t[x].end&&q<b->t[y].end){int c=jchar(a->s,a->t[x].end,&p),d=jchar(b->s,b->t[y].end,&q);if(c<0||d<0)return 0;
  if(fold){if(c>='A'&&c<='Z')c+=32;if(d>='A'&&d<='Z')d+=32;}if(c!=d)return 0;}return p==a->t[x].end&&q==b->t[y].end;
}
static int match_value(JSON *a,unsigned x,JSON *b,unsigned y,unsigned depth){
 if(depth>12||x>=a->count||y>=b->count||a->t[x].type!=b->t[y].type)return 0;
 if(a->t[x].type=='{'){
  for(unsigned k=x+1;k<a->t[x].after;k=a->t[k+1].after){char key[96];if(!copy_text(a,k,key,sizeof(key)))return 0;
   unsigned v=jfind(b,y,key);if(same(key,"UUID")){if(!strings_match(a,k+1,b,v,1))return 0;}
   else if(!match_value(a,k+1,b,v,depth+1))return 0;}return 1;
 }
 if(a->t[x].type=='['){unsigned i=x+1,j=y+1;while(i<a->t[x].after&&j<b->t[y].after){
   if(!match_value(a,i,b,j,depth+1))return 0;i=a->t[i].after;j=b->t[j].after;}return i==a->t[x].after&&j==b->t[y].after;}
 if(a->t[x].type=='s')return strings_match(a,x,b,y,0);
 UN n=a->t[x].end-a->t[x].start;return n==b->t[y].end-b->t[y].start&&eq(a->s+a->t[x].start,b->s+b->t[y].start,n);
}
static int number_is(unsigned t,unsigned n){
 if(t>=actual.count||actual.t[t].type!='d')return 0;UN p=actual.t[t].start,e=actual.t[t].end;unsigned value=0;
 if(e-p>3||e==p)return 0;while(p<e){unsigned c=(uint8_t)actual.s[p++];if(c<'0'||c>'9')return 0;value=value*10+c-'0';}return value==n;
}
static int empty_array(unsigned t){return t<actual.count&&actual.t[t].type=='['&&actual.t[t].after==t+1;}
static int placeholder(unsigned t){return t==JNONE||actual.t[t].type=='n'||jeq(&actual,t,"")||jeq(&actual,t," ")||jeq(&actual,t,"NA")||jeq(&actual,t,"N/A");}
static int blank_or_expected(const char *key,const char *value){unsigned t=jfind(&actual,0,key);return placeholder(t)||jeq(&actual,t,value);}
static int parse(const TLS_REPLY *r,const char *path){
 if(r->status!=200||!jparse(&actual,r->body,r->length)||actual.t[0].type!='{'||jfind(&actual,0,"error")<actual.count)return 0;
 unsigned t=jfind(&actual,0,"@odata.id");return t==JNONE||jeq(&actual,t,path);
}
static ES read(const char *path,TLS_REPLY *r){
 if(!inventory_bulk71_path_allowed(path))return ERR(15);
 ES e=private_tls_bulk71_exchange(0,path,0,0,0,r);logtext("I3C_GET ");logtext(path);logtext("\r\n");status("I3C_GET_TRANSPORT",e);
 if(!FAILED(e))status("I3C_GET_HTTP",r->status);return e;
}
static ES read_object(const char *path,TLS_REPLY *r){ES e=read(path,r);return FAILED(e)?e:parse(r,path)?0:ERR(33);}
static int linked(unsigned object,const char *key,const char *path){return jeq(&actual,jfind(&actual,jfind(&actual,object,key),"@odata.id"),path);}
static int source_valid(void){return i3_inventory_source_valid()&&epoch==i3_inventory_source_epoch();}
static int item_matches(unsigned item){return jparse(&expected,inv71_items[item].body,inv71_items[item].bytes)&&match_value(&expected,0,&actual,0,0);}
static int empty_collection(void){return number_is(jfind(&actual,0,"Members@odata.count"),0)&&empty_array(jfind(&actual,0,"Members"))&&jfind(&actual,0,"Members@odata.nextLink")==JNONE;}
static int collection_matches(unsigned group){
 unsigned a=jfind(&actual,0,"Members"),n=group?4:1,mask=0;
 if(!number_is(jfind(&actual,0,"Members@odata.count"),n)||a>=actual.count||actual.t[a].type!='['||jfind(&actual,0,"Members@odata.nextLink")!=JNONE)return 0;
 for(unsigned t=a+1;t<actual.t[a].after;t=actual.t[t].after){unsigned bit=0,v=jfind(&actual,t,"@odata.id");
  for(unsigned i=group?2:1;i<(group?6:2);i++)if(jeq(&actual,v,core_paths[i]))bit=1u<<i;
  if(!bit||(mask&bit))return 0;mask|=bit;}return mask==(group?60U:2U);
}
static int add_guard(const char *path,unsigned kind){
 if(!inventory_bulk71_path_allowed(path))return 0;
 for(unsigned i=0;i<guard_count;i++)if(same(guards[i],path))return guard_kind[i]==kind;
 UN n=0;while(path[n])n++;if(n>=sizeof(guards[0])||guard_count==MAX_GUARDS)return 0;
 memcpy(guards[guard_count],path,n+1);guard_kind[guard_count++]=kind;return 1;
}
/* Optional absent relation is absent inventory, not a guessed URL to probe. If
 * the relation is advertised, its exact allowed link must be fetched. */
static int relation(unsigned object,const char *key,const char *path,unsigned kind,int required){
 unsigned t=jfind(&actual,object,key);if(t==JNONE)return !required;
 if(empty_array(t))return 1;
 if(actual.t[t].type!='{'||!linked(object,key,path))return 0;
 return add_guard(path,kind);
}
static int inline_empty_or_link(unsigned object,const char *key,const char *count_key,const char *path,unsigned kind){
 unsigned count=jfind(&actual,object,count_key);if(count!=JNONE&&!number_is(count,0))return 0;
 return relation(object,key,path,kind,0);
}
static int inspect_system(void){
 if(!blank_or_expected("Model","ROG MAXIMUS Z790 HERO")||!blank_or_expected("Manufacturer","ASUS")||!blank_or_expected("BiosVersion","3107"))return 0;
 unsigned t=jfind(&actual,0,"UUID");if(!placeholder(t)&&!jeq(&actual,t,"00000000-0000-0000-0000-000000000000")){
  char value[64];if(!copy_text(&actual,t,value,sizeof(value)))return 0;for(unsigned i=0;value[i];i++)if(value[i]>='A'&&value[i]<='Z')value[i]+=32;if(!same(value,inv71_uuid))return 0;}
 if(!blank_or_expected("Name","System")||!placeholder(jfind(&actual,0,"SerialNumber"))||!placeholder(jfind(&actual,0,"PartNumber"))||!placeholder(jfind(&actual,0,"SKU"))||
    !blank_or_expected("AssetTag","Free form asset tag"))return 0;
 if(!linked(0,"Processors",collection_paths[0])||!linked(0,"Memory",collection_paths[1]))return 0;
 const char *keys[]={"MemoryDomains","Storage","SimpleStorage","NetworkInterfaces","EthernetInterfaces"};
 for(unsigned i=0;i<5;i++)if(!relation(0,keys[i],optional_paths[i],0,0))return 0;
 return inline_empty_or_link(0,"PCIeDevices","PCIeDevices@odata.count",optional_paths[6],0)&&
        inline_empty_or_link(0,"PCIeFunctions","PCIeFunctions@odata.count",optional_paths[7],0);
}
static int inspect_chassis(void){
 if(!blank_or_expected("Id","Self")||!blank_or_expected("Name","Chassis"))return 0;
 const char *keys[]={"Manufacturer","Model","SerialNumber","PartNumber","SKU"};
 for(unsigned i=0;i<5;i++)if(!placeholder(jfind(&actual,0,keys[i])))return 0;
 if(!blank_or_expected("AssetTag","Free form asset tag"))return 0;
 if(!relation(0,"NetworkAdapters",optional_paths[5],0,0)||
    !inline_empty_or_link(0,"PCIeDevices","PCIeDevices@odata.count",optional_paths[8],0)||
    !relation(0,"PCIeSlots",optional_paths[9],1,0)||!relation(0,"Assembly",optional_paths[10],2,0))return 0;
 return relation(0,"Thermal",optional_paths[11],3,0)&&relation(0,"Power",optional_paths[12],4,0);
}
static uint64_t identity_hash(unsigned kind,int *ok){
 /* Local collateral detector only; never used or sent as an AMI group CRC. */
 static const char *thermal[]={"Fans","Temperatures"};
 static const char *power[]={"PowerControl","Voltages","PowerSupplies","Redundancy"};
 const char **keys=kind==3?thermal:power;unsigned count=kind==3?2:4;uint64_t h=1469598103934665603ULL;*ok=1;
 for(unsigned k=0;k<count;k++){
  unsigned a=jfind(&actual,0,keys[k]);if(a==JNONE)continue;if(actual.t[a].type!='['){*ok=0;return 0;}
  h=(h^k)*1099511628211ULL;
  for(unsigned t=a+1;t<actual.t[a].after;t=actual.t[t].after){
   if(actual.t[t].type!='{'){*ok=0;return 0;}unsigned id=jfind(&actual,t,"MemberId");
   if(id==JNONE)id=jfind(&actual,t,"@odata.id");if(id==JNONE)id=jfind(&actual,t,"Name");
   char value[160];if(!copy_text(&actual,id,value,sizeof(value))){*ok=0;return 0;}
   for(unsigned i=0;value[i];i++)h=(h^(uint8_t)value[i])*1099511628211ULL;
   h=(h^255)*1099511628211ULL;
  }
 }return h;
}
static ES check_guards(int save){
 TLS_REPLY r;for(unsigned i=0;i<guard_count;i++){
  ES e=read(guards[i],&r);if(FAILED(e))return e;
  if(r.status==404){if(guard_kind[i]>=3&&baseline_saved)return ERR(33);continue;}
  if(!parse(&r,guards[i]))return ERR(33);
  unsigned kind=guard_kind[i];
  if(kind==0){if(!empty_collection())return ERR(15);}
  else if(kind==1||kind==2){if(!empty_array(jfind(&actual,0,kind==1?"Slots":"Assemblies")))return ERR(15);}
  else{int ok=0;uint64_t h=identity_hash(kind,&ok);if(!ok)return ERR(33);
   if(save){if(kind==3){thermal_before=h;has_thermal=1;}else{power_before=h;has_power=1;}}
   else if((kind==3&&(!has_thermal||h!=thermal_before))||(kind==4&&(!has_power||h!=power_before)))return ERR(33);
  }
 }
 return 0;
}
static ES census(int save){
 TLS_REPLY r;ES e;unsigned previous_count=guard_count;
 if(!source_valid())return ERR(15);
 guard_count=0;if(save){has_thermal=has_power=baseline_saved=0;}
 e=read_object(root_path,&r);if(FAILED(e))return e;
 if(!jeq(&actual,jfind(&actual,0,"RedfishVersion"),"1.8.0")||!jeq(&actual,jfind(&actual,jfind(&actual,jfind(&actual,0,"Oem"),"Ami"),"RtpVersion"),"1.8.a")||!linked(0,"Systems",systems_path))return ERR(33);
 e=read_object(systems_path,&r);if(FAILED(e))return e;
 unsigned a=jfind(&actual,0,"Members");if(!number_is(jfind(&actual,0,"Members@odata.count"),1)||a>=actual.count||actual.t[a].type!='['||
    actual.t[a].after<=a+1||actual.t[a+1].after!=actual.t[a].after||!jeq(&actual,jfind(&actual,a+1,"@odata.id"),system_path)||jfind(&actual,0,"Members@odata.nextLink")!=JNONE)return ERR(33);
 e=read_object(inventory_path,&r);if(FAILED(e))return e;
 if(!linked(0,"System",system_path)||!linked(0,"Chassis",chassis_path))return ERR(15);
 unsigned system=jfind(&actual,0,"System"),chassis=jfind(&actual,0,"Chassis");
 if(!linked(system,"Processors",collection_paths[0])||!linked(system,"Memory",collection_paths[1]))return ERR(15);
 const char *keys[]={"MemoryDomains","Storage","SimpleStorage","NetworkInterfaces","EthernetInterfaces"};
 for(unsigned i=0;i<5;i++)if(!relation(system,keys[i],optional_paths[i],0,0))return ERR(15);
 if(!relation(chassis,"NetworkAdapters",optional_paths[5],0,0)||!relation(chassis,"Thermal",optional_paths[11],3,0))return ERR(15);
 e=read_object(system_path,&r);if(FAILED(e)||!inspect_system())return FAILED(e)?e:ERR(15);
 e=read_object(chassis_path,&r);if(FAILED(e)||!inspect_chassis())return FAILED(e)?e:ERR(15);
 for(unsigned i=0;i<2;i++){e=read_object(collection_paths[i],&r);if(FAILED(e)||!empty_collection())return FAILED(e)?e:ERR(15);}
 /* Same relation count is a minimum continuity check; deterministic discovery
  * order and allowlisted fixed paths keep this bounded to the original census. */
 if(!save&&guard_count!=previous_count)return ERR(15);
 e=check_guards(save);if(!FAILED(e)&&save)baseline_saved=1;return e;
}
static ES concrete_core_readback(void){
 TLS_REPLY r;ES e;for(unsigned i=0;i<2;i++){e=read_object(collection_paths[i],&r);if(FAILED(e)||!collection_matches(i))return FAILED(e)?e:ERR(33);}
 for(unsigned i=0;i<6;i++){e=read_object(core_paths[i],&r);if(FAILED(e)||!item_matches(i))return FAILED(e)?e:ERR(33);}
 return check_guards(0);
}
ES inventory_bulk71_preflight(void){
 if(post_attempted||finish_attempted||phase==5)return ERR(15);phase=0;
 if(!i3_inventory_source_valid())return ERR(15);epoch=i3_inventory_source_epoch();
 ES e=census(1);if(FAILED(e))return e;
 phase=1;status("I3C_OMITTED_RELATIONS_CHECKED",guard_count);logtext("I3C_BULK_PREFLIGHT_READY_NO_WRITES\r\n");return 0;
}
ES inventory_bulk71_post(void){
 TLS_REPLY r;if(phase!=1||post_attempted||!source_valid())return ERR(15);
 ES e=census(0);if(FAILED(e)){phase=5;return e;}
 post_attempted=1;logtext("I3C_POST_INTENT_MULTIPART_SHA256=");logtext(bulk71_multipart_sha);logtext("\r\n");status("I3C_POST_BYTES",sizeof(bulk71_multipart)-1);
 e=private_tls_bulk71_exchange(1,inventory_path,"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",bulk71_multipart,sizeof(bulk71_multipart)-1,&r);
 status("I3C_POST_TRANSPORT",e);if(!FAILED(e))status("I3C_POST_HTTP",r.status);
 if(FAILED(e)||!(r.status==200||r.status==201||r.status==204)){phase=5;logtext("I3C_POST_UNKNOWN_OR_REJECTED_NO_BOOTCOMPLETE_NO_REPLAY\r\n");return FAILED(e)?e:ERR(7);}
 phase=2;logtext("I3C_POST_POSITIVE_ACK_FINISH_NOT_YET_SENT\r\n");return 0;
}
ES inventory_bulk71_finish(void){
 TLS_REPLY r;if(phase!=2||!post_attempted||finish_attempted||!source_valid())return ERR(15);
 finish_attempted=1;logtext("I3C_FINISH_INTENT_SHA256=");logtext(bulk71_complete_sha);logtext("\r\n");
 ES e=private_tls_bulk71_exchange(2,inventory_path,"application/json;charset=utf-8",bulk71_complete,sizeof(bulk71_complete)-1,&r);
 status("I3C_FINISH_TRANSPORT",e);if(!FAILED(e))status("I3C_FINISH_HTTP",r.status);
 if(FAILED(e)||!(r.status==200||r.status==201||r.status==204)){phase=5;logtext("I3C_FINISH_UNKNOWN_OR_REJECTED_NO_REPLAY\r\n");return FAILED(e)?e:ERR(7);}
 phase=3;return inventory_bulk71_verify();
}
ES inventory_bulk71_verify(void){
 TLS_REPLY r;ES e=ERR(18);unsigned initial=phase,warnings=0;int completed=0;
 if(!post_attempted||!source_valid())return ERR(15);
 for(unsigned attempt=0;attempt<3;attempt++){
  e=read_object(status_path,&r);if(FAILED(e))break;
  unsigned data=jfind(&actual,0,"InventoryData"),state=jfind(&actual,data,"Status");
  if(jeq(&actual,state,"Completed")){
   unsigned messages=jfind(&actual,data,"Messages"),deleted=jfind(&actual,data,"DeletedModules");
   if((messages!=JNONE&&!empty_array(messages))||(deleted!=JNONE&&!empty_array(deleted)))warnings=1;
   completed=1;break;
  }
  if(attempt<2)gST->bs->stall(1000000);
 }
 if(completed)e=concrete_core_readback();else if(!FAILED(e))e=ERR(18);
 if(FAILED(e)){phase=5;logtext("I3C_VERIFY_INCOMPLETE_HOLD\r\n");return e;}
 if(initial!=3){phase=5;logtext("I3C_VALUES_MATCH_BUT_WRITE_OUTCOME_UNCERTAIN_HOLD\r\n");return ERR(15);}
 phase=warnings?6:4;logtext(warnings?"I3C_CORE_VERIFIED_WITH_STATUS_WARNINGS\r\n":"I3C_CORE_INVENTORY_VERIFIED\r\n");
 logtext("PCIe_Storage_dynamic_updates_and_reboot_persistence_not_claimed\r\n");return 0;
}
unsigned inventory_bulk71_state(void){return phase;}
