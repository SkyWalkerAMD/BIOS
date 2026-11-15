/* .71-only first live publisher. The immutable body catalogue is protected by
 * a fresh exact SMBIOS Type0/1/2/4/17 comparison in I3b before each mutation.
 * This is metadata publication, not BIOS configuration, flashing or OEM IPMI.
 */
#include "inventory_legacy71.h"
#include "legacy71_json.h"
#include "catalog71.h"

static JSON actual,expected,baseline;
static char baseline_body[32769],fresh_etag[256];
static UN baseline_bytes;
static uint64_t source_epoch;
static unsigned stage,done_mask,attempted_mask;
static const char *paths[]={
 "/redfish/v1/","/redfish/v1/Systems/Self","/redfish/v1/Systems/Self/Processors",
 "/redfish/v1/Systems/Self/Memory","/redfish/v1/Oem/Ami/InventoryData",
 "/redfish/v1/Oem/Ami/InventoryData/Status","/redfish/v1/Systems/Self/Oem/Ami/Inventory/Crc",
 "/redfish/v1/Systems/Self/Processors/DevType1_CPU0",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM0",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM1",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM2",
 "/redfish/v1/Systems/Self/Memory/DevType2_DIMM3","/redfish/v1/Systems"};

static int text_copy(JSON *j,unsigned t,char *out,UN cap){
 if(t>=j->count||j->t[t].type!='s'||!cap)return 0;UN p=j->t[t].start,n=0;
 while(p<j->t[t].end){int ch=jchar(j->s,j->t[t].end,&p);if(ch<32||ch>=127||n+1>=cap)return 0;out[n++]=(char)ch;}
 out[n]=0;return 1;
}
static int small_uint(JSON *j,unsigned t,unsigned *out){
 if(t>=j->count||j->t[t].type!='d')return 0;UN p=j->t[t].start,e=j->t[t].end;unsigned n=0;
 if(p==e||e-p>3)return 0;while(p<e){unsigned ch=(uint8_t)j->s[p++];if(ch<'0'||ch>'9')return 0;n=n*10+ch-'0';}
 *out=n;return n<=256;
}
static int strings_equal(JSON *a,unsigned x,JSON *b,unsigned y,int insensitive){
 if(x>=a->count||y>=b->count||a->t[x].type!='s'||b->t[y].type!='s')return 0;
 UN p=a->t[x].start,q=b->t[y].start;
 while(p<a->t[x].end&&q<b->t[y].end){int c=jchar(a->s,a->t[x].end,&p),d=jchar(b->s,b->t[y].end,&q);
  if(c<0||d<0)return 0;if(insensitive){if(c>='A'&&c<='Z')c+=32;if(d>='A'&&d<='Z')d+=32;}if(c!=d)return 0;}
 return p==a->t[x].end&&q==b->t[y].end;
}
static int values_match(JSON *want,unsigned x,JSON *got,unsigned y,unsigned depth){
 if(depth>12||x>=want->count||y>=got->count||want->t[x].type!=got->t[y].type)return 0;
 char type=want->t[x].type;
 if(type=='{'){
  for(unsigned k=x+1;k<want->t[x].after;k=want->t[k+1].after){char key[96];if(!text_copy(want,k,key,sizeof(key)))return 0;
   unsigned v=jfind(got,y,key);if(same(key,"UUID")){if(!strings_equal(want,k+1,got,v,1))return 0;}
   else if(!values_match(want,k+1,got,v,depth+1))return 0;}
  return 1;
 }
 if(type=='['){unsigned a=x+1,b=y+1;while(a<want->t[x].after&&b<got->t[y].after){
   if(!values_match(want,a,got,b,depth+1))return 0;a=want->t[a].after;b=got->t[b].after;
  }return a==want->t[x].after&&b==got->t[y].after;}
 if(type=='s')return strings_equal(want,x,got,y,0);
 UN n=want->t[x].end-want->t[x].start;
 return n==got->t[y].end-got->t[y].start&&eq(want->s+want->t[x].start,got->s+got->t[y].start,n);
}
static int parse_reply(const TLS_REPLY *r,unsigned id){
 if(r->status!=200||!jparse(&actual,r->body,r->length)||actual.t[0].type!='{'||jfind(&actual,0,"error")<actual.count)return 0;
 unsigned self=jfind(&actual,0,"@odata.id");return self==512||jeq(&actual,self,paths[id]);
}
static ES get(unsigned id,TLS_REPLY *r){
 ES e=private_tls_inventory_exchange(0,id,0,0,0,r);status("I3B_READ_TRANSPORT",e);
 if(!FAILED(e))status("I3B_READ_HTTP",r->status);return e;
}
static ES checked_get(unsigned id,TLS_REPLY *r){ES e=get(id,r);if(FAILED(e))return e;return parse_reply(r,id)?0:ERR(33);}
static int linked(unsigned object,const char *name,const char *uri){return jeq(&actual,jfind(&actual,jfind(&actual,object,name),"@odata.id"),uri);}
static int root_valid(void){return jeq(&actual,jfind(&actual,0,"RedfishVersion"),"1.8.0")&&
 jeq(&actual,jfind(&actual,jfind(&actual,jfind(&actual,0,"Oem"),"Ami"),"RtpVersion"),"1.8.a")&&linked(0,"Systems",paths[12]);}
static int collection_valid(unsigned id,unsigned *mask){
 unsigned count=0,a=jfind(&actual,0,"Members"),seen=0,n=0;
 if(!small_uint(&actual,jfind(&actual,0,"Members@odata.count"),&count)||a>=actual.count||actual.t[a].type!='['||
    jfind(&actual,0,"Members@odata.nextLink")<actual.count)return 0;
 for(unsigned t=a+1;t<actual.t[a].after;t=actual.t[t].after){
  if(actual.t[t].type!='{')return 0;unsigned u=jfind(&actual,t,"@odata.id"),bit=0;
  if(id==12){if(jeq(&actual,u,paths[1]))bit=1;}
  else for(unsigned item=id==2?1:2;item<(id==2?2:6);item++)if(jeq(&actual,u,paths[inv71_items[item].get_id]))bit=1u<<item;
  if(!bit||(seen&bit))return 0;seen|=bit;n++;
 }
 if(n!=count||(id==12&&(n!=1||seen!=1)))return 0;*mask=seen;return 1;
}
static int system_valid(void){
 if(!linked(0,"Processors",paths[2])||!linked(0,"Memory",paths[3]))return 0;
 /* First-host trial: never overwrite a meaningful different identity even if
  * UUID is missing. Only the observed blank/NA cases or exact expected values
  * are admitted. A later generic update policy requires separate review.
  */
 static const char *keys[]={"Model","Manufacturer","BiosVersion"};
 if(!jparse(&expected,inv71_items[0].body,inv71_items[0].bytes))return 0;
 for(unsigned k=0;k<3;k++){
  unsigned field=jfind(&actual,0,keys[k]);
  if(field==512||actual.t[field].type=='n'||jeq(&actual,field,"")||jeq(&actual,field," ")||jeq(&actual,field,"NA")||jeq(&actual,field,"N/A"))continue;
  if(!strings_equal(&expected,jfind(&expected,0,keys[k]),&actual,field,0))return 0;
 }
 unsigned t=jfind(&actual,0,"UUID");
 if(t==512||actual.t[t].type=='n'||jeq(&actual,t,"")||jeq(&actual,t," ")||jeq(&actual,t,"NA")||jeq(&actual,t,"N/A")||
    jeq(&actual,t,"00000000-0000-0000-0000-000000000000"))return 1;
 char value[64];if(!text_copy(&actual,t,value,sizeof(value)))return 0;
 for(unsigned i=0;value[i];i++)if(value[i]>='A'&&value[i]<='Z')value[i]+=32;
 return same(value,inv71_uuid);
}
static int item_matches(unsigned item){
 const INV71_ITEM *p=&inv71_items[item];return jparse(&expected,p->body,p->bytes)&&values_match(&expected,0,&actual,0,0);
}
static int baseline_unchanged(void){
 static const char *keys[]={"Model","Manufacturer","BiosVersion","UUID"};
 if(!jparse(&baseline,baseline_body,baseline_bytes))return 0;
 for(unsigned k=0;k<4;k++){
  unsigned a=jfind(&baseline,0,keys[k]),b=jfind(&actual,0,keys[k]);
  if(a==512||b==512){if(a!=b)return 0;continue;}
  if(!values_match(&baseline,a,&actual,b,0))return 0;
 }return 1;
}
static int source_valid(void){
 return i3_inventory_source_valid()&&source_epoch==i3_inventory_source_epoch();
}
static ES verify_item(unsigned item,int retry){
 TLS_REPLY r;unsigned mask=0;ES e=0;
 for(unsigned attempt=0;attempt<(retry?3U:1U);attempt++){
  if(item){e=checked_get(inv71_items[item].write_id,&r);
   if(!FAILED(e)&&(!collection_valid(inv71_items[item].write_id,&mask)||!(mask&(1u<<item))))e=ERR(33);
  }
  if(!item||!FAILED(e)){e=checked_get(inv71_items[item].get_id,&r);if(!FAILED(e)&&(!item_matches(item)||(!item&&!system_valid())))e=ERR(33);}
  status("I3B_VERIFY_ITEM",item);status("I3B_VERIFY_ATTEMPT",attempt+1);status("I3B_VERIFY_RESULT",e);
  if(!FAILED(e))return 0;
  if(private_tls_active())return e;
  if(retry&&attempt+1<3)gST->bs->stall(1000000);
 }
 return e;
}
static ES final_verify(void){
 TLS_REPLY r;ES e;unsigned mask=0;
 if(!source_valid())return ERR(15);
 e=checked_get(2,&r);if(FAILED(e)||!collection_valid(2,&mask)||mask!=2)return FAILED(e)?e:ERR(33);
 e=checked_get(3,&r);if(FAILED(e)||!collection_valid(3,&mask)||mask!=60)return FAILED(e)?e:ERR(33);
 for(unsigned item=0;item<6;item++){e=checked_get(inv71_items[item].get_id,&r);if(FAILED(e)||!item_matches(item))return FAILED(e)?e:ERR(33);}
 stage=3;logtext("I3B_CORE_INVENTORY_READBACK_VERIFIED\r\nPCIe_Storage_and_reboot_persistence_not_claimed\r\n");return 0;
}
ES inventory_legacy71_preflight(void){
 TLS_REPLY r;ES e;unsigned masks[2]={0,0},mask=0;
 if(attempted_mask||stage==2)return ERR(15);
 stage=0;done_mask=0;baseline_bytes=0;
 if(!i3_inventory_source_valid())return ERR(15);source_epoch=i3_inventory_source_epoch();
 logtext("I3B_LEGACY_PREFLIGHT_READ_ONLY\r\n");
 e=checked_get(0,&r);if(FAILED(e)||!root_valid())return FAILED(e)?e:ERR(33);
 e=checked_get(12,&r);if(FAILED(e)||!collection_valid(12,&mask))return FAILED(e)?e:ERR(33);
 e=checked_get(1,&r);if(FAILED(e)||!system_valid())return FAILED(e)?e:ERR(15);
 if(r.length>sizeof(baseline_body)-1)return ERR(4);memcpy(baseline_body,r.body,r.length);baseline_body[r.length]=0;baseline_bytes=r.length;
 if(item_matches(0))done_mask|=1;
 for(unsigned group=0;group<2;group++){e=checked_get(group+2,&r);if(FAILED(e)||!collection_valid(group+2,&masks[group]))return FAILED(e)?e:ERR(33);}
 for(unsigned item=1;item<6;item++)if((masks[0]|masks[1])&(1u<<item)){
  e=checked_get(inv71_items[item].get_id,&r);if(FAILED(e)||!item_matches(item))return FAILED(e)?e:ERR(33);done_mask|=1u<<item;
 }
 if(!source_valid())return ERR(15);
 for(unsigned item=0;item<6;item++){
  status("I3B_PLAN_ITEM",item);status("I3B_PLAN_ALREADY_MATCHES",(done_mask>>item)&1u);
  logtext("I3B_PLAN_BODY_SHA256=");logtext(inv71_items[item].sha);logtext("\r\n");
 }
 stage=1;status("I3B_PREFLIGHT_DONE_MASK",done_mask);logtext("I3B_PREFLIGHT_READY_NO_WRITES_SENT\r\n");return 0;
}
ES inventory_legacy71_step(void){
 TLS_REPLY r;ES e;unsigned item=0,mask=0;
 if(stage!=1||!source_valid())return ERR(15);
 while(item<6&&(done_mask&(1u<<item)))item++;
 if(item==6){e=final_verify();if(FAILED(e))stage=2;return e;}
 const INV71_ITEM *p=&inv71_items[item];if(attempted_mask&(1u<<item)){stage=2;return ERR(15);}
 fresh_etag[0]=0;
 e=checked_get(1,&r);if(FAILED(e)||!system_valid())return FAILED(e)?e:ERR(15);
 if(item==0){
  if(item_matches(0)){done_mask|=1;logtext("I3B_SYSTEM_ALREADY_MATCHES_SKIP\r\n");return 0;}
  if(!baseline_unchanged()||!text_copy(&actual,jfind(&actual,0,"@odata.etag"),fresh_etag,sizeof(fresh_etag))||!fresh_etag[0])return ERR(15);
 }else{
  e=checked_get(p->write_id,&r);if(FAILED(e)||!collection_valid(p->write_id,&mask))return FAILED(e)?e:ERR(33);
  if(mask&(1u<<item)){e=verify_item(item,0);if(FAILED(e))return e;done_mask|=1u<<item;logtext("I3B_RESOURCE_ALREADY_MATCHES_SKIP\r\n");return 0;}
 }
 if(!source_valid())return ERR(15);
 attempted_mask|=1u<<item;
 status("I3B_WRITE_INTENT_ITEM",item);status("I3B_WRITE_INTENT_METHOD",p->method);status("I3B_WRITE_INTENT_RESOURCE",p->write_id);
 logtext("I3B_WRITE_BODY_SHA256=");logtext(p->sha);logtext("\r\n");status("I3B_WRITE_BODY_BYTES",p->bytes);
 e=private_tls_inventory_exchange(p->method,p->write_id,p->body,p->bytes,item?0:fresh_etag,&r);
 status("I3B_WRITE_TRANSPORT",e);if(!FAILED(e))status("I3B_WRITE_HTTP",r.status);
 if(FAILED(e)||!(r.status==200||r.status==201||r.status==204)){
  stage=2;logtext("I3B_WRITE_NOT_CONFIRMED_NO_REPLAY_NO_ROUTE_SWITCH\r\n");
  if(!private_tls_active()){ES read=verify_item(item,0);status("I3B_AFTER_FAILED_WRITE_READBACK",read);}
  return FAILED(e)?e:ERR(7);
 }
 e=verify_item(item,1);if(FAILED(e)){stage=2;logtext("I3B_HOLD_READBACK_MISMATCH_NO_REPLAY\r\n");return e;}
 done_mask|=1u<<item;status("I3B_ITEM_VERIFIED",item);status("I3B_DONE_MASK",done_mask);
 if(done_mask==63){e=final_verify();if(FAILED(e))stage=2;return e;}
 return 0;
}
unsigned inventory_legacy71_state(void){return stage;}
unsigned inventory_legacy71_completed_mask(void){return done_mask;}
