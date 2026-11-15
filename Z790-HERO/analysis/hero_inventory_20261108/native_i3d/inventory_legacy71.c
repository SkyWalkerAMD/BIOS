/* .71-only I3d continuation publisher; frozen I3b remains unchanged. The immutable body catalogue is protected by
 * a fresh exact SMBIOS Type0/1/2/4/17 comparison in I3b before each mutation.
 * This is metadata publication, not BIOS configuration, flashing or OEM IPMI.
 */
#include "inventory_legacy71.h"
#include "legacy71_json.h"
#include "catalog71.h"

static JSON actual,expected;
static char fresh_etag[256];
static uint64_t source_epoch;
static unsigned stage,done_mask,attempted_mask,indexed_mask,summary_attempted,summary_verified;
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
 unsigned self=jfind(&actual,0,"@odata.id");return ((id<7||id>11)&&self==512)||jeq(&actual,self,paths[id]);
}
static ES get(unsigned id,TLS_REPLY *r){
 ES e=private_tls_inventory_exchange(0,id,0,0,0,r);status("I3D_READ_TRANSPORT",e);
 if(!FAILED(e))status("I3D_READ_HTTP",r->status);return e;
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
static int source_valid(void){
 return i3_inventory_source_valid()&&source_epoch==i3_inventory_source_epoch();
}
/* This read is mandatory even when Members is empty: real .71 accepts a POST
 * into an addressable member while leaving the standard collection empty.
 * Collection-advertised members must exist; orphan members must match exactly.
 */
static ES probe_item(unsigned item,unsigned advertised,int *exists){
 TLS_REPLY r;ES e=get(inv71_items[item].get_id,&r);*exists=0;
 if(FAILED(e))return e;
 if(r.status==404)return advertised&(1u<<item)?ERR(33):0;
 if(!parse_reply(&r,inv71_items[item].get_id)||!item_matches(item))return ERR(33);
 *exists=1;return 0;
}
static ES read_collection(unsigned id,unsigned *mask){
 TLS_REPLY r;ES e=checked_get(id,&r);
 if(FAILED(e)||!collection_valid(id,mask))return FAILED(e)?e:ERR(33);
 unsigned group=id==2?2u:60u;indexed_mask=(indexed_mask&~group)|*mask;
 status("I3D_COLLECTION_INDEX_MASK",indexed_mask);return 0;
}
static ES verify_item(unsigned item,int retry){
 TLS_REPLY r;unsigned mask=0;ES e=0;
 for(unsigned attempt=0;attempt<(retry?3U:1U);attempt++){
  e=checked_get(inv71_items[item].get_id,&r);
  if(!FAILED(e)&&(!item_matches(item)||(!item&&!system_valid())))e=ERR(33);
  status("I3D_VERIFY_ITEM",item);status("I3D_VERIFY_ATTEMPT",attempt+1);status("I3D_DIRECT_VERIFY_RESULT",e);
  if(!FAILED(e)){
   if(item){
    e=read_collection(inv71_items[item].write_id,&mask);if(FAILED(e))return e;
    if(!(mask&(1u<<item)))logtext("I3D_DIRECT_OBJECT_VERIFIED_COLLECTION_INDEX_PENDING\r\n");
   }
   return 0;
  }
  if(private_tls_active())return e;
  if(retry&&attempt+1<3)gST->bs->stall(1000000);
 }
 return e;
}
static ES final_verify(void){
 TLS_REPLY r;ES e;unsigned mask=0;
 if(!source_valid())return ERR(15);
 e=read_collection(2,&mask);if(FAILED(e))return e;
 e=read_collection(3,&mask);if(FAILED(e))return e;
 for(unsigned item=0;item<6;item++){
  e=checked_get(inv71_items[item].get_id,&r);
  if(FAILED(e)||!item_matches(item)||(!item&&!system_valid()))return FAILED(e)?e:ERR(33);
 }
 if(!source_valid())return ERR(15);
 stage=indexed_mask==62?3:4;
 logtext("I3D_ALL_SIX_DIRECT_OBJECTS_READBACK_VERIFIED\r\n");
 if(stage==3)logtext("I3D_STANDARD_COLLECTIONS_COMPLETE\r\n");
 else logtext("I3D_STANDARD_COLLECTIONS_INCOMPLETE_NOT_FULL_REDFISH_SUCCESS\r\n");
 logtext("PCIe_Storage_and_reboot_persistence_not_claimed\r\n");return 0;
}
ES inventory_legacy71_preflight(void){
 TLS_REPLY r;ES e;unsigned mask=0,masks[2]={0,0};int exists=0;
 if(attempted_mask||summary_attempted||stage==2)return ERR(15);
 stage=0;done_mask=0;indexed_mask=0;summary_verified=0;
 if(!i3_inventory_source_valid())return ERR(15);source_epoch=i3_inventory_source_epoch();
 logtext("I3D_CONTINUATION_PREFLIGHT_READ_ONLY\r\n");
 e=checked_get(0,&r);if(FAILED(e)||!root_valid())return FAILED(e)?e:ERR(33);
 e=checked_get(12,&r);if(FAILED(e)||!collection_valid(12,&mask))return FAILED(e)?e:ERR(33);
 e=checked_get(1,&r);if(FAILED(e)||!system_valid()||!item_matches(0))return FAILED(e)?e:ERR(15);
 done_mask=1;
 for(unsigned group=0;group<2;group++){e=read_collection(group+2,&masks[group]);if(FAILED(e))return e;}
 for(unsigned item=1;item<6;item++){
  e=probe_item(item,masks[0]|masks[1],&exists);if(FAILED(e))return e;
  if(exists)done_mask|=1u<<item;
 }
 /* This limited continuation never creates CPU or rewrites System identity. */
 if((done_mask&3)!=3||!source_valid())return ERR(15);
 for(unsigned item=0;item<6;item++){
  status("I3D_PLAN_ITEM",item);status("I3D_PLAN_DIRECT_ALREADY_MATCHES",(done_mask>>item)&1u);
  logtext("I3D_PLAN_BODY_SHA256=");logtext(inv71_items[item].sha);logtext("\r\n");
 }
 stage=1;status("I3D_PREFLIGHT_DONE_MASK",done_mask);status("I3D_PREFLIGHT_INDEXED_MASK",indexed_mask);
 logtext("I3D_PREFLIGHT_READY_NO_WRITES_SENT\r\n");return 0;
}
ES inventory_legacy71_step(void){
 TLS_REPLY r;ES e;unsigned item=2,mask=0;int exists=0;
 if(stage!=1||!source_valid())return ERR(15);
 while(item<6&&(done_mask&(1u<<item)))item++;
 if(item==6){e=final_verify();if(FAILED(e))stage=2;return e;}
 const INV71_ITEM *p=&inv71_items[item];if(attempted_mask&(1u<<item)){stage=2;return ERR(15);}
 e=checked_get(1,&r);if(FAILED(e)||!system_valid()||!item_matches(0))return FAILED(e)?e:ERR(15);
 e=checked_get(7,&r);if(FAILED(e)||!item_matches(1))return FAILED(e)?e:ERR(33);
 e=read_collection(3,&mask);if(FAILED(e))return e;
 e=probe_item(item,mask,&exists);if(FAILED(e))return e;
 if(exists){
  done_mask|=1u<<item;logtext("I3D_EXISTING_DIRECT_OBJECT_MATCHES_SKIP_NO_POST\r\n");
  if(done_mask==63){e=final_verify();if(FAILED(e))stage=2;return e;}return 0;
 }
 if(!source_valid())return ERR(15);
 attempted_mask|=1u<<item;
 status("I3D_WRITE_INTENT_ITEM",item);status("I3D_WRITE_INTENT_METHOD",p->method);status("I3D_WRITE_INTENT_RESOURCE",p->write_id);
 logtext("I3D_WRITE_BODY_SHA256=");logtext(p->sha);logtext("\r\n");status("I3D_WRITE_BODY_BYTES",p->bytes);
 e=private_tls_inventory_exchange(p->method,p->write_id,p->body,p->bytes,0,&r);
 status("I3D_WRITE_TRANSPORT",e);if(!FAILED(e))status("I3D_WRITE_HTTP",r.status);
 if(FAILED(e)||!(r.status==200||r.status==201||r.status==204)){
  stage=2;logtext("I3D_WRITE_NOT_CONFIRMED_NO_REPLAY_NO_ROUTE_SWITCH\r\n");
  if(!private_tls_active()){ES read=verify_item(item,0);status("I3D_AFTER_FAILED_WRITE_READBACK",read);}
  return FAILED(e)?e:ERR(7);
 }
 e=verify_item(item,1);if(FAILED(e)){stage=2;logtext("I3D_HOLD_DIRECT_READBACK_MISMATCH_NO_REPLAY\r\n");return e;}
 done_mask|=1u<<item;status("I3D_ITEM_DIRECT_VERIFIED",item);status("I3D_DONE_MASK",done_mask);
 if(done_mask==63){e=final_verify();if(FAILED(e))stage=2;return e;}return 0;
}
/* Original donor 0xd3d0 builds ProcessorSummary.Count and .Model; 0x1f7c
 * later PATCHes the pending System object. This minimal subset does not infer
 * Health, does not claim to rebuild collections, and is not BootComplete.
 */
static const char summary_body[]="{\"ProcessorSummary\":{\"Count\":1,\"Model\":\"Intel(R) Core(TM) i9-14900KS\"}}";
static int summary_matches(void){
 return jparse(&expected,summary_body,sizeof(summary_body)-1)&&values_match(&expected,0,&actual,0,0);
}
static int summary_admissible(void){
 unsigned s=jfind(&actual,0,"ProcessorSummary");if(s==512||actual.t[s].type=='n')return 1;
 if(actual.t[s].type!='{')return 0;
 unsigned c=jfind(&actual,s,"Count"),m=jfind(&actual,s,"Model"),n=0;
 if(c!=512&&actual.t[c].type!='n'&&(!small_uint(&actual,c,&n)||n>1))return 0;
 if(m==512||actual.t[m].type=='n'||jeq(&actual,m,"")||jeq(&actual,m," ")||jeq(&actual,m,"NA")||jeq(&actual,m,"N/A"))return 1;
 return jeq(&actual,m,"Intel(R) Core(TM) i9-14900KS");
}
ES inventory_legacy71_summary_step(void){
 TLS_REPLY r;ES e;unsigned saved_stage=stage;
 if((stage!=1&&stage!=3&&stage!=4)||summary_attempted||!source_valid())return ERR(15);
 /* A summary cannot be written merely because a preflight previously passed. */
 e=checked_get(7,&r);if(FAILED(e)||!item_matches(1))return FAILED(e)?e:ERR(33);
 e=checked_get(1,&r);if(FAILED(e)||!system_valid()||!item_matches(0))return FAILED(e)?e:ERR(15);
 if(summary_matches()){summary_verified=1;logtext("I3D_PROCESSOR_SUMMARY_ALREADY_MATCHES_SKIP\r\n");return 0;}
 fresh_etag[0]=0;
 if(!summary_admissible()||!text_copy(&actual,jfind(&actual,0,"@odata.etag"),fresh_etag,sizeof(fresh_etag))||!fresh_etag[0]||!source_valid())return ERR(15);
 summary_attempted=1;status("I3D_SUMMARY_WRITE_INTENT_BYTES",sizeof(summary_body)-1);
 logtext("I3D_SUMMARY_WRITE_BODY=");logtext(summary_body);logtext("\r\n");
 e=private_tls_inventory_exchange(2,1,summary_body,sizeof(summary_body)-1,fresh_etag,&r);
 status("I3D_SUMMARY_WRITE_TRANSPORT",e);if(!FAILED(e))status("I3D_SUMMARY_WRITE_HTTP",r.status);
 if(FAILED(e)||!(r.status==200||r.status==201||r.status==204)){
  stage=2;logtext("I3D_SUMMARY_UNCONFIRMED_NO_REPLAY\r\n");
  if(!private_tls_active()){ES read=checked_get(1,&r);status("I3D_SUMMARY_AFTER_FAILURE_READ",read);
   if(!FAILED(read))status("I3D_SUMMARY_AFTER_FAILURE_MATCH",summary_matches());}
  return FAILED(e)?e:ERR(7);
 }
 for(unsigned attempt=0;attempt<3;attempt++){
  e=checked_get(1,&r);
  if(!FAILED(e)&&(!item_matches(0)||!system_valid()||!summary_matches()))e=ERR(33);
  status("I3D_SUMMARY_VERIFY_ATTEMPT",attempt+1);status("I3D_SUMMARY_VERIFY_RESULT",e);
  if(!FAILED(e)){
   if(!source_valid()){stage=2;return ERR(15);}
   summary_verified=1;stage=saved_stage;logtext("I3D_PROCESSOR_SUMMARY_READBACK_VERIFIED\r\n");return 0;
  }
  if(private_tls_active())break;if(attempt+1<3)gST->bs->stall(1000000);
 }
 stage=2;logtext("I3D_SUMMARY_READBACK_HOLD_NO_REPLAY\r\n");return e;
}
unsigned inventory_legacy71_state(void){return stage;}
unsigned inventory_legacy71_completed_mask(void){return done_mask;}
unsigned inventory_legacy71_indexed_mask(void){return indexed_mask;}
unsigned inventory_legacy71_summary_state(void){return summary_verified?1:(summary_attempted?2:0);}
int inventory_legacy71_write_allowed(unsigned method,unsigned id,const char *body,UN bytes){
 if(!body||!bytes)return 0;
 if(method==2&&id==1)return bytes==sizeof(summary_body)-1&&eq(body,summary_body,bytes);
 if(method==1&&id==3){for(unsigned item=2;item<6;item++)
  if(bytes==inv71_items[item].bytes&&eq(body,inv71_items[item].body,bytes))return 1;}
 return 0;
}
