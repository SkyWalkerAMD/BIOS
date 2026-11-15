#include "depex_probe.h"
/* GUIDs/marker behavior from official EDK2 stable202502 headers in provenance.
 * NULL interface is valid for architectural/marker protocols: status decides. */
static GUID protocols[]={
 {0x30cfe3e7,0x3de1,0x4586,{0xbe,0x20,0xde,0xab,0xa1,0xb3,0xb7,0x93}},
 {0x6441f818,0x6362,0x4e44,{0xb5,0x70,0x7d,0xba,0x31,0xdd,0x24,0x53}},
 {0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}},
 {0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}},
 {0x6a1ee763,0xd47a,0x43b4,{0xaa,0xbe,0xef,0x1d,0xe2,0xab,0x56,0xfc}}
};
static const char *const names[]={"PciEnumerationComplete","VariableWriteArch","HiiDatabase","HiiString","HiiPackageList_related_only"};
static const char *const guid_names[]={
 "30cfe3e7-3de1-4586-be20-deaba1b3b793","6441f818-6362-4e44-b570-7dba31dd2453",
 "ef9fc172-a1b2-4693-b327-6d32fc416042","0fd96974-23aa-4cdc-b9cb-98d17750322a",
 "6a1ee763-d47a-43b4-aabe-ef1de2ab56fc"};
static GUID net_guid={0xd1405d16,0x7afc,0x4695,{0xbb,0x12,0x41,0x45,0x9d,0x36,0x95,0xa2}};
static C16 net_name[]={'N','e','t','w','o','r','k','S','t','a','c','k','V','a','r',0};
typedef struct {DP_APPEND append;void *context;size_t bytes;unsigned incomplete;} OUTPUT;
static unsigned busy;
static void text(OUTPUT *o,const char *s){size_t n=0;while(s[n])n++;if(n>8192-o->bytes){o->incomplete=1;return;}o->append(o->context,s,n);o->bytes+=n;}
static void hex(OUTPUT *o,uint64_t v,unsigned digits){char s[17];for(unsigned i=0;i<digits;i++)s[i]="0123456789ABCDEF"[(v>>((digits-i-1)*4))&15];s[digits]=0;text(o,s);}
static void field(OUTPUT *o,const char *s,uint64_t v){text(o,s);text(o,"=");hex(o,v,16);text(o,"\r\n");}
static unsigned both(unsigned a,unsigned b){return (!a||!b)?0:(a==2||b==2)?2:1;}
ES depex_probe(ST *st,DP_APPEND append,void *context){
 if(!st||!st->bs||!st->bs->locate_protocol||!append)return ERR(2);
 if(busy)return ERR(20);busy=1;OUTPUT o={append,context,0,0};unsigned present[5];
 text(&o,"HERO_DEPEX_READONLY_D1_BEGIN\r\nSTATUS success counts as present even with NULL interface.\r\n");
 for(unsigned i=0;i<5;i++){
  void *interface=0;ES e=st->bs->locate_protocol(&protocols[i],0,&interface);
  present[i]=e==0?1:e==ERR(14)?0:2;
  text(&o,"DP_PROTOCOL=");text(&o,names[i]);text(&o,"\r\nDP_GUID=");text(&o,guid_names[i]);text(&o,"\r\n");
  field(&o,"DP_LOCATE_STATUS",e);field(&o,"DP_INTERFACE",(UN)interface);field(&o,"DP_PRESENT",present[i]);
  if(present[i]==2)o.incomplete=1;
 }
 text(&o,"DP_VALUE_LEGEND=0 false, 1 true, 2 unknown\r\n");
 field(&o,"DP_R2_DEPEX_AT_CAPTURE",both(present[0],present[1]));
 field(&o,"DP_P6_DEPEX_AT_CAPTURE",both(both(present[2],present[3]),present[1]));
 text(&o,"HiiPackageList is informational; it is NOT in the captured R2/P6 expressions.\r\n");
 text(&o,"DP_VARIABLE=NetworkStackVar\r\nDP_VARIABLE_GUID=d1405d16-7afc-4695-bb12-41459d3695a2\r\n");
 if(!st->rt||!st->rt->get_variable){text(&o,"DP_GET_VARIABLE_UNAVAILABLE\r\n");o.incomplete=1;}
 else{
  struct {uint8_t before[8],data[64],after[8];} b;
  for(unsigned i=0;i<8;i++){b.before[i]=0xa5;b.after[i]=0xa5;}
  for(unsigned i=0;i<64;i++)b.data[i]=0;
  uint32_t attributes=0;UN size=sizeof(b.data);ES e=st->rt->get_variable(net_name,&net_guid,&attributes,&size,b.data);
  unsigned guard=1;for(unsigned i=0;i<8;i++)if(b.before[i]!=0xa5||b.after[i]!=0xa5)guard=0;
  field(&o,"DP_NETWORK_STATUS",e);field(&o,"DP_NETWORK_BYTES",size);field(&o,"DP_NETWORK_ATTRIBUTES",attributes);field(&o,"DP_NETWORK_BUFFER_GUARD",guard);
  if(!e&&guard&&size<=sizeof(b.data)){
   field(&o,"DP_NETWORK_EXPECTED_8_BYTES",size==8);
   text(&o,"DP_NETWORK_RAW=");for(UN i=0;i<size;i++)hex(&o,b.data[i],2);text(&o,"\r\n");
   if(size)field(&o,"DP_NETWORK_BYTE0",b.data[0]);
  }else if(e!=ERR(14)||!guard)o.incomplete=1;
 }
 text(&o,"Current presence does not reconstruct DXE dispatch history; no protocol method or variable write was invoked.\r\nHERO_DEPEX_READONLY_D1_END\r\n");
 busy=0;return o.incomplete?ERR(33):0;
}
