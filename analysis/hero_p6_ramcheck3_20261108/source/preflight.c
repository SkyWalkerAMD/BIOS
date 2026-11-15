#include "preflight.h"
static GUID cfg={0xbef09fe1,0x8540,0x4be1,{0x90,0x82,0xe6,0x62,0x43,0x28,0xf4,0x35}};
static const uint8_t defaults[32]={0,0,0,10,1};
static void read_one(VAR_SNAPSHOT *v,C16 *name,UN expected,const char *label){
 memset(v,0,sizeof(*v));v->bytes=expected;
 v->status=gST->rt->get_variable(name,&cfg,&v->attrs,&v->bytes,v->data);
 logtext(label);logtext(" STATUS=");loghex(v->status,16);logtext(" BYTES=");loghex(v->bytes,8);logtext(" ATTRS=");loghex(v->attrs,8);logtext("\r\n");
 if(v->status==0&&v->bytes<=sizeof(v->data)){logtext("RAW=");logbytes(v->data,v->bytes);}
}
ES preflight_read(PREFLIGHT *p,const char *label){
 logtext(label);logtext("\r\n");memset(p,0,sizeof(*p));
 read_one(&p->settings,W("HeroIpmiSettings"),32,"HeroIpmiSettings");
 read_one(&p->state,W("HeroIpmiState"),144,"HeroIpmiState");
 VAR_SNAPSHOT *s=&p->settings,*j=&p->state;
 if(s->status!=ERR(14)&&(s->status!=0||(s->bytes!=21&&s->bytes!=32)||s->attrs!=3||!eq(s->data,defaults,s->bytes)))return ERR(15);
 if(j->status!=ERR(14)){
  if(j->status!=0||j->bytes!=144||j->attrs!=3)return ERR(15);
  uint8_t copy[144];memcpy(copy,j->data,144);memset(copy+12,0,4);
  if(u32(j->data)!=0x36504948||u32(j->data+4)!=1||u32(j->data+8)!=144||u32(j->data+12)!=probe_crc32(copy,144)||u32(j->data+16)||u32(j->data+20)||!eq(j->data+24,defaults,32)||!eq(j->data+56,defaults,32))return ERR(15);
 }
 logtext(s->status==ERR(14)?"EXPECTED_P6_NV_SEED=HeroIpmiSettings 32B attrs3 safe defaults\r\n":"EXPECTED_P6_NV_SEED=NONE\r\n");
 if(s->status==0&&s->bytes==21)logtext("S21_NATIVE_FIELDS_EXACT_DEFAULT; reserved11 normalized in RAM; stored21 retained\r\n");
 logtext("PREFLIGHT_SAFE_DEFAULTS_NO_PENDING_LAN_WDT_SEL_RETRY_OR_RECOVERY\r\n");return 0;
}
int preflight_equal(const PREFLIGHT *a,const PREFLIGHT *b){return eq(a,b,sizeof(*a));}
