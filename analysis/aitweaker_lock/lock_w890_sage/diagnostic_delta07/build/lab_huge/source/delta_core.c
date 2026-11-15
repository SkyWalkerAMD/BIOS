/* Narrow diagnostic extraction. No firmware / variable / config callback API. */
#include "delta_core.h"
#include "password_core.h"
#include "probe_core.h"
static const uint8_t cpu_guid[16]={0xfe,0x38,0xf3,0xdb,0xbe,0x93,0xd6,0x46,0xad,0xf5,0xc1,0x7c,0x22,0x36,0xd8,0x38};
static const uint8_t unknown_guid[16]={0x0b,0x9f,0xfd,0x25,0xef,0xa3,0x88,0x47,0xa4,0x0c,0x81,0x84,0x9d,0x17,0x8a,0x6c};
static const uint8_t nvme_guid[16]={0xb2,0x06,0x87,0x66,0xfc,0xbc,0xd4,0x4a,0xa1,0x85,0x75,0xe7,0x9f,0x3f,0xe1,0x69};
static const uint8_t socket_guid[16]={0x80,0xd3,0x6f,0x6b,0x55,0x2c,0xc6,0x42,0x98,0xbf,0xcb,0xbc,0x5a,0x9a,0xa6,0x66};
static const uint8_t cpu_baseline_sha[32]={0xc1,0x1c,0xb4,0x70,0xf9,0xaa,0x84,0xeb,0xa8,0xa7,0xfc,0x5b,0xf0,0x84,0xca,0x8a,0x1a,0x46,0x62,0x90,0xf7,0xc5,0x9f,0x4a,0xc3,0xf9,0x47,0x4f,0xa6,0x84,0xa0,0x6a};
static const uint8_t nvme_baseline_sha[32]={0xbd,0x16,0xc4,0x75,0x4e,0x07,0x09,0xb4,0xa3,0xa2,0x63,0x77,0x88,0xde,0x90,0x25,0xb3,0x2e,0xa6,0xf2,0xf4,0xd0,0xdc,0x46,0x42,0x4e,0x29,0xbd,0x6d,0xa3,0x18,0x7e};
static const uint8_t socket_baseline_sha[32]={0x54,0xa3,0x7e,0xac,0xf5,0xf5,0xa1,0x0f,0x38,0x70,0x39,0xe2,0x51,0xdf,0xee,0x4a,0x5b,0xe2,0x11,0x38,0xf3,0xae,0x73,0x5a,0xc5,0xc9,0x77,0x0f,0x87,0x76,0x5e,0x7a};
static uint32_t u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(8*i));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(8*i));}
static void zero(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
static int same(const void *a,const void *b,size_t n){const uint8_t *p=a,*q=b;while(n--)if(*p++!=*q++)return 0;return 1;}
static int nonzero(const uint8_t *p,size_t n){uint8_t v=0;while(n--)v|=*p++;return v!=0;}
static int overlap(const void *a,size_t na,const void *b,size_t nb){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;if(na>UINTPTR_MAX-x||nb>UINTPTR_MAX-y)return 1;return x<y+nb&&y<x+na;}
static int forms(const uint8_t *p,size_t n,uint32_t *count){
 *count=0;if(!p||n<4||n>0xffffff||((u32(p)&0xffffff)!=n)||(p[3]!=2))return 0;
 unsigned depth=0,sets=0;size_t at=4;
 while(at<n){if(n-at<2)return 0;unsigned op=p[at],len=p[at+1]&127,scope=p[at+1]>>7;
  if(len<2||len>n-at)return 0;
  if(op==14){if(len<23||depth||!scope)return 0;sets++;}
  if(op==1){if(len!=6||!depth||!scope)return 0;(*count)++;}
  if(op==41){if(len!=2||!depth||scope)return 0;depth--;}
  else if(scope){if(++depth>256)return 0;}
  at+=len;
 }
 return !depth&&sets&&*count;
}
int d7_select_forms(const uint8_t *p,size_t n,const uint8_t g[16],uint32_t index,D7_FORMS *r){
 if(!r)return D7_FORMAT;zero(r,sizeof(*r));if(!p||!g||n<24||n>0xffffffffU||u32(p+16)!=n)return D7_FORMAT;
 if(!same(g,cpu_guid,16)&&!same(g,unknown_guid,16)&&!same(g,nvme_guid,16)&&!same(g,socket_guid,16))return D7_TARGET;
 if(!same(p,g,16))return D7_TARGET;
 size_t at=20;uint32_t current=0;unsigned selected=0,end=0;D7_FORMS found;zero(&found,sizeof(found));
 while(at<n){if(n-at<4)return D7_FORMAT;uint32_t h=u32(p+at),len=h&0xffffff,type=h>>24;
  if(len<4||len>n-at||end)return D7_FORMAT;
  if(type==2){if(current++==index){uint32_t count;if(!forms(p+at,len,&count))return D7_FORMAT;
    found.offset=(uint32_t)at;found.bytes=len;found.form_count=count;ap_sha256(p+at,len,found.sha);selected++;}}
  if(type==0xdf){if(len!=4)return D7_FORMAT;end=1;}
  at+=len;
 }
 if(!end||selected!=1)return D7_FORMAT;copy(r,&found,sizeof(found));return D7_OK;
}
static int cpu_text_shape(const uint8_t *base,const uint8_t *current,size_t n){
 if(n<157||(n-157)%8||!same(base+4,current+4,128)||!same(base+132,current+n-25,25))return 0;
 for(size_t at=132;at<n-25;at+=8)if(current[at]!=3||current[at+1]!=8)return 0;
 return 1;
}
int d7_packet(const D7_META *m,const uint8_t *base,size_t bn,const uint8_t *current,size_t n,uint8_t *out,size_t capacity,D7_RESULT *r){
 if(!r)return D7_FORMAT;zero(r,sizeof(*r));uint32_t count=0;uint8_t actual[32],base_sha[32]={0};
 if(!m||!current||!m->current_hii||!m->artifact_id||!m->observed_instances||m->observed_instances>4096||m->instance_index>=m->observed_instances||
    !nonzero(m->source_log_sha,32)||!nonzero(m->selection_sha,32)||n>UINT32_MAX||!forms(current,n,&count))return D7_FORMAT;
 if((m->kind==D7_KIND_CPU_DELTA&&!same(m->package_guid,cpu_guid,16))||
    (m->kind==D7_KIND_UNKNOWN_RAW&&!same(m->package_guid,unknown_guid,16))||
    (m->kind==D7_KIND_FIXED_DELTA&&!same(m->package_guid,nvme_guid,16)&&!same(m->package_guid,socket_guid,16))||
    (m->kind!=D7_KIND_CPU_DELTA&&m->kind!=D7_KIND_UNKNOWN_RAW&&m->kind!=D7_KIND_FIXED_DELTA))return D7_TARGET;
 ap_sha256(current,n,actual);if(n!=m->expected_length||!same(actual,m->expected_sha,32))return D7_FINGERPRINT;
 uint32_t prefix=0,suffix=0;const uint8_t *body=current;size_t body_n=n;r->flags=D7_DIAGNOSTIC_ONLY;
 if(m->kind!=D7_KIND_UNKNOWN_RAW){
  size_t expected_size=m->kind==D7_KIND_CPU_DELTA?157:same(m->package_guid,nvme_guid,16)?259:135794;
  const uint8_t *expected_sha=m->kind==D7_KIND_CPU_DELTA?cpu_baseline_sha:same(m->package_guid,nvme_guid,16)?nvme_baseline_sha:socket_baseline_sha;
  if(!base||bn!=expected_size)return D7_BASELINE;ap_sha256(base,bn,base_sha);if(!same(base_sha,expected_sha,32))return D7_BASELINE;
  /* Package header length is reconstructed from result length. Difference
   * matching starts after the fixed four-byte type/length header. */
  while(prefix<bn-4&&prefix<n-4&&base[4+prefix]==current[4+prefix])prefix++;
  while(suffix<bn-4-prefix&&suffix<n-4-prefix&&base[bn-1-suffix]==current[n-1-suffix])suffix++;
  body=current+4+prefix;body_n=n-4-prefix-suffix;
  if(m->kind==D7_KIND_CPU_DELTA&&cpu_text_shape(base,current,n))r->flags|=D7_CPU_TEXT_SHAPE;
 }else{
  if(base||bn)return D7_BASELINE;r->flags|=D7_UNKNOWN_CONTENT;
 }
 if(body_n>UINT32_MAX-D7_HEADER_BYTES)return D7_OVERFLOW;
 r->required=D7_HEADER_BYTES+(uint32_t)body_n;r->body_bytes=(uint32_t)body_n;r->prefix=prefix;r->suffix=suffix;r->body_crc=probe_crc32(body,body_n);
 if(!out||capacity<r->required)return D7_NEED_SPACE;
 if(overlap(out,r->required,current,n)||(base&&overlap(out,r->required,base,bn))||overlap(out,r->required,m,sizeof(*m))||overlap(out,r->required,r,sizeof(*r)))return D7_FORMAT;
 zero(out,D7_HEADER_BYTES);copy(out,"AITD07\0\0",8);out[8]=1;out[10]=(uint8_t)m->kind;put32(out+12,D7_HEADER_BYTES);
 put32(out+16,m->artifact_id);put32(out+20,m->package_index);put64(out+24,m->current_hii);copy(out+32,m->package_guid,16);
 copy(out+48,m->source_log_sha,32);copy(out+80,m->selection_sha,32);copy(out+112,base_sha,32);copy(out+144,actual,32);
 put32(out+176,(uint32_t)bn);put32(out+180,(uint32_t)n);put32(out+184,prefix);put32(out+188,suffix);put32(out+192,(uint32_t)body_n);
 put32(out+196,r->body_crc);put32(out+200,r->required);put32(out+204,r->flags);put32(out+208,m->observed_instances);put32(out+212,m->instance_index);
 put32(out+220,probe_crc32(out,220));copy(out+D7_HEADER_BYTES,body,body_n);ap_sha256(out,r->required,r->packet_sha);return D7_OK;
}
size_t d7_b64_size(size_t n){if(n>SIZE_MAX-2||(n+2)/3>SIZE_MAX/4)return 0;return (n+2)/3*4;}
int d7_base64(const uint8_t *p,size_t n,char *out,size_t cap){
 static const char t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";size_t required=d7_b64_size(n);
 if(!p||!out||!n||!required||cap<required||overlap(p,n,out,required))return 0;
 size_t i=0,o=0;while(i<n){size_t left=n-i;uint32_t v=(uint32_t)p[i++]<<16;if(left>1)v|=(uint32_t)p[i++]<<8;if(left>2)v|=p[i++];out[o++]=t[v>>18];out[o++]=t[(v>>12)&63];out[o++]=left>1?t[(v>>6)&63]:'=';out[o++]=left>2?t[v&63]:'=';}
 return 1;
}
