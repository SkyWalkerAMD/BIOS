#include "policy04.h"
#include "../password/w890_policy.h"
#include "catalog04.inc"
static void zero(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *p,const void *q,size_t n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;}
static int equal(const void *p,const void *q,size_t n){const uint8_t *a=p,*b=q;uint8_t x=0;while(n--)x|=*a++^*b++;return !x;}
static uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t *p){return u16(p)|((uint32_t)u16(p+2)<<16);}
static size_t namelen(const uint16_t *p){if(!p)return 40;size_t n=0;while(n<40&&p[n])n++;return n;}
static int samename(const uint16_t *a,const uint16_t *b){size_t n=namelen(a);return n&&n<40&&n==namelen(b)&&equal(a,b,2*n);}
WS_API int ws04_known(const uint8_t g[16],const uint16_t n[40],uint32_t attrs,uint32_t size){
 if(!g||!n||!size||size>WS_MAX_VARIABLE_BYTES||namelen(n)>=40)return 0;
 for(size_t i=0;i<sizeof(ws_catalog)/sizeof(ws_catalog[0]);i++)if(equal(g,ws_catalog[i].guid,16)&&samename(n,ws_catalog[i].name)&&attrs==ws_catalog[i].attrs&&size==ws_catalog[i].size)return 1;
 return 0;
}
WS_API int ws04_descriptor(const uint8_t d[124],WS_INTENT *out){
 if(!d||!out)return WS_INVALID;zero(out,sizeof(*out));copy(out->guid,d,16);copy(out->name,d+16,80);
 out->attributes=u32(d+0x60);out->size=u16(d+0x78);
 if(!namelen(out->name)||namelen(out->name)==40)return WS_INVALID;
 return ws04_known(out->guid,out->name,out->attributes,out->size)?WS_SAFE:WS_UNKNOWN;
}
static int provider_live(uint32_t f){return(f&3u)==3u&&!(f&112u)&&!(f&~127u)&&(f&12u)!=12u;}
static int classify(const WS_INTENT *v,int *changed,int *protected_change){
 if(!v||v->reserved||!v->before||!v->after||v->size!=v->old_size||v->attributes!=v->old_attributes||
    !ws04_known(v->guid,v->name,v->attributes,v->size))return WS_UNKNOWN;
 if(v->route!=WS_SET_VARIABLE&&v->route!=WS_SETUP_ROUTE)return WS_UNKNOWN;
 int kind=w890_variable_change(v->name,namelen(v->name),v->guid,v->old_attributes,v->before,v->old_size,v->attributes,v->after,v->size);
 if(kind==W890_UNKNOWN||kind==W890_CREDENTIAL)return WS_UNKNOWN;
 *changed=!equal(v->before,v->after,v->size);*protected_change=kind==W890_PROTECTED;return WS_SAFE;
}
WS_API int ws04_preflight(const WS_INTENT *v,size_t n,uint32_t flags,WS_RESULT *out){
 WS_RESULT r={WS_SAFE,0xffffffffu,0,0};if(!out)return WS_INVALID;
 if(!v||!n||n>WS_MAX_BATCH||!provider_live(flags)){r.result=WS_DENIED;*out=r;return r.result;}
 for(size_t i=0;i<n;i++){
  int changed=0,protected_change=0;int result=classify(v+i,&changed,&protected_change);
  if(result!=WS_SAFE){r.result=(uint32_t)result;r.first_rejected=(uint32_t)i;break;}
  for(size_t j=0;j<i;j++)if(equal(v[i].guid,v[j].guid,16)&&samename(v[i].name,v[j].name)){
   if(v[i].size!=v[j].size||v[i].attributes!=v[j].attributes||v[i].route!=v[j].route||
      !equal(v[i].before,v[j].before,v[i].size)||!equal(v[i].after,v[j].after,v[i].size)){
    r.result=WS_UNKNOWN;r.first_rejected=(uint32_t)i;break;
   }
  }
  if(r.result!=WS_SAFE)break;r.changed+=(uint32_t)changed;r.protected_changed+=(uint32_t)protected_change;
  if(protected_change&&!(flags&12u)){r.result=WS_DENIED;r.first_rejected=(uint32_t)i;break;}
 }
 *out=r;return(int)r.result;
}
static int hex(uint16_t c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int token(const uint16_t *s,size_t n,size_t *at,const char *want){size_t k=*at;for(;*want;want++,k++)if(k>=n||s[k]!=(uint8_t)*want)return 0;*at=k;return 1;}
static int digits(const uint16_t *s,size_t n,size_t *at,size_t count,uint64_t *value){
 if(count>16||*at>n||count>n-*at)return 0;uint64_t v=0;for(size_t i=0;i<count;i++){int h=hex(s[*at+i]);if(h<0)return 0;v=(v<<4)|(unsigned)h;}*at+=count;*value=v;return 1;
}
static int number(const uint16_t *s,size_t n,size_t *at,uint64_t *v){size_t k=*at,count=0;while(k+count<n&&hex(s[k+count])>=0)count++;return count&&digits(s,n,at,count,v);}
static int path_syntax(const uint16_t *s,size_t begin,size_t end){
 size_t at=begin;unsigned nodes=0;
 while(at<end){uint64_t t,sub,lo,hi;size_t node=at;
  if(++nodes>256||!digits(s,end,&at,2,&t)||!digits(s,end,&at,2,&sub)||!digits(s,end,&at,2,&lo)||!digits(s,end,&at,2,&hi))return 0;
  size_t bytes=(size_t)(lo|(hi<<8));if(bytes<4||bytes>(end-node)/2)return 0;
  if(t==0x7f)return sub==0xff&&bytes==4&&node+8==end;
  if(t<1||t>5)return 0;at=node+bytes*2;
 }
 return 0;
}
WS_API int ws04_route_header(const uint16_t *s,size_t n,uint8_t guid[16],uint16_t name[40],size_t *blocks){
 size_t at=0;uint64_t v;if(!s||!guid||!name||!blocks||n<48||n>WS_MAX_CONFIG_UNITS||s[n-1])return WS_INVALID;
 zero(guid,16);zero(name,80);*blocks=0;if(!token(s,n,&at,"GUID="))return WS_INVALID;
 for(unsigned i=0;i<16;i++){if(!digits(s,n,&at,2,&v))return WS_INVALID;guid[i]=(uint8_t)v;}
 if(!token(s,n,&at,"&NAME="))return WS_INVALID;size_t names=0;
 while(at<n&&s[at]!='&'){if(names>=39||!digits(s,n,&at,4,&v)||!v)return WS_INVALID;name[names++]=(uint16_t)v;}
 if(!names||!token(s,n,&at,"&PATH="))return WS_INVALID;
 size_t start=at;while(at<n&&hex(s[at])>=0)at++;
 if(at==start||((at-start)&1u)||at-start>4096||at>=n||s[at]!='&'||!path_syntax(s,start,at))return WS_INVALID;
 *blocks=at;return WS_SAFE;
}
WS_API int ws04_route_apply(const uint16_t *s,size_t n,size_t blocks,const uint8_t *before,size_t size,uint8_t *after,size_t cap){
 if(!s||!before||!after||!size||size>WS_MAX_VARIABLE_BYTES||cap<size||!n||n>WS_MAX_CONFIG_UNITS||s[n-1]||blocks>=n)return WS_INVALID;
 uintptr_t b=(uintptr_t)before,a=(uintptr_t)after,t=(uintptr_t)s;
 if(b>UINTPTR_MAX-size||a>UINTPTR_MAX-size||t>UINTPTR_MAX-n*2||(a<b+size&&b<a+size)||(a<t+n*2&&t<a+size))return WS_INVALID;
 /* Parse twice: the first pass validates all ranges and rejects overlap
  * before touching output. No partial output on any malformed later block. */
 uint32_t ranges[256][2];size_t count=0,at=blocks;
 while(at<n-1){uint64_t off,width;
  if(count==256||!token(s,n,&at,"&OFFSET=")||!number(s,n,&at,&off)||!token(s,n,&at,"&WIDTH=")||!number(s,n,&at,&width)||
     !token(s,n,&at,"&VALUE=")||!width||off>=size||width>size-off||width>(n-at)/2)return WS_INVALID;
  for(size_t j=0;j<count;j++)if(off<ranges[j][0]+ranges[j][1]&&ranges[j][0]<off+width)return WS_INVALID;
  ranges[count][0]=(uint32_t)off;ranges[count][1]=(uint32_t)width;count++;
  for(uint64_t j=0;j<width*2;j++)if(hex(s[at+j])<0)return WS_INVALID;at+=(size_t)width*2;
  if(at<n-1&&s[at]!='&')return WS_INVALID;
 }
 if(!count||at!=n-1)return WS_INVALID;copy(after,before,size);at=blocks;
 for(size_t i=0;i<count;i++){uint64_t off,width,v;
  if(!token(s,n,&at,"&OFFSET=")||!number(s,n,&at,&off)||!token(s,n,&at,"&WIDTH=")||!number(s,n,&at,&width)||!token(s,n,&at,"&VALUE="))return WS_INVALID;
  for(uint64_t j=0;j<width;j++){if(!digits(s,n,&at,2,&v))return WS_INVALID;after[off+width-1-j]=(uint8_t)v;}
 }
 return WS_SAFE;
}
WS_API size_t ws04_intent_bytes(void){return sizeof(WS_INTENT);}
