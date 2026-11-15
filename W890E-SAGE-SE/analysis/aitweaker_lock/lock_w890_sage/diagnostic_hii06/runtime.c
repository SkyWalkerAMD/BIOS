#include "runtime.h"
#include "core.h"
#include "memory.h"
#include "password_core.h"
#include "probe_core.h"
static I04_VM vm;
static ST *system_table;static void (*output)(const char *);
static unsigned issues,records,forms_records,extra_bytes,overflow;
static char pending_line[1024];static unsigned pending_count,pending_bad;
typedef struct {HANDLE handle;void *base;uint64_t size;uint32_t matched;uint8_t guid[16];} SEEN;
static SEEN seen[32];
static HANDLE bad_loaded[64];static unsigned bad_count;
static void out(const char *s){
 while(*s){char c=*s++;if(pending_count<sizeof(pending_line)-1)pending_line[pending_count++]=c;else pending_bad=1;
  /* Reserve 192 bytes for the HII06 header/count/overflow status outside records. */
  if(c=='\n'){if(pending_bad||pending_count>8000-extra_bytes)overflow=1;
   else{pending_line[pending_count]=0;output(pending_line);extra_bytes+=pending_count;}pending_count=pending_bad=0;}
 }
}
static void hex(uint64_t v,unsigned count){char b[17];const char *h="0123456789ABCDEF";for(unsigned i=0;i<count;i++)b[i]=h[(v>>(4*(count-i-1)))&15];b[count]=0;out(b);}
static void sha(const uint8_t *p){for(unsigned i=0;i<32;i++)hex(p[i],2);}
static void guid(const GUID *p){hex(p->a,8);out("-");hex(p->b,4);out("-");hex(p->c,4);out("-");for(unsigned i=0;i<8;i++){if(i==2)out("-");hex(p->d[i],2);}}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x<*y?-1:1;x++;y++;}return 0;}
int h6_refresh(void){return system_table&&i04_capture(&vm,system_table);}
int h6_range(const void *p,size_t n){return i04_vm_current(&vm)&&i04_access(&vm,(uintptr_t)p,n,0,0);}
int h6_code(const void *p){return i04_vm_current(&vm)&&i04_access(&vm,(uintptr_t)p,1,0,1);}
int h6_known(const GUID *g){return h6_profile((const uint8_t *)g)!=0;}
void h6_loaded_bad(HANDLE h,const char *reason){
 for(unsigned i=0;i<bad_count;i++)if(bad_loaded[i]==h)return;
 if(bad_count<64)bad_loaded[bad_count++]=h;else{issues++;return;}
 issues++;out("L6 I=");hex((uintptr_t)h,16);out(" E=");out(reason);out("\r\n");
}
static int copy(void *c,uint64_t address,void *dest,size_t n){(void)c;if(!h6_range((void *)(uintptr_t)address,n))return 0;memcpy(dest,(const void *)(uintptr_t)address,n);return 1;}
static void *alloc(void *c,size_t n){(void)c;void *p=0;if(!h6_refresh()||!h6_code(system_table->bs->allocate_pool))return 0;ES e=system_table->bs->allocate_pool(4,n,&p);if(e||!p||!h6_refresh()||!h6_range(p,n))return 0;return p;}
static int release(void *c,void *p){(void)c;return h6_refresh()&&h6_code(system_table->bs->free_pool)&&system_table->bs->free_pool(p)==0;}
int h6_begin(ST *st,void (*emit)(const char *)){
 memset(&vm,0,sizeof(vm));memset(seen,0,sizeof(seen));memset(bad_loaded,0,sizeof(bad_loaded));system_table=st;output=emit;issues=records=forms_records=extra_bytes=overflow=pending_count=pending_bad=bad_count=0;
 output("HII06_FINGERPRINTS_DIAGNOSTIC_NOT_AUTHORITY\r\n");
 if(!h6_refresh()){issues++;output("H6.MAP=REFUSED\r\n");return 0;}
 return 1;
}
void h6_module(HANDLE handle,const LOADED *li,const GUID *g){
 if(!h6_range(li,sizeof(*li))){issues++;out("M6=LOADED_RANGE\r\n");return;}
 LOADED snapshot;memcpy(&snapshot,li,sizeof(snapshot));
 for(unsigned i=0;i<records;i++)if(seen[i].handle==handle){
  if(seen[i].base!=snapshot.image_base||seen[i].size!=snapshot.image_size){issues++;out("M6=CHANGED\r\n");}return;
 }
 if(records==32){issues++;out("M6=LIMIT\r\n");return;}
 SEEN *s=seen+records++;s->handle=handle;s->base=snapshot.image_base;s->size=snapshot.image_size;if(g)memcpy(s->guid,g,16);
 H6_HOST host={0,copy,alloc,release};H6_RESULT result;const H6_PROFILE *p=g?h6_profile((const uint8_t *)g):0;
 h6_probe(&host,(uintptr_t)snapshot.image_base,snapshot.image_size,p,&result);
 if(!h6_refresh()||!h6_range(li,sizeof(*li))||memcmp(li,&snapshot,sizeof(snapshot)))result.status=H6_CHANGED;
 s->matched=(result.status==H6_OK);
 out("M6 I=");hex((uintptr_t)handle,16);out(" B=");hex((uintptr_t)snapshot.image_base,16);out(" Z=");hex(snapshot.image_size,8);out(" G=");if(g)guid(g);else out("NONFV");
 out(" T=");hex(result.text_rva,8);out(":");hex(result.text_size,8);
 out(" R=");if(result.raw_valid)sha(result.raw);else out("-");
 out(" N=");if(result.normalized_valid)sha(result.normalized);else out("-");
 out(" C=");out(h6_status(result.status));out("\r\n");
 if(result.status!=H6_OK)issues++;
 if(!g){
  uint8_t path[1024];size_t used=0;int valid=0;
  while(used+4<=sizeof(path)){
   if(!snapshot.filepath||!copy(0,(uintptr_t)snapshot.filepath+used,path+used,4))break;
   unsigned n=path[used+2]|((unsigned)path[used+3]<<8);if(n<4||n>sizeof(path)-used||!copy(0,(uintptr_t)snapshot.filepath+used,path+used,n))break;
   unsigned type=path[used],sub=path[used+1];used+=n;if(type==0x7f&&sub==0xff&&n==4){valid=1;break;}
  }
  out("D6 I=");hex((uintptr_t)handle,16);out(" P=");if(valid){uint8_t d[32];ap_sha256(path,used,d);sha(d);}else out("UNKNOWN");out("\r\n");
 }
}
void h6_forms(HANDLE handle,const void *buffer,size_t bytes){
 if(!h6_range(buffer,bytes)){issues++;out("F6=BUFFER_RANGE\r\n");return;}
 HII_INFO info;if(!probe_hii(buffer,bytes,&info)){issues++;out("F6=PARSE\r\n");return;}
 const uint8_t *p=buffer;size_t pos=20;unsigned index=0;
 while(pos<bytes){uint32_t len=p[pos]|((uint32_t)p[pos+1]<<8)|((uint32_t)p[pos+2]<<16);uint8_t type=p[pos+3];
  if(type==2){uint8_t digest[32];ap_sha256(p+pos,len,digest);
   out("F6 H=");hex((uintptr_t)handle,16);out(" G=");guid((const GUID *)p);out(" P=");hex(index++,4);out(" L=");hex(len,8);out(" S=");sha(digest);out("\r\n");forms_records++;
  }pos+=len;
 }
}
int h6_null_driver(HANDLE h,const GUID *g){
 static const GUID cpu={0xdbf338fe,0x93be,0x46d6,{0xad,0xf5,0xc1,0x7c,0x22,0x36,0xd8,0x38}};
 if(memcmp(g,&cpu,16))return 0;
 static const uint8_t producer[16]={0x80,0xff,0x0b,0xee,0x33,0x2b,0x05,0x40,0x8e,0xf1,0x3f,0x9b,0x23,0xc2,0x51,0x36};
 unsigned found=0;uint64_t saved=0;
 for(unsigned i=0;i<records;i++)if(seen[i].matched&&!memcmp(seen[i].guid,producer,16)){
  uint64_t value=0;if(seen[i].size>=0x3540&&copy(0,(uintptr_t)seen[i].base+0x3538,&value,8)){saved=value;found++;}
 }
 out("C6 H=");hex((uintptr_t)h,16);out(" DRIVER=NULL_ORIGINAL S=");
 if(found==1&&saved==(uintptr_t)h)out("SAVED_HANDLE_MATCH");else{out("UNKNOWN");issues++;}out("\r\n");return 1;
}
unsigned h6_end(void){
 if(overflow){output("H6.EXTRA=OVER_BUDGET_PARTIAL\r\n");issues++;}
 output("H6.RECORDS=");char n[17];const char *h="0123456789ABCDEF";uint64_t v=((uint64_t)records<<32)|forms_records;
 for(unsigned i=0;i<16;i++)n[i]=h[(v>>(60-4*i))&15];n[16]=0;output(n);output("\r\n");
 return issues;
}
