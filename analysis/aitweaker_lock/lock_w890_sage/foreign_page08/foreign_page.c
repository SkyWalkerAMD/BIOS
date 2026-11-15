#include "foreign_page.h"
#include "../password/w890_policy.h"
#define PKG_CAP (8u*1024u*1024u)
#define MAX_NATIVE_OFFSET (16u*1024u*1024u)
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
typedef struct {uint32_t offset;uint16_t form,fs;uint8_t control;int8_t risk;uint16_t flags;} FP08_RECORD;
typedef struct {uint8_t hash[32];uint32_t bytes;const uint8_t (*fs)[16];uint32_t fs_count;const FP08_RECORD *records;uint32_t record_count;} FP08_PACKAGE;
#include "scope_data.h"
static uint8_t package_buffer[PKG_CAP];
static uint32_t busy;
static const uint8_t setup_fs[16]={0x4a,0x10,0x59,0x7b,0x0d,0xc0,0x58,0x41,0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15};
static const uint8_t setup_list[16]={0xd7,0x07,0x94,0x89,0xfe,0x99,0xd8,0x43,0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21};
static void cp(void *d,const void *s,UN n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
static void zero(void *d,UN n){uint8_t *a=d;while(n--)*a++=0;}
static int eq(const void*a,const void*b,UN n){const uint8_t*x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint16_t u16(const void*p){const uint8_t*b=p;return(uint16_t)(b[0]|(uint16_t)b[1]<<8);}
static uint32_t u32(const void*p){const uint8_t*b=p;return(uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static uintptr_t ptr(const void*p){uintptr_t v;cp(&v,p,sizeof(v));return v;}
static int range(uintptr_t p,UN n){return p>=4096&&n&&n<=UINTPTR_MAX-p&&no_range(p,n,NO_READ);}
static int add(uintptr_t p,UN n,uintptr_t *v){if(n>UINTPTR_MAX-p)return 0;*v=p+n;return 1;}
typedef struct {NO_IDENTITY id;uint64_t visit,generation;uint32_t restricted;HII database;} ANCHOR;
typedef struct {
 uintptr_t app,array,page,raw,table,blob,cb,hii,control,opcode,vtable;
 uint32_t index,current,count,table_count,raw_count,var_id,qid;
 uint16_t form,type;uint32_t opcode_bytes;uint8_t ifr[127];
} NATIVE;
static int anchor(ANCHOR *a){
 zero(a,sizeof(*a));
 if(!no_identity(&a->id)||!no_native_visit_identity(&a->visit,&a->restricted)||!no_catalog_generation(&a->generation)||
    !a->visit||a->id.fault||a->id.ended||!a->id.loop_depth||!a->id.database||
    a->id.tse_base>UINTPTR_MAX-0xde000u||!range((uintptr_t)a->id.database,sizeof(HII)))return 0;
 cp(&a->database,a->id.database,sizeof(HII));return a->database.export_list!=0;
}
static int stable(const ANCHOR*a,const ANCHOR*b){
 const NO_IDENTITY*x=&a->id,*y=&b->id;
 return x->st==y->st&&x->database==y->database&&x->hii==y->hii&&x->setup_driver==y->setup_driver&&
        x->tse_driver==y->tse_driver&&x->config==y->config&&x->setup_base==y->setup_base&&x->tse_base==y->tse_base&&
        x->setup_size==y->setup_size&&x->tse_size==y->tse_size&&x->epoch==y->epoch&&x->loop_depth==y->loop_depth&&
        x->send_depth==y->send_depth&&x->fault==y->fault&&x->ended==y->ended&&a->visit==b->visit&&a->generation==b->generation&&
        a->restricted==b->restricted&&eq(&a->database,&b->database,sizeof(HII));
}
static int global(const ANCHOR*a,uint32_t rva,uintptr_t*v){uintptr_t at=a->id.tse_base+rva;if(!range(at,8))return 0;*v=ptr((void*)at);return 1;}
static int page_native(const ANCHOR*a,uintptr_t page,uint32_t index,NATIVE*n){
 zero(n,sizeof(*n));uintptr_t at;
 if(!global(a,0xafdd0,&n->app)||!range(n->app,0x60))return 0;
 n->count=u32((void*)(n->app+0x2c));n->current=u32((void*)(n->app+0x28));n->array=ptr((void*)(n->app+0x30));
 if(!n->count||n->count>4096||n->current>=n->count||!range(n->array,8u*n->count))return 0;
 unsigned found=0;for(uint32_t i=0;i<n->count;i++)if(ptr((void*)(n->array+8u*i))==page){n->index=i;found++;}
 if(found!=1||(index!=UINT32_MAX&&index!=n->index)||!range(page,0x68)||u16((void*)(page+0x30))!=n->index)return 0;
 n->page=page;n->hii=ptr((void*)(page+0x20));n->form=u16((void*)(page+0x2a));
 if(!n->hii||!n->form||!global(a,0xbaaf0,&n->table)||!global(a,0xbabc0,&n->blob)||!global(a,0xbab08,&n->cb)||!range(n->table,4))return 0;
 n->table_count=u32((void*)n->table);
 if(!n->table_count||n->table_count>4096||n->index>=n->table_count||!range(n->table,4+4u*n->table_count))return 0;
 uint32_t off=u32((void*)(n->table+4+4u*n->index));
 if(off>MAX_NATIVE_OFFSET||!add(n->blob,off,&at)||!range(at,0x20))return 0;n->raw=at;
 if(ptr((void*)at)!=n->hii||u16((void*)(at+0xa))!=n->form)return 0;
 n->raw_count=u32((void*)(at+0x1c));
 return n->raw_count<=4096&&range(at,0x20+4u*n->raw_count);
}
static int control_native(const ANCHOR*a,NATIVE*n,uintptr_t control){
 if(n->index!=n->current||!control||!range(control,0x60))return 0;
 uint32_t nf=u32((void*)(n->page+0x4c));uintptr_t fa=ptr((void*)(n->page+0x50));unsigned found=0;
 if(!nf||nf>64||!range(fa,8u*nf))return 0;
 for(uint32_t i=0;i<nf;i++){
  uintptr_t f=ptr((void*)(fa+8u*i));if(!range(f,0x50))return 0;
  uint32_t nc=u32((void*)(f+0x3c));uintptr_t ca=ptr((void*)(f+0x48));if(nc>4096||(nc&&!range(ca,8u*nc)))return 0;
  for(uint32_t j=0;j<nc;j++)if(ptr((void*)(ca+8u*j))==control)found++;
 }
 if(found!=1||ptr((void*)(control+0x20))!=n->hii)return 0;
 n->control=control;n->type=u16((void*)(control+0x34));n->vtable=ptr((void*)control);
 n->var_id=u32((void*)(control+0x28));n->qid=u32((void*)(control+0x2c));
 static const uint32_t types[][2]={{14,0x95680},{1,0xa5520},{2,0xa51f0},{3,0xa5250},{19,0xa5190},{4,0xa5380},{5,0xa5440},{6,0x93f90},{10,0x93f90},{8,0x93ff0},{11,0xa52c0},{15,0xa53e0},{13,0xa54c0},{27,0x95620},{28,0xa5320}};
 found=0;for(unsigned i=0;i<COUNT(types);i++)if(n->type==types[i][0]&&n->vtable==a->id.tse_base+types[i][1])found++;
 if(found!=1)return 0;n->opcode=ptr((void*)(control+0x48));if(!range(n->opcode,2))return 0;
 n->opcode_bytes=((uint8_t*)n->opcode)[1]&127;
 if(n->opcode_bytes<2||!range(n->opcode,n->opcode_bytes))return 0;
 cp(n->ifr,(void*)n->opcode,n->opcode_bytes);found=0;
 for(uint32_t i=0;i<n->raw_count;i++){
  uint32_t off=u32((void*)(n->raw+0x20+4u*i));uintptr_t d;
  if(off>MAX_NATIVE_OFFSET||!add(n->cb,off,&d)||!range(d,0x40))return 0;
  if(ptr((void*)d)==n->hii&&u16((void*)(d+0x14))==n->type&&ptr((void*)(d+0x28))==n->opcode&&
     u32((void*)(d+8))==n->var_id&&u32((void*)(d+0xc))==n->qid)found++;
 }
 return found==1;
}
static const FP08_PACKAGE*catalog(const uint8_t*forms,uint32_t bytes,uint8_t hash[32]){
 unsigned size_matches=0;for(unsigned i=0;i<COUNT(packages);i++)if(packages[i].bytes==bytes)size_matches++;
 if(!size_matches)return 0;ap_sha256(forms,bytes,hash);const FP08_PACKAGE*p=0;
 for(unsigned i=0;i<COUNT(packages);i++)if(packages[i].bytes==bytes&&eq(packages[i].hash,hash,32)){if(p)return 0;p=&packages[i];}return p;
}
static const FP08_RECORD*record(const FP08_PACKAGE*p,const uint8_t*fs,uint16_t form,uint32_t off,unsigned control){
 if(!p)return 0;unsigned fi=p->fs_count;for(unsigned i=0;i<p->fs_count;i++)if(eq(p->fs[i],fs,16)){if(fi!=p->fs_count)return 0;fi=i;}
 if(fi==p->fs_count)return 0;uint32_t lo=0,hi=p->record_count;
 while(lo<hi){uint32_t mid=lo+(hi-lo)/2;if(p->records[mid].offset<off)lo=mid+1;else hi=mid;}
 if(lo==p->record_count)return 0;const FP08_RECORD*r=&p->records[lo];
 return r->offset==off&&r->fs==fi&&r->form==form&&r->control==control?r:0;
}
typedef struct {const uint8_t*fs;uint16_t form;} SCOPE;
static int parse_forms(const uint8_t*b,uint32_t bytes,const NATIVE*n,int setup,FP08_VIEW*v,unsigned*total,uint8_t seen_fs[64][16],unsigned*fs_count){
 uint8_t hash[32]={0};const FP08_PACKAGE*p=catalog(b,bytes,hash);
 const uint8_t*fs=0;uint16_t form=0;SCOPE stack[128];unsigned depth=0,form_matches=0,op_matches=0;
 FP08_VIEW hit;zero(&hit,sizeof(hit));hit.classification=FP08_UNKNOWN;int page_risk=FP08_UNKNOWN;
 for(uint32_t at=4;at<bytes;){
  if(bytes-at<2)return 0;const uint8_t*o=b+at;unsigned len=o[1]&127,sc=o[1]>>7;
  if(len<2||len>bytes-at)return 0;
  SCOPE previous={fs,form};
  if(o[0]==0x0e){if(len<23||!sc||depth||fs||form||*fs_count>=64)return 0;fs=o+2;
   for(unsigned i=0;i<*fs_count;i++)if(eq(seen_fs[i],fs,16))return 0;
   cp(seen_fs[*fs_count],fs,16);(*fs_count)++;
  }
  else if(o[0]==1){if(len!=6||!sc||!fs||form)return 0;form=u16(o+2);
   if(form==n->form){
    form_matches++;hit.form=form;hit.form_offset=at;cp(hit.formset,fs,16);cp(hit.forms_sha256,hash,32);
    if((setup&&!eq(fs,setup_fs,16))||(!setup&&eq(fs,setup_fs,16)))return 0;
    const FP08_RECORD*r=record(p,fs,form,at,0);
    if(r){hit.classification=r->risk;hit.review_flags=r->flags;
     if(setup){int c=w890_classify_form(fs,form);hit.classification=c;}
    }page_risk=hit.classification;
   }
  }
  if(n->control&&fs&&form==n->form&&len==n->opcode_bytes&&eq(o,n->ifr,len)){
   const FP08_RECORD*r=record(p,fs,form,at,1);int risk=FP08_UNKNOWN;uint32_t flags=16;
   if(r){risk=r->risk;flags=r->flags;
    if(setup&&w890_classify_control(fs,form,o,len)==W890_PROTECTED)risk=FP08_PROTECTED;
   }else if(p&&(o[0]==2||o[0]==3)){const FP08_RECORD*f=record(p,fs,form,hit.form_offset,0);if(f){risk=f->risk;flags=f->flags;}}
   if(page_risk==FP08_PROTECTED||risk==FP08_PROTECTED)risk=FP08_PROTECTED;
   else if(page_risk==FP08_UNKNOWN)risk=FP08_UNKNOWN;
   if(!op_matches){hit.classification=risk;hit.ifr_offset=at;hit.review_flags=flags;}
   else if(hit.classification!=risk)hit.classification=FP08_UNKNOWN;
   hit.review_flags|=flags;op_matches++;
  }
  if(o[0]==0x29){if(len!=2||sc||!depth)return 0;SCOPE old=stack[--depth];fs=old.fs;form=old.form;}
  else if(sc){if(depth>=COUNT(stack))return 0;stack[depth++]=previous;}
  at+=len;
 }
 if(depth||fs||form||form_matches>1)return 0;
 if(form_matches){if(n->control&&!op_matches)return 0;if(++*total!=1)return 0;
  v->classification=hit.classification;v->review_flags=hit.review_flags;v->form_offset=hit.form_offset;v->ifr_offset=hit.ifr_offset;
  cp(v->formset,hit.formset,16);cp(v->forms_sha256,hit.forms_sha256,32);
 }
 return 1;
}
static int describe(uintptr_t page,uint32_t index,uintptr_t control,FP08_VIEW*out){
 if(!out||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE))return 0;
 uint32_t expected=0;if(!__atomic_compare_exchange_n(&busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))return 0;
 int ok=0;ANCHOR a,b;NATIVE n,m;FP08_VIEW v;zero(&v,sizeof(v));v.classification=FP08_UNKNOWN;
 if(!anchor(&a)||!page_native(&a,page,index,&n)||(control&&!control_native(&a,&n,control)))goto done;
 UN bytes=sizeof(package_buffer);ES r=a.database.export_list(a.id.database,(HANDLE)n.hii,&bytes,package_buffer);
 if(FAILED(r)||bytes<24||bytes>sizeof(package_buffer)||u32(package_buffer+16)!=bytes||!anchor(&b)||!stable(&a,&b))goto done;
 int setup=n.hii==(uintptr_t)a.id.hii;
 if((setup&&!eq(package_buffer,setup_list,16))||(!setup&&eq(package_buffer,setup_list,16)))goto done;
 unsigned total=0,end=0,fs_count=0;uint8_t seen_fs[64][16];UN at=20;
 while(at<bytes){
  if(bytes-at<4)goto done;uint32_t h=u32(package_buffer+at),len=h&0xffffff;unsigned type=h>>24;
  if(len<4||len>bytes-at||end)goto done;
  if(type==2&&!parse_forms(package_buffer+at,len,&n,setup,&v,&total,seen_fs,&fs_count))goto done;
  if(type==0xdf){if(len!=4||at+4!=bytes)goto done;end++;}
  at+=len;
 }
 if(!end||total!=1||!anchor(&b)||!stable(&a,&b)||!page_native(&b,page,index,&m)||
    (control&&!control_native(&b,&m,control))||!eq(&n,&m,sizeof(n)))goto done;
 v.revision=FP08_REVISION;v.size=sizeof(v);v.visit=a.visit;v.epoch=a.id.epoch;v.catalog_generation=a.generation;
 v.native_base=a.id.tse_base;v.application=n.app;v.page=n.page;v.raw_page=n.raw;v.hii=n.hii;v.control=n.control;
 v.page_index=n.index;v.application_index=n.current;v.owner=setup?WG_OWNER_SETUP:WG_OWNER_FOREIGN;
 v.form=n.form;v.native_type=n.type;v.ifr_size=n.opcode_bytes;cp(v.ifr,n.ifr,n.opcode_bytes);cp(v.package_list_guid,package_buffer,16);
 cp(out,&v,sizeof(v));ok=1;
done:
 __atomic_store_n(&busy,0,__ATOMIC_RELEASE);return ok;
}
int EA fp08_describe_page(uintptr_t page,uint32_t index,FP08_VIEW*out){return describe(page,index,0,out);}
int EA fp08_describe_control(uintptr_t page,uintptr_t control,FP08_VIEW*out){return describe(page,UINT32_MAX,control,out);}
size_t EA fp08_view_bytes(void){return sizeof(FP08_VIEW);}
