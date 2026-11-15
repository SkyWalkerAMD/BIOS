/* Read-only, exact-build DXE dispatch inventory. Never invokes the dispatcher,
 * LoadImage, StartImage, Schedule, Trust, SetVariable, a BMC or PCI operation.
 * Actual 3107 DxeCore code/layout evidence is in code-identity.json and *.asm.
 * Status bits record dispatcher history, not a successful driver entrypoint. */
#include "dxe_state_probe.h"
#include "dxe_core_anchors.h"
static uint64_t u64(const uint8_t *p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static uint32_t u32(const uint8_t *p){uint32_t v=0;for(unsigned i=0;i<4;i++)v|=(uint32_t)p[i]<<(8*i);return v;}
static int same(const void *a,const void *b,size_t n){const uint8_t *p=a,*q=b;for(size_t i=0;i<n;i++)if(p[i]!=q[i])return 0;return 1;}
static void zero(void *a,size_t n){uint8_t *p=a;for(size_t i=0;i<n;i++)p[i]=0;}
static void copy(void *a,const void *b,size_t n){uint8_t *p=a;const uint8_t *q=b;for(size_t i=0;i<n;i++)p[i]=q[i];}
static const GUID target[2]={
 {0x89924765,0xf984,0x4ad3,{0x83,0x9b,0x51,0xfd,0xce,0x37,0x8d,0x88}},
 {0x261135b0,0x7b73,0x49c0,{0xbc,0xc8,0x2f,0x9c,0xf4,0xee,0xf1,0x9e}}
};
static int finish(DX_RESULT *r,int status){r->status=(uint32_t)status;r->complete=status==DX_OK;return status;}

int dx_state_snapshot(DX_READ read,void *ctx,uint64_t load,uint64_t start,DX_RESULT *r){
 uint8_t buf[1024],initial[16],raw[0x90],again[0x90],run;
 uint64_t node,prev;
 if(!read||!r)return DX_ARGUMENT;zero(r,sizeof(*r));
 if(load<0x75b8||start<0x76b8||(load-0x75b8)!=(start-0x76b8))return finish(r,DX_IDENTITY);
 uint64_t base=load-0x75b8;
 if(!base||base>UINT64_MAX-0x1b300)return finish(r,DX_IDENTITY);
 r->core_base=base;r->list_head=base+0x16c10;
 for(unsigned i=0;i<sizeof(dx_anchors)/sizeof(dx_anchors[0]);i++){
  const DX_ANCHOR *a=&dx_anchors[i];
  if(a->bytes>sizeof(buf)||!read(ctx,base+a->rva,buf,a->bytes,DX_CODE)||!same(buf,a->p,a->bytes))return finish(r,DX_IDENTITY);
 }
 r->code_identity=1;
 if(!read(ctx,base+0x17bd8,&run,1,DX_DATA))return finish(r,DX_UNREADABLE);
 r->running=run;if(run)return finish(r,DX_RUNNING);
 if(!read(ctx,r->list_head,initial,16,DX_DATA))return finish(r,DX_UNREADABLE);
 node=u64(initial);prev=r->list_head;
 while(node!=r->list_head){
  if(r->nodes>=DX_MAX_NODES)return finish(r,DX_LIMIT);
  if(node<8||node%8)return finish(r,DX_BAD_LIST);
  for(unsigned i=0;i<r->nodes;i++)if(r->visited[i]==node)return finish(r,DX_BAD_LIST);
  r->visited[r->nodes]=node;
  if(!read(ctx,node-8,raw,sizeof(raw),DX_DATA)||!read(ctx,node-8,again,sizeof(again),DX_DATA))return finish(r,DX_UNREADABLE);
  if(!same(raw,again,sizeof(raw)))return finish(r,DX_CHANGED);
  if(u64(raw)!=0x72767264||u64(raw+0x10)!=prev)return finish(r,DX_BAD_LIST);
  const unsigned flags[]={0x60,0x61,0x74,0x75,0x76,0x77,0x78,0x79,0x88};
  for(unsigned i=0;i<sizeof(flags)/sizeof(flags[0]);i++)if(raw[flags[i]]>1)return finish(r,DX_BAD_LIST);
  r->nodes++;r->dependent+=raw[0x74];r->unrequested+=raw[0x75];r->scheduled+=raw[0x76];r->untrusted+=raw[0x77];r->initialized+=raw[0x78];r->depex_error+=raw[0x79];
  for(unsigned j=0;j<2;j++)if(same(raw+0x30,&target[j],16)){
   r->target_count[j]++;if(r->matches>=DX_MAX_MATCHES)return finish(r,DX_LIMIT);
   DX_MATCH *m=&r->match[r->matches++];m->which=j;m->address=node-8;copy(m->raw,raw,sizeof(raw));
   uint64_t dp=u64(raw+0x50),dn=u64(raw+0x58);
   if(dp&&dn&&dn<=sizeof(m->depex)){
    m->depex_bytes=(uint32_t)dn;
    m->depex_readable=read(ctx,dp,m->depex,(size_t)dn,DX_DATA)!=0;
   }
  }
  prev=node;node=u64(raw+8);
 }
 if(u64(initial+8)!=prev)return finish(r,DX_BAD_LIST);
 if(!read(ctx,r->list_head,buf,16,DX_DATA)||!read(ctx,base+0x17bd8,&run,1,DX_DATA))return finish(r,DX_UNREADABLE);
 if(run||!same(initial,buf,16))return finish(r,DX_CHANGED);
 for(unsigned i=0;i<r->matches;i++)if(!read(ctx,r->match[i].address,raw,sizeof(raw),DX_DATA)||!same(raw,r->match[i].raw,sizeof(raw)))return finish(r,DX_CHANGED);
 return finish(r,DX_OK);
}

/* Only allocated BootServices code/data. MMIO, RP, conventional/free and other
 * types are deliberately rejected. Cross-descriptor spans are validated. */
int dx_range(const uint8_t *map,size_t bytes,size_t stride,uint64_t at,size_t n,unsigned code){
 if(!map||!bytes||bytes>65536||stride<40||stride>256||stride%8||bytes%stride||bytes/stride>2048||!at||!n||at+(uint64_t)n<at)return 0;
 uint64_t end=at+(uint64_t)n;unsigned spans=0;
 while(at<end&&spans++<=2048){
  uint64_t advance=at;
  for(size_t off=0;off<bytes;off+=stride){
   const uint8_t *p=map+off;uint32_t type=u32(p);uint64_t begin=u64(p+8),pages=u64(p+24),attr=u64(p+32);
   if((code?type!=3:(type!=3&&type!=4))||(attr&0x2000)||!pages||pages>(UINT64_MAX-begin)/4096)continue;
   uint64_t limit=begin+pages*4096;if(at>=begin&&at<limit&&limit>advance)advance=limit;
  }
  if(at==advance)return 0;at=advance<end?advance:end;
 }
 return at==end;
}
typedef ES (EA *GET_MAP)(UN *,void *,UN *,UN *,uint32_t *);
static uint64_t map_buffer[65536/8];
static DX_RESULT result;
static unsigned busy;
typedef struct {size_t bytes,stride;DX_APPEND append;void *ctx;} DX_ENV;
static int actual_read(void *ctx,uint64_t at,void *out,size_t n,unsigned code){
 DX_ENV *s=ctx;if(!dx_range((const uint8_t *)map_buffer,s->bytes,s->stride,at,n,code))return 0;
 const volatile uint8_t *p=(const volatile uint8_t *)(UN)at;uint8_t *q=out;
 for(size_t i=0;i<n;i++)q[i]=p[i];return 1;
}
static void add(DX_ENV *s,const char *p){size_t n=0;while(p[n])n++;s->append(s->ctx,p,n);}
static void hex(DX_ENV *s,uint64_t v,unsigned n){char b[16];for(unsigned i=0;i<n;i++)b[i]="0123456789ABCDEF"[(v>>((n-i-1)*4))&15];s->append(s->ctx,b,n);}
static void field(DX_ENV *s,const char *k,uint64_t v){add(s,k);add(s,"=");hex(s,v,16);add(s,"\r\n");}
ES dxe_state_probe(ST *st,DX_APPEND append,void *ctx){
 if(!st||!st->bs||!st->bs->get_memory_map||!append)return ERR(2);
 if(busy)return ERR(20);busy=1;DX_ENV env={0,0,append,ctx};DX_ENV *s=&env;
 add(s,"DXE_STATE_PROBE_V1_READ_ONLY\r\n");
 UN bytes=sizeof(map_buffer),key=0,stride=0;uint32_t version=0;
 ES e=((GET_MAP)st->bs->get_memory_map)(&bytes,map_buffer,&key,&stride,&version);
 field(s,"DX_MAP_STATUS",e);field(s,"DX_MAP_BYTES",bytes);field(s,"DX_MAP_STRIDE",stride);
 if(e||version!=1||bytes>sizeof(map_buffer)||stride<40||stride>256||stride%8||!bytes||bytes%stride||bytes/stride>2048){busy=0;return e?e:ERR(33);}
 s->bytes=(size_t)bytes;s->stride=(size_t)stride;
 field(s,"DX_BS_LOAD_IMAGE",(UN)st->bs->load_image);field(s,"DX_BS_START_IMAGE",(UN)st->bs->start_image);
 int status=dx_state_snapshot(actual_read,s,(UN)st->bs->load_image,(UN)st->bs->start_image,&result);
 field(s,"DX_SNAPSHOT_STATUS",status);field(s,"DX_EXACT_CODE_ANCHORS",result.code_identity);field(s,"DX_CORE_BASE",result.core_base);
 field(s,"DX_DISPATCHER_RUNNING",result.running);field(s,"DX_COMPLETE",result.complete);field(s,"DX_NODES",result.nodes);
 field(s,"DX_INITIALIZED_COUNT",result.initialized);field(s,"DX_DEPENDENT_COUNT",result.dependent);field(s,"DX_SCHEDULED_COUNT",result.scheduled);
 field(s,"DX_UNTRUSTED_COUNT",result.untrusted);field(s,"DX_UNREQUESTED_COUNT",result.unrequested);field(s,"DX_DEPEX_ERROR_COUNT",result.depex_error);
 field(s,"DX_R2_COUNT",result.target_count[0]);field(s,"DX_P5_P6_COUNT",result.target_count[1]);
 for(unsigned i=0;i<result.matches;i++){
  const DX_MATCH *m=&result.match[i];const uint8_t *p=m->raw;
  add(s,m->which?"DX_TARGET=P5_P6\r\n":"DX_TARGET=R2\r\n");field(s,"DX_ENTRY",m->address);field(s,"DX_FV_HANDLE",u64(p+0x28));
  field(s,"DX_BEFORE",p[0x60]);field(s,"DX_AFTER",p[0x61]);field(s,"DX_DEPENDENT",p[0x74]);field(s,"DX_UNREQUESTED",p[0x75]);
  field(s,"DX_SCHEDULED",p[0x76]);field(s,"DX_UNTRUSTED",p[0x77]);field(s,"DX_INITIALIZED",p[0x78]);field(s,"DX_DEPEX_ERROR",p[0x79]);
  field(s,"DX_IMAGE_HANDLE",u64(p+0x80));field(s,"DX_IS_FV_IMAGE",p[0x88]);field(s,"DX_DEPEX_SIZE",u64(p+0x58));field(s,"DX_DEPEX_READABLE",m->depex_readable);
  if(m->depex_readable){add(s,"DX_DEPEX_RAW=");for(unsigned j=0;j<m->depex_bytes;j++)hex(s,m->depex[j],2);add(s,"\r\n");}
 }
 add(s,"DX_NOTE=Initialized is not entrypoint success; only COMPLETE permits absence claims.\r\nDX_END\r\n");
 busy=0;return status?ERR(33):0;
}
