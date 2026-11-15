/* Read-only, fixed-selection HII structure collector. No runtime variables,
 * string lookups, ConfigAccess calls, image execution or firmware writes. */
#include "efi_min.h"
#include "kvm.h"
#include "runtime.h"
#include "core.h"
#include "delta_core.h"
#include "password_core.h"
#include "probe_core.h"
#include "memory.h"
#include "sampler.h"

typedef struct {
 D7_META meta;
 const uint8_t *baseline;uint32_t baseline_size;
 uint8_t producer_guid[16];uint32_t callback_rva[3];
 uint32_t image_size,text_rva,text_size;uint8_t raw_sha[32],path_sha[32];
} TARGET;
#include "selection.h"

static const GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static const GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static const GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static const uint8_t tse_guid[16]={0xdf,0x0a,0xda,0xb1,0x77,0x4f,0x70,0x40,0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a};

typedef struct {
 const TARGET *target;HANDLE hii,producer;uint64_t base;uint32_t length;
 uint8_t forms_sha[32];H6_RESULT code;
 const char *status;uint8_t *packet;D7_RESULT packet_result;unsigned chosen;
} ITEM;
static ST *st;static HII *db;static HII db_snapshot;
static HANDLE *images;static UN image_count;
static unsigned issues,group_count[D7_TARGET_GROUPS],had_begin;
static ITEM items[D7_OBJECTS];
static char logbuf[D7_BUDGET_BYTES];static size_t loglen;static unsigned log_overflow;
static uint64_t tse_base,tse_size;static unsigned tse_found;
static HANDLE tse_handle;static S7_PAIR spf_pair;static const char *spf_state;

void *memset(void *p,int c,size_t n){uint8_t *a=p;while(n--)*a++=(uint8_t)c;return p;}
void *memcpy(void *p,const void *q,size_t n){uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;return p;}
static int equal(const void *a,const void *b,size_t n){return memcmp(a,b,n)==0;}
static void discard(const char *s){(void)s;}
#define READY(member) (h6_refresh()&&h6_code(st->bs->member))
static int host_copy(void *context,uint64_t a,void *out,size_t n){
 (void)context;if(!n||!h6_range((const void *)(uintptr_t)a,n))return 0;
 memcpy(out,(const void *)(uintptr_t)a,n);return 1;
}
static void *host_alloc(void *context,size_t n){
 (void)context;void *p=0;if(!n||n>16U*1024U*1024U||!READY(allocate_pool))return 0;
 if(st->bs->allocate_pool(4,n,&p)||!p||!h6_refresh()||!h6_range(p,n))return 0;return p;
}
static int host_free(void *context,void *p){
 (void)context;return p&&READY(free_pool)&&st->bs->free_pool(p)==0;
}
static H6_HOST host={0,host_copy,host_alloc,host_free};
static void release(void *p){if(p&&!host_free(0,p))issues++;}
static uint32_t u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int database_ready(void){return h6_refresh()&&h6_range(db,sizeof(*db))&&equal(db,&db_snapshot,sizeof(*db))&&
 h6_code(db_snapshot.list)&&h6_code(db_snapshot.export_list)&&h6_code(db_snapshot.get_driver);}
static int loaded(HANDLE h,LOADED *out){
 LOADED *p=0;if(!READY(handle_protocol)||st->bs->handle_protocol(h,(GUID *)&loaded_guid,(void **)&p)||
 !h6_refresh()||!h6_range(p,sizeof(*p)))return 0;
 memcpy(out,p,sizeof(*out));return out->image_base&&out->image_size&&out->image_size<=64U*1024U*1024U;
}
/* A complete bounded DevicePath snapshot. Non-FV is an observation, not trust. */
static int image_path(const LOADED *li,uint8_t guid[16],uint8_t digest[32],int *has_guid){
 uint8_t path[1024];size_t at=0;unsigned found=0;*has_guid=0;memset(guid,0,16);
 while(at+4<=sizeof(path)){
  if(!li->filepath||!host_copy(0,(uintptr_t)li->filepath+at,path+at,4))return 0;
  uint32_t n=path[at+2]|((uint32_t)path[at+3]<<8);if(n<4||n>sizeof(path)-at||!host_copy(0,(uintptr_t)li->filepath+at,path+at,n))return 0;
  if(path[at]==4&&path[at+1]==6){if(n!=20||found++)return 0;memcpy(guid,path+at+4,16);*has_guid=1;}
  if(path[at]==0x7f&&path[at+1]==0xff){if(n!=4)return 0;ap_sha256(path,at+n,digest);return 1;}
  at+=n;
 }
 return 0;
}
static int same_loaded(const LOADED *a,const LOADED *b){return equal(a,b,sizeof(*a));}
static void enumerate_images(void){
 if(!READY(locate_handles)||st->bs->locate_handles(2,(GUID *)&loaded_guid,0,&image_count,&images)||
 !image_count||image_count>4096||!images||!h6_refresh()||!h6_range(images,image_count*sizeof(HANDLE))){issues++;images=0;image_count=0;return;}
 for(UN i=0;i<image_count;i++){
  for(UN j=0;j<i;j++)if(images[i]==images[j]){issues++;image_count=0;return;}
  LOADED li;uint8_t g[16],path[32];int has=0;
  if(loaded(images[i],&li)&&image_path(&li,g,path,&has)&&has&&equal(g,tse_guid,16)){
   tse_found++;tse_base=(uintptr_t)li.image_base;tse_size=li.image_size;tse_handle=images[i];
  }
 }
}
static void capture_spf(void){
 memset(&spf_pair,0,sizeof(spf_pair));spf_pair.a.status_mask=spf_pair.b.status_mask=S7_PROFILE_MISMATCH;spf_state="MODULE_UNAVAILABLE";
 if(tse_found!=1)return;
 LOADED before,after;uint8_t g[16],path[32],again_path[32];int has=0;
 if(!loaded(tse_handle,&before)||(uintptr_t)before.image_base!=tse_base||before.image_size!=tse_size||
  !image_path(&before,g,path,&has)||!has||!equal(g,tse_guid,16)){spf_state="MODULE_CHANGED";return;}
 int complete=s7_capture_pair(&host,tse_base,tse_size,&spf_pair);
 if(!loaded(tse_handle,&after)||!same_loaded(&before,&after)||!image_path(&after,g,again_path,&has)||!has||!equal(g,tse_guid,16)||!equal(path,again_path,32)){
  memset(&spf_pair,0,sizeof(spf_pair));spf_pair.a.status_mask=spf_pair.b.status_mask=S7_PROFILE_MISMATCH;spf_state="MODULE_CHANGED";issues++;return;
 }
 spf_state=complete?"COMPLETE_OBSERVATION":"INCOMPLETE_OBSERVATION";
}
/* Read addresses, locate the unique containing image, then verify actual bytes.
 * No method is invoked. Recheck ConfigAccess and LoadedImage after hashing. */
static int observe_producer(ITEM *item,HANDLE driver){
 const TARGET *t=item->target;LOADED selected={0};HANDLE owner=0;unsigned matches=0;
 CONFIG *config=0,snapshot={0};
 if(t->meta.kind!=D7_KIND_CPU_DELTA){
  if(!driver||!READY(handle_protocol)||st->bs->handle_protocol(driver,(GUID *)&config_guid,(void **)&config)||
   !h6_refresh()||!h6_range(config,sizeof(*config)))return 0;
  memcpy(&snapshot,config,sizeof(snapshot));void *fn[3]={snapshot.extract,snapshot.route,snapshot.callback};
  for(unsigned j=0;j<3;j++)if(!h6_code(fn[j]))return 0;
  for(UN i=0;i<image_count;i++){
   LOADED li;if(!loaded(images[i],&li))continue;uint64_t b=(uintptr_t)li.image_base;unsigned contained=1;
   for(unsigned j=0;j<3;j++){uint64_t a=(uintptr_t)fn[j];if(a<b||a-b>=li.image_size)contained=0;}
   if(contained){selected=li;owner=images[i];matches++;}
  }
  if(matches!=1)return 0;
  for(unsigned j=0;j<3;j++)if((uintptr_t)fn[j]-(uintptr_t)selected.image_base!=t->callback_rva[j])return 0;
 }else{
  if(driver)return 0;
  for(UN i=0;i<image_count;i++){
   LOADED li;uint8_t g[16],path[32];int has=0;
   if(loaded(images[i],&li)&&image_path(&li,g,path,&has)&&has&&equal(g,t->producer_guid,16)){selected=li;owner=images[i];matches++;}
  }
  if(matches!=1)return 0;
 }
 item->producer=owner;item->base=(uintptr_t)selected.image_base;
 uint8_t g[16],path[32];int has=0;
 if(!image_path(&selected,g,path,&has))return 0;
 const H6_PROFILE *profile=has?h6_profile(g):0;
 if(t->meta.kind==D7_KIND_UNKNOWN_RAW){if(has||!equal(path,t->path_sha,32))return 0;}
 else if(!has||!equal(g,t->producer_guid,16)||!profile)return 0;
 h6_probe(&host,(uintptr_t)selected.image_base,selected.image_size,profile,&item->code);
 LOADED again;if(!loaded(owner,&again)||!same_loaded(&selected,&again))return 0;
 if(t->meta.kind==D7_KIND_UNKNOWN_RAW){
  if(item->code.status!=H6_UNKNOWN||!item->code.raw_valid||selected.image_size!=t->image_size||
   item->code.text_rva!=t->text_rva||item->code.text_size!=t->text_size||!equal(item->code.raw,t->raw_sha,32))return 0;
 }else if(item->code.status!=H6_OK)return 0;
 if(t->meta.kind==D7_KIND_CPU_DELTA){
  uint64_t saved=0;if(selected.image_size<0x3540||!host_copy(0,(uintptr_t)selected.image_base+0x3538,&saved,8)||saved!=(uintptr_t)item->hii)return 0;
 }else if(!h6_refresh()||!h6_range(config,sizeof(*config))||!equal(config,&snapshot,sizeof(snapshot)))return 0;
 return 1;
}
static unsigned forms_count(const uint8_t *p,size_t n){
 if(n<24||u32(p+16)!=n)return 0;unsigned count=0,end=0;
 for(size_t at=20;at<n;){if(n-at<4)return 0;uint32_t v=u32(p+at),len=v&0xffffff,type=v>>24;
  if(end||len<4||len>n-at)return 0;if(type==2)count++;if(type==0xdf){if(len!=4)return 0;end=1;}at+=len;}
 return end?count:0;
}
static void inspect_package(HANDLE handle,const uint8_t *buffer,size_t bytes){
 if(bytes<24)return;
 for(unsigned g=0;g<D7_TARGET_GROUPS;g++){
  const TARGET *t=targets+g;if(!equal(buffer,t->meta.package_guid,16))continue;
  unsigned instance=group_count[g]++;if(instance>=t->meta.observed_instances)return;
  ITEM *item=items+t->meta.artifact_id-1+instance;item->hii=handle;
  D7_FORMS form;if(forms_count(buffer,bytes)!=1||d7_select_forms(buffer,bytes,t->meta.package_guid,t->meta.package_index,&form)){
   item->status="FORM_STRUCTURE";return;
  }
  item->length=form.bytes;memcpy(item->forms_sha,form.sha,32);
  if(form.bytes!=t->meta.expected_length||!equal(form.sha,t->meta.expected_sha,32)){item->status="FORM_CHANGED";return;}
  HANDLE driver=0;if(!database_ready()||db_snapshot.get_driver(db,handle,&driver)||!database_ready()){
   item->status="DRIVER_SERVICE";return;
  }
  if(!observe_producer(item,driver)){item->status="PRODUCER_CHANGED";return;}
  D7_META meta=t->meta;meta.artifact_id+=instance;meta.instance_index=instance;meta.current_hii=(uintptr_t)handle;
  int e=d7_packet(&meta,t->baseline,t->baseline_size,buffer+form.offset,form.bytes,0,0,&item->packet_result);
  if(e!=D7_NEED_SPACE||item->packet_result.required>t->meta.expected_length+D7_HEADER_BYTES){item->status="PACKET_PREFLIGHT";return;}
  item->packet=host_alloc(0,item->packet_result.required);if(!item->packet){item->status="ALLOC_FAILED";return;}
  e=d7_packet(&meta,t->baseline,t->baseline_size,buffer+form.offset,form.bytes,item->packet,item->packet_result.required,&item->packet_result);
  if(e){release(item->packet);item->packet=0;item->status="PACKET_FAILED";return;}
  item->status=t->meta.kind==D7_KIND_UNKNOWN_RAW?"UNKNOWN_OBSERVED":"ORIGINAL_CODE_MATCH";return;
 }
}
static void collect_forms(void){
 if(!READY(locate_protocol)||st->bs->locate_protocol((GUID *)&database_guid,0,(void **)&db)||!h6_refresh()||!h6_range(db,sizeof(*db))){issues++;return;}
 memcpy(&db_snapshot,db,sizeof(db_snapshot));if(!database_ready()){issues++;return;}
 UN n=0;HANDLE *handles=0;ES e=db_snapshot.list(db,2,0,&n,0);
 if(e!=ERR(5)||!n||n>32768||n%8){issues++;return;}
 UN cap=n;handles=host_alloc(0,cap);if(!handles){issues++;return;}
 if(!database_ready()||db_snapshot.list(db,2,0,&n,handles)||!database_ready()||!n||n>cap||n%8){issues++;release(handles);return;}
 for(UN i=0;i<n/8;i++)for(UN j=0;j<i;j++)if(handles[i]==handles[j]){issues++;release(handles);return;}
 for(UN i=0;i<n/8;i++){
  UN z=0;if(!database_ready()){issues++;break;}e=db_snapshot.export_list(db,handles[i],&z,0);
  if((e!=ERR(5)&&e!=ERR(9))||z<24||z>16U*1024U*1024U){issues++;continue;}
  UN size=z;uint8_t *buffer=host_alloc(0,size);if(!buffer){issues++;continue;}
  if(!database_ready()||db_snapshot.export_list(db,handles[i],&z,buffer)||!database_ready()||z>size||z<24||!h6_range(buffer,z))issues++;
  else inspect_package(handles[i],buffer,(size_t)z);
  release(buffer);
 }
 release(handles);
 for(unsigned g=0;g<D7_TARGET_GROUPS;g++){
  const TARGET *t=targets+g;
  if(group_count[g]!=t->meta.observed_instances){
   issues++;for(unsigned j=0;j<t->meta.observed_instances;j++){
    ITEM *item=items+t->meta.artifact_id-1+j;release(item->packet);item->packet=0;item->status="INSTANCE_COUNT";
   }
  }
 }
}
static void emit(const char *s){while(*s){if(loglen<sizeof(logbuf))logbuf[loglen++]=*s;else log_overflow=1;s++;}}
static void number(uint64_t n){char b[24];unsigned at=23;b[at]=0;do{b[--at]=(char)('0'+n%10);n/=10;}while(n);emit(b+at);}
static void hex(uint64_t n,unsigned digits){char b[17];const char *h="0123456789ABCDEF";for(unsigned i=0;i<digits;i++)b[i]=h[(n>>(4*(digits-1-i)))&15];b[digits]=0;emit(b);}
static void sha(const uint8_t *p){const char *h="0123456789abcdef";char b[65];for(unsigned i=0;i<32;i++){b[2*i]=h[p[i]>>4];b[2*i+1]=h[p[i]&15];}b[64]=0;emit(b);}
static void render(void){
 loglen=0;log_overflow=0;
 emit("AITWEAKER-PROBE-P3-KVM\r\nW890_DELTA07_DIAGNOSTIC_ONLY\r\nD7 SOURCE=");sha(targets[0].meta.source_log_sha);
 emit(" SELECTION=");sha(targets[0].meta.selection_sha);emit(" PLANNED=");number(D7_OBJECTS);emit("\r\n");
 emit("D7 ENV ISSUES=");number(issues);emit(" MAP=");emit(had_begin?"READY":"REFUSED");emit(" TSE_COUNT=");number(tse_found);emit("\r\n");
 uint8_t spf_sha[32];ap_sha256((const uint8_t *)&spf_pair,sizeof(spf_pair),spf_sha);
 emit("D7 SPF A=");for(unsigned i=0;i<sizeof(S7_SNAPSHOT);i++)hex(((const uint8_t *)&spf_pair.a)[i],2);
 emit(" B=");for(unsigned i=0;i<sizeof(S7_SNAPSHOT);i++)hex(((const uint8_t *)&spf_pair.b)[i],2);
 emit(" CRC=");hex(probe_crc32(&spf_pair,sizeof(spf_pair)),8);emit(" SHA=");sha(spf_sha);emit(" E=");emit(spf_state);emit("\r\n");
 unsigned exported=0;
 for(unsigned i=0;i<D7_OBJECTS;i++){
  const ITEM *item=items+i;
  emit("D7 OBS=");hex(i+1,8);emit(" H=");hex((uintptr_t)item->hii,16);emit(" I=");hex((uintptr_t)item->producer,16);emit(" B=");hex(item->base,16);
  emit(" L=");number(item->length);emit(" S=");sha(item->forms_sha);emit(" C=");emit(item->status);
  emit(" R=");if(item->code.raw_valid)sha(item->code.raw);else emit("-");
  emit(" N=");if(item->code.normalized_valid)sha(item->code.normalized);else emit("-");emit("\r\n");
  emit("D7 OBJ=");hex(i+1,8);emit(" N=");number(item->packet?item->packet_result.required:0);emit(" SHA=");
  if(item->packet)sha(item->packet_result.packet_sha);else{static const uint8_t zero[32]={0};sha(zero);}
  if(!item->packet){emit(" REFUSED\r\n");continue;}
  if(!item->chosen){emit(" OMITTED_BUDGET\r\n");continue;}
  emit(" PRESENT\r\n");exported++;
  for(size_t at=0;at<item->packet_result.required;){char text[97];size_t n=item->packet_result.required-at;if(n>72)n=72;
   if(!d7_base64(item->packet+at,n,text,96)){log_overflow=1;return;}text[d7_b64_size(n)]=0;emit("D7+ ");emit(text);emit("\r\n");at+=n;
  }
 }
 emit("D7 EXPORTED=");number(exported);emit(" PLANNED=");number(D7_OBJECTS);emit(" STATUS=");emit(exported==D7_OBJECTS?"COMPLETE":"PARTIAL");
 emit("\r\nCOLLECTION_STATUS=PARTIAL\r\nPROBE_COMPLETE\r\n");
}
static void choose_budget(void){
 render();if(log_overflow)return;size_t used=loglen+16;/* footer/count digit reserve */
 for(unsigned i=0;i<D7_OBJECTS;i++){
  ITEM *item=items+i;if(!item->packet)continue;size_t chars=d7_b64_size(item->packet_result.required),lines=(chars+95)/96;
  size_t extra=chars+lines*6;/* PRESENT is shorter than OMITTED_BUDGET: conservative. */
  if(extra<=sizeof(logbuf)-used){item->chosen=1;used+=extra;}
 }
 render();
}
ES EA efi_main(HANDLE image,ST *table){
 (void)image;st=table;if(!st||!st->bs)return ERR(2);
 memset(items,0,sizeof(items));memset(group_count,0,sizeof(group_count));issues=0;image_count=0;images=0;tse_found=0;tse_base=tse_size=0;tse_handle=0;
 memset(&spf_pair,0,sizeof(spf_pair));spf_pair.a.status_mask=spf_pair.b.status_mask=S7_PROFILE_MISMATCH;spf_state="MAP_UNAVAILABLE";
 for(unsigned g=0;g<D7_TARGET_GROUPS;g++)for(unsigned j=0;j<targets[g].meta.observed_instances;j++){
  ITEM *item=items+targets[g].meta.artifact_id-1+j;item->target=targets+g;item->status="MISSING";
 }
 had_begin=(unsigned)h6_begin(st,discard);
 if(had_begin){
  typedef ES(EA *WD)(UN,uint64_t,UN,C16 *);if(READY(set_watchdog)){if(((WD)st->bs->set_watchdog)(0,0,0,0))issues++;}else issues++;
  enumerate_images();collect_forms();capture_spf();release(images);images=0;image_count=0;
 }else issues++;
 choose_budget();if(log_overflow)return ERR(9);
 ES result=kvm_present(st,logbuf,loglen,1);
 for(unsigned i=0;i<D7_OBJECTS;i++)release(items[i].packet);
 return result;
}
