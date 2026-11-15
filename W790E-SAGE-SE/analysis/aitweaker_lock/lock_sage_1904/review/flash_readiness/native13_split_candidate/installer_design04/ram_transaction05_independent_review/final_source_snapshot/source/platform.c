/* RAM test adapter. No foreign page attributes, RT-table replacement, original
 * image-size change or generic patch API. All BootServices calls occur outside
 * the transaction; tx_validate uses only cached metadata, bounded reads, local
 * hashing and read-only CPU page-table walks. Standard allocator/loader and BSP
 * execution contracts are explicit premises; TPL does not quiesce APs/SMM. */
#include "app.h"
#include "transaction_plan.h"
#include "split_profile.h"
#include "provider_asset.h"
typedef struct{uint32_t type,pad;uint64_t start,virtual_start,pages,attrs;}MD;
typedef struct{const char *name;uint32_t old_size,new_size,entry,text_rva,text_size;const uint8_t *text_hash;}TARGET;
typedef struct{const char *name;uint32_t module,rva,length,pointer,old_rva;uint8_t bytes[24];}PATCH;
#include "targets.h"
#include "context_binding.h"
#include "launch_binding.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID target_guids[2]={{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}},{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}}};
static GUID bds_guid={0x8f4b8f82,0x9b91,0x4028,{0x86,0xe6,0xf4,0xdb,0x7d,0x4c,0x1d,0xff}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID smbios3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID smbios_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID cpu_guid={0x26baccb1,0x6f42,0x11d4,{0xbc,0xe7,0x00,0x80,0xc7,0x3c,0x88,0x81}};
static GUID provider_guid={0x87e3c6fa,0x11fb,0x4e77,{0xaf,0x2d,0xea,0x50,0xb6,0x40,0xfa,0x13}};
static ST *system_table;static uint8_t map[1024*1024];static UN map_bytes,stride;
static LOADED *loaded[2],*extra_loaded[2],*self_loaded;static uint8_t *images[2],*extra_images[2];
static unsigned found[2],extra_found[2];static CPU *cpu;static CONFIG *setup_config;
static HANDLE handles[4096],hii_handles[512];static UN image_count;
typedef struct{uint64_t base,size;}SPAN;
static SPAN all_images[4096];static uint8_t normalized[0x21000];
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
static uint16_t u16(const void *p){uint16_t v;memcpy(&v,p,2);return v;}
static uint32_t u32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t u64(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static int refresh_map(void){
 UN n=sizeof(map),key=0;uint32_t version=0;app_require_services();
 ES status=system_table->bs->memory_map(&n,map,&key,&stride,&version);app_require_services();
 map_bytes=0;if(FAILED(status)||!n||n>sizeof(map)||stride<sizeof(MD)||stride>256||n%stride||version!=1)return 0;
 for(UN at=0;at<n;at+=stride){const MD *d=(void *)(map+at);if(!d->pages||(d->start&4095)||d->pages>(UINT64_MAX-d->start)/4096)return 0;}
 map_bytes=n;return 1;
}
#include "platform_readonly.inc"
static CPU_ENV environment;
typedef struct{uint64_t page;PAGE_VIEW view;}OBSERVATION;
static OBSERVATION foreign_pages[12];static unsigned foreign_count;
typedef struct{uint64_t allocation,pages,base,bytes;uint32_t type,ready;PAGE_VIEW first,last;}BLOCK;
static BLOCK blocks[2][3];static uint8_t guard_hashes[2][2][32];
static uint32_t inventory_ready,provider_attempted;static LOADED *provider_loaded;static SPAN provider_span;
static uint8_t original_headers[2][0x108];static uint32_t original_pe[2];
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return n&&m&&(a<=b?b-a<n:a-b<m);}
static int span_ok(uint64_t a,uint64_t n){return a>=4096&&a<(1ULL<<47)&&n&&n<=(1ULL<<47)-a;}
static int same_effect(const PAGE_VIEW *a,const PAGE_VIEW *b){return a->physical==b->physical&&a->rw==b->rw&&a->nx==b->nx&&a->user==b->user&&a->pat_index==b->pat_index;}
static int current_environment(void){CPU_ENV now={0};return read_cpu_env(&now)&&!memcmp(&environment,&now,sizeof(now));}
static int access_range(uint64_t base,uint64_t n,int writable,int executable){
 if(!span_ok(base,n)||!readable((void *)(uintptr_t)base,n))return 0;
 uint64_t end=base+n;for(uint64_t p=base&~4095ULL;p<end;p+=4096){PAGE_VIEW v;if(walk_with_env(p,&environment,&v)||v.user||(writable&&!v.rw)||(executable&&v.nx))return 0;}return 1;
}
static int header_matches(LOADED *li,const TARGET *t,int rounded){
 if(!readable(li,sizeof(*li)))return 0;uint64_t n=li->image_size,b=(uintptr_t)li->image_base;
 if(n!=t->old_size&&(!rounded||n!=(((uint64_t)t->old_size+4095)&~4095ULL)))return 0;
 if((b&4095)||!access_range(b,64,0,0))return 0;uint8_t *p=(void *)(uintptr_t)b;uint32_t pe=u32(p+0x3c);
 return u16(p)==0x5a4d&&pe>=0x40&&pe<=0x800&&pe+0x108<=t->old_size&&access_range(b+pe,0x108,0,0)&&u32(p+pe)==0x4550&&u16(p+pe+4)==0x8664&&u16(p+pe+24)==0x20b&&u32(p+pe+40)==t->entry&&u32(p+pe+80)==t->old_size;
}
static int original_text(unsigned i){
 const TARGET *t=&expected_targets[i];uint8_t hash[32];
 if(!access_range((uintptr_t)images[i]+t->text_rva,t->text_size,0,1))return 0;
 ap_sha256(images[i]+t->text_rva,t->text_size,hash);return ap_constant_equal(hash,t->text_hash,32);
}
static int original_sites(void){for(unsigned i=0;i<12;i++){const TX_SITE *p=&tx_sites[i];uint8_t *at=images[p->module]+p->rva;
 if(!access_range((uintptr_t)at,p->length,0,0))return 0;
 if(!p->kind){if(u64(at)!=(uintptr_t)images[p->module]+p->original_rva)return 0;}
 else if(memcmp(at,p->original,p->length))return 0;}return 1;}
static int immutable_text(unsigned module){
 const ID_SEGMENT *s=module?setup_segments:amitse_segments;UN count=module?sizeof(setup_segments)/sizeof(*s):sizeof(amitse_segments)/sizeof(*s);
 uint8_t hash[32];for(UN i=0;i<count;i++){if(!access_range((uintptr_t)images[module]+s[i].rva,s[i].size,0,1))return 0;ap_sha256(images[module]+s[i].rva,s[i].size,hash);if(!ap_constant_equal(hash,s[i].hash,32))return 0;}return 1;
}
static int extra_identity(unsigned i){
 const TARGET *t=&extra_targets[i];if(extra_found[i]!=1||!header_matches(extra_loaded[i],t,i==0)||t->text_size>sizeof(normalized))return 0;
 uint8_t *p=extra_loaded[i]->image_base;if(!access_range((uintptr_t)p+t->text_rva,t->text_size,0,1))return 0;
 memcpy(normalized,p+t->text_rva,t->text_size);
 if(!i)for(UN j=0;j<sizeof(core_relocs)/sizeof(*core_relocs);j++){uint32_t rva=core_relocs[j].rva;uint64_t value=core_relocs[j].original;
  if(rva<t->text_rva||rva-t->text_rva>t->text_size-8||value>=t->old_size||u64(normalized+rva-t->text_rva)!=(uintptr_t)p+value)return 0;
  memcpy(normalized+rva-t->text_rva,&value,8);}
 uint8_t hash[32];ap_sha256(normalized,t->text_size,hash);if(!ap_constant_equal(hash,t->text_hash,32))return 0;extra_images[i]=p;return 1;
}
static int exact_entry_context(void){
 uint64_t sp=captured_entry.rsp;if(captured_entry.st!=(uintptr_t)system_table||captured_entry.image!=(uintptr_t)app_image||(sp&15)!=8||!access_range(sp,0x198,0,0))return 0;
 for(uint64_t at=sp;at<sp+0x198;){const MD *d=descriptor(at);if(!d||(d->type!=2&&d->type!=4))return 0;uint64_t end=d->start+d->pages*4096;at=end<sp+0x198?end:sp+0x198;}
 uint8_t *p=(void *)(uintptr_t)sp;
 if((uintptr_t)system_table->bs->start_image!=(uintptr_t)extra_images[0]+0x8720||u64(p)!=(uintptr_t)extra_images[0]+0x88af||u64(p+0x68)!=(uintptr_t)app_image||u64(p+0x60)!=(uintptr_t)images[0]+0xa8e6||u64(p+0x78)!=sp+0x131)return 0;
 uint8_t hash[32];ap_sha256(images[0]+0x9f78,0xaada-0x9f78,hash);if(!ap_constant_equal(hash,amitse_launch_hash,32))return 0;
 uint64_t ret=u64(p+0x190),rva=ret-(uintptr_t)images[0];if(rva!=0x2d7d&&rva!=0x960c)return 0;
 uint8_t *call=images[0]+rva-5;int32_t disp=(int32_t)u32(call+1);if(*call!=0xe8||(uint64_t)((int64_t)ret+disp)!=(uintptr_t)images[0]+0x9f78)return 0;
 app_number("EntryOuterReturnRVA",rva);app_log("ENTRY_BOUND=EXACT_CORE_AMITSE_BOOT_CALL_RETURN\r\nBROWSER_ABSENCE_PROOF=NO\r\nBSP_TPL_TRANSACTION_PREMISE=YES\r\n");return 1;
}
static int interface_inventory(void){
 HII *db=0;app_require_services();ES status=system_table->bs->locate_protocol(&browser_guid,0,&app_browser);app_require_services();
 if(FAILED(status)||!refresh_map()||!access_range((uintptr_t)app_browser,16,0,0)||u64(app_browser)!=(uintptr_t)images[0]+0x20ee4)return 0;
 app_require_services();status=system_table->bs->locate_protocol(&database_guid,0,(void **)&db);app_require_services();
 if(FAILED(status)||!refresh_map()||!readable(db,sizeof(*db))||!db->list||!db->get_driver)return 0;
 UN bytes=sizeof(hii_handles);app_require_services();status=db->list(db,0,0,&bytes,hii_handles);app_require_services();
 if(FAILED(status)||!bytes||bytes>sizeof(hii_handles)||bytes%sizeof(HANDLE))return 0;
 unsigned matches=0;for(UN i=0;i<bytes/sizeof(HANDLE);i++){
  HANDLE driver=0;CONFIG *cfg=0;app_require_services();status=db->get_driver(db,hii_handles[i],&driver);app_require_services();if(FAILED(status)||!driver)continue;
  app_require_services();status=system_table->bs->handle_protocol(driver,&config_guid,(void **)&cfg);app_require_services();if(FAILED(status)||!refresh_map()||!readable(cfg,sizeof(*cfg)))continue;
  if((uintptr_t)cfg->route==(uintptr_t)images[1]+0x152c&&(uintptr_t)cfg->callback==(uintptr_t)images[1]+0x1534){matches++;app_setup_hii=hii_handles[i];setup_config=cfg;}
 }
 app_number("OriginalSetupHiiMatches",matches);return matches==1;
}
static int capture_foreign(void){
 foreign_count=0;for(unsigned i=0;i<12;i++){const TX_SITE *s=&tx_sites[i];uint64_t p=((uintptr_t)images[s->module]+s->rva)&~4095ULL;unsigned j;for(j=0;j<foreign_count;j++)if(foreign_pages[j].page==p)break;if(j<foreign_count)continue;
  PAGE_VIEW v;if(walk_with_env(p,&environment,&v)||!v.rw||v.nx||v.user||!access_range(p,4096,1,1))return 0;foreign_pages[foreign_count++]=(OBSERVATION){p,v};}
 app_number("OriginalWritableSupervisorCodePages",foreign_count);return foreign_count==8;
}
static int foreign_unchanged(void){
 if(!current_environment())return 0;for(unsigned i=0;i<foreign_count;i++){PAGE_VIEW v;if(walk_with_env(foreign_pages[i].page,&environment,&v)||!same_effect(&v,&foreign_pages[i].view)||!v.rw||v.nx||v.user)return 0;}return foreign_count==8;
}
int platform_inventory(void){
 system_table=app_st;BS *bs=system_table->bs;
 if(!bs->memory_map||!bs->handle_protocol||!bs->locate_handle||!bs->locate_protocol||!bs->allocate_pages||!bs->raise_tpl||!bs->restore_tpl||!bs->load_image||!bs->start_image)return 0;
 if(!refresh_map()||!readable(system_table,sizeof(*system_table))||!readable(bs,sizeof(*bs))||!readable(system_table->rt,sizeof(RT)))return 0;
 if(!read_cpu_env(&environment)||!(environment.cr0&(1ULL<<16))||!(environment.efer&(1ULL<<11)))return 0;
 int board=board_matches();app_result("exact SAGE SE 1904 SMBIOS",board);if(!board)return 0;
 UN bytes=sizeof(handles);typedef ES(EA *LOCATE)(uint32_t,GUID *,void *,UN *,HANDLE *);
 app_require_services();ES status=((LOCATE)bs->locate_handle)(2,&loaded_guid,0,&bytes,handles);app_require_services();
 if(FAILED(status)||!bytes||bytes>sizeof(handles)||bytes%sizeof(HANDLE))return 0;image_count=0;
 for(UN i=0;i<bytes/sizeof(HANDLE);i++){
  LOADED *li=0;app_require_services();status=bs->handle_protocol(handles[i],&loaded_guid,(void **)&li);app_require_services();if(FAILED(status)||!refresh_map()||!readable(li,sizeof(*li)))return 0;
  if(!span_ok((uintptr_t)li->image_base,li->image_size))return 0;all_images[image_count++]=(SPAN){(uintptr_t)li->image_base,li->image_size};
  if(handles[i]==app_image)self_loaded=li;
  if((uintptr_t)bs->start_image>=0x8720&&(uintptr_t)li->image_base==(uintptr_t)bs->start_image-0x8720){extra_found[0]++;extra_loaded[0]=li;}
  GUID file;if(!image_guid(li,&file))continue;
  if(!memcmp(&file,&bds_guid,16)){extra_found[1]++;extra_loaded[1]=li;}
  for(unsigned j=0;j<2;j++)if(!memcmp(&file,&target_guids[j],16)){found[j]++;loaded[j]=li;}
 }
 if(!self_loaded||!refresh_map())return 0;
 for(unsigned i=0;i<2;i++){
  app_number(i?"SetupCount":"AMITSECount",found[i]);if(found[i]!=1||!header_matches(loaded[i],&expected_targets[i],0))return 0;
  images[i]=loaded[i]->image_base;original_pe[i]=u32(images[i]+0x3c);memcpy(original_headers[i],images[i]+original_pe[i],0x108);
  if(!original_text(i))return 0;app_number(i?"SetupBase":"AMITSEBase",(uintptr_t)images[i]);
 }
 if(!original_sites()||!extra_identity(0)||!extra_identity(1)||!exact_entry_context()||!interface_inventory())return 0;
 app_require_services();status=bs->locate_protocol(&cpu_guid,0,(void **)&cpu);app_require_services();
 if(FAILED(status)||!refresh_map()||!readable(cpu,sizeof(*cpu))||!cpu->set_attributes||!access_range((uintptr_t)cpu->set_attributes,1,0,1)||!capture_foreign())return 0;
 void *existing=0;app_require_services();status=bs->locate_protocol(&provider_guid,0,&existing);app_require_services();
 if(status!=ERR(14)||existing){app_result("no preexisting split provider",0);return 0;}
 if(!refresh_map()||!foreign_unchanged()||!original_text(0)||!original_text(1)||!original_sites())return 0;
 inventory_ready=1;return 1;
}
static int exclusive(uint64_t a,uint64_t n,uint32_t type,const BLOCK *skip){
 if(!span_ok(a,n)||(a&4095)||(n&4095))return 0;
 for(uint64_t p=a;p<a+n;p+=4096){const MD *d=descriptor(p);if(!d||d->type!=type||d->attrs&0x2000)return 0;}
 for(UN i=0;i<image_count;i++)if(overlap(a,n,all_images[i].base,all_images[i].size))return 0;
 if(provider_span.size&&overlap(a,n,provider_span.base,provider_span.size))return 0;
 if(overlap(a,n,(uintptr_t)system_table,sizeof(*system_table))||overlap(a,n,(uintptr_t)system_table->bs,sizeof(BS))||overlap(a,n,(uintptr_t)system_table->rt,sizeof(RT))||overlap(a,n,(uintptr_t)cpu,sizeof(*cpu)))return 0;
 uint64_t sp;__asm__ volatile("mov %%rsp,%0":"=r"(sp));const MD *stack=descriptor(sp);if(!stack||overlap(a,n,stack->start,stack->pages*4096))return 0;
 for(unsigned i=0;i<2;i++){if(overlap(a,n,(uintptr_t)loaded[i],sizeof(LOADED))||overlap(a,n,(uintptr_t)extra_loaded[i],sizeof(LOADED)))return 0;
  for(unsigned j=0;j<3;j++){const BLOCK *b=&blocks[i][j];if(b!=skip&&b->allocation&&overlap(a,n,b->allocation,b->pages*4096))return 0;}}
 return !overlap(a,n,(uintptr_t)self_loaded,sizeof(LOADED))&&!overlap(a,n,(uintptr_t)setup_config,sizeof(CONFIG))&&!overlap(a,n,(uintptr_t)app_browser,16);
}
static int allocate_block(BLOCK *b,uint32_t type,uint64_t size){
 if(b->allocation||b->pages)return 0;uint64_t pages=((size+4095)>>12)+2,address=0x7fffffff;
 app_require_services();ES status=system_table->bs->allocate_pages(1,type,pages,&address);app_require_services();
 if(FAILED(status)){app_number("AllocatePagesStatus",status);return 0;}
 /* Allocation is recorded before validation and is never freed/reused. A bad
  * returned range is not dereferenced or given to SetMemoryAttributes. */
 b->allocation=address;b->pages=pages;b->base=address+4096;b->bytes=size;b->type=type;
 if(!refresh_map()||address>0x7fffffff-pages*4096+1||!exclusive(address,pages*4096,type,b)||!foreign_unchanged())return 0;
 if(walk_with_env(address,&environment,&b->first)||walk_with_env(address+(pages-1)*4096,&environment,&b->last)||b->first.user||b->last.user)return 0;
 return 1;
}
static int block_neighbors(const BLOCK *b){PAGE_VIEW first,last;return !walk_with_env(b->allocation,&environment,&first)&&!walk_with_env(b->allocation+(b->pages-1)*4096,&environment,&last)&&same_effect(&first,&b->first)&&same_effect(&last,&b->last);}
static int owned_attribute(BLOCK *b,uint64_t attr){
 if(!exclusive(b->allocation,b->pages*4096,b->type,b)||!foreign_unchanged())return 0;
 typedef ES(EA *SET_ATTR)(CPU *,uint64_t,uint64_t,uint64_t);app_require_services();
 ES status=((SET_ATTR)cpu->set_attributes)(cpu,b->base,(b->pages-2)*4096,attr);app_require_services();
 if(!refresh_map()||!foreign_unchanged()||!original_text(0)||!original_text(1)||!original_sites()||!block_neighbors(b))app_hold(0x50450001u);
 if(FAILED(status))return 0;
 for(uint64_t p=b->base;p<b->base+(b->pages-2)*4096;p+=4096){PAGE_VIEW v;if(walk_with_env(p,&environment,&v)||v.user||v.rw!=!(attr&0x20000)||v.nx!=!!(attr&0x4000)||v.pat_index!=b->first.pat_index)return 0;}
 return 1;
}
static uint32_t crc32_bytes(const uint8_t *p,UN n){uint32_t c=~0u;while(n--){c^=*p++;for(unsigned i=0;i<8;i++)c=(c>>1)^(0xedb88320u&-(int32_t)(c&1));}return~c;}
static void bind_guard(RAM_SESSION *s,unsigned module){
 TX_PLAN *p=&s->tx.plan;uint8_t *g=(void *)(uintptr_t)p->guard_base[module];memset(g,0,(p->guard_size[module]+4095)&~4095ULL);memcpy(g,split_template,sizeof(split_template));
 if(p->guard_size[module]>sizeof(split_template))memset(g+sizeof(split_template),0x90,p->guard_size[module]-sizeof(split_template));
 SPLIT_BINDING b={0};b.magic=SPLIT_BINDING_MAGIC;b.revision=1;b.kind=module+1;b.self_offset=SPLIT_BINDING_OFFSET;b.payload_size=(uint32_t)p->guard_size[module];
 b.original_base=p->module_base[module];b.original_size=p->module_size[module];b.guard_base=p->guard_base[module];b.state_base=p->state_base;b.state_size=p->state_size;
 b.setup_base=p->module_base[1];b.setup_size=p->module_size[1];b.setup_callback=p->guard_base[1]+SPLIT_CALLBACK_OFFSET;b.setup_route=p->guard_base[1]+SPLIT_ROUTE_OFFSET;b.setup_guard=p->guard_base[1];b.setup_guard_size=p->guard_size[1];
 if(!module){uint64_t *slots[5]={&b.original_loop,&b.original_frame,&b.original_commit,&b.original_defaults,&b.original_save};
  for(unsigned i=0;i<5;i++){const ID_TRAMP *t=&split_trampolines[i];uint8_t *at=g+t->offset;memcpy(at,t->original,t->length);const uint8_t jump[6]={0xff,0x25,0,0,0,0};memcpy(at+t->length,jump,6);uint64_t back=p->module_base[0]+t->rva+t->length;memcpy(at+t->length+6,&back,8);*slots[i]=p->guard_base[0]+t->offset;}
  b.setup_guard_crc=crc32_bytes((void *)(uintptr_t)p->guard_base[1],p->guard_size[1]);}
 memcpy(g+SPLIT_BINDING_OFFSET,&b,sizeof(b));
}
static int provider_before_start(LOADED *li){
 if(!readable(li,sizeof(*li))||li->image_size!=PROVIDER_IMAGE_BYTES||((uintptr_t)li->image_base&4095)||!access_range((uintptr_t)li->image_base,provider_segments[0].size,0,0))return 0;
 uint8_t *p=li->image_base;uint32_t pe=u32(p+0x3c);if(u16(p)!=0x5a4d||pe<0x40||pe>0x800||u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664||u16(p+pe+24)!=0x20b||u32(p+pe+40)!=PROVIDER_ENTRY_RVA||u32(p+pe+80)!=PROVIDER_IMAGE_BYTES)return 0;
 for(UN i=0;i<sizeof(provider_segments)/sizeof(*provider_segments);i++){const ID_SEGMENT *s=&provider_segments[i];if(!access_range((uintptr_t)p+s->rva,s->size,0,0))return 0;memcpy(normalized+s->rva,p+s->rva,s->size);}
 uint64_t header_base=u64(normalized+PROVIDER_IMAGEBASE_FIELD);if(header_base!=(uintptr_t)p&&header_base!=PROVIDER_PREFERRED_BASE)return 0;
 uint64_t preferred=PROVIDER_PREFERRED_BASE;memcpy(normalized+PROVIDER_IMAGEBASE_FIELD,&preferred,8);
 uint64_t delta=(uintptr_t)p-PROVIDER_PREFERRED_BASE;
 for(UN i=0;i<sizeof(provider_relocs)/sizeof(*provider_relocs);i++){uint32_t at=provider_relocs[i];int inside=0;for(UN j=0;j<sizeof(provider_segments)/sizeof(*provider_segments);j++){const ID_SEGMENT *s=&provider_segments[j];if(at>=s->rva&&at-s->rva<=s->size-8)inside=1;}if(!inside)return 0;uint64_t value=u64(normalized+at)-delta;memcpy(normalized+at,&value,8);}
 for(UN i=0;i<sizeof(provider_segments)/sizeof(*provider_segments);i++){const ID_SEGMENT *s=&provider_segments[i];uint8_t hash[32];ap_sha256(normalized+s->rva,s->size,hash);if(!ap_constant_equal(hash,s->hash,32))return 0;}return 1;
}
/* Explicitly exported for actual-byte validator tests. This function must not
 * call app_require_services: high-TPL failure is reported to transaction.c. */
int EA tx_validate(TX_CONTEXT *c,uint32_t mode){
 if(app_ended||!inventory_ready||mode>TX_PERMISSIONS)return 0;
 unsigned slot=c==&app_sessions[0].tx?0:c==&app_sessions[1].tx?1:2;if(slot>1||!foreign_unchanged())return 0;
 for(unsigned i=0;i<2;i++){
  if(!header_matches(loaded[i],&expected_targets[i],0)||loaded[i]->image_base!=images[i]||c->plan.module_base[i]!=(uintptr_t)images[i]||c->plan.module_size[i]!=expected_targets[i].old_size||memcmp(images[i]+original_pe[i],original_headers[i],0x108))return 0;
  BLOCK *b=&blocks[slot][i];if(!b->ready||c->plan.guard_base[i]!=b->base||c->plan.guard_size[i]!=b->bytes||!exclusive(b->allocation,b->pages*4096,3,b)||!block_neighbors(b))return 0;
  if(!access_range(b->base,(b->bytes+4095)&~4095ULL,0,1))return 0;for(uint64_t p=b->base;p<b->base+b->bytes;p+=4096){PAGE_VIEW v;if(walk_with_env(p,&environment,&v)||v.rw||v.nx||v.user)return 0;}
  uint8_t hash[32];ap_sha256((void *)(uintptr_t)b->base,b->bytes,hash);if(!ap_constant_equal(hash,guard_hashes[slot][i],32))return 0;
 }
 BLOCK *state=&blocks[slot][2];if(!state->ready||c->plan.state_base!=state->base||c->plan.state_size!=4096||!exclusive(state->allocation,state->pages*4096,4,state)||!block_neighbors(state)||!access_range(state->base,4096,1,0))return 0;
 PAGE_VIEW v;if(walk_with_env(state->base,&environment,&v)||!v.nx||v.user)return 0;
 if(!access_range((uintptr_t)c,sizeof(*c),1,0)||overlap((uintptr_t)c,sizeof(*c),c->plan.state_base,c->plan.state_size))return 0;
 if(mode==TX_PERMISSIONS)return 1;
 if(!immutable_text(0)||!immutable_text(1))return 0;
 if(mode==TX_ORIGINAL)return original_sites();
 for(unsigned i=0;i<12;i++){const TX_SITE *p=&tx_sites[i];if(memcmp(images[p->module]+p->rva,c->replacement[i],p->length))return 0;}return 1;
}
static void require_application_tpl(void){
 /* Before any map/allocation/loader service, establish the wrapper's own
  * entry TPL. An anomalous caller stays at HIGH_LEVEL without RestoreTPL or
  * further firmware services; the exact reason remains only in private RAM. */
 app_require_services();UN prior=system_table->bs->raise_tpl(31);app_require_services();
 if(prior!=4)app_hold(0x50450040u);system_table->bs->restore_tpl(4);app_require_services();
}
int platform_prepare(RAM_SESSION *s,unsigned mode){
 require_application_tpl();unsigned slot=s==&app_sessions[0]?0:s==&app_sessions[1]?1:2;
 if(slot>1||mode!=slot+1||s->prepared||s->tx.magic||!inventory_ready||!refresh_map()||!foreign_unchanged()||!original_text(0)||!original_text(1)||!original_sites())return 0;
 s->prepared=1;TX_PLAN p={0};for(unsigned i=0;i<2;i++){p.module_base[i]=(uintptr_t)images[i];p.module_size[i]=expected_targets[i].old_size;p.guard_size[i]=i?SETUP_GUARD_BYTES:AMITSE_GUARD_BYTES;
  if(!allocate_block(&blocks[slot][i],3,p.guard_size[i])||!owned_attribute(&blocks[slot][i],0x4000))return 0;p.guard_base[i]=blocks[slot][i].base;}
 if(!allocate_block(&blocks[slot][2],4,4096)||!owned_attribute(&blocks[slot][2],0x4000))return 0;p.state_base=blocks[slot][2].base;p.state_size=4096;
 /* Temporarily use the context's plan only to construct owned immutable blobs;
  * tx_prepare then initializes the context from a separate stable local plan. */
 s->tx.plan=p;bind_guard(s,1);bind_guard(s,0);memset((void *)(uintptr_t)p.state_base,0,4096);SPLIT_STATE *state=(void *)(uintptr_t)p.state_base;state->magic=SPLIT_STATE_MAGIC;state->phase=1;
 for(unsigned i=0;i<2;i++){ap_sha256((void *)(uintptr_t)p.guard_base[i],p.guard_size[i],guard_hashes[slot][i]);if(!owned_attribute(&blocks[slot][i],0x20000))return 0;blocks[slot][i].ready=1;}blocks[slot][2].ready=1;
 if(mode==2){
  if(provider_attempted)return 0;provider_attempted=1;
  app_require_services();ES status=system_table->bs->load_image(0,app_image,0,(void *)provider_file,sizeof(provider_file),&s->provider_image);app_require_services();
  app_number("ProviderLoadImageStatus",status);if(FAILED(status)||!s->provider_image)return 0;
  app_require_services();status=system_table->bs->handle_protocol(s->provider_image,&loaded_guid,(void **)&provider_loaded);app_require_services();
  if(FAILED(status)||!refresh_map()||!provider_before_start(provider_loaded))return 0;
  provider_span=(SPAN){(uintptr_t)provider_loaded->image_base,provider_loaded->image_size};
  if(provider_loaded->options||provider_loaded->options_size)return 0;
  s->provider_context=(SPLIT_CONTEXT){SPLIT_CONTEXT_MAGIC,1,sizeof(SPLIT_CONTEXT),{p.module_base[0],p.module_base[1]},{p.module_size[0],p.module_size[1]},{p.guard_base[0],p.guard_base[1]},{p.guard_size[0],p.guard_size[1]},p.state_base,p.state_size};
  if(!access_range((uintptr_t)&provider_loaded->options_size,sizeof(provider_loaded->options_size),1,0)||!access_range((uintptr_t)&provider_loaded->options,sizeof(provider_loaded->options),1,0))return 0;
  provider_loaded->options=&s->provider_context;provider_loaded->options_size=sizeof(s->provider_context);
 }
 if(!refresh_map())return 0;TX_HOST host={system_table->bs->raise_tpl,system_table->bs->restore_tpl,tx_validate};
 uint32_t result=tx_prepare(&s->tx,&p,&host);if(result==TX_ENDED)app_hold(0x50450002u);app_require_services();app_number("PrepareResult",result);return result==TX_OK;
}
uint32_t platform_install(RAM_SESSION *s){
 require_application_tpl();if(!s||!refresh_map())return TX_REFUSED;uint32_t result=tx_install(&s->tx);
 if(result==TX_HOLD||result==TX_ENDED||result==TX_BUSY||s->tx.saved_tpl!=4)app_hold(0x50450010u|result);
 app_require_services();if(result==TX_OK)s->published=1;return result;
}
int platform_start_provider(RAM_SESSION *s){
 app_require_services();if(s!=&app_sessions[1]||s->mode!=2||!s->provider_image||s->provider_started||s->tx.phase!=TX_INSTALLED)return 0;
 require_application_tpl();if(!refresh_map()||!tx_validate(&s->tx,TX_PATCHED)||!provider_before_start(provider_loaded))return 0;
 s->provider_started=1;app_require_services();ES status=system_table->bs->start_image(s->provider_image,0,0);app_require_services();app_number("ProviderStartImageStatus",status);
 if(FAILED(status)){provider_loaded=0;return 0;} /* StartImage error may destroy its LoadedImage interface. Cached exclusion span stays conservative. */
 if(!refresh_map()||!tx_validate(&s->tx,TX_PATCHED))return 0;
 app_require_services();status=system_table->bs->locate_protocol(&provider_guid,0,(void **)&s->provider);app_require_services();
 if(FAILED(status)||!refresh_map()||!access_range((uintptr_t)s->provider,sizeof(*s->provider),0,0))return 0;
 if(s->provider->magic!=PROVIDER_MAGIC||s->provider->revision!=1||s->provider->size!=sizeof(*s->provider))return 0;
 uint64_t base=provider_span.base,end=base+provider_span.size;uint64_t ptrs[5]={(uintptr_t)s->provider->begin,(uintptr_t)s->provider->end,(uintptr_t)s->provider->query,(uintptr_t)s->provider->request,(uintptr_t)s->provider->manage};
 if((uintptr_t)s->provider!=base+PROVIDER_OBJECT_RVA||(uintptr_t)s->provider>end-sizeof(*s->provider))return 0;
 for(unsigned i=0;i<5;i++)if(ptrs[i]!=base+provider_method_rvas[i]||ptrs[i]>=end||!access_range(ptrs[i],1,0,1))return 0;
 app_require_services();uint32_t flags=s->provider->query(s->provider);app_require_services();require_application_tpl();app_number("ProviderInitialFlags",flags);return flags==PROVIDER_READY;
}
uint32_t platform_remove(RAM_SESSION *s){
 require_application_tpl();if(!s||!refresh_map())app_hold(0x50450020u);uint32_t result=tx_remove(&s->tx);
 if((result!=TX_ROLLED_BACK&&result!=TX_BUSY)||s->tx.saved_tpl!=4)app_hold(0x50450030u|result);
 app_require_services();if(result==TX_ROLLED_BACK)app_log("ALL_12_ORIGINAL_SITES_RESTORED\r\nALL_PUBLISHED_ALLOCATION_LIFETIMES=UNTIL_POWER_OFF\r\n");return result;
}
