/* Derived from frozen TX05 read-only inventory; no installer/allocator/provider payload. */
#include "baseline.h"
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
static GUID provider_guid={0x87e3c6fa,0x11fb,0x4e77,{0xaf,0x2d,0xea,0x50,0xb6,0x40,0xfa,0x13}};
static ST *system_table;static uint8_t map[1024*1024];static UN map_bytes,stride;
static LOADED *loaded[2],*extra_loaded[2],*self_loaded;static uint8_t *images[2],*extra_images[2];
static unsigned found[2],extra_found[2];static CONFIG *setup_config;
static HANDLE handles[4096],hii_handles[512];
typedef struct{uint64_t base,size;}SPAN;
static uint8_t normalized[0x21000];
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
static uint8_t original_headers[2][0x108];static uint32_t original_pe[2];static int inventory_ready;
static int span_ok(uint64_t a,uint64_t n){return a>=4096&&a<(1ULL<<47)&&n&&n<=(1ULL<<47)-a;}
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
 app_number("EntryOuterReturnRVA",rva);app_log("ENTRY_BOUND=EXACT_CORE_AMITSE_BOOT_CALL_RETURN\r\nBROWSER_ABSENCE_PROOF=NO\r\nBROWSER_BASELINE_NO_TRANSACTION=YES\r\n");return 1;
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
static int original_sites(void){for(unsigned i=0;i<12;i++){const PATCH *p=&expected_patches[i];uint8_t *at=images[p->module]+p->rva;
 if(!access_range((uintptr_t)at,p->length,0,0))return 0;
 if(p->pointer){if(u64(at)!=(uintptr_t)images[p->module]+p->old_rva)return 0;}
 else if(memcmp(at,p->bytes,p->length))return 0;}return 1;}
int baseline_inventory(void){
 system_table=app_st;BS *bs=system_table->bs;
 if(!bs->memory_map||!bs->handle_protocol||!bs->locate_handle||!bs->locate_protocol||!bs->raise_tpl||!bs->restore_tpl||!bs->start_image)return 0;
 if(!refresh_map()||!readable(system_table,sizeof(*system_table))||!readable(bs,sizeof(*bs))||!readable(system_table->rt,sizeof(RT)))return 0;
 if(!read_cpu_env(&environment)||!(environment.cr0&(1ULL<<16))||!(environment.efer&(1ULL<<11)))return 0;
 int board=board_matches();app_result("exact SAGE SE 1904 SMBIOS",board);if(!board)return 0;
 UN bytes=sizeof(handles);typedef ES(EA *LOCATE)(uint32_t,GUID *,void *,UN *,HANDLE *);
 app_require_services();ES status=((LOCATE)bs->locate_handle)(2,&loaded_guid,0,&bytes,handles);app_require_services();
 if(FAILED(status)||!bytes||bytes>sizeof(handles)||bytes%sizeof(HANDLE))return 0;
 for(UN i=0;i<bytes/sizeof(HANDLE);i++){
  LOADED *li=0;app_require_services();status=bs->handle_protocol(handles[i],&loaded_guid,(void **)&li);app_require_services();if(FAILED(status)||!refresh_map()||!readable(li,sizeof(*li)))return 0;
  if(!span_ok((uintptr_t)li->image_base,li->image_size))return 0;
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
 void *existing=0;app_require_services();status=bs->locate_protocol(&provider_guid,0,&existing);app_require_services();
 if(status!=ERR(14)||existing){app_result("no preexisting split provider",0);return 0;}
 if(!refresh_map()||!current_environment()||!original_text(0)||!original_text(1)||!original_sites())return 0;
 inventory_ready=1;return 1;
}

int baseline_map(void){return refresh_map();}
int baseline_access(const void *p,UN bytes,int write){return current_environment()&&access_range((uintptr_t)p,bytes,write,0);}
int baseline_original_unchanged(void){
 if(!inventory_ready||!refresh_map()||!current_environment())return 0;
 for(unsigned i=0;i<2;i++)if(!header_matches(loaded[i],&expected_targets[i],0)||loaded[i]->image_base!=images[i]||!original_text(i)||memcmp(images[i]+original_pe[i],original_headers[i],0x108))return 0;
 return original_sites()&&extra_identity(0)&&extra_identity(1)&&access_range((uintptr_t)app_browser,16,0,0)&&u64(app_browser)==(uintptr_t)images[0]+0x20ee4;
}
void baseline_globals(const char *label){
 static const uint32_t rvas[]={0x83588,0x83468,0x930b0,0x93948,0x93028,0x83580};
 static const char *names[]={"NativeAppPtr","NativeStage","NativePagesPtr","NativeRecordsPtr","NativeExternalPtr","NativePendingReset"};
 app_log(label);app_log("\r\n");if(!inventory_ready||!refresh_map()||!current_environment()){app_result("native globals readable",0);return;}
 for(unsigned i=0;i<6;i++){uint8_t *at=images[0]+rvas[i];if(!access_range((uintptr_t)at,i==5?1:8,0,0)){app_result("native global readable",0);return;}app_number(names[i],i==5?*at:u64(at));}
}
