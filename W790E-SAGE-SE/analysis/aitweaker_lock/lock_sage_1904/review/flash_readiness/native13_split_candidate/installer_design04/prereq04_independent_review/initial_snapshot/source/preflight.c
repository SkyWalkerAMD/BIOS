/* Diagnostic prerequisite. Only exclusively allocated temporary pages may be written or have attributes changed. No OEM patch, variable, native UI, flash or disk writes. */
#include "efi.h"
#include "password_core.h"
typedef struct{uint32_t type,pad;uint64_t start,virtual_start,pages,attrs;}MD;
typedef struct{const char *name;uint32_t old_size,new_size,entry,text_rva,text_size;const uint8_t *text_hash;}TARGET;
typedef struct{const char *name;uint32_t module,rva,length,pointer,old_rva;uint8_t bytes[24];}PATCH;
#include "targets.h"
#include "context_binding.h"
extern ES kvm_present(ST *,const char *,size_t,unsigned);
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID target_guids[2]={{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}},{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}}};
static GUID attr_guid={0xf4560cf6,0x40ec,0x4b4a,{0xa1,0x92,0xbf,0x1d,0x57,0xd0,0xb1,0x89}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID database_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID smbios3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID smbios_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static ST *system_table;static uint8_t *map;static UN map_bytes,map_capacity,stride;static MEMATTR *attributes;
static uint8_t *images[2];static LOADED *loaded[2];static unsigned found[2],valid[2],warnings;static int running,log_overflow,writing_footer;
static int prerequisite_ended;
char probe_log[24576];UN probe_log_bytes;
typedef struct{UN rsp,rbp,rbx,rsi,rdi,r12,r13,r14,r15,image,st;}ENTRY_CAPTURE;
ENTRY_CAPTURE captured_entry;
static LOADED *extra_loaded[2];static uint8_t *extra_images[2];static unsigned extra_found[2],extra_valid[2];
static GUID bds_file_guid={0x8f4b8f82,0x9b91,0x4028,{0x86,0xe6,0xf4,0xdb,0x7d,0x4c,0x1d,0xff}};
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
static uint16_t u16(const void *p){uint16_t v;memcpy(&v,p,2);return v;}
static uint32_t u32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t u64(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static void add(const char *s){UN limit=sizeof(probe_log)-(writing_footer?1:1024);while(*s&&probe_log_bytes<limit)probe_log[probe_log_bytes++]=*s++;if(*s)log_overflow=1;probe_log[probe_log_bytes]=0;}
static void hex(uint64_t v){const char h[]="0123456789ABCDEF";for(int i=15;i>=0;i--){char s[]={h[(v>>(i*4))&15],0};add(s);}}
static void number(const char *label,uint64_t v){add(label);add("=");hex(v);add("\r\n");}
static void result(const char *label,int ok){if(!ok)warnings++;add(ok?"PASS ":"WARN ");add(label);add("\r\n");}
static int refresh_map(void){
 UN key=0,n=map_capacity;uint32_t version=0;ES status;
 for(unsigned attempt=0;attempt<3;attempt++){
  status=system_table->bs->memory_map(&n,map,&key,&stride,&version);
  if(prerequisite_ended)return 0;
  if(status!=ERR(5))break;
  if(n>1024*1024||stride<sizeof(MD)||stride>256)return 0;
  if(map){void *old=map;map=0;map_bytes=map_capacity=0;system_table->bs->free_pool(old);if(prerequisite_ended)return 0;}
  map_capacity=n+64*stride;status=system_table->bs->allocate_pool(4,map_capacity,(void **)&map);
  if(prerequisite_ended)return 0;
  if(FAILED(status)||!map){map_capacity=0;return 0;}n=map_capacity;
 }
 if(FAILED(status)||!map||!n||n>map_capacity||stride<sizeof(MD)||stride>256||n%stride||version!=1){map_bytes=0;return 0;}
 map_bytes=n;
 for(UN i=0;i<n;i+=stride){MD *d=(MD *)(map+i);if(!d->pages||(d->start&4095)||d->pages>(UINT64_MAX-d->start)/4096){map_bytes=0;return 0;}}
 return 1;
}
static const MD *descriptor(uint64_t a){
 const MD *found=0;
 for(UN i=0;i<map_bytes;i+=stride){const MD *d=(void *)(map+i);if(a>=d->start&&a-d->start<d->pages*4096){if(found)return 0;found=d;}}
 if(found)for(UN i=0;i<map_bytes;i+=stride){const MD *d=(void *)(map+i);if(d!=found&&d->start<found->start+found->pages*4096&&found->start<d->start+d->pages*4096)return 0;}
 return found;
}
static int ram_type(uint32_t t){return(t>=1&&t<=7)||t==9||t==10;}
static int readable(const void *p,UN bytes){
 uint64_t a=(uint64_t)(uintptr_t)p;if(!bytes||a<4096||a>=(1ULL<<47)||bytes>(1ULL<<47)-a)return 0;
 while(bytes){const MD *d=descriptor(a);if(!d||!ram_type(d->type)||(d->attrs&0x2000))return 0;uint64_t available=d->start+d->pages*4096-a;UN take=bytes<available?bytes:available;bytes-=take;a+=take;}return 1;
}
static int image_read(unsigned index,UN rva,UN n){const TARGET *t=&expected_targets[index];return valid[index]&&rva<=t->old_size&&n<=t->old_size-rva&&readable(images[index]+rva,n);}
#include "pagewalk.inc"
static void page_info(uint64_t page,const char *label){
 add(label);add(" ");hex(page);const MD *d=descriptor(page);
 if(!d){add(" MAP=UNKNOWN\r\n");warnings++;return;}
 add(" TYPE=");hex(d->type);add(" MAP_ATTR=");hex(d->attrs);
 if(attributes&&ram_type(d->type)){uint64_t attr=0;ES status=attributes->get(attributes,page,4096,&attr);add(" GET_ATTR_STATUS=");hex(status);if(!FAILED(status)){add(" ACTUAL_ATTR=");hex(attr);}}
 else add(" ACTUAL_ATTR=UNKNOWN");add("\r\n");pagewalk_log(page);
}
static int image_guid(LOADED *li,GUID *out){
 uint8_t *p=li->filepath;
 if((uintptr_t)p<4096||(uintptr_t)p>=(1ULL<<47)-65536)return 0;
 for(UN off=0;off<65536;){if(!readable(p+off,4))return 0;UN n=u16(p+off+2);if(n<4||n>65536-off||!readable(p+off,n))return 0;
  if(p[off]==4&&p[off+1]==6&&n==20){memcpy(out,p+off+4,16);return 1;}if(p[off]==0x7f)return 0;off+=n;}return 0;
}
static int ascii_equal(const uint8_t *p,UN n,const char *want){UN i=0;while(i<n&&want[i]&&p[i]==(uint8_t)want[i])i++;return i<n&&!want[i]&&!p[i];}
static int smbios_string(const uint8_t *p,UN n,unsigned index,const char *want){if(!index)return 0;UN at=p[1];for(unsigned i=1;i<index;i++){while(at<n&&p[at])at++;if(at+1>=n||!p[at+1])return 0;at++;}return at<n&&ascii_equal(p+at,n-at,want);}
static int board_table(uint8_t *p,UN n){
 if(n<6||n>2*1024*1024||!readable(p,n))return 0;int board=0,version=0;
 for(UN at=0,count=0;at+6<=n&&count<4096;count++){unsigned type=p[at],len=p[at+1];if(len<4||len>n-at)return 0;UN end=at+len;while(end+1<n&&(p[end]||p[end+1]))end++;if(end+1>=n)return 0;end+=2;
  if(type==0&&len>=6)version=smbios_string(p+at,end-at,p[at+5],"1904");
  if(type==2&&len>=6)board=smbios_string(p+at,end-at,p[at+5],"Pro WS W790E-SAGE SE");
  if(type==127)break;at=end;}return board&&version;
}
static int board_matches(void){
 if(system_table->table_count>1024||!readable(system_table->tables,system_table->table_count*sizeof(CT)))return 0;
 for(UN i=0;i<system_table->table_count;i++){CT *ct=&system_table->tables[i];uint8_t *p=ct->table;UN len,n;uint64_t address;
  if(!memcmp(&ct->guid,&smbios3_guid,16)){if(!readable(p,24)||memcmp(p,"_SM3_",5))continue;len=p[6];n=u32(p+12);address=u64(p+16);}
  else if(!memcmp(&ct->guid,&smbios_guid,16)){if(!readable(p,31)||memcmp(p,"_SM_",4)||memcmp(p+16,"_DMI_",5)||p[5]<31)continue;uint8_t sum=0;for(UN j=16;j<31;j++)sum+=p[j];if(sum)continue;len=p[5];n=u16(p+22);address=u32(p+24);}
  else continue;if(len<24||len>64||!readable(p,len))continue;uint8_t sum=0;for(UN j=0;j<len;j++)sum+=p[j];if(!sum&&board_table((void *)(uintptr_t)address,n))return 1;
 }return 0;
}
static void inspect_module(unsigned index){
 const TARGET *t=&expected_targets[index];add("MODULE ");add(t->name);add("\r\n");number("Count",found[index]);
 if(found[index]!=1||!loaded[index]){warnings++;return;}LOADED *li=loaded[index];number("Base",(uint64_t)(uintptr_t)li->image_base);number("LoadedSize",li->image_size);
 if(li->image_size!=t->old_size||((uintptr_t)li->image_base&4095)||!readable(li->image_base,64)){result("original image range",0);return;}
 uint8_t *p=li->image_base;uint32_t pe=u32(p+0x3c);
 if(u16(p)!=0x5a4d||pe<0x40||pe>0x800||pe+0x108>t->old_size||!readable(p+pe,0x108)||u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664||u16(p+pe+24)!=0x20b||u32(p+pe+40)!=t->entry||u32(p+pe+80)!=t->old_size){result("original PE header identity",0);return;}
 if(t->text_rva>t->old_size||t->text_size>t->old_size-t->text_rva||!readable(p+t->text_rva,t->text_size)){result("text inside loaded and readable range",0);return;}
 uint8_t hash[32];ap_sha256(p+t->text_rva,t->text_size,hash);int match=ap_constant_equal(hash,t->text_hash,32);result("original relocation-free text SHA256",match);if(!match)return;
 valid[index]=1;images[index]=p;number("NewImageSizeRequired",t->new_size);number("OldPEImageSizeField",(uint64_t)(uintptr_t)(p+pe+80));number("LoadedImageSizeField",(uint64_t)(uintptr_t)&li->image_size);
 page_info((uint64_t)(uintptr_t)p&~4095ULL,"HEADER_PAGE");page_info((uint64_t)(uintptr_t)li&~4095ULL,"LOADED_META_PAGE");
 for(unsigned i=0;i<sizeof(expected_patches)/sizeof(expected_patches[0]);i++){const PATCH *patch=&expected_patches[i];if(patch->module!=index)continue;
  int ok=image_read(index,patch->rva,patch->length);if(ok)ok=patch->pointer?u64(p+patch->rva)==(uint64_t)(uintptr_t)p+patch->old_rva:!memcmp(p+patch->rva,patch->bytes,patch->length);
  add("PATCH ");add(patch->name);add(" RVA=");hex(patch->rva);add(ok?" ORIGINAL_OK\r\n":" ORIGINAL_MISMATCH\r\n");if(!ok)warnings++;
  page_info(((uint64_t)(uintptr_t)p+patch->rva)&~4095ULL,"PATCH_PAGE");
 }
 uint64_t old_end=(uint64_t)(uintptr_t)p+t->old_size,start=(old_end+4095)&~4095ULL,end=((uint64_t)(uintptr_t)p+t->new_size+4095)&~4095ULL;
 number("UndeclaredAllocationTailBytes",start-old_end);page_info(old_end&~4095ULL,"TAIL_PAGE_NO_CONTENT_READ");
 for(uint64_t page=start;page<end;page+=4096)page_info(page,"EXTENSION_PAGE_NO_CONTENT_READ");
 add("ExtensionOwnership=NOT_ACQUIRED\r\nPE_METADATA_MUTATION=NOT_REVIEWED_FOR_INSTALL\r\n");
 if(index==0&&image_read(0,0x83468,8)&&image_read(0,0x83588,8)){number("AMITSE.stage",u64(p+0x83468));number("AMITSE.app_pointer",u64(p+0x83588));add("StageIsNotIdleProof=YES\r\n");}
}
static void inspect_interfaces(void){
 void **browser=0;ES s=system_table->bs->locate_protocol(&browser_guid,0,(void **)&browser);if(!refresh_map())return;
 int ok=!FAILED(s)&&readable(browser,16)&&valid[0]&&browser[0]==images[0]+0x20ee4;result("original SendForm pointer identity only",ok);
 HII *db=0;s=system_table->bs->locate_protocol(&database_guid,0,(void **)&db);if(!refresh_map()||FAILED(s)||!readable(db,sizeof(*db))||!db->list||!db->get_driver||!readable((void *)db->list,1)||!readable((void *)db->get_driver,1))return;
 UN bytes=0;s=db->list(db,0,0,&bytes,0);if(s!=ERR(5)||!bytes||bytes>8192||bytes%sizeof(HANDLE)){result("bounded HII list",0);return;}
 HANDLE *handles=0;UN capacity=bytes;if(FAILED(system_table->bs->allocate_pool(4,capacity,(void **)&handles))||!handles)return;
 s=db->list(db,0,0,&bytes,handles);unsigned matches=0;
 if(!FAILED(s)&&bytes<=capacity&&!(bytes%sizeof(HANDLE))&&refresh_map()&&readable(handles,bytes))for(UN i=0;i<bytes/sizeof(HANDLE);i++){
  HANDLE driver=0;CONFIG *cfg=0;if(FAILED(db->get_driver(db,handles[i],&driver))||!driver||FAILED(system_table->bs->handle_protocol(driver,&config_guid,(void **)&cfg))||!refresh_map()||!readable(cfg,sizeof(*cfg)))continue;
  if(valid[1]&&cfg->callback==(CALLBACK)(images[1]+0x1534)&&cfg->route==(ROUTE)(images[1]+0x152c)){matches++;number("OriginalSetupHiiHandle",(uint64_t)(uintptr_t)handles[i]);number("OriginalConfigAccess",(uint64_t)(uintptr_t)cfg);}
 }
 result("exactly one original Setup HII interface",matches==1);system_table->bs->free_pool(handles);
 add("NativeBrowserInactiveProof=NOT_AVAILABLE\r\nNO_SEND_FORM_OR_DXE_ENTRY_CALLED\r\n");
}
#include "context_inspect.inc"
#include "owned_fixture.inc"
int collect(ST *st){
 if(running||prerequisite_ended)return 0;running=1;system_table=st;probe_log_bytes=0;warnings=0;log_overflow=writing_footer=0;memset(extra_loaded,0,sizeof(extra_loaded));memset(extra_found,0,sizeof(extra_found));memset(extra_valid,0,sizeof(extra_valid));memset(found,0,sizeof(found));memset(valid,0,sizeof(valid));memset(loaded,0,sizeof(loaded));attributes=0;
 add("AITWK-P3-KVM\r\nSAGE_NATIVE13_PREREQUISITE04_OWNED_ONLY\r\nINSTALLER_PRESENT=NO\r\nNO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES\r\n");
 if(!st||!st->bs||!st->bs->memory_map||!st->bs->allocate_pool||!st->bs->free_pool||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->locate_protocol){add("INVALID_BOOT_SERVICES\r\n");warnings++;goto done;}
 if(!refresh_map()){result("memory map readable bounds available",0);goto done;}
 result("SMBIOS W790E-SAGE SE version1904",board_matches());
 MEMATTR *ma=0;ES s=st->bs->locate_protocol(&attr_guid,0,(void **)&ma);
 if(refresh_map()&&!FAILED(s)&&readable(ma,sizeof(*ma))&&ma->get&&readable((void *)ma->get,1))attributes=ma;
 add(attributes?"MemoryAttributeProtocol=AVAILABLE_READ_ONLY\r\n":"MemoryAttributeProtocol=UNAVAILABLE_ACTUAL_PERMISSIONS_UNKNOWN\r\n");
 HANDLE *handles=0;UN count=0;s=st->bs->locate_handles(2,&loaded_guid,0,&count,&handles);
 if(!FAILED(s)&&handles&&count&&count<=4096&&refresh_map()&&readable(handles,count*sizeof(*handles)))for(UN i=0;i<count;i++){
  LOADED *li=0;GUID guid;if(FAILED(st->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li))||!refresh_map()||!readable(li,sizeof(*li)))continue;
  uintptr_t start=(uintptr_t)st->bs->start_image;if(start>=0x8720&&(uintptr_t)li->image_base==start-0x8720){extra_found[0]++;extra_loaded[0]=li;}
  if(!image_guid(li,&guid))continue;
  if(!memcmp(&guid,&bds_file_guid,16)){extra_found[1]++;extra_loaded[1]=li;}
  for(unsigned index=0;index<2;index++)if(!memcmp(&guid,&target_guids[index],16)){found[index]++;loaded[index]=li;}
 }
 else result("bounded LoadedImage inventory",0);
 /* Release the temporary handle list before final memory-map observation;
  * image interfaces remain owned by their original loaded drivers. */
 if(handles)st->bs->free_pool(handles);
 if(!refresh_map()){result("final memory map",0);goto done;}
 inspect_module(0);inspect_module(1);inspect_interfaces();inspect_entry_context();inspect_prerequisites();
done:
 writing_footer=1;if(log_overflow){warnings++;add("\r\nLOG_OVERFLOW=YES\r\nLOG_COMPLETE=NO\r\n");}else add("LOG_OVERFLOW=NO\r\nLOG_COMPLETE=YES\r\n");
 add("INSTALLATION_AUTHORIZED_BY_PROBE=NO\r\nAVAILABLE_MEMORY_IS_NOT_OWNED_MEMORY\r\nBROWSER_ABSENCE_PROOF=NO\r\nRuntimeTableChanged=NO\r\nProviderStarted=NO\r\nNO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES\r\n");number("Warnings",warnings);add("SAGE_NATIVE13_PREREQUISITE04_END\r\n");
 if(map&&!prerequisite_ended){st->bs->free_pool(map);map=0;map_bytes=map_capacity=0;}running=0;return valid[0]&&valid[1];
}
static int tcg(void){uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));return b==0x54474354&&c==0x43544743&&d==0x47435447;}
ES EA probe_main(HANDLE image,ST *st){
 (void)image;collect(st);
 /* QEMU-only debug mirror. No I/O-port logging on physical firmware. */
 if(tcg())for(UN i=0;i<probe_log_bytes;i++)__asm__ volatile("outb %0,%1"::"a"((uint8_t)probe_log[i]),"Nd"((uint16_t)0x402));
 if(!prerequisite_ended&&st&&st->bs&&st->out&&st->in){ES status=kvm_present(st,probe_log,probe_log_bytes,warnings);if(tcg()){const char *msg=FAILED(status)?"PROBE_DISPLAY_EXIT_ERROR\n":"PROBE_DISPLAY_EXIT_OK\n";while(*msg)__asm__ volatile("outb %0,%1"::"a"((uint8_t)*msg++),"Nd"((uint16_t)0x402));}}
 if(prerequisite_hold||prerequisite_ended)for(;;)__asm__ volatile("pause");
 return 0;
}
