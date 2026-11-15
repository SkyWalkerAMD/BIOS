/* SPI-INVENTORY-03: read-only status inventory, never a flash dump.
 * PCI/MMIO write slots are opaque padding, not callable interfaces.
 * Register references and conservative ID gate: sources.json.
 */
#include "efi_min.h"
#include "kvm.h"
#include <string.h>

typedef struct PCI PCI;
typedef ES (EA *CFG_READ)(PCI *,uint32_t,uint32_t,UN,void *);
typedef ES (EA *MEM_READ)(PCI *,uint32_t,uint8_t,uint64_t,UN,void *);
typedef ES (EA *LOCATION)(PCI *,UN *,UN *,UN *,UN *);
struct PCI {
 void *poll_mem,*poll_io;
 struct { MEM_READ read; void *unused_write; } mem;
 void *unused_io[2];
 struct { CFG_READ read; void *unused_write; } pci;
 void *copy_mem,*map,*unmap,*alloc,*free,*flush;
 LOCATION location;
};
OFF(PCI,mem.read,0x10);OFF(PCI,pci.read,0x30);OFF(PCI,location,0x70);
typedef struct ROOT ROOT;
typedef ES(EA *ROOT_READ)(ROOT *,uint32_t,uint64_t,UN,void *);
typedef ES(EA *ROOT_CONFIG)(ROOT *,void **);
struct ROOT {
 void *parent,*poll_mem,*poll_io;
 struct {ROOT_READ read;void *unused_write;} mem;
 void *unused_io[2],*unused_pci[2];
 void *copy_mem,*map,*unmap,*allocate,*free,*flush,*get_attributes,*set_attributes;
 ROOT_CONFIG configuration;uint32_t segment;
};
OFF(ROOT,mem.read,0x18);OFF(ROOT,configuration,0x88);OFF(ROOT,segment,0x90);
OFF(BS,get_memory_map,0x38);OFF(ST,table_count,0x68);OFF(ST,tables,0x70);
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID root_guid={0x2f707ebb,0x4a1a,0x11d4,{0x9a,0x38,0x00,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID cpuio2_guid={0xad61f191,0xae5f,0x4c0e,{0xb9,0xfa,0xe8,0x69,0xd2,0x88,0xc6,0x4f}};
static GUID sm3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID sm2_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static ST *st;
static uint8_t mmap_buffer[65536];
static UN mmap_size,mmap_stride;
static char log_buffer[16384];
static size_t log_size;
static unsigned warnings,overflow;

void *memset(void *dst,int c,size_t n){uint8_t *d=dst;while(n--)*d++=(uint8_t)c;return dst;}
void *memcpy(void *dst,const void *src,size_t n){uint8_t *d=dst;const uint8_t *s=src;while(n--)*d++=*s++;return dst;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint16_t u16(const void *p){uint16_t v;memcpy(&v,p,2);return v;}
static uint32_t u32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t u64(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static void put(const char *s){while(*s){if(log_size+1<sizeof(log_buffer))log_buffer[log_size++]=*s;else overflow=1;s++;}log_buffer[log_size]=0;}
static void hex(uint64_t v,unsigned n){const char *h="0123456789ABCDEF";char b[17];for(unsigned i=0;i<n;i++)b[i]=h[(v>>((n-i-1)*4))&15];b[n]=0;put(b);}
static void dec(uint64_t v){char b[24];unsigned i=23;b[i]=0;do{b[--i]=(char)('0'+v%10);v/=10;}while(v);put(b+i);}
static void field(const char *name,uint64_t v,unsigned digits){put(name);put("=0x");hex(v,digits);put("\r\n");}
static void failure(const char *name,ES status){warnings++;field(name,status,16);}

/* An identity pointer must be covered by a RAM-type UEFI descriptor.
 * This deliberately refuses MMIO ranges and fragmented/oversized tables. */
static int readable(const void *ptr,UN n){
 uint64_t a=(uint64_t)(uintptr_t)ptr;if(!a||!n||a+n<a)return 0;
 for(UN p=0;p<mmap_size;p+=mmap_stride){
  const uint8_t *d=mmap_buffer+p;uint32_t type=u32(d);uint64_t start=u64(d+8),pages=u64(d+24);
  if(!(type==2||type==3||type==4||type==5||type==6||type==7||type==9||type==10))continue;
  if(pages>(UINT64_MAX-start)/4096)continue;
  if(a>=start&&a+n<=start+pages*4096)return 1;
 }
 return 0;
}
static int ascii(const uint8_t *s,UN n,const char *wanted){
 UN i=0;for(;i<n&&wanted[i];i++)if(s[i]!=(uint8_t)wanted[i])return 0;
 return i<n&&!wanted[i]&&!s[i];
}
static int sm_string(const uint8_t *s,UN n,uint8_t index,const char *want){
 if(!index)return 0;UN p=s[1];
 for(unsigned i=1;i<index;i++){while(p<n&&s[p])p++;if(p+1>=n||!s[p+1])return 0;p++;}
 return p<n&&ascii(s+p,n-p,want);
}
static int sm_table(const uint8_t *s,UN n){
 if(n<6||n>2*1024*1024||!readable(s,n))return 0;
 unsigned board=0,version=0;
 for(UN p=0,count=0;p+4<=n&&count<4096;count++){
  unsigned type=s[p],len=s[p+1];if(len<4||len>n-p)return 0;
  UN end=p+len;while(end+1<n&&(s[end]||s[end+1]))end++;
  if(end+1>=n)return 0;end+=2;
  if(type==0){if(len<6||version++||!sm_string(s+p,end-p,s[p+5],"1904"))return 0;}
  if(type==2){if(len<6||board++||!sm_string(s+p,end-p,s[p+5],"Pro WS W790E-SAGE SE"))return 0;}
  if(type==127)return board==1&&version==1;p=end;
 }
 return 0;
}
static int identity(void){
 if(!st->table_count||st->table_count>256||!readable(st->tables,st->table_count*sizeof(CT)))return 0;
 unsigned matched=0;
 for(UN i=0;i<st->table_count;i++){
  CT *ct=st->tables+i;const uint8_t *ep=ct->table;UN len,n;uint64_t address;
  if(equal(&ct->guid,&sm3_guid,16)){
   if(!readable(ep,24)||!equal(ep,"_SM3_",5))return 0;
   len=ep[6];if(len<24||len>64||!readable(ep,len))return 0;
   n=u32(ep+12);address=u64(ep+16);
  }else if(equal(&ct->guid,&sm2_guid,16)){
   if(!readable(ep,31)||!equal(ep,"_SM_",4)||!equal(ep+16,"_DMI_",5))return 0;
   len=ep[5];if(len<31||len>64||!readable(ep,len))return 0;
   uint8_t sum=0;for(unsigned k=16;k<31;k++)sum=(uint8_t)(sum+ep[k]);if(sum)return 0;
   n=u16(ep+22);address=u32(ep+24);
  }else continue;
  uint8_t sum=0;for(UN k=0;k<len;k++)sum=(uint8_t)(sum+ep[k]);
  if(sum||!sm_table((const uint8_t *)(uintptr_t)address,n))return 0;
  matched++;
 }
 return matched>0;
}
static int cfg(PCI *p,uint32_t offset,uint32_t *v){
 ES e=p->pci.read(p,2,offset,1,v);
 if(FAILED(e)){failure("PCI_READ_FAILED",e);field("PCI_OFFSET",offset,4);return 0;}return 1;
}
static void location_text(UN seg,UN bus,UN dev,UN fun){
 put("PCI_LOCATION=");hex(seg,4);put(":");hex(bus,2);put(":");hex(dev,2);put(".");hex(fun,1);put("\r\n");
}
static void range(uint32_t raw,int protection){
 uint32_t base=(raw&0x7fff)<<12,limit=(((raw>>16)&0x7fff)<<12)|0xfff;
 put(" BASE=0x");hex(base,8);put(" LIMIT=0x");hex(limit,8);
 if(protection)put(base>limit?" RANGE_INVALID":" RANGE_VALID");else put(base>limit?" DISABLED":" ENABLED");
}
/* Limited metadata only. Do not dereference the SPIBAR or call CPU_IO2. */
static void fallback_metadata(void){
 unsigned count=0;
 for(UN p=0;p<mmap_size;p+=mmap_stride){
  const uint8_t *d=mmap_buffer+p;uint64_t a=u64(d+8),n=u64(d+24);
  if(!n||n>(UINT64_MAX-a)/4096)continue;
  uint64_t end=a+n*4096-1;
  if(a<=0xfe010000&&end>=0xfe010097){
   count++;put("UEFI_MAP_COVERS_BAR TYPE=");dec(u32(d));put(" START=0x");hex(a,16);put(" END=0x");hex(end,16);put(" ATTR=0x");hex(u64(d+32),16);put("\r\n");
  }
 }
 put("UEFI_MAP_BAR_COVER_COUNT=");dec(count);put(" (metadata, not permission)\r\n");
 void *p=0;ES e=st->bs->locate_protocol?st->bs->locate_protocol(&cpuio2_guid,0,&p):ERR(3);
 field("CPU_IO2_LOCATE_STATUS",e,16);put(!FAILED(e)&&p?"CPU_IO2=PRESENT_NOT_CALLED\r\n":"CPU_IO2=UNAVAILABLE\r\n");
}
static int observed_target(PCI *p){
 UN seg=0,bus=0,dev=0,fun=0;uint32_t id=0,rev=0,command=0,bar=0;
 if(FAILED(p->location(p,&seg,&bus,&dev,&fun))||seg||bus||dev!=31||fun!=5)return 0;
 return cfg(p,0,&id)&&id==0x7aa48086&&cfg(p,8,&rev)&&rev==0x0c800011&&
        cfg(p,4,&command)&&command!=0xffffffff&&(command&2)&&cfg(p,0x10,&bar)&&bar==0xfe010000;
}
/* UEFI Configuration returns borrowed, read-only QWORD descriptors and an
 * End Tag. Reject unknown/ambiguous/malformed/translated descriptions. No
 * returned configuration buffer is freed. Each dereference is RAM bounded. */
static int root_resources(const uint8_t *p,unsigned *bus_match,unsigned *mem_match){
 *bus_match=0;*mem_match=0;UN total=0;uint8_t sum=0;
 if((uintptr_t)p>UINT64_MAX-4096){put("ROOT_RESOURCE=POINTER_OVERFLOW\r\n");return 0;}
 for(unsigned count=0;count<64;count++){
  if(!readable(p+total,2)){put("ROOT_RESOURCE=UNREADABLE_HEADER\r\n");return 0;}
  const uint8_t *d=p+total;
  if(d[0]==0x79){
   if(d[1]&&(uint8_t)(sum+d[0]+d[1]))return 0;
   return *bus_match<=1;
  }
  if(!readable(d,46)||d[0]!=0x8a||u16(d+1)!=43){put("ROOT_RESOURCE=UNKNOWN_OR_TRUNCATED_DESCRIPTOR\r\n");return 0;}
  uint8_t type=d[3];uint64_t gran=u64(d+6),lo=u64(d+14),hi=u64(d+22),trans=u64(d+30),len=u64(d+38);
  put("ROOT_RESOURCE TYPE=");dec(type);put(" GEN=0x");hex(d[4],2);put(" SPEC=0x");hex(d[5],2);put(" MIN=0x");hex(lo,16);put(" MAX=0x");hex(hi,16);put(" TRANS=0x");hex(trans,16);put(" LEN=0x");hex(len,16);put("\r\n");
  if(type>2||(d[4]&0xf3)||trans||!len||hi<lo||hi-lo==UINT64_MAX||len!=hi-lo+1)return 0;
  if(type==2){
   if(d[5]||gran||hi>255)return 0;
   put("ROOT_BUS_RANGE=0x");hex(lo,2);put("..0x");hex(hi,2);put("\r\n");
   if(lo==0)(*bus_match)++;
  }else if(type==0){
   if((d[5]&0xe0)||(gran!=32&&gran!=64)||(gran==32&&hi>0xffffffff))return 0;
   put("ROOT_MEM_RANGE=0x");hex(lo,16);put("..0x");hex(hi,16);put("\r\n");
   if(lo<=0xfe010000&&hi>=0xfe010097)(*mem_match)++;
  }
  for(unsigned i=0;i<46;i++)sum=(uint8_t)(sum+d[i]);total+=46;
 }
 return 0;
}
static ROOT *select_root(void){
 HANDLE *handles=0;UN count=0;ROOT *selected=0;unsigned matches=0,uncertain=0,coverage=0;
 ES e=st->bs->locate_handles(2,&root_guid,0,&count,&handles);field("ROOT_ENUM_STATUS",e,16);
 if(FAILED(e))return 0;
 if(!count||count>32||!handles||!readable(handles,count*sizeof(HANDLE))){if(handles)st->bs->free_pool(handles);put("ROOT_GATE=INVALID_HANDLE_LIST\r\n");return 0;}
 for(UN i=0;i<count;i++){
  ROOT *root=0;e=st->bs->handle_protocol(handles[i],&root_guid,(void **)&root);
  if(FAILED(e)||!root||!readable(root,sizeof(ROOT))){uncertain=1;put("ROOT_INTERFACE=UNAVAILABLE\r\n");continue;}
  field("ROOT_SEGMENT",root->segment,8);if(root->segment)continue;
  if(!root->configuration){uncertain=1;put("ROOT_CONFIGURATION=NO_METHOD\r\n");continue;}
  void *resources=0;e=root->configuration(root,&resources);field("ROOT_CONFIGURATION_STATUS",e,16);
  unsigned bus=0,mem=0;
  if(FAILED(e)||!resources||!root_resources(resources,&bus,&mem)){uncertain=1;put("ROOT_CONFIGURATION=INVALID_OR_UNKNOWN\r\n");continue;}
  if(bus){matches++;selected=root;coverage=mem;}
 }
 e=st->bs->free_pool(handles);if(FAILED(e)){failure("ROOT_HANDLES_FREE",e);uncertain=1;}
 if(uncertain||matches!=1||!selected||!selected->mem.read||coverage!=1){
  put("ROOT_GATE=REFUSED COVERING_BUS0_COUNT=");dec(matches);put(" UNKNOWN=");dec(uncertain);put(" MEMORY_COVERS=");dec(coverage);put("\r\n");return 0;
 }
 put("ROOT_GATE=UNIQUE_SEG0_BUS0_WITH_UNTRANSLATED_MEMORY_COVERAGE\r\n");return selected;
}
static int observation(unsigned i,const char *name,uint32_t offset,ES e,uint32_t raw){
 put(name);put(" OFFSET=0x");hex(offset,2);
 if(FAILED(e)){put(" STATUS=0x");hex(e,16);put("\r\n");warnings++;return 0;}
 put(" RAW=0x");hex(raw,8);
 if(raw==0xffffffff){put(" UNTRUSTED_ALL_ONES\r\n");warnings++;return 0;}
 if(i==0||(i>=3&&i<=8)||i>=9)range(raw,i>=9);
 unsigned valid=1;
 if(i==1){put(" FDV=");dec((raw>>14)&1);put(" FLOCKDN=");dec((raw>>15)&1);put(" SCIP=");dec((raw>>5)&1);if(!(raw&(1U<<14))||(raw&(1U<<5))){valid=0;warnings++;}}
 if(i==2){put(" BRRA=0x");hex(raw&255,2);put(" BRWA=0x");hex((raw>>8)&255,2);put(" BMRAG=0x");hex((raw>>16)&255,2);put(" BMWAG=0x");hex((raw>>24)&255,2);}
 if(i>=9){put(" RPE=");dec((raw>>15)&1);put(" WPE=");dec(raw>>31);}
 put("\r\n");return valid;
}
static ES collect_pci(void){
 HANDLE *handles=0;UN count=0;
 ES e=st->bs->locate_handles(2,&pci_guid,0,&count,&handles);field("PCI_ENUM_STATUS",e,16);
 if(FAILED(e))return e;
 if(!handles||!count||count>4096){if(handles)st->bs->free_pool(handles);return ERR(3);}
 PCI *chosen=0;unsigned matches=0;uint32_t chosen_id=0;
 for(UN i=0;i<count;i++){
  PCI *p=0;e=st->bs->handle_protocol(handles[i],&pci_guid,(void **)&p);
  if(FAILED(e)||!p||!p->pci.read||!p->location){failure("PCI_PROTOCOL_UNAVAILABLE",FAILED(e)?e:ERR(3));continue;}
  uint32_t id=0,revclass=0;if(!cfg(p,0,&id))continue;
  UN seg=0,bus=0,dev=0,fun=0;
  if(FAILED(e=p->location(p,&seg,&bus,&dev,&fun))){failure("PCI_LOCATION_FAILED",e);continue;}
  /* Log all BDF 31:5 candidates including unsupported IDs, plus known Intel
   * IDs found elsewhere; never touch their vendor MMIO until the full gate. */
  if((dev==31&&fun==5)||id==0x7a248086||id==0x7aa48086||id==0x7a8a8086){
   location_text(seg,bus,dev,fun);field("PCI_VID_DID",id,8);
   if(cfg(p,8,&revclass))field("PCI_REV_CLASS",revclass,8);
  }
  if((id==0x7a248086||id==0x7aa48086)&&seg==0&&bus==0&&dev==31&&fun==5){chosen=p;chosen_id=id;matches++;}
 }
 e=st->bs->free_pool(handles);if(FAILED(e))failure("PCI_HANDLES_FREE",e);
 if(matches!=1){put("SPI_ID_GATE=REJECTED_OR_AMBIGUOUS\r\n");return ERR(3);}
 put("SPI_ID_GATE=8086:");hex(chosen_id>>16,4);put("_AT_0000:00:1F.5\r\n");
 if(!chosen->mem.read){put("MMIO_READ_METHOD=UNAVAILABLE\r\n");return ERR(3);}
 uint32_t id=0,command=0,bar=0,bc=0,revclass=0;
 if(!cfg(chosen,0,&id)||id!=chosen_id||!cfg(chosen,8,&revclass)||!cfg(chosen,4,&command)||!cfg(chosen,0x10,&bar)||!cfg(chosen,0xdc,&bc))return ERR(7);
 /* 7AA4 is pinned to the revision/class actually observed in INV01.
  * Both IDs use the same Linux INTEL_SPI_CNL register layout. */
 if(id==0x7aa48086&&revclass!=0x0c800011){field("SPI_REV_CLASS",revclass,8);put("SPI_REV_CLASS_GATE=REJECTED\r\n");return ERR(3);}
 field("SPI_REV_CLASS",revclass,8);field("PCI_COMMAND_STATUS",command,8);field("SPIBAR0_RAW",bar,8);field("BIOS_CNTL",bc,8);
 if(bc==0xffffffff){put("BC=UNTRUSTED_ALL_ONES\r\n");warnings++;}
 else{put("BC BIOSWE=");dec(bc&1);put(" BLE=");dec((bc>>1)&1);put(" SMM_BWP=");dec((bc>>5)&1);put(" BILD=");dec((bc>>7)&1);put("\r\n");}
 if(command==0xffffffff||!(command&2)||!bar||bar>=0xfffff000||(bar&0xfff)){
  put("MMIO_GATE=REJECTED_DECODE_OR_BAR\r\n");return ERR(3);
 }
 static const uint32_t offsets[]={0,4,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x84,0x88,0x8c,0x90,0x94};
 static const char *names[]={"BFPR","HSFSTS_HSFC","FRAP","FREG0","FREG1","FREG2","FREG3","FREG4","FREG5","PR0","PR1","PR2","PR3","PR4"};
 unsigned complete=bc!=0xffffffff,unsupported=0;
 for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++){
  uint32_t raw=0;e=chosen->mem.read(chosen,2,0,offsets[i],1,&raw);
  if(e==ERR(3))unsupported++;
  if(!observation(i,names[i],offsets[i],e,raw))complete=0;
 }
 if(unsupported==14){
  put("PCI_IO_ALL_UNSUPPORTED: not evidence of flash read protection.\r\n");
  if(!observed_target(chosen)){put("ROOT_FALLBACK=REFUSED_TARGET_BINDING\r\n");return ERR(7);}
  fallback_metadata();ROOT *root=select_root();
  if(!root){put("ROOT_FALLBACK=REFUSED_RESOURCE_EVIDENCE\r\n");return ERR(7);}
  if(!observed_target(chosen)){put("ROOT_FALLBACK=REFUSED_TARGET_RECHECK\r\n");return ERR(7);}
  put("ROOT_OBSERVATIONS_BEGIN (14 allowlisted addresses only)\r\n");complete=bc!=0xffffffff;
  for(unsigned i=0;i<14;i++){
   uint32_t raw=0;e=root->mem.read(root,2,0xfe010000ULL+offsets[i],1,&raw);
   put("ROOT ");if(!observation(i,names[i],offsets[i],e,raw))complete=0;
  }
  put("ROOT_OBSERVATIONS_END (not a flash dump)\r\n");
 }
 return complete?0:ERR(7);
}

ES EA efi_main(HANDLE image,ST *table){
 (void)image;st=table;log_size=0;warnings=0;overflow=0;mmap_size=0;mmap_stride=0;
 if(!st||!st->bs||!st->bs->get_memory_map||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(3);
 put("SPI-INVENTORY-03 LOCAL-CANDIDATE\r\n");
 put("Flash bytes read=0; application PCI/MMIO write calls=0; SPI cycles=0; SetVariable calls=0\r\n");
 put("This is register inventory, not a flash backup or recovery guarantee.\r\n");
 /* Same display-lifetime protection as P3. This Boot Service does not ask
  * the application to write PCI, SPI or NVRAM. If firmware rejects it, the
  * default watchdog can still expire; record that limitation explicitly. */
 typedef ES(EA *WATCHDOG)(UN,uint64_t,UN,C16 *);
 ES wd=st->bs->set_watchdog?((WATCHDOG)st->bs->set_watchdog)(0,0,0,0):ERR(3);
 field("Watchdog.disable",wd,16);
 if(FAILED(wd)){warnings++;put("WATCHDOG_UNCONTROLLED: firmware may reset while log is displayed.\r\n");}
 typedef ES(EA *GETMAP)(UN *,void *,UN *,UN *,uint32_t *);
 UN key=0;uint32_t version=0;mmap_size=sizeof(mmap_buffer);
 ES result=((GETMAP)st->bs->get_memory_map)(&mmap_size,mmap_buffer,&key,&mmap_stride,&version);
 if(FAILED(result)||mmap_size>sizeof(mmap_buffer)||mmap_stride<40||mmap_stride>256||mmap_size%mmap_stride||version!=1){
  put("IDENTITY_GATE=REJECTED_MEMORY_MAP\r\n");result=ERR(3);goto done;
 }
 if(!identity()){put("IDENTITY_GATE=REJECTED_BOARD_OR_BIOS\r\n");result=ERR(3);goto done;}
 put("IDENTITY_GATE=Pro WS W790E-SAGE SE; BIOS=1904\r\n");
 result=collect_pci();if(!FAILED(result)&&FAILED(wd))result=ERR(7);
done:
 field("INVENTORY_STATUS",result,16);
 put("actual_component_capacity=null; component_count=null\r\n");
 put("Reference_CAP=64MiB; reference_BIOS=16MiB; neither is live capacity proof.\r\n");
 put("Coverage=FREG0..5 only; extension slot9 not inferred; no JEDEC/SFDP/FDOC.\r\n");
 put("Read permissions are observations only; no flash READ cycle was attempted.\r\n");
 if(FAILED(result))warnings++;
 put(FAILED(result)?"COLLECTION_STATUS=PARTIAL_OR_REFUSED\r\n":"COLLECTION_STATUS=DEFINED_REGISTERS_OBSERVED\r\n");
 put("PROBE_COMPLETE\r\n");
 if(overflow)return ERR(9);
 /* Existing P3 display transport only: no file, network or runtime service.
  * Its console/GOP routines can update the screen, not the SPI controller. */
 if(st->bs->allocate_pool&&st->bs->locate_protocol&&st->bs->stall){
  ES shown=kvm_present(st,log_buffer,log_size,warnings);if(FAILED(shown)&&!FAILED(result))result=shown;
 }
 return result;
}
