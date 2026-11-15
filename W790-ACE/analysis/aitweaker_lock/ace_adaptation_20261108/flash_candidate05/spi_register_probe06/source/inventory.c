/* ACE1904-SPI-PROBE06. Flash-controller inventory only, no SPI cycle.
 * The PCI/MMIO write methods are deliberately opaque and never called.
 * Exact observed ACE BAR, with original CPU_IO2 read code and fresh map gates.
 * No application MMIO dereference, PCI_IO/RootBridge read, or other fallback.
 * SMBIOS/memory-map parsing follows the previously reviewed inventory design,
 * but SAGE board/address observations are not accepted as ACE evidence.
 */
#include "efi_min.h"
#include "kvm.h"
#include "build_identity.h"
#include "cpu_reference.h"
#include <string.h>

typedef struct PCI PCI;
typedef ES (EA *CFG_READ)(PCI *,uint32_t,uint32_t,UN,void *);
typedef ES (EA *MEM_READ)(PCI *,uint32_t,uint8_t,uint64_t,UN,void *);
typedef ES (EA *LOCATION)(PCI *,UN *,UN *,UN *,UN *);
struct PCI {
 void *poll_mem,*poll_io;
 struct {MEM_READ read;void *opaque_write;} mem;
 void *opaque_io[2];
 struct {CFG_READ read;void *opaque_write;} pci;
 void *copy_mem,*map,*unmap,*alloc,*free,*flush;
 LOCATION location;
};
OFF(PCI,mem.read,0x10);OFF(PCI,pci.read,0x30);OFF(PCI,location,0x70);
typedef struct CPU CPU;
typedef ES(EA *CPU_READ)(CPU *,uint32_t,uint64_t,UN,void *);
struct CPU {struct {CPU_READ read;void *opaque_write;} mem;void *opaque_io[2];};
OFF(CPU,mem.read,0);_Static_assert(sizeof(CPU)==32,"CPU_IO2 x64 ABI");
OFF(BS,get_memory_map,0x38);OFF(BS,set_watchdog,0x100);
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID cpu_guid={0xad61f191,0xae5f,0x4c0e,{0xb9,0xfa,0xe8,0x69,0xd2,0x88,0xc6,0x4f}};
static GUID sm3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID sm2_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static const uint32_t offsets[14]={0,4,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x84,0x88,0x8c,0x90,0x94};
static const char *names[14]={"BFPR","HSFSTS_HSFC","FRAP","FREG0","FREG1","FREG2","FREG3","FREG4","FREG5","PR0","PR1","PR2","PR3","PR4"};
static uint8_t memory_map[65536];
static UN map_size,map_stride;
static char log_buffer[16384];
static size_t log_size;
static unsigned warnings,overflow;
static ST *st;

void *memset(void *p,int value,size_t n){uint8_t *s=p;while(n--)*s++=(uint8_t)value;return p;}
void *memcpy(void *p,const void *q,size_t n){uint8_t *d=p;const uint8_t *s=q;while(n--)*d++=*s++;return p;}
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t u32(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static uint64_t u64(const void *p){uint64_t x;memcpy(&x,p,8);return x;}
static int equal(const void *p,const void *q,size_t n){const uint8_t *a=p,*b=q;while(n--)if(*a++!=*b++)return 0;return 1;}
static void put(const char *s){while(*s){if(log_size+1<sizeof(log_buffer))log_buffer[log_size++]=*s;else overflow=1;s++;}log_buffer[log_size]=0;}
static void hex(uint64_t value,unsigned digits){static const char h[]="0123456789ABCDEF";char b[17];for(unsigned i=0;i<digits;i++)b[i]=h[(value>>((digits-i-1)*4))&15];b[digits]=0;put(b);}
static void field(const char *name,uint64_t value,unsigned digits){put(name);put("=0x");hex(value,digits);put("\r\n");}
static void problem(const char *name,ES status){warnings++;field(name,status,16);}

static int readable(const void *ptr,UN length){
 uint64_t start=(uint64_t)(uintptr_t)ptr;
 if(!start||!length||start+length<start)return 0;
 unsigned overlaps=0,covered=0;
 for(UN p=0;p<map_size;p+=map_stride){
  const uint8_t *d=memory_map+p;uint32_t type=u32(d);uint64_t base=u64(d+8),pages=u64(d+24),attributes=u64(d+32);
  if(pages>(UINT64_MAX-base)/4096)continue;
  if(start<base+pages*4096&&base<start+length)overlaps++;
  if(!(type==1||type==2||type==3||type==4||type==5||type==6||type==7||type==9||type==10)||(attributes&0x2000))continue;
  if(start>=base&&start+length<=base+pages*4096)covered++;
 }
 return covered==1&&overlaps==1;
}
static int code_range(const void *ptr,UN length){
 uint64_t address=(uint64_t)(uintptr_t)ptr;unsigned overlaps=0,covered=0;
 if(!address||!length||address+length<address)return 0;
 for(UN p=0;p<map_size;p+=map_stride){
  const uint8_t *d=memory_map+p;uint32_t type=u32(d);uint64_t base=u64(d+8),pages=u64(d+24),attributes=u64(d+32);
  if(pages>(UINT64_MAX-base)/4096)continue;
  if(address<base+pages*4096&&base<address+length)overlaps++;
  if(!(type==1||type==3||type==5)||(attributes&0x6000))continue;
  if(address>=base&&address+length<=base+pages*4096)covered++;
 }
 return covered==1&&overlaps==1;
}
static int executable(const void *ptr){return code_range(ptr,1);}
static int mmio_page(uint64_t *attributes){
 unsigned overlaps=0,covered=0;
 for(UN p=0;p<map_size;p+=map_stride){
  const uint8_t *d=memory_map+p;uint64_t base=u64(d+8),pages=u64(d+24),a=u64(d+32);
  if(base>=0xfe011000ULL||base+pages*4096<=0xfe010000ULL)continue;
  overlaps++;
  put("UEFI_MAP_BAR TYPE=0x");hex(u32(d),2);put(" BASE=0x");hex(base,16);put(" PAGES=0x");hex(pages,8);put(" ATTR=0x");hex(a,16);put("\r\n");
  /* Exact existing controller page, UC capability only; RP/conflicting cache
   * flags or unknown attributes refuse. Attributes are not a permission grant. */
  if(u32(d)==11&&base==0xfe010000ULL&&pages==1&&(a&1)&&
     !(a&~(0x8000000000000001ULL|0x4000ULL|0x20000ULL))){covered++;*attributes=a;}
 }
 return overlaps==1&&covered==1;
}
static int get_map(void){
 typedef ES(EA *GET_MAP)(UN *,void *,UN *,UN *,uint32_t *);
 UN size=sizeof(memory_map),key=0,stride=0;uint32_t version=0;
 if(!st->bs->get_memory_map){problem("MEMORY_MAP_MISSING",ERR(3));return 0;}
 ES e=((GET_MAP)st->bs->get_memory_map)(&size,memory_map,&key,&stride,&version);
 field("MemoryMap.status",e,16);
 if(FAILED(e)||size>sizeof(memory_map)||!size||stride<40||stride>4096||size%stride||version!=1){problem("MEMORY_MAP_REJECTED",e);return 0;}
 for(UN p=0;p<size;p+=stride){
  const uint8_t *d=memory_map+p;uint64_t base=u64(d+8),pages=u64(d+24);
  if(u32(d)>15||!pages||(base&4095)||pages>(UINT64_MAX-base)/4096){problem("MEMORY_MAP_DESCRIPTOR_REJECTED",ERR(2));return 0;}
 }
 map_size=size;map_stride=stride;return 1;
}
static int sm_string(const uint8_t *s,UN bytes,uint8_t index,const char *wanted){
 if(!index)return 0;UN p=s[1];
 for(unsigned i=1;i<index;i++){while(p<bytes&&s[p])p++;if(p+1>=bytes||!s[p+1])return 0;p++;}
 UN j=0;for(;p+j<bytes&&wanted[j];j++)if(s[p+j]!=(uint8_t)wanted[j])return 0;
 return p+j<bytes&&!wanted[j]&&!s[p+j];
}
static int sm_table(const uint8_t *s,UN bytes){
 if(bytes<6||bytes>2*1024*1024||!readable(s,bytes))return 0;
 unsigned board=0,version=0;
 for(UN p=0,count=0;p+4<=bytes&&count<4096;count++){
  unsigned type=s[p],len=s[p+1];if(len<4||len>bytes-p)return 0;
  UN end=p+len;while(end+1<bytes&&(s[end]||s[end+1]))end++;
  if(end+1>=bytes)return 0;end+=2;
  if(type==0){if(len<6||version++||!sm_string(s+p,end-p,s[p+5],"1904"))return 0;}
  if(type==2){if(len<6||board++||!sm_string(s+p,end-p,s[p+5],"Pro WS W790-ACE"))return 0;}
  if(type==127)return board==1&&version==1;
  p=end;
 }
 return 0;
}
static int identity(void){
 if(!st->table_count||st->table_count>256||!readable(st->tables,st->table_count*sizeof(CT)))return 0;
 unsigned matched=0;
 for(UN i=0;i<st->table_count;i++){
  CT *ct=st->tables+i;const uint8_t *ep=ct->table;UN size,bytes;uint64_t address;
  if(equal(&ct->guid,&sm3_guid,16)){
   if(!readable(ep,24)||!equal(ep,"_SM3_",5))return 0;
   size=ep[6];if(size<24||size>64||!readable(ep,size))return 0;
   bytes=u32(ep+12);address=u64(ep+16);
  }else if(equal(&ct->guid,&sm2_guid,16)){
   if(!readable(ep,31)||!equal(ep,"_SM_",4)||!equal(ep+16,"_DMI_",5))return 0;
   size=ep[5];if(size<31||size>64||!readable(ep,size))return 0;
   uint8_t sum=0;for(unsigned j=16;j<31;j++)sum=(uint8_t)(sum+ep[j]);if(sum)return 0;
   bytes=u16(ep+22);address=u32(ep+24);
  }else continue;
  uint8_t sum=0;for(UN j=0;j<size;j++)sum=(uint8_t)(sum+ep[j]);
  if(sum||!sm_table((const uint8_t *)(uintptr_t)address,bytes))return 0;
  matched++;
 }
 return matched>0;
}
/* Only enumerated CPUID leaves. No RDMSR/RDPMC, exception hooking or TXT MMIO. */
static void cpuid(uint32_t leaf,uint32_t sub,uint32_t out[4]){
 __asm__ volatile("cpuid":"=a"(out[0]),"=b"(out[1]),"=c"(out[2]),"=d"(out[3]):"a"(leaf),"c"(sub));
}
static int cpu_identity(void){
 uint32_t v[4];char vendor[13];cpuid(0,0,v);uint32_t max=v[0];
 memcpy(vendor,v+1,4);memcpy(vendor+4,v+3,4);memcpy(vendor+8,v+2,4);vendor[12]=0;
 put("CPU.vendor=");put(vendor);put("\r\n");field("CPU.max_leaf",max,8);
 if(!equal(vendor,"GenuineIntel",12)||max<1)return 0;
 cpuid(1,0,v);uint32_t observed=v[0];for(unsigned i=0;i<4;i++){put("CPUID.1.REG");hex(i,1);put("=0x");hex(v[i],8);put("\r\n");}
 uint32_t family=(v[0]>>8)&15,model=(v[0]>>4)&15;
 if(family==6||family==15)model|=(v[0]>>12)&0xf0;
 if(family==15)family+=(v[0]>>20)&255;
 field("CPU.family",family,2);field("CPU.model",model,2);
 if(max>=7){cpuid(7,0,v);for(unsigned i=0;i<4;i++){put("CPUID.7.0.REG");hex(i,1);put("=0x");hex(v[i],8);put("\r\n");}}
 put("SACM_MSR_READ=NOT_ATTEMPTED\r\nBootGuard.live_policy=UNKNOWN\r\n");
 return family==6&&model==0x8f&&observed==0x000806f8;
}
static int cpu_unchanged(void){
 uint32_t v[4];cpuid(0,0,v);
 if(v[0]<1||v[1]!=0x756e6547||v[3]!=0x49656e69||v[2]!=0x6c65746e)return 0;
 cpuid(1,0,v);return v[0]==0x806f8;
}
static int cfg(PCI *pci,uint32_t offset,uint32_t *value){
 ES e=pci->pci.read(pci,2,offset,1,value);
 if(FAILED(e)){problem("PCI_READ_FAILED",e);field("PCI_READ_OFFSET",offset,4);return 0;}return 1;
}
typedef struct {UN segment,bus,device,function;uint32_t id,revclass,command,bar,control;} SNAP;
static int snapshot(PCI *pci,SNAP *s){
 memset(s,0,sizeof(*s));
 ES e=pci->location(pci,&s->segment,&s->bus,&s->device,&s->function);
 if(FAILED(e)||s->segment>65535||s->bus>255||s->device>31||s->function>7){problem("PCI_LOCATION_REJECTED",e);return 0;}
 return cfg(pci,0,&s->id)&&cfg(pci,8,&s->revclass)&&cfg(pci,4,&s->command)&&cfg(pci,0x10,&s->bar)&&cfg(pci,0xdc,&s->control);
}
static void print_snapshot(const char *kind,const SNAP *s){
 put("PCI_KIND=");put(kind);put(" PCI_LOCATION=");hex(s->segment,4);put(":");hex(s->bus,2);put(":");hex(s->device,2);put(".");hex(s->function,1);put("\r\n");
 field("PCI.VID_DID",s->id,8);field("PCI.REVISION_CLASS",s->revclass,8);field("PCI.COMMAND_STATUS",s->command,8);field("PCI.BAR0",s->bar,8);field("PCI.BIOS_CNTL",s->control,8);
}
static int provider(PCI *pci){
 return readable(pci,sizeof(*pci))&&executable((void *)pci->pci.read)&&executable((void *)pci->location);
}
static int spi_ready(const SNAP *s){
 return !s->segment&&!s->bus&&s->device==31&&s->function==5&&s->id==0x7aa48086&&
        s->revclass==0x0c800011&&s->command==0x402&&s->bar==0xfe010000&&s->control==0x100008aa;
}
static int lpc_ready(const SNAP *s){
 return !s->segment&&!s->bus&&s->device==31&&!s->function&&s->id==0x7a8a8086&&
        s->revclass==0x06010011&&s->command==0x547&&!s->bar&&s->control==0xa6;
}
static int cpu_provider(CPU *cpu){
 if(!readable(cpu,sizeof(*cpu)))return 0;
 uintptr_t read=(uintptr_t)cpu->mem.read;if(read<0x3d4)return 0;
 uint8_t *base=(uint8_t *)(read-0x3d4);
 if((uint8_t *)cpu!=base+0x730||!code_range(base+0x30c,0x481-0x30c)||!readable(base+0x720,0x50))return 0;
 if((uintptr_t)cpu->mem.opaque_write!=(uintptr_t)base+0x484||
    (uintptr_t)cpu->opaque_io[0]!=(uintptr_t)base+0x534||(uintptr_t)cpu->opaque_io[1]!=(uintptr_t)base+0x624)return 0;
 return equal(base+0x30c,cpu_parameters,sizeof(cpu_parameters))&&equal(base+0x3d4,cpu_read_code,sizeof(cpu_read_code))&&
        equal(base+0x750,cpu_strides,sizeof(cpu_strides))&&equal(base+0x720,&cpu_guid,16);
}
static CPU *select_cpu(HANDLE *owner){
 HANDLE *handles=0;UN count=0;CPU *cpu=0;ES e=st->bs->locate_handles(2,&cpu_guid,0,&count,&handles);
 field("CPU_IO2_ENUM_STATUS",e,16);field("CPU_IO2_COUNT",count,8);
 if(FAILED(e)||count!=1||!readable(handles,sizeof(HANDLE))){problem("CPU_IO2_UNAVAILABLE_OR_AMBIGUOUS",e);goto done;}
 *owner=handles[0];e=st->bs->handle_protocol(*owner,&cpu_guid,(void **)&cpu);
 if(FAILED(e)){problem("CPU_IO2_HANDLE_FAILED",e);cpu=0;}
done:
 if(handles&&readable(handles,sizeof(HANDLE))){e=st->bs->free_pool(handles);if(FAILED(e)){problem("CPU_IO2_HANDLE_FREE_FAILED",e);cpu=0;}}
 return cpu;
}
static void decoded_range(uint32_t value,int pr){
 uint32_t base=(value&0x7fff)<<12,end=(((value>>16)&0x7fff)<<12)|0xfff;
 put(" BASE=0x");hex(base,8);put(" LIMIT=0x");hex(end,8);put(base<=end?" RANGE_VALID":" DISABLED_OR_INVALID");
 if(pr){put(value&0x8000?" RPE=1":" RPE=0");put(value&0x80000000u?" WPE=1":" WPE=0");}
}
static int inventory(void){
 HANDLE *handles=0,*cleanup=0;UN count=0;PCI *selected=0,*lpc_selected=0;SNAP original,lpc_original;unsigned spi_count=0,lpc_count=0,complete=0,scan_ok=1;
 ES e=st->bs->locate_handles(2,&pci_guid,0,&count,&handles);
 field("PCI_ENUM_STATUS",e,16);field("PCI_HANDLE_COUNT",count,8);
 if(!FAILED(e)&&readable(handles,sizeof(HANDLE)))cleanup=handles;
 if(FAILED(e)||!count||count>2048||!readable(handles,count*sizeof(HANDLE))){problem("PCI_ENUM_REJECTED",e);goto finish;}
 for(UN i=0;i<count;i++){
  PCI *pci=0;e=st->bs->handle_protocol(handles[i],&pci_guid,(void **)&pci);
  if(FAILED(e)||!provider(pci)){problem("PCI_PROTOCOL_REJECTED",e);scan_ok=0;continue;}
  uint32_t id=0;if(!cfg(pci,0,&id)){scan_ok=0;continue;}
  if(id==0x7a8a8086){SNAP lpc;if(!snapshot(pci,&lpc)||lpc.id!=id){scan_ok=0;continue;}lpc_count++;lpc_selected=pci;lpc_original=lpc;print_snapshot("W790_LPC_REFERENCE_ID",&lpc);}
  if(id==0x7a248086||id==0x7aa48086){
   SNAP s;if(!snapshot(pci,&s)||s.id!=id){scan_ok=0;continue;}spi_count++;print_snapshot("KNOWN_700_SERIES_SPI_ID",&s);
   selected=pci;original=s;
  }
 }
 field("SPI_CANDIDATE_COUNT",spi_count,8);field("W790_LPC_COUNT",lpc_count,8);
 if(!scan_ok||spi_count!=1||lpc_count!=1||!spi_ready(&original)||!lpc_ready(&lpc_original)){
  problem("SPI_GATE_REJECTED_OR_AMBIGUOUS",ERR(3));goto finish;
 }
 CFG_READ spi_cfg=selected->pci.read,lpc_cfg=lpc_selected->pci.read;
 LOCATION spi_loc=selected->location,lpc_loc=lpc_selected->location;
 HANDLE cpu_owner=0;CPU *cpu=select_cpu(&cpu_owner);uint64_t attributes=0;
 if(!get_map()||!identity()||!cpu_unchanged()||!mmio_page(&attributes)||!cpu_provider(cpu)){
  problem("CPU_IO2_RESOURCE_OR_PROVIDER_GATE_REFUSED",ERR(3));goto finish;
 }
 put("CPU_IO2_GATE=ORIGINAL_ACE_READ_CODE_EXACT_PCI_AND_MMIO_PAGE\r\n");
 for(unsigned i=0;i<14;i++){
  SNAP current,lpc_current;CPU *current_cpu=0;uint64_t current_attributes=0;
  e=st->bs->handle_protocol(cpu_owner,&cpu_guid,(void **)&current_cpu);
  if(FAILED(e)||!get_map()||!identity()||!cpu_unchanged()||!mmio_page(&current_attributes)||current_attributes!=attributes||
     current_cpu!=cpu||!cpu_provider(cpu)||!provider(selected)||!provider(lpc_selected)||
     selected->pci.read!=spi_cfg||selected->location!=spi_loc||lpc_selected->pci.read!=lpc_cfg||lpc_selected->location!=lpc_loc){
   problem("READINESS_CHANGED_BEFORE_MMIO",ERR(3));goto finish;
  }
  if(!snapshot(lpc_selected,&lpc_current)||!equal(&lpc_current,&lpc_original,sizeof(lpc_current))||
     !snapshot(selected,&current)||!equal(&current,&original,sizeof(current))){problem("PCI_IDENTITY_CHANGED_BEFORE_MMIO",ERR(3));goto finish;}
  /* Only these14 DWORD addresses, never a caller-provided range or SPI cycle. */
  uint32_t value=0;e=cpu->mem.read(cpu,2,0xfe010000ULL+offsets[i],1,&value);
  put(names[i]);put(" OFFSET=0x");hex(offsets[i],4);put(" STATUS=0x");hex(e,16);put(" VALUE=0x");hex(value,8);
  if(!FAILED(e)&&i>=3)decoded_range(value,i>=9);put("\r\n");
  if(FAILED(e)||value==0xffffffff){problem("SPI_MMIO_READ_UNAVAILABLE",e);goto finish;}
  if(i==1&&(!(value&0x4000)||(value&0x20))){problem("SPI_DESCRIPTOR_INVALID_OR_CONTROLLER_BUSY",ERR(6));goto finish;}
 }
 {SNAP current,lpc_current;uint64_t final_attributes=0;CPU *final_cpu=0;
  e=st->bs->handle_protocol(cpu_owner,&cpu_guid,(void **)&final_cpu);
  if(FAILED(e)||!get_map()||!identity()||!cpu_unchanged()||!mmio_page(&final_attributes)||final_attributes!=attributes||
     final_cpu!=cpu||!cpu_provider(cpu)||
     !provider(selected)||!provider(lpc_selected)||selected->pci.read!=spi_cfg||selected->location!=spi_loc||
     lpc_selected->pci.read!=lpc_cfg||lpc_selected->location!=lpc_loc||
     !snapshot(selected,&current)||!equal(&current,&original,sizeof(current))||
     !snapshot(lpc_selected,&lpc_current)||!equal(&lpc_current,&lpc_original,sizeof(lpc_current))){problem("IDENTITY_CHANGED_AFTER_MMIO",ERR(3));goto finish;}}
 complete=1;
finish:
 if(cleanup){e=st->bs->free_pool(cleanup);if(FAILED(e)){problem("PCI_HANDLE_FREE_FAILED",e);complete=0;}}
 return complete!=0;
}
ES EA efi_main(HANDLE image,ST *table){
 (void)image;st=table;log_size=0;warnings=0;overflow=0;map_size=map_stride=0;
 if(!st||!st->bs||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(2);
 put("ACE1904-SPI-PROBE06\r\nToolSourceSHA256=" TOOL_SOURCE_SHA256 "\r\n");
 put("ACCESS_PATH=EFI_CPU_IO2_MEM_READ_ONLY\r\nMAX_REGISTER_READS=14\r\nMAX_ADDRESS=0xFE010097\r\n");
 put("SPI_REGISTER_WRITES_BY_INVENTORY=0\r\nPCI_CONFIG_WRITES_BY_INVENTORY=0\r\nFLASH_READ_CYCLES=0\r\nFLASH_PROGRAM_ERASE_CYCLES=0\r\n");
 put("actual_component_capacity=null\r\nFLASH_BYTES_ACQUIRED=0\r\nEXTENDED_FREG_SLOT9_PERMISSION=UNKNOWN\r\n");
 put("LIVE_DESCRIPTOR_BYTES=NOT_READ\r\nLIVE_FIT_ACM_KM_BPM_BYTES=NOT_READ\r\nBOOT_GUARD_FUSES_AND_PROVISIONING=UNKNOWN\r\n");
 unsigned complete=0;
 typedef ES(EA *WATCHDOG)(UN,uint64_t,UN,C16 *);
 if(st->bs->set_watchdog){ES e=((WATCHDOG)st->bs->set_watchdog)(0,0,0,0);field("Watchdog.disable",e,16);if(FAILED(e))warnings++;}
 if(!get_map())goto done;
 int cpu_ok=cpu_identity();
 if(!identity()){problem("IDENTITY_GATE_REJECTED_BOARD_OR_BIOS",ERR(3));goto done;}
 put("IDENTITY_GATE=Pro WS W790-ACE; BIOS=1904\r\n");
 if(!cpu_ok){problem("CPU_GATE_REJECTED_FAMILY_MODEL",ERR(3));goto done;}
 complete=(unsigned)inventory();
done:
 put(complete&&!warnings&&!overflow?"COLLECTION_STATUS=DEFINED_REGISTER_SNAPSHOT_COMPLETE\r\n":"COLLECTION_STATUS=PARTIAL_OR_REFUSED\r\n");
 field("Warnings",warnings,8);field("LogOverflow",overflow,8);
 put("NO_FLASH_DUMP_OR_READ_PERMISSION_GUARANTEE\r\nPROBE_COMPLETE\r\n");
 return kvm_present(st,log_buffer,log_size,warnings+overflow);
}
