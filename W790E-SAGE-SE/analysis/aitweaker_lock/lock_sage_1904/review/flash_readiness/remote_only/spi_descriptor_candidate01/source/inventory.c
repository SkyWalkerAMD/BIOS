/* SPI-DESCRIPTOR-01: fixed 4 KiB flash READ, never a full backup.
 * Only the isolated core can request MMIO command/status writes. All PCI write,
 * raw port, runtime variable, disk/file and network methods remain unused. */
#include "efi_min.h"
#include "kvm.h"
#include "fd_core.h"
#include "cpu_reference.h"
#include <string.h>
typedef struct PCI PCI;
typedef ES (EA *CFG_READ)(PCI *,uint32_t,uint32_t,UN,void *);
typedef ES (EA *MEM_READ)(PCI *,uint32_t,uint8_t,uint64_t,UN,void *);
typedef ES (EA *LOCATION)(PCI *,UN *,UN *,UN *,UN *);
struct PCI {
 void *poll_mem,*poll_io;
 struct {MEM_READ read;void *unused_write;} mem;
 void *unused_io[2];
 struct {CFG_READ read;void *unused_write;} pci;
 void *copy_mem,*map,*unmap,*alloc,*free,*flush;
 LOCATION location;
};
OFF(PCI,pci.read,0x30);OFF(PCI,location,0x70);
typedef struct CPU CPU;
typedef ES(EA *CPU_READ)(CPU *,uint32_t,uint64_t,UN,void *);
struct CPU {struct {CPU_READ read,write;} mem;void *unused_io[2];};
OFF(CPU,mem.read,0);OFF(CPU,mem.write,8);_Static_assert(sizeof(CPU)==32,"CPU_IO2 ABI");
OFF(BS,get_memory_map,0x38);OFF(ST,table_count,0x68);OFF(ST,tables,0x70);
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID cpuio2_guid={0xad61f191,0xae5f,0x4c0e,{0xb9,0xfa,0xe8,0x69,0xd2,0x88,0xc6,0x4f}};
static GUID sm3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID sm2_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static ST *st;
static uint8_t mmap_buffer[65536];
static UN mmap_size,mmap_stride;
static char log_buffer[16384];
static size_t log_size;
static unsigned warnings,overflow;
static uint8_t capture_a[4096],capture_b[4096];
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

static int observed_target(PCI *p){
 UN seg=0,bus=0,dev=0,fun=0;uint32_t id=0,rev=0,command=0,bar=0;
 if(FAILED(p->location(p,&seg,&bus,&dev,&fun))||seg||bus||dev!=31||fun!=5)return 0;
 return cfg(p,0,&id)&&id==0x7aa48086&&cfg(p,8,&rev)&&rev==0x0c800011&&
        cfg(p,4,&command)&&command!=0xffffffff&&(command&2)&&cfg(p,0x10,&bar)&&bar==0xfe010000;
}

static int cpu_map_gate(void){
 typedef ES(EA *GETMAP)(UN *,void *,UN *,UN *,uint32_t *);
 UN size=sizeof(mmap_buffer),key=0,stride=0;uint32_t version=0;
 ES e=((GETMAP)st->bs->get_memory_map)(&size,mmap_buffer,&key,&stride,&version);field("CPU_MAP_REFRESH_STATUS",e,16);
 mmap_size=0;mmap_stride=0;
 if(FAILED(e)||!size||size>sizeof(mmap_buffer)||stride<40||stride>256||size%stride||version!=1){put("CPU_GATE=REFUSED_MAP_FORMAT\r\n");return 0;}
 mmap_size=size;mmap_stride=stride;unsigned overlaps=0,exact=0;
 for(UN p=0;p<size;p+=stride){
  const uint8_t *d=mmap_buffer+p;uint32_t type=u32(d);uint64_t start=u64(d+8),pages=u64(d+24),attr=u64(d+32);
  if(type>15||(start&0xfff)||!pages||pages>(UINT64_MAX-start)/4096){put("CPU_GATE=REFUSED_MALFORMED_MAP_RANGE\r\n");return 0;}
  uint64_t end=start+pages*4096-1;
  if(start<=0xfe010fff&&end>=0xfe010000){
   overlaps++;put("CPU_MAP_OVERLAP TYPE=");dec(type);put(" START=0x");hex(start,16);put(" END=0x");hex(end,16);put(" ATTR=0x");hex(attr,16);put("\r\n");
   if(type==11&&start==0xfe010000&&pages==1&&attr==0x8000000000000001ULL)exact++;
  }
 }
 if(overlaps!=1||exact!=1){put("CPU_GATE=REFUSED_MMIO_PAGE_BINDING OVERLAPS=");dec(overlaps);put(" EXACT=");dec(exact);put("\r\n");return 0;}
 put("CPU_MAP_GATE=EXACT_OBSERVED_TYPE11_UC_RUNTIME_PAGE; attributes are capabilities\r\n");return 1;
}

static int cpu_method_in_code(CPU_READ method){
 uint64_t address=(uint64_t)(uintptr_t)method;field("CPU_METHOD_POINTER",address,16);if(!address)return 0;
 unsigned matches=0;
 for(UN p=0;p<mmap_size;p+=mmap_stride){
  const uint8_t *d=mmap_buffer+p;uint32_t type=u32(d);uint64_t start=u64(d+8),pages=u64(d+24),attr=u64(d+32);
  if(address>=start&&address-start<pages*4096){
   put("CPU_METHOD_MAP TYPE=");dec(type);put(" START=0x");hex(start,16);put(" END=0x");hex(start+pages*4096-1,16);put(" ATTR=0x");hex(attr,16);put("\r\n");
   if((type!=3&&type!=5)||(attr&0x6000))return 0;
   matches++;
  }
 }
 return matches==1;
}

static CPU *select_cpu(PCI *target){
 if(!cpu_map_gate()||!identity()||!observed_target(target)){put("CPU_GATE=REFUSED_INITIAL_BINDING\r\n");return 0;}
 HANDLE *handles=0;UN count=0;CPU *cpu=0;
 ES e=st->bs->locate_handles(2,&cpuio2_guid,0,&count,&handles);field("CPU_ENUM_STATUS",e,16);
 if(FAILED(e))return 0;
 if(!handles||!readable(handles,sizeof(HANDLE))){put("CPU_GATE=REFUSED_HANDLE_BUFFER\r\n");return 0;}
 if(count!=1){st->bs->free_pool(handles);put("CPU_GATE=REFUSED_INTERFACE_COUNT\r\n");return 0;}
 e=st->bs->handle_protocol(handles[0],&cpuio2_guid,(void **)&cpu);field("CPU_PROTOCOL_STATUS",e,16);
 ES released=st->bs->free_pool(handles);
 if(FAILED(e)||FAILED(released)||!cpu){put("CPU_GATE=REFUSED_PROTOCOL_OR_RELEASE\r\n");return 0;}
 /* Protocol lookup/free may affect memory allocation; validate a fresh map. */
 if(!cpu_map_gate()||!identity()||!observed_target(target)){put("CPU_GATE=REFUSED_FINAL_BINDING\r\n");return 0;}
 if(!readable(cpu,sizeof(CPU))||!cpu_method_in_code(cpu->mem.read)){put("CPU_GATE=REFUSED_INTERFACE_OR_METHOD_MAPPING\r\n");return 0;}
 put("CPU_GATE=UNIQUE_VALIDATED_PROTOCOL_AND_EXACT_OBSERVED_MMIO_PAGE\r\n");return cpu;
}

typedef struct {PCI *pci;CPU *cpu;uint32_t reads,writes,initial_address;int have_address;} CONTEXT;
static int native_binding(CPU *cpu){
 if(!cpu||!readable(cpu,sizeof(*cpu))||!cpu_method_in_code(cpu->mem.write))return 0;
 uintptr_t read=(uintptr_t)cpu->mem.read,write=(uintptr_t)cpu->mem.write;
 if(read<0x3d4||write-read!=0xb0)return 0;
 const uint8_t *base=(const uint8_t *)(read-0x3d4);
 if((uintptr_t)base&0xfff)return 0;
 return readable(base+0x30c,sizeof(cpu_reference_code))&&readable(base+0x750,sizeof(cpu_reference_tables))&&
        equal(base+0x30c,cpu_reference_code,sizeof(cpu_reference_code))&&equal(base+0x750,cpu_reference_tables,sizeof(cpu_reference_tables));
}
static int EA io_binding(void *opaque){
 CONTEXT *c=opaque;uint32_t bc=0;
 /* The code/table snapshots cannot select a new hardware address. */
 return c&&c->cpu&&c->pci&&observed_target(c->pci)&&cfg(c->pci,0xdc,&bc)&&bc==0x100008aa;
}
static int allowed_read(uint32_t off){
 if(off==4||off==8||off==0x0c||off==0x50||off==0x54||off==0x98)return 1;
 return !(off&3)&&((off>=0x10&&off<=0x4c)||(off>=0x84&&off<=0x94));
}
static ES EA io_read(void *opaque,uint32_t off,uint32_t *value){
 CONTEXT *c=opaque;if(!value||!allowed_read(off))return ERR(15);
 c->reads++;ES s=c->cpu->mem.read(c->cpu,2,0xfe010000ULL+off,1,value);
 if(!FAILED(s)&&off==8&&!c->have_address){c->initial_address=*value;c->have_address=1;}
 return s;
}
static ES EA io_write(void *opaque,uint32_t off,uint32_t value){
 CONTEXT *c=opaque;
 if(off==8){
  if(!((value<4096&&!(value&63))||(c->have_address&&value==c->initial_address)))return ERR(15);
 }else if(off==4){
  if((value&0xffffU)!=0xe800U&&(value&0xffffU)!=0xe801U)return ERR(15);
  if(value&0xc0e00000U||((value>>17)&15)>8)return ERR(15);
  if(value&0x10000U){
   if(value!=0x3f01e800U)return ERR(15);
   uint32_t address=0;ES s=io_read(c,8,&address);
   if(FAILED(s)||address>=4096||(address&63))return ERR(15);
  }
 }else return ERR(15);
 c->writes++;return c->cpu->mem.write(c->cpu,2,0xfe010000ULL+off,1,&value);
}
static ES EA io_stall(void *opaque,UN us){(void)opaque;if(us!=10)return ERR(2);return st->bs->stall(us);}
static PCI *select_pci(void){
 HANDLE *handles=0;UN count=0;PCI *selected=0;unsigned matches=0,uncertain=0;
 ES e=st->bs->locate_handles(2,&pci_guid,0,&count,&handles);field("PCI_ENUM",e,16);
 if(FAILED(e))return 0;
 if(!handles||!count||count>4096||!readable(handles,count*sizeof(HANDLE))){if(handles)st->bs->free_pool(handles);return 0;}
 for(UN i=0;i<count;i++){
  PCI *p=0;e=st->bs->handle_protocol(handles[i],&pci_guid,(void **)&p);
  if(FAILED(e)||!p||!readable(p,sizeof(PCI))||!p->location||!p->pci.read){uncertain=1;continue;}
  UN seg=0,bus=0,dev=0,fun=0;
  if(FAILED(p->location(p,&seg,&bus,&dev,&fun))){uncertain=1;continue;}
  if(!seg&&!bus&&dev==31&&fun==5){selected=p;matches++;}
 }
 if(FAILED(st->bs->free_pool(handles)))return 0;
 if(uncertain||matches!=1||!selected||!observed_target(selected))return 0;
 uint32_t bc=0;if(!cfg(selected,0xdc,&bc)||bc!=0x100008aa)return 0;
 field("BIOS_CNTL",bc,8);return selected;
}
static void report_capture(const FD_RESULT *r,const CONTEXT *c,ES result){
 field("CAPTURE_STATUS",result,16);field("FAILURE_STAGE",r->failure_stage,4);field("FAILURE_OFFSET",r->failure_offset,4);
 field("FAILURE_STATUS",r->failure_status,16);field("LAST_STATUS",r->last_status,8);
 field("INITIAL_HSFC",r->initial_hsfc,8);field("INITIAL_FADDR",r->initial_faddr,8);
 field("ACTUAL_MMIO_READ_CALLS",c->reads,8);field("ACTUAL_MMIO_WRITE_CALLS",c->writes,8);
 field("READ_CYCLE_START_ATTEMPTS",r->go_attempts,8);field("COMPLETED_BLOCKS",r->blocks,8);field("COMPLETED_PASSES",r->passes,8);
 field("TRANSIENT_FIELDS_RESTORED",r->final_transients_restored,1);field("PROTECTION_SNAPSHOT_UNCHANGED",r->protection_unchanged,1);
 if(!FAILED(result)){
  put("DESCRIPTOR_TWO_PASSES_MATCH=YES\r\nDESCRIPTOR_HEX_BEGIN\r\n");
  for(unsigned offset=0;offset<4096;offset+=32){hex(offset,4);put(":");for(unsigned j=0;j<32;j++)hex(capture_a[offset+j],2);put("\r\n");}
  put("DESCRIPTOR_HEX_END\r\n");
 }else put("DESCRIPTOR_DATA_NOT_EXPORTED; no retry or alternative path\r\n");
}
ES EA efi_main(HANDLE image,ST *table);
static ES(EA *const volatile loader_entry_anchor)(HANDLE,ST *)=efi_main;
ES EA efi_main(HANDLE image,ST *table){
 if(loader_entry_anchor!=efi_main)return ERR(3);
 (void)image;st=table;log_size=0;warnings=0;overflow=0;mmap_size=0;mmap_stride=0;
 if(!st||!st->bs||!st->bs->get_memory_map||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool||!st->bs->stall)return ERR(3);
 put("SPI-DESCRIPTOR-01 LOCAL-CANDIDATE\r\n");
 put("Fixed flash READ 0..0xFFF twice; transient controller MMIO writes required.\r\n");
 put("Flash programming/erase=0; permission/unlock/PCI writes=0; file/network/SetVariable calls=0\r\n");
 typedef ES(EA *WATCHDOG)(UN,uint64_t,UN,C16 *);
 ES wd=st->bs->set_watchdog?((WATCHDOG)st->bs->set_watchdog)(0,0,0,0):ERR(3);field("Watchdog.disable",wd,16);
 ES result=ERR(3);FD_RESULT capture={0};CONTEXT context={0};
 if(FAILED(wd)){put("REFUSED_UNCONTROLLED_WATCHDOG\r\n");goto done;}
 typedef ES(EA *GETMAP)(UN *,void *,UN *,UN *,uint32_t *);
 UN key=0;uint32_t version=0;mmap_size=sizeof(mmap_buffer);
 result=((GETMAP)st->bs->get_memory_map)(&mmap_size,mmap_buffer,&key,&mmap_stride,&version);
 if(FAILED(result)||!mmap_size||mmap_size>sizeof(mmap_buffer)||mmap_stride<40||mmap_stride>256||mmap_size%mmap_stride||version!=1){result=ERR(3);put("REFUSED_MEMORY_MAP\r\n");goto done;}
 if(!identity()){result=ERR(3);put("REFUSED_IDENTITY\r\n");goto done;}
 put("IDENTITY=Pro WS W790E-SAGE SE; BIOS=1904\r\n");
 context.pci=select_pci();if(!context.pci){result=ERR(3);put("REFUSED_PCI_BINDING\r\n");goto done;}
 context.cpu=select_cpu(context.pci);if(!context.cpu||!native_binding(context.cpu)){result=ERR(3);put("REFUSED_CPU_CODE_OR_TABLE_BINDING\r\n");goto done;}
 put("CPU_CODE_TABLES=EXACT_ORIGINAL_VALIDATOR_READ_WRITE\r\n");
 FD_IO io={&context,io_read,io_write,io_stall,io_binding};
 result=fd_capture(&io,capture_a,capture_b,&capture);
done:
 report_capture(&capture,&context,result);
 put("Scope=descriptor only, not a complete SPI backup or recovery test.\r\n");
 put("No RDID/SFDP/FDOC, extended-region guesses, flash programming or update.\r\n");
 put("PROBE_COMPLETE\r\n");if(FAILED(result))warnings++;
 if(overflow)return ERR(9);
 if(st->bs->allocate_pool&&st->bs->locate_protocol){ES shown=kvm_present(st,log_buffer,log_size,warnings);if(FAILED(shown)&&!FAILED(result))result=shown;}
 return result;
}
