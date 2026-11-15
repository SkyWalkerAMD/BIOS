"""Build source scaffolding from the pinned INV04 identity/mapping checks."""
from pathlib import Path
import hashlib,json,re,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[6]
OLD=HERE.parent/'spi_inventory_candidate04'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
src=OLD/'source/inventory.c'
assert sha(src)=='cdee28b549b0d99939425e08021860b71ab826d9fa0048a131e28bc763910c54'
old=src.read_text(encoding='utf-8')
def function(name):
    match=re.search(r'(?m)^[^\n]*\b'+re.escape(name)+r'\([^;]*?\)\s*\{',old)
    assert match,name
    start=match.start();p=match.end();depth=1
    while depth:
        depth+=(old[p]=='{')-(old[p]=='}');p+=1
    return old[start:p]+'\n'

header='''/* SPI-DESCRIPTOR-02: fixed 4 KiB flash READ, never a full backup.
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
'''
functions=['memset','memcpy','equal','u16','u32','u64','put','hex','dec','field','failure',
           'readable','ascii','sm_string','sm_table','identity','cfg','observed_target',
           'cpu_map_gate','cpu_method_in_code','select_cpu']
foundation='\n'.join(function(n) for n in functions).replace('CPU_MEM_READ_POINTER','CPU_METHOD_POINTER')
extra=(HERE/'source/frontend.inc').read_text(encoding='utf-8')
(HERE/'source/inventory.c').write_text(header+foundation+'\n'+extra,encoding='utf-8')

native=HERE.parent/'cpuio2_native/OriginalCpuIo2.efi'
assert sha(native)=='4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
pe=pefile.PE(str(native))
assert not any(0x30c<=x.rva<0x534 or 0x750<=x.rva<0x76c for b in pe.DIRECTORY_ENTRY_BASERELOC for x in b.entries if x.type)
ref='/* Exact original CPU_IO2 validator, Mem.Read/Mem.Write, and stride tables. */\n'
for name,rva,n in [('cpu_reference_code',0x30c,0x228),('cpu_reference_tables',0x750,0x1c)]:
    data=pe.get_data(rva,n);assert len(data)==n
    ref+='static const uint8_t '+name+'[]={'+','.join('0x%02x'%x for x in data)+'};\n'
(HERE/'source/cpu_reference.h').write_text(ref,encoding='ascii')

builder=(OLD/'build_candidate.py').read_text(encoding='utf-8')
builder=builder.replace('SPI INVENTORY 04 - KVM LOG','SPI DESCRIPTOR 02 - KVM LOG').replace('SPI inventory 04 - registers only','SPI descriptor read - diagnostic').replace('DEFINED REGISTERS - NO FLASH DUMP','4K DESCRIPTOR ONLY - NOT A BACKUP').replace('SPI inventory ended. Log displayed only; no flash bytes read.','Descriptor log ended. No flash programming or erasing.')
builder=builder.replace('SPIINV04','SPIFD02').replace('SAGE_SPIINV04','SAGE_SPIFD02').replace('SAGE1904-SPI-INVENTORY04.iso','SAGE1904-SPI-DESCRIPTOR02.iso')
builder=builder.replace("[SRC/'inventory.c',SRC/'p3/probe_core.c'", "[SRC/'inventory.c',SRC/'fd_core.c',SRC/'p3/probe_core.c'")
builder=builder.replace("'-I',str(SRC/'p3'),", "'-I',str(SRC),'-I',str(SRC/'p3'),")
start=builder.index("report={'status':")
end=builder.index("save(OUT/'build.json'",start)
builder=builder[:start]+'''report={'status':'BUILT_AWAITING_LOCAL_TESTS','hardware_tested':False,
 'scope':'Descriptor 0..0xFFF READ twice. Transient DWORD MMIO writes only to FADDR and HSFSTS_CTL; no flash program/erase, unlock, PCI writes, SetVariable, file or network calls.',
 'efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'iso_sha256':sha(target),'iso_bytes':target.stat().st_size,
 'iso_embedded_efi_verified':True,'source_archive_sha256':sha(archive),'source_files':source_files,
 'reused_p3':reused,'compiler_sha256':sha(zig),'commands':commands,
 'limitations':['No physical acceptance or full SPI backup.','Exact observed SAGE1904/7AA4/rev11/BAR and original CPU_IO2 code/table binding required.',
 'Requires measured FRAP0x4ACF/FREG0=0/PR0..4=0, plus GPR0=0 and a stable locked status.',
 'First unexpected state, timeout or ambiguous command result stops without another cycle.',
 'Descriptor configured capacity is not independent JEDEC/SFDP capacity proof.']}
''' + builder[end:]
(HERE/'build_candidate.py').write_text(builder,encoding='utf-8')
sources={
 'status':'OFFLINE_SOURCE_READY_FOR_LOCAL_TESTS',
 'original_inventory_source':{'path':str(src),'sha256':sha(src),'functions_reused':functions},
 'cpu_reference':{'path':str(native),'sha256':sha(native),'code_rva':'0x30c..0x533','tables_rva':'0x750..0x76b'},
 'register_manual':{'url':'https://cdrdv2-public.intel.com/743845/743845_001.pdf',
   'path':str(HERE.parent/'spi_descriptor_review01/Intel-743845-001.pdf'),
   'sha256':'9d6491fec3cda0b6709f2fc815e236a0052776bd638e5f14bb3917addeabad9c',
   'pages':[398,399,400],'interpretation':'DWORD RMW keeps lock/control bits. Acknowledge FDONE only when error-free and idle. READ is cycle0; 64-byte count is63. FADDR reserved bits are zero and never changed.'},
 'implementation_crosscheck':{'path':str(HERE.parent/'read_only_backup_design/references/linux-spi-intel.c'),
   'sha256':sha(HERE.parent/'read_only_backup_design/references/linux-spi-intel.c'),'lines':[575,577,578,579,580,581,582,583]},
 'legacy_progress_review_preserved':True,
 'no_device_access':True,
}
(HERE/'sources.json').write_text(json.dumps(sources,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('Prepared isolated FD02 sources and builder; no build or hardware operation yet.')
