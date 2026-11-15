"""Original AMITSE action mapper and a correction to frozen test descriptions.

No instruction patch, hardware, HII callback or credential operation. The old
test labeled FormClose2 actually exercised native action 2 (RETRIEVE). This
review does not promote that test to coverage of UEFI FORM_CLOSE=4.
"""
from pathlib import Path
import hashlib,json,struct,sys
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile,unicorn
from unicorn.x86_const import *
P=B/'navigation/modules/AMITSE.efi';raw=P.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
p=pefile.PE(data=raw);base=0x2000000;p.relocate_image(base);mapped=p.get_memory_mapped_image()
start,end=0x3f90c,0x3f957
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
assembly=[{'rva':x.address,'hex':bytes(x.bytes).hex(),'instruction':x.mnemonic+' '+x.op_str}for x in md.disasm(mapped[start:end],start)]
cases=[];STACK=0x5000000;STOP=0x6000000
for given,expected in [(0,0),(1,0),(2,2),(3,3),(4,4),(5,5),(0x1000,0x1000),(0x1001,0x1001)]:
 u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);u.mem_map(base,(len(mapped)+4095)&~4095);u.mem_write(base,mapped)
 u.mem_protect(base,(len(mapped)+4095)&~4095,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
 u.mem_map(STACK,4096);u.mem_map(STOP,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
 u.mem_write(STACK+0x808,struct.pack('<Q',STOP));u.reg_write(UC_X86_REG_RSP,STACK+0x808);u.reg_write(UC_X86_REG_RCX,given)
 u.emu_start(base+start,STOP,count=100)
 output=u.reg_read(UC_X86_REG_RAX)
 assert u.reg_read(UC_X86_REG_RIP)==STOP and output==expected
 cases.append({'native_input':given,'mapped_config_access_action':output,'pass':True})
chain=[(0x3f504,0x3f516),(0x3e7dd,0x3e7ec),(0x3ec95,0x3eca9),(0x3e4af,0x3e4f0)]
windows=[]
for a,z in chain:
 windows.append({'rva':a,'hex':mapped[a:z].hex(),'instructions':[x.mnemonic+' '+x.op_str for x in md.disasm(mapped[a:z],a)]})
result={'status':'PASS_ORIGINAL_ACTION_MAPPING_WITH_COVERAGE_CORRECTION','scope':__doc__,
 'original_module_sha256':hashlib.sha256(raw).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'original_mapper_assembly':assembly,'action_parameter_chain_windows':windows,'cases':cases,'check_count':len(cases),
 'primary_definition':'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/HiiConfigAccess.h',
 'uefi_actions':{'RETRIEVE':2,'FORM_OPEN':3,'FORM_CLOSE':4},
 'frozen_test_correction':{'path':'navigation05/bridges_build/form_open_tests.json','old_label':'Security FormClose2 phase0 exactly preserves the original callback batch','correct_label':'Security native action2 / RETRIEVE phase0 preserves the original callback batch within its stated destination model'},
 'actual_form_close_4_verified':False,'n05_bridge_current_accepted_actions':[2,3],
 'frozen_artifacts_modified':False,'hardware_actions':0}
(H/'action_mapping.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'checks':len(cases),'true_form_close_4_verified':False}))
