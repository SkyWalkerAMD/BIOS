"""Independent machine-code policy checks on the built A1 application.

No UEFI/PCI operation is executed. Authorized reads deliberately fail at the
first simulated KCS read; disallowed commands must not reach any callback.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
BASE=ROOT/'analysis/hero_p6_a1_diagnostic_20261108'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
raw=(BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes();pe=pefile.PE(data=raw)
build=json.loads((BASE/'build.json').read_text(encoding='utf8'))
sha=hashlib.sha256(raw).hexdigest()
assert sha==build['launcher_sha256']
text=(BASE/'build/BOOTX64.map').read_text()
symbols={n:int(a,16) for n,a in re.findall(r'^\s+[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\s',text,re.M|re.I)}
for forbidden in ('p6_seed_settings','p6_apply_settings','p6_start_os_watchdog','p6_stop_os_watchdog',
 'p6_transport_open','p6_transport_close','p6_exchange','p6_delay','p6_write_armed',
 'candidate_query','candidate_arm','candidate_step','fan_query','fan_arm','fan_packet'):
 assert forbidden not in symbols,forbidden
assert pe.OPTIONAL_HEADER.Subsystem==10 and pe.FILE_HEADER.Machine==0x8664
assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.verify_checksum()
uc=Uc(UC_ARCH_X86,UC_MODE_64)
base=pe.OPTIONAL_HEADER.ImageBase
uc.mem_map(base,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095)
uc.mem_write(base,pe.get_memory_mapped_image())
STACK=0x10000000;DATA=0x20000000;CODE=0x30000000
uc.mem_map(STACK,0x10000);uc.mem_map(DATA,0x10000);uc.mem_map(CODE,0x1000)
uc.mem_write(CODE,b'\xc3'*0x1000)
STOP=CODE+0x100;READ=CODE+0x200;WRITE=CODE+0x300;DELAY=CODE+0x400
seen=[]
def q(p):return struct.unpack('<Q',bytes(uc.mem_read(p,8)))[0]
def w(p,x):uc.mem_write(p,struct.pack('<Q',x))
def ret(value):
 sp=uc.reg_read(UC_X86_REG_RSP);uc.reg_write(UC_X86_REG_RAX,value)
 uc.reg_write(UC_X86_REG_RIP,q(sp));uc.reg_write(UC_X86_REG_RSP,sp+8)
def hook(machine,address,size,user):
 if address==STOP:machine.emu_stop()
 elif address==READ:seen.append('read');ret(1)
 elif address in (WRITE,DELAY):raise AssertionError('No test may reach write or delay callback')
uc.hook_add(UC_HOOK_CODE,hook)
rows=[]
def case(name,f,c,p,allowed):
 seen.clear();uc.mem_write(DATA,bytes(0x1000))
 w(DATA+8,READ);w(DATA+16,WRITE);w(DATA+24,DELAY)
 if p:uc.mem_write(DATA+0x100,p)
 w(DATA+0x800,999)
 sp=STACK+0xefe8;uc.mem_write(sp,bytes(0x100));w(sp,STOP)
 for reg,value in ((UC_X86_REG_RCX,DATA),(UC_X86_REG_RDX,f),(UC_X86_REG_R8,c),(UC_X86_REG_R9,DATA+0x100 if p else 0),(UC_X86_REG_RSP,sp)):
  uc.reg_write(reg,value)
 for off,value in ((0x28,len(p)),(0x30,DATA+0x400),(0x38,272),(0x40,DATA+0x800)):w(sp+off,value)
 uc.emu_start(symbols['kcs_query'],STOP,count=100000)
 result=uc.reg_read(UC_X86_REG_RAX)&0xffffffff
 assert uc.reg_read(UC_X86_REG_RIP)==STOP
 assert q(DATA+0x800)==0
 assert result==(1 if allowed else 7),(name,result,seen)
 assert seen==(['read'] if allowed else []),(name,result,seen)
 rows.append({'case':name,'netfn':f,'cmd':c,'payload':p.hex(),'allowed':allowed,'simulated_io_reads':len(seen),'passed':True})

for f,c,p in [(6,0x24,bytes(6)),(6,0x22,b''),(6,2,b''),(6,3,b''),(6,0x2e,b'\x08'),
 (0xc,1,b'\x01\x03\xac\x14\x01\x47'),(0xa,0x47,b'\0\0CLR\xaa'),(0xa,0x42,b''),
 (0xa,0x44,b'\0'*16),(0x30,0x90,b'\x80'),(0x30,0x94,b'\x20\x01'),
 (0x30,0x9a,b'\x01\x01'+bytes(15)),(0x30,4,b'\0' + b'3107\0'),
 (0x30,3,b'\0\0\0\x10'),(0x2e,0,b''),(0xff,0xff,b'')]:
 case('reject mutating/OEM/non-allowlist',f,c,p,False)
for f,c,p in [(6,1,b''),(6,4,b''),(6,0x25,b''),(6,0x2f,b''),(6,0x42,b'\x01'),
 (6,0x42,b'\x0b'),(0xc,2,b'\x01\x03\0\0'),(0xc,2,b'\x0b\x0c\0\0'),
 (0xa,0x40,b''),(0xa,0x43,b'\0\0\x01\0\0\xff')]:
 case('approved standard GET stops at simulated read failure',f,c,p,True)
for f,c,p in [(6,1,b'\0'),(6,0x42,b'\0'),(6,0x42,b'\x0c'),(6,0x42,b'\x01\0'),
 (0xc,2,b'\x01\x02\0\0'),(0xc,2,b'\x01\x03\x01\0'),(0xc,2,b'\x01\x03\0\x01'),
 (0xa,0x43,b'\x01\0\x01\0\0\xff'),(0xa,0x43,b'\0\0\x01\0\0\x10')]:
 case('malformed GET denied',f,c,p,False)
report={'passed':True,'launcher_sha256':sha,'cases':len(rows),'pe_kind':'x64 EFI_APPLICATION, valid checksum, no imports',
 'forbidden_write_symbols_absent':True,'results':rows,
 'scope':'Compiled kcs_query and command allowlist with simulated callback that fails before any transport transaction. This is not real hardware or a complete UEFI/HII lifecycle test.'}
(OUT/'a1-compiled-policy-independent.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:v for k,v in report.items() if k!='results'}))
