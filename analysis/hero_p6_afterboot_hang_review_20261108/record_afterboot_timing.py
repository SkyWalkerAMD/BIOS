"""Exact AMITSE launch-return instruction order; static only."""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
path=ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi';raw=path.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
pe=pefile.PE(data=raw);data=pe.get_memory_mapped_image();cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
whole=list(cs.disasm(data[0xd090:0xdc66],0xd090))
instructions={i.address:i for i in whole}
for rva,target in ((0xda68,'qword ptr [rax + 0xd0]'),(0xdae3,'0x3c38'),(0xdaec,'0x176c'),(0xdaf1,'0x79b0')):
 assert instructions[rva].mnemonic=='call' and instructions[rva].op_str==target
def window(start,end):return [{'rva':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(data[start:end],start)]
reuse=ROOT/'analysis/hero_ipmi_p6_20261104/native/rea-loopback/responses/012-boot-lifecycle.json'
evidence=json.loads(reuse.read_text(encoding='utf8'))['result']['structuredContent']
result={'subject':{'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(raw).hexdigest()},
 'reused_rea':{'path':str(reuse.relative_to(ROOT)),'sha256':hashlib.sha256(reuse.read_bytes()).hexdigest(),'evidence_id':evidence.get('evidence_id'),'function':'0xd090'},
 'ordinary_return_path':[
  {'rva':'0xda68','operation':'Boot Services StartImage call; returns at 0xda6e'},
  {'rva':'0xda73..0xdad0','operation':'Conditional UEFI watchdog disable and closing two event handles'},
  {'rva':'0xdae3','operation':'Dispatch AMITSE callback group 0xffff000c synchronously'},
  {'rva':'0xdaec','operation':'Publish AfterBoot GUID via helper0x176c'},
  {'rva':'0x1790','operation':'Helper calls InstallProtocolInterface with null interface'},
  {'rva':'0x17a8','operation':'Helper calls UninstallProtocolInterface then returns'},
  {'rva':'0xdaf1','operation':'Call0x79b0: GOP Blt VideoFill using current Mode Info width/height'},
  {'rva':'0xdb01 or 0xdbc9','operation':'Additional AMITSE helper0x4ab40'},
  {'rva':'0xdc65','operation':'Return from outer boot-launch function'}],
 'conclusion':'A synchronous AfterBoot notification runs while AMITSE is inside the boot-return publication, before this path calls the GOP clear helper and before the outer launch routine returns. A delayed timer can run after that point. This establishes different timing only, not deadlock freedom or a hardware fix.',
 'limits':['The FFFF000C callback group runs before AfterBoot and can itself perform opaque work. Its resulting state is not reconstructed here.','Notification execution is still inside the AMITSE/Boot Services stack. Other synchronous HII callbacks and external service blocking remain possible.','A1 uses a bounded board/UUID detector differing from the older S21R detector, so application success does not isolate timer context as the sole variable.','No firmware change, target execution, new REA session or hardware operation.'],
 'windows':{'post_start_to_after':window(0xda68,0xdaf6),'publisher':window(0x176c,0x17b4),'gop_clear_helper':window(0x79b0,0x7a03)}}
(OUT/'afterboot-timing-evidence.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps({'passed':True,'start':'0xda68','afterboot_publish':'0xdaec','next_gop_fill':'0xdaf1','native_auto_fix_claimed':False}))
