"""Ordinary static PE/Capstone corroboration of the extra BeforeBoot publisher."""
from pathlib import Path
import hashlib,json,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
p=ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi';raw=p.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
pe=pefile.PE(data=raw);m=pe.get_memory_mapped_image();cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
blocks={}
for a,b in ((0x3bd4,0x3c8b),(0x4e93c,0x4ebd2),(0xda58,0xdaf1),(0xdbd0,0xdbf6)):
 blocks[hex(a)]=[f'{x.address:08x}: {x.bytes.hex()} {x.mnemonic} {x.op_str}' for x in cs.disasm(m[a:b],a)]
table={hex(a):hex(struct.unpack_from('<Q',m,a)[0]) for a in range(0x16eda8,0x16ee10,8)}
assert table['0x16eda8']=='0xffff000b' and table['0x16edf0']=='0x4e93c' and table['0x16edf8']=='0xffff000c'
report=dict(scope='Ordinary static PE/Capstone output, not an REA Evidence export.',sha256=hashlib.sha256(raw).hexdigest(),blocks=blocks,callback_table=table,
 strings={hex(a):m[a:a+140].decode('utf-16-le','replace').split('\0')[0] for a in (0x16f638,0x16f648)},
 helper_required_protocol=str(uuid.UUID(bytes_le=m[0x10ced0:0x10cee0])),
 boundary='The special helper publishes BeforeBoot and calls StartImage but contains no corresponding AfterBoot publication. Its callback-table relationship to the normal synchronous D090 launch path is corroborated; no claim of all firmware launch callers.')
(HERE/'special-beforeboot-helper.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='blocks'},indent=2))
