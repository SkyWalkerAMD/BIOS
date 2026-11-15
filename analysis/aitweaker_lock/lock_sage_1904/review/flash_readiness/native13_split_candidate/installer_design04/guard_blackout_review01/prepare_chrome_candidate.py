"""Create a separate local classifier candidate. Never edit frozen sources."""
from pathlib import Path
import hashlib,json,shutil,sys,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;DST=D04/'static_chrome_candidate07';ROOT=HERE.parents[7]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
assert not DST.exists(),'Use a new revision; do not overwrite an existing candidate'
(DST/'source').mkdir(parents=True)
source=D04/'split_core'
for p in (source/'source').iterdir():
 if p.is_file():shutil.copyfile(p,DST/'source'/p.name)
for name in ['build_split.py','verify_split.py']:shutil.copyfile(source/name,DST/name)
original=D04.parent/'boot_context/AMITSE.original.efi';pe=pefile.PE(str(original));b=pe.get_memory_mapped_image()
ranges=[(0x148e4,0x14a80),(0x16354,0x164d2),(0x16840,0x1691c),(0x16a90,0x16c1f),(0x171d4,0x17238),(0x1bd14,0x1c1d4),(0x1c2cc,0x1c474),(0x1cafc,0x1cc20),(0x31da4,0x31e36),(0x3224a,0x32264)]
vtable=[0x1bd14,0x1bd64,0x1bdac,0x1be5c,0x1c2cc,0x18d24,0x18d24,0x1896c,0x1c3a4,0x1897c,0x1c428,0x1c410]
for i,x in enumerate(vtable):assert int.from_bytes(b[0x6bb20+i*8:0x6bb28+i*8],'little')==x
lines=['/* Generated solely from pinned original1904 bytes. */',f'#define CHROME_PE_OFFSET 0x{pe.DOS_HEADER.e_lfanew:x}u',f'#define CHROME_ENTRY_RVA 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}u','static const uint32_t chrome_methods[]={'+','.join(hex(x)for x in vtable)+'};','static const struct {uint32_t rva,size,crc;} chrome_ranges[]={']
lines += [f' {{{hex(a)},{hex(e-a)},0x{zlib.crc32(b[a:e]):08x}}},'for a,e in ranges]
lines+=['};']
(DST/'source/native_chrome_data.h').write_text('\n'.join(lines)+'\n')
report={'status':'ISOLATED_CLASSIFIER_ONLY_NOT_PROVIDER_OR_INSTALLER','original_amitse_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'source_guard_sha256':hashlib.sha256((source/'source/gate.c').read_bytes()).hexdigest(),'range_crcs':[{'rva':hex(a),'bytes':e-a,'sha256':hashlib.sha256(b[a:e]).hexdigest(),'crc32':f'{zlib.crc32(b[a:e]):08x}'}for a,e in ranges],'known_methods':[hex(x)for x in vtable],'preserved':['split_core','provider13','ram_transaction05','N12','P12'],'unimplemented':['New provider binding','New RAM installer/app/ISO','Safe no-page native unwind','Physical GUI acceptance']}
(DST/'candidate_scope.json').write_text(json.dumps(report,indent=2)+'\n')
print(str(DST))
