"""Generate native chrome identity constants from exact original1904 bytes."""
from pathlib import Path
import hashlib,json,sys,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[7]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
original=HERE.parent.parent/'boot_context/AMITSE.original.efi'
assert hashlib.sha256(original.read_bytes()).hexdigest()=='531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
p=pefile.PE(str(original));b=p.get_memory_mapped_image()
ranges=[(0x148e4,0x15294),(0x1532f,0x155a4),(0x16354,0x164d2),(0x16840,0x1691c),(0x16a90,0x16c1f),(0x171d4,0x17238),(0x1bd14,0x1c1d4),(0x1c2cc,0x1c474),(0x1cafc,0x1cc20),(0x31da4,0x31e36),(0x3224a,0x32264)]
methods=[0x1bd14,0x1bd64,0x1bdac,0x1be5c,0x1c2cc,0x18d24,0x18d24,0x1896c,0x1c3a4,0x1897c,0x1c428,0x1c410]
frames=[0x148e4,0x1494c,0x14a00,0x14a80,0x15320,0x122bc,0x155a4,0x165e4,0x16658,0x16684]
for at,table in [(0x6bb20,methods),(0x6b8b8,frames)]:
 for i,x in enumerate(table):assert int.from_bytes(b[at+i*8:at+i*8+8],'little')==x
lines=['/* Generated solely from pinned original1904 bytes. */',f'#define CHROME_PE_OFFSET 0x{p.DOS_HEADER.e_lfanew:x}u',f'#define CHROME_ENTRY_RVA 0x{p.OPTIONAL_HEADER.AddressOfEntryPoint:x}u','static const uint32_t chrome_methods[]={'+','.join(hex(x)for x in methods)+'};','static const uint32_t chrome_frame_methods[]={'+','.join(hex(x)for x in frames)+'};','static const struct {uint32_t rva,size,crc;} chrome_ranges[]={']
lines += [f' {{{hex(a)},{hex(e-a)},0x{zlib.crc32(b[a:e]):08x}}},'for a,e in ranges];lines+=['};']
(HERE/'source/native_chrome_data.h').write_text('\n'.join(lines)+'\n')
(HERE/'native_chrome_identity.json').write_text(json.dumps({'original_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'unchanged_native_ranges':[{'rva':hex(a),'bytes':e-a,'sha256':hashlib.sha256(b[a:e]).hexdigest(),'crc32':f'{zlib.crc32(b[a:e]):08x}'}for a,e in ranges],'frame_method_rvas':[hex(x)for x in frames],'control_method_rvas':[hex(x)for x in methods],'post_detour_original_frame_body_start':'0x1532f','dynamic_15320_prologue':'checked as exact local E9 gate_frame_input +10 NOP bytes'},indent=2)+'\n')
print(hashlib.sha256((HERE/'source/native_chrome_data.h').read_bytes()).hexdigest())
