"""Independent original byte/header inventory; no firmware writes."""
from pathlib import Path
import sys, hashlib, struct, json
H=Path(__file__).resolve().parent; B=H.parent; ROOT=B.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile, capstone
source=next((ROOT/'analysis/workstation_20261008/W890_SAGE_0603').rglob('434 AMITSESetupData/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/0 FE612B72-203C-47B1-8560-A66D946EB371/body.bin'))
raw=source.read_bytes(); start=raw.index(b'$SPF'); b=raw[start:]
def d(at):return struct.unpack_from('<I',b,at)[0]
def q(at):return struct.unpack_from('<Q',b,at)[0]
headers=[{'offset':hex(at),'u32':d(at),'hex':hex(d(at))} for at in range(0,0x60,4)]
table=0x60; count=d(table); offsets=[d(table+4+4*i) for i in range(count)]
items=[]
for index,off in enumerate(offsets):
    items.append({'index':index,'offset':hex(off),'relative_to_table':hex(off+table),'prefix':b[table+off:table+off+32].hex(),
                  'relative_to_spf_prefix':b[off:off+32].hex()})
tse=B/'navigation/modules/AMITSE.efi'; pe=pefile.PE(str(tse)); image=pe.get_memory_mapped_image()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
windows={name:[{'rva':hex(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str} for i in md.disasm(image[lo:hi],lo)]
 for name,lo,hi in [('parser',0x40d94,0x41580),('init19cf8',0x19cf8,0x19d60),('init1b7dc',0x1b7dc,0x1b9c0),('init1c17c',0x1c17c,0x1c280)]}
result={'original_source':str(source),'original_sha256':hashlib.sha256(raw).hexdigest(),'original_size':len(raw),
        'spf_offset':start,'spf_size':len(b),'spf_sha256':hashlib.sha256(b).hexdigest(),'headers':headers,
        'page_table_offset':table,'page_count':count,'table_span_end':hex(table+4+count*4),'items':items,
        'unlisted_next_slot_value':d(table+4+count*4),'tse_sha256':hashlib.sha256(tse.read_bytes()).hexdigest(),'windows':windows}
(H/'original_inventory.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items()if k not in ['windows','items']},indent=2))
print('First/last:',json.dumps(items[:2]+items[-2:],indent=2))
for name,instructions in windows.items():
    print(name)
    for i in instructions: print(i['rva'],i['bytes'],i['asm'])
