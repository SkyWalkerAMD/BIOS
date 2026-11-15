from pathlib import Path
import json,sys,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import capstone,pefile
src=B/'navigation/modules/Setup.efi';raw=src.read_bytes();p=pefile.PE(data=raw)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;md.skipdata=True
out={'source_sha256':hashlib.sha256(raw).hexdigest(),'tool':'Capstone original bytes; this is not a REA result','windows':[]}
for needle in [0xf864,0x1d2dd,0x1d798]:
 ext=[{'begin':hex(e.struct.BeginAddress),'end':hex(e.struct.EndAddress)}for e in getattr(p,'DIRECTORY_ENTRY_EXCEPTION',[])if e.struct.BeginAddress<=needle<e.struct.EndAddress]
 print('PE_exception_extent',hex(needle),ext)
 for start in range(needle-600,needle):
  if p.get_data(start,3)==b'\xc3\xcc\xcc':print('padding_candidate_after_ret',hex(start))
for start,end in [(0x1f00,0x1fb0),(0x7c40,0x7d38),(0xf7f0,0xf890),(0x1d240,0x1d300),(0x1d6e0,0x1d7c0)]:
 ins=[{'rva':hex(i.address),'hex':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str}for i in md.disasm(p.get_data(start,end-start),start)]
 out['windows'].append({'start_rva':hex(start),'instructions':ins})
 for i in ins:print(i['rva'],i['text'])
(H/'original_windows.json').write_text(json.dumps(out,indent=2)+'\n')
