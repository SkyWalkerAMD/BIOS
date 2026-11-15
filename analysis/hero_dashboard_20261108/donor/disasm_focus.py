from pathlib import Path
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[3];OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
guid=sys.argv[1].upper();start=int(sys.argv[2],0);end=int(sys.argv[3],0)
mods=json.loads((ROOT/'analysis/inventory.json').read_text())['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP']
m=next(m for m in mods if m['guid']==guid)
p=next(p for p in (ROOT/m['path']).rglob('body.bin') if 'PE32 image' in p.parent.name)
b=p.read_bytes(); (OUT/(guid+'.efi')).write_bytes(b)
pe=pefile.PE(data=b);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
image=pe.get_memory_mapped_image();lines=[]
for ins in cs.disasm(pe.sections[0].get_data(),pe.sections[0].VirtualAddress):
    if not start<=ins.address<end: continue
    notes=[]
    for op in ins.operands if ins.id else []:
        if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
            addr=ins.address+ins.size+op.mem.disp
            data=image[addr:addr+64]
            notes.append(f'[{addr:x}] {data.hex()}')
    lines.append(f'{ins.address:06x}: {ins.mnemonic:<8} {ins.op_str:<45} '+ '; '.join(notes))
name=f'{guid}-{start:x}-{end:x}.asm'
(OUT/name).write_text('\n'.join(lines))
print('\n'.join(lines))
