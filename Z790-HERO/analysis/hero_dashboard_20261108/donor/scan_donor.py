from pathlib import Path
import sys,json,uuid,re,hashlib
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
mods=json.loads((ROOT/'analysis/inventory.json').read_text())['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP']
transport=uuid.UUID('4a1d0e66-5271-4e22-83fe-90921b748213').bytes_le
smbios=uuid.UUID('03583ff6-cb36-4940-947e-b9b39f4afaf7').bytes_le
report=[]
for m in mods:
    if m['type'] not in ('DXE driver','SMM module'): continue
    for p in (ROOT/m['path']).rglob('body.bin'):
        if 'PE32 image' not in p.parent.name: continue
        b=p.read_bytes()
        pe=pefile.PE(data=b)
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        cs.detail=True; cs.skipdata=True
        ins=[]
        for s in pe.sections:
            if s.Characteristics&0x20000000:
                ins.extend(cs.disasm(s.get_data(),s.VirtualAddress))
        hits=[]
        for i,x in enumerate(ins):
            if x.mnemonic=='mov' and x.op_str in ('dl, 0x30','edx, 0x30'):
                hits.append({'rva':hex(x.address),'context':[f'{z.address:x}: {z.mnemonic} {z.op_str}' for z in ins[max(0,i-16):i+16]]})
        if hits:
            report.append({'guid':m['guid'],'ui':m['ui'],'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'smbios':smbios in b,'ipmi':transport in b,'path':str(p.relative_to(ROOT)),'netfn30':hits})
(OUT/'donor-netfn-candidates.json').write_text(json.dumps(report,indent=2))
for r in report:
    if r['ipmi'] or r['smbios']: print(r['guid'],r['size'],'smbios',r['smbios'],'ipmi',r['ipmi'],'netfn30',','.join(h['rva'] for h in r['netfn30']))
