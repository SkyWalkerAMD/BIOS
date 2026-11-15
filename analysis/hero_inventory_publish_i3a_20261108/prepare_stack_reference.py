from pathlib import Path
import hashlib,json,sys,re,shutil
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
ref=OUT/'reference';ref.mkdir(exist_ok=True)
rows=list(json.loads((ROOT/'analysis/hero_3107_official/inventory.json').read_text()).values())[0]
wanted={'A2F436EA-A127-4EF8-957C-8048606FF670':'SnpDxe','025BBFC7-E6A9-4B8B-82AD-6815A1AEAF4A':'MnpDxe','529D3F93-E8E9-4E73-B1E1-BDF6A9D50113':'ArpDxe','9FB1A1F3-3B71-4324-B39A-745CBB015FFF':'Ip4Dxe'}
wanted.update({'1A7E4468-2F55-4A56-903C-01265EB7622B':'TcpDxe','A210F973-229D-4F4D-AA37-9895E6C9EABA':'DpcDxe'})
out=[]
for row in rows:
 if row['guid'] not in wanted:continue
 src=ROOT/row['path'];pes=list(src.glob('*PE32*/body.bin'));assert len(pes)==1
 data=pes[0].read_bytes();name=wanted[row['guid']];dst=ref/(name+'.efi');dst.write_bytes(data)
 p=pefile.PE(data=data);ep=p.OPTIONAL_HEADER.AddressOfEntryPoint
 s={'name':name,'guid':row['guid'],'source':str(pes[0].relative_to(ROOT)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'entry':hex(ep),'imagebase':hex(p.OPTIONAL_HEADER.ImageBase),'depex':row['depex']}
 out.append(s)
 md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
 ins=list(md.disasm(p.get_memory_mapped_image()[ep:ep+512],ep))
 (ref/(name+'-entry.asm')).write_text('\n'.join(f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in ins))
 print(s)
(ref/'origin.json').write_text(json.dumps(out,indent=2)+'\n')
shutil.copy2(ROOT/'analysis/hero_remote_bios_r6/rea_session.py',OUT/'rea_session.py')
