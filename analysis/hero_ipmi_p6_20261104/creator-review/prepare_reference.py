"""Read-only source artifacts -> new static review copies/evidence summaries."""
from pathlib import Path
import hashlib,json,sys,re,struct
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
mods={
 '6372357A-06D7-43EF-B55C-1964F3DD6916':'DxeIpmiInitialize',
 '43788BEB-638F-434C-8A84-46D33A589E76':'DxeBmcElog',
 '543323CE-9F0C-4DDF-A33C-BC3B3A5AC227':'SmmBmcElog',
 '9D0CEA63-745B-417D-BBA4-E5193061C907':'DxeFrb',
 'AE587172-CC15-48E1-8BE0-29DDF05C6A1F':'DxeSelStatusCode',
 'BC0B9FB8-97CF-4B17-9A9E-F574E62CBCC4':'Ip4BmcLanConfig',
 '1B08A1DB-F91A-4FA1-A911-255C417F1CF7':'ServerMgmtSetup',
 '0EF53039-3A38-42D1-BCEC-CE966E87061A':'PeiFrb',
 '2700F72F-E0EA-4767-9A1E-D172F0704778':'PeiSelStatusCode'}
manifest=[]
(P/'artifacts').mkdir(exist_ok=True)
(P/'disassembly').mkdir(exist_ok=True)
inv=json.loads((ROOT/'analysis/inventory.json').read_text(encoding='utf-8'))
for m in inv['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP']:
 if m['guid'] not in mods:continue
 name=mods[m['guid']]
 files=[p for p in (ROOT/m['path']).rglob('body.bin') if 'PE32 image' in p.parent.name or 'TE image' in p.parent.name]
 assert len(files)==1,(name,files)
 data=files[0].read_bytes(); dest=P/'artifacts'/f'Creator-{name}.efi';dest.write_bytes(data)
 info={'name':name,'guid':m['guid'],'source':str(files[0].relative_to(ROOT)),'copy':str(dest.relative_to(ROOT)),
       'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'depex':m['depex']}
 if data[:2]==b'MZ':
  pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase
  info.update(image_base=hex(base),entry=hex(base+pe.OPTIONAL_HEADER.AddressOfEntryPoint),machine=hex(pe.FILE_HEADER.Machine))
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if pe.FILE_HEADER.Machine==0x8664 else capstone.CS_MODE_32);cs.detail=True
  lines=[]
  for sec in pe.sections:
   if not sec.Characteristics&0x20000000:continue
   for ins in cs.disasm(sec.get_data(),base+sec.VirtualAddress):
    notes=[]
    for op in ins.operands:
     if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
      addr=ins.address+ins.size+op.mem.disp
      try:
       sample=data[pe.get_offset_from_rva(addr-base):][:90]
       text=re.match(rb'(?:[ -~]\x00){4,}',sample)
       notes.append(hex(addr)+' '+(text[0].decode('utf-16le') if text else sample[:16].hex()))
      except Exception:notes.append(hex(addr))
    lines.append(f'{ins.address:08x}: {ins.bytes.hex():26} {ins.mnemonic:8} {ins.op_str:42} '+ '; '.join(notes))
  (P/'disassembly'/f'{name}.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
 elif data[:2]==b'VZ':
  machine=struct.unpack_from('<H',data,2)[0];base=struct.unpack_from('<Q',data,16)[0]
  stripped=struct.unpack_from('<H',data,6)[0]-40
  info.update(image_base=hex(base),entry=hex(base+struct.unpack_from('<I',data,8)[0]),machine=hex(machine),te_stripped_adjustment=stripped)
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if machine==0x8664 else capstone.CS_MODE_32);cs.detail=True
  lines=[]
  for i in range(data[4]):
   o=40+i*40;vs,va,size,raw=struct.unpack_from('<4I',data,o+8);flags=struct.unpack_from('<I',data,o+36)[0]
   if not flags&0x20000000:continue
   for ins in cs.disasm(data[raw-stripped:raw-stripped+size],base+va):
    lines.append(f'{ins.address:08x}: {ins.bytes.hex():26} {ins.mnemonic:8} {ins.op_str}')
  (P/'disassembly'/f'{name}.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
 manifest.append(info)
(P/'artifact-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
old=ROOT/'analysis/hero_rea_20261102/p1-server-setup-local/responses'
(P/'reused-rea').mkdir(exist_ok=True)
index=[]
for path in sorted(old.glob('*.json')):
 r=json.loads(path.read_text())['result']; ev=r.get('structuredContent')
 if ev is None:
  for content in r.get('content',[]):
   if content.get('type')=='text':
    try: ev=json.loads(content['text']);break
    except ValueError:pass
 if not isinstance(ev,dict):continue
 nr=ev.get('normalized_result',{})
 rows=[]
 for item in nr.get('items',[]) if isinstance(nr,dict) else []:
  if item.get('pseudocode'):
   dest=P/'reused-rea'/f"{path.stem}-{item['address']}.c"
   dest.write_text(item['pseudocode'].replace('\r\n','\n'),encoding='utf-8')
   rows.append({'address':item['address'],'file':str(dest.relative_to(ROOT))})
 index.append({'source':str(path.relative_to(ROOT)),'evidence_id':ev.get('evidence_id'),
               'subject':ev.get('subject'),'operation':ev.get('operation'),'functions':rows})
(P/'reused-rea/index.json').write_text(json.dumps(index,indent=2)+'\n',encoding='utf-8')
# Reuse the local static REA controller; change only its workspace root because
# this review sits one directory deeper. It creates no global configuration.
controller=(ROOT/'analysis/hero_ipmi_p5_rea_review_20261103/session.py').read_text()
controller=controller.replace('ROOT = BASE.parents[1]','ROOT = BASE.parents[2]')
(P/'session.py').write_text(controller,encoding='utf-8')
print(json.dumps({'artifacts':[{k:v for k,v in m.items() if k in ('name','bytes','sha256','entry','machine')} for m in manifest],
                  'reused_functions':sum(len(x['functions']) for x in index)},indent=2))
