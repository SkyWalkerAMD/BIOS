"""Generate exact P13 identity tables for one local split guard build."""
from pathlib import Path
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;N13=D04.parent;ROOT=N13.parents[5]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,capstone
CORE=D04/'split_core';b=json.loads((CORE/'build/split_build.json').read_text())
raw=(CORE/'build/guard_template.bin').read_bytes();sha=lambda data:hashlib.sha256(data).hexdigest()
assert sha(raw)==b['template_sha256']
sy={k:int(v,16)for k,v in b['symbol_offsets'].items()}
decl=['/* Generated exact split profile; original images are never rewritten. */',
 'typedef struct {uint32_t rva,size;uint8_t hash[32];} ID_SEGMENT;',
 'typedef struct {uint32_t rva;uint64_t original;} ID_RELOC;',
 'typedef struct {uint32_t module,rva,kind,length,target;uint8_t original[18];} ID_PATCH;',
 'typedef struct {uint32_t offset,rva,length;uint8_t original[18];} ID_TRAMP;']
arr=lambda data:','.join(f'0x{x:02x}'for x in data)
decl += [f'#define SPLIT_TEMPLATE_BYTES {len(raw)}u',f'#define SPLIT_BINDING_OFFSET 0x{sy["gate_binding"]:x}u',
 'static const uint8_t split_template[SPLIT_TEMPLATE_BYTES]={'+arr(raw)+'};']
patch_rows=[];modules={}
for idx,name in enumerate(['AMITSE','Setup']):
 path=N13/'boot_context'/(name+'.original.efi');p=pefile.PE(str(path));original=path.read_bytes()
 assert sha(original)==b['module_fixtures'][name]['original_sha256']
 text=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text');lo=text.VirtualAddress;hi=lo+text.Misc_VirtualSize
 rows=[x for x in b['patches']if x['module']==name];holes=[];relocs=[]
 for row in rows:
  kind=0 if row['kind']=='DIR64 slot'else 1 if row['kind']=='rel32 prologue jump'else 2
  rva=int(row['rva'],16);old=bytes.fromhex(row['old']);offset=sy[row['entry']]
  patch_rows.append('{'+f'{idx},0x{rva:x},{kind},{row["length"]},0x{offset:x},'+'{'+arr(old)+'}}')
  if lo<=rva<hi:assert kind and rva+len(old)<=hi;holes.append((rva,rva+len(old)))
 for block in getattr(p,'DIRECTORY_ENTRY_BASERELOC',[]):
  for r in block.entries:
   if r.type and lo<=r.rva<hi:
    assert r.type==10 and r.rva+8<=hi and not any(r.rva<e and a<r.rva+8 for a,e in holes)
    relocs.append((r.rva,struct.unpack('<Q',p.get_data(r.rva,8))[0]));holes.append((r.rva,r.rva+8))
 holes.sort();segments=[];pos=lo
 for a,e in holes+[(hi,hi)]:
  assert pos<=a
  if a>pos:segments.append((pos,a-pos,hashlib.sha256(p.get_data(pos,a-pos)).digest()))
  pos=e
 tag=name.upper();decl += [f'#define {tag}_IMAGE_BYTES 0x{p.OPTIONAL_HEADER.SizeOfImage:x}u',f'#define {tag}_TEXT_RVA 0x{lo:x}u',f'#define {tag}_TEXT_BYTES 0x{hi-lo:x}u',f'#define {tag}_ENTRY_RVA 0x{p.OPTIONAL_HEADER.AddressOfEntryPoint:x}u',f'#define {tag}_IMAGE_BASE 0x{p.OPTIONAL_HEADER.ImageBase:x}ULL',f'#define {tag}_GUARD_BYTES {b["module_fixtures"][name]["guard_bytes"]}u']
 decl.append('static const ID_SEGMENT '+name.lower()+'_segments[]={'+','.join('{'+f'0x{a:x},{n},'+'{'+arr(h)+'}}'for a,n,h in segments)+'};')
 decl.append('static const ID_RELOC '+name.lower()+'_relocs[]={'+(','.join('{'+f'0x{a:x},0x{v:x}ULL'+'}'for a,v in relocs)or'{0,0}')+'};')
 decl.append(f'#define {tag}_RELOC_COUNT {len(relocs)}u')
 modules[name]={'original_file_sha256':sha(original),'image_bytes':p.OPTIONAL_HEADER.SizeOfImage,'entry_rva':p.OPTIONAL_HEADER.AddressOfEntryPoint,'text_rva':lo,'text_bytes':hi-lo,'segments':len(segments),'text_dir64_relocations':len(relocs),'text_identity_coverage_bytes':sum(x[1]for x in segments)+sum(e-a for a,e in holes)}
 assert modules[name]['text_identity_coverage_bytes']==hi-lo
decl.append('static const ID_PATCH split_patches[]={'+','.join(patch_rows)+'};')
tr=[]
for r in b['trampolines']:
 offset=int(r['entry'],16)-int(b['guard_bases']['AMITSE'],16);code=bytes.fromhex(r['bytes'])[:r['original_bytes']]
 tr.append('{'+f'0x{offset:x},{int(r["original_rva"],16)},{len(code)},'+'{'+arr(code)+'}}')
decl.append('static const ID_TRAMP split_trampolines[]={'+','.join(tr)+'};')
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
start=sy['gate_loop'];end=min(v for v in sy.values()if v>start);calls={}
for ins in cs.disasm(raw[start:end],start):
 if ins.mnemonic=='call'and len(ins.operands)==1 and ins.operands[0].type==capstone.x86.X86_OP_MEM and ins.operands[0].mem.disp in [16,24]:
  disp=ins.operands[0].mem.disp;assert disp not in calls;calls[disp]=ins.address+ins.size
assert set(calls)=={16,24},calls
for key,value in [('BEGIN_RETURN',calls[16]),('END_RETURN',calls[24]),('CALLBACK',sy['gate_callback']),('ROUTE',sy['gate_route'])]:decl.append(f'#define SPLIT_{key}_OFFSET 0x{value:x}u')
header=HERE/'source/split_profile.h';header.write_text('\n'.join(decl)+'\n')
report={'status':'P13_EXACT_LOCAL_SPLIT_PROFILE_NOT_HARDWARE_IDENTITY_ACCEPTANCE','split_build_sha256':sha((CORE/'build/split_build.json').read_bytes()),'guard_template_sha256':sha(raw),'profile_header_sha256':sha(header.read_bytes()),'modules':modules,'begin_return_offset':calls[16],'end_return_offset':calls[24],'immutable_binding_bytes':160,'sources_sha256':{n:sha((CORE/'source'/n).read_bytes())for n in ['gate.c','gate.h','policy_data.h']},'generator_sha256':sha(Path(__file__).read_bytes())}
(HERE/'split_profile.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'modules':modules}))
