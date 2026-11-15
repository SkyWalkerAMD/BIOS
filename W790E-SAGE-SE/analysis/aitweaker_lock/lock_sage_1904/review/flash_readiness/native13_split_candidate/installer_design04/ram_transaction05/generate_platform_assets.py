"""Derive auditable app assets without modifying any frozen dependency."""
from pathlib import Path
import hashlib,json,sys,re
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=D04.parents[6];SRC=HERE/'source'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sha=lambda b:hashlib.sha256(b).hexdigest()
manifest=json.loads((D04/'provider13/local_candidate_manifest.json').read_text())
for row in manifest['artifacts']:assert sha((D04/row['path']).read_bytes())==row['sha256']
old=D04/'prerequisite_probe04/source'
source=(old/'preflight.c').read_text()
chunks=[]
for start,end in [('static const MD *descriptor','static int image_read'),('static int image_guid','static void inspect_module')]:
 chunks.append(source[source.index(start):source.index(end)])
walk=(old/'pagewalk.inc').read_text();walk=walk[:walk.index('static int walk_page')]
walk=walk.replace('static CPU_ENV walk_env;','')
(SRC/'platform_readonly.inc').write_text('/* Derived bounded read-only helpers; source provenance in platform_assets.json. */\n'+chunks[0]+walk+chunks[1])
(SRC/'split_profile.h').write_bytes((D04/'provider13/source/split_profile.h').read_bytes())
p13=D04/'provider13/build/AiTweakerSplitProvider13.UNSIGNED.local.efi';data=p13.read_bytes();p=pefile.PE(data=data)
mapped=bytearray(p.get_memory_mapped_image());mapped+=bytes(p.OPTIONAL_HEADER.SizeOfImage-len(mapped))
relocs=[]
for block in p.DIRECTORY_ENTRY_BASERELOC:
 for row in block.entries:
  if not row.type:continue
  assert row.type==10
  relocs.append(row.rva)
def arr(name,b):return 'static const uint8_t '+name+'[]={'+','.join(str(x)for x in b)+'};\n'
h='/* Exact frozen P13 file and declared loaded ranges. Alignment gaps and raw\n * padding beyond VirtualSize have no specified loaded contents and are not read.\n * BasePeCoff.official.c copies min(VirtualSize,RawSize), except zero VS uses RawSize,\n * and zeroes the remaining VirtualSize. Exact declared BSS remains validated. */\n'
h+=arr('provider_file',data)
h+=f'#define PROVIDER_IMAGE_BYTES {p.OPTIONAL_HEADER.SizeOfImage}u\n#define PROVIDER_ENTRY_RVA {p.OPTIONAL_HEADER.AddressOfEntryPoint}u\n#define PROVIDER_PREFERRED_BASE {p.OPTIONAL_HEADER.ImageBase}ULL\n'
h+=f'#define PROVIDER_IMAGEBASE_FIELD {p.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase")}u\n'
ranges=[(0,p.OPTIONAL_HEADER.SizeOfHeaders)]+[(s.VirtualAddress,s.Misc_VirtualSize or s.SizeOfRawData)for s in p.sections]
for a,n in ranges:assert 0<=a<len(mapped) and n>0 and n<=len(mapped)-a
for rva in relocs:assert any(a<=rva and rva+8<=a+n for a,n in ranges)
h+='static const ID_SEGMENT provider_segments[]={'+','.join('{'+str(a)+','+str(n)+',{'+','.join(str(v)for v in hashlib.sha256(mapped[a:a+n]).digest())+'}}'for a,n in ranges)+'};\n'
h+='static const uint32_t provider_relocs[]={'+','.join(str(x)for x in relocs)+'};\n'
symbols={name:int(addr,16)-p.OPTIONAL_HEADER.ImageBase for name,addr in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})',(D04/'provider13/build/provider.map').read_text(),re.M)}
h+=f'#define PROVIDER_OBJECT_RVA {symbols["native_provider"]}u\n'
h+='static const uint32_t provider_method_rvas[]={'+','.join(str(symbols[n])for n in ['provider_begin','provider_end','provider_query','provider_request','provider_manage'])+'};\n'
(SRC/'provider_asset.h').write_text(h)
out={'dependencies':{'p13_manifest':sha((D04/'provider13/local_candidate_manifest.json').read_bytes()),'p13_efi':sha(data),'preflight_source':sha((old/'preflight.c').read_bytes()),'pagewalk_source':sha((old/'pagewalk.inc').read_bytes()),'split_profile':sha((SRC/'split_profile.h').read_bytes()),'official_edk2_loader':sha((D04/'ram_test05_delivery/BasePeCoff.official.c').read_bytes())},'provider_image_bytes':len(mapped),'provider_declared_ranges':[{'rva':a,'bytes':n}for a,n in ranges],'provider_declared_bytes':sum(n for a,n in ranges),'provider_relocations':len(relocs),'generated':{n:sha((SRC/n).read_bytes())for n in ['platform_readonly.inc','split_profile.h','provider_asset.h']}}
(HERE/'platform_assets.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items()if k!='generated'}))
