"""Independent object relink and embedded P14 declared-range audit. No EFI runs."""
from pathlib import Path
import hashlib,json,re,struct,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;TX=D04/'ram_transaction08';P14=D04/'provider14_chrome07'
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
EXPECTED='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def manifest(path,expected):
 assert sha(path)==expected
 obj=json.loads(path.read_text())
 assert obj['path_base']=='installer_design04'
 for row in obj['artifacts']:
  p=(D04/row['path']).resolve();assert p.is_relative_to(D04.resolve())
  assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],p
 return len(obj['artifacts'])
def main():
 buildpath=TX/'app_build/app_build.json';build=json.loads(buildpath.read_text())
 assert build['efi_sha256']==EXPECTED and sha(TX/'app_build/SageNative13RamTest08.efi')==EXPECTED
 for row in build['sources']:assert sha(TX/row['path'])==row['sha256']
 for name,digest in build['objects'].items():assert sha(TX/'app_build'/name)==digest
 counts={
  'tx08_manifest':manifest(TX/'ram_candidate_manifest.json','7f08d975710179f88f953636b1da72db34ebd0c41ef04447bdf40b296a599e96'),
  'p14_manifest':manifest(P14/'local_candidate_manifest.json','150ae9aaba738a2c70f3075d741f4875f0c9f26ce8006ca83eafd71c5e9e7019')}
 # Link pinned existing objects again in a new output directory. The only
 # post-link alteration is the same standard optional-header checksum update.
 out=HERE/'object_relink';out.mkdir(exist_ok=True);efi=out/'RELINK_ONLY_NEVER_BOOT.efi'
 command=build['commands'][-1][:]
 assert command[1]=='lld-link' and command[0]==str(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe')
 original_objects=[str(TX/'app_build'/n) for n in build['objects']]
 assert command[-len(original_objects):]==original_objects
 command=[('/out:'+str(efi))if a.startswith('/out:')else('/map:'+str(out/'app.map'))if a.startswith('/map:')else a for a in command]
 run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,check=True)
 p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write())
 assert sha(efi)==EXPECTED
 header=(TX/'source/provider_asset.h').read_text()
 raw=bytes(map(int,re.search(r'provider_file\[\]=\{([^}]+)\}',header).group(1).split(',')))
 provider=P14/'build/AiTweakerSplitProvider14.UNSIGNED.local.efi'
 assert raw==provider.read_bytes() and sha(provider)=='495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630'
 pe=pefile.PE(data=raw);mapped=bytearray(pe.get_memory_mapped_image());mapped+=bytes(pe.OPTIONAL_HEADER.SizeOfImage-len(mapped))
 segments=re.search(r'provider_segments\[\]=\{(.+?)\};',header).group(1)
 ranges=[]
 for rva,n,digest in re.findall(r'\{(\d+),(\d+),\{([^}]+)\}\}',segments):
  rva,n=int(rva),int(n);digest=bytes(map(int,digest.split(',')))
  assert hashlib.sha256(mapped[rva:rva+n]).digest()==digest
  assert not any(rva<old+nold and old<rva+n for old,nold in ranges)
  ranges.append((rva,n))
 expected_ranges=[(0,pe.OPTIONAL_HEADER.SizeOfHeaders)]+[(s.VirtualAddress,s.Misc_VirtualSize or s.SizeOfRawData)for s in pe.sections]
 assert ranges==expected_ranges
 relocations=[r.rva for block in pe.DIRECTORY_ENTRY_BASERELOC for r in block.entries if r.type]
 assert all(r.type in [0,10]for block in pe.DIRECTORY_ENTRY_BASERELOC for r in block.entries)
 embedded_relocs=list(map(int,re.search(r'provider_relocs\[\]=\{([^}]+)\}',header).group(1).split(',')))
 assert embedded_relocs==relocations and len(set(relocations))==len(relocations)==17
 assert all(any(a<=r and r+8<=a+n for a,n in ranges)for r in relocations)
 symbols={n:int(a,16)-pe.OPTIONAL_HEADER.ImageBase for n,a in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})',(P14/'build/provider.map').read_text(),re.M)}
 obj=int(re.search(r'#define PROVIDER_OBJECT_RVA (\d+)u',header).group(1))
 methods=list(map(int,re.search(r'provider_method_rvas\[\]=\{([^}]+)\}',header).group(1).split(',')))
 assert obj==symbols['native_provider']
 assert methods==[symbols[x]for x in ['provider_begin','provider_end','provider_query','provider_request','provider_manage']]
 assert bytes(mapped[obj+16:obj+56])==b''.join(struct.pack('<Q',pe.OPTIONAL_HEADER.ImageBase+r)for r in methods)
 # No unchanged-source inference is used to transfer actual runtime results.
 same_provider=[]
 for path in (P14/'source').glob('*'):
  if path.is_file() and path.name!='split_profile.h':
   old=D04/'provider13/source'/path.name
   if not old.exists():old=D04/'provider13_candidate/source'/path.name
   if not old.exists():continue
   assert path.read_bytes()==old.read_bytes();same_provider.append(path.name)
 for name in ['transaction.c','transaction.h','efi.h','entry.S','ui_bindings.h']:
  assert (TX/'source'/name).read_bytes()==(D04/'ram_transaction05/source'/name).read_bytes()
 result={'status':'PASS_INDEPENDENT_EXACT_OBJECT_RELINK_AND_P14_ASSET_BINDING','efi_sha256':EXPECTED,'provider_sha256':sha(provider),
  'verified_manifest_items':counts,'source_count':len(build['sources']),'object_count':len(build['objects']),
  'link_command':command,'linker_sha256':sha(Path(command[0])),'link_stdout':run.stdout,'link_stderr':run.stderr,
  'relinked_file_sha256':sha(efi),'declared_provider_ranges':[{'rva':a,'bytes':n}for a,n in ranges],
  'declared_provider_bytes':sum(n for a,n in ranges),'provider_dir64_entries':len(relocations),'provider_object_rva':obj,'provider_method_rvas':methods,
  'provider_same_nonbinding_sources_if_found':same_provider,'test_source_sha256':sha(Path(__file__)),
  'limits':['Relinks already hashed objects, not an independent compiler/source proof. No candidate entry or target machine code executed in this audit.',
   'Undefined loader padding is intentionally excluded; all declared section virtual bytes including BSS remain exact.',
   'Direct-map PE analysis and object equality do not establish ASUS runtime page attributes, native rendering, or flash acceptability.']}
 target=HERE/'link_and_assets_review.json';assert not target.exists();target.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'counts':counts,'sha256':sha(target)}))
if __name__=='__main__':main()
