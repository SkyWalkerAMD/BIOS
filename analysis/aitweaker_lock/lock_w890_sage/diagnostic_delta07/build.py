"""Build only the new fixed-selection, read-only D7 collector and optical image."""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];SAGE=HERE.parent;H6=SAGE/'diagnostic_hii06'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
from prepare_selection import canonical
from decode_packet import CPU,NVME,SOCKET,UNKNOWN,BASELINES
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def arr(b):return '{'+','.join('0x%02x'%x for x in b)+'}'
def selection_header(selection,src):
 payload=selection['payload'];digest=hashlib.sha256(canonical(payload)).hexdigest();assert digest==selection['selection_sha256']
 assert payload['qr_budget_bytes']==15360 and payload['authorization'] is False
 targets=payload['targets'];assert sum(t['expected_instances'] for t in targets)==5
 expected=[(CPU,1,1),(NVME,3,1),(UNKNOWN,2,2),(SOCKET,3,1)]
 assert [(t['package_list_guid'],t['kind'],t['expected_instances']) for t in targets]==expected
 arrays=[];entries=[];bindings=[]
 modules={m['loaded_image_handle']:m for m in payload['source_module_observations']}
 paths={}
 for line in payload['source_nonfv_path_observations']:
  m=re.fullmatch(r'D6 I=([0-9A-F]{16}) P=([0-9A-F]{64})',line);assert m;paths[m[1]]=bytes.fromhex(m[2])
 names={CPU:'GetCpuInfo',NVME:'NvmeDynamicSetup',SOCKET:'SocketSetup'}
 for k,t in enumerate(targets):
  g=t['package_list_guid'];bn=0;baseline='0'
  if g!=UNKNOWN:
   p=SAGE/'foreign_hii05/blobs'/f'{names[g]}_0.forms.bin';data=p.read_bytes();bn=len(data);assert (bn,sha(p))==BASELINES[g]
   baseline=f'baseline_{k}';arrays.append('static const uint8_t '+baseline+'[]='+arr(data)+';');bindings.append({'path':str(p),'sha256':sha(p)})
  if g==CPU:
   producer='EE0BFF80-2B33-4005-8EF1-3F9B23C25136';m=[m for m in modules.values() if m['reported_ffs_guid']==producer];assert len(m)==1 and m[0]['comparison']=='MATCH';m=m[0];callback=[0,0,0];psha=bytes(32)
  else:
   records=[]
   for h in t['source_hii_handles']:
    entries_by_method={i['method']:i['observation'] for i in t['source_interfaces'][h]['interfaces']}
    rows=[re.fullmatch(r'([0-9A-F-]{36}|NON_FV_IMAGE) I=0x([0-9A-F]{16}) RVA=0x([0-9A-F]{8})',entries_by_method[n]) for n in ('ExtractConfig','RouteConfig','Callback')];assert all(rows)
    assert len({r[1] for r in rows})==len({r[2] for r in rows})==1
    module=modules[rows[0][2]];record=(rows[0][1],[int(r[3],16) for r in rows],module,paths.get(rows[0][2],bytes(32)));records.append(record)
   producer,callback,m,psha=records[0]
   assert all((r[0],r[1],r[2]['image_bytes'],r[2]['text_rva'],r[2]['text_bytes'],r[2]['raw_sha256'],r[3])==(producer,callback,m['image_bytes'],m['text_rva'],m['text_bytes'],m['raw_sha256'],psha) for r in records)
   assert (m['comparison']=='UNKNOWN' and producer=='NON_FV_IMAGE' and any(psha)) if g==UNKNOWN else (m['comparison']=='MATCH' and producer==g.upper())
  pg=bytes(16) if g==UNKNOWN else uuid.UUID(producer).bytes_le
  meta='{'+','.join(str(t[x]) for x in ('kind','artifact_base','package_index','result_bytes','expected_instances'))+',0,0,'+arr(uuid.UUID(g).bytes_le)+','+arr(bytes.fromhex(payload['source_log_sha256']))+','+arr(bytes.fromhex(digest))+','+arr(bytes.fromhex(t['result_sha256']))+'}'
  entries.append('{'+meta+','+baseline+','+str(bn)+','+arr(pg)+','+'{'+','.join(map(str,callback))+'},'+','.join(str(m[x]) for x in ('image_bytes','text_rva','text_bytes'))+','+arr(bytes.fromhex(m['raw_sha256']))+','+arr(psha)+'}')
 (src/'selection.h').write_text('/* Immutable source-log selection; not authorization. */\n#define D7_TARGET_GROUPS 4U\n#define D7_OBJECTS 5U\n#define D7_BUDGET_BYTES 15360U\n'+'\n'.join(arrays)+'\nstatic const TARGET targets[]={\n'+',\n'.join(entries)+'\n};\n')
 return bindings
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--selection',default=str(HERE/'selection_hardware02.json'));parser.add_argument('--out',default=str(HERE/'build'));a=parser.parse_args();out=Path(a.out);src=out/'source';src.mkdir(parents=True,exist_ok=True)
 frozen=json.loads((H6/'component_manifest.json').read_text());assert sha(H6/'component_manifest.json')=='0af72ade1c3e0b8dfa1350216cf5db37dbd4935e86f1aa005e85558657dcfe97'
 for record in frozen['files']:assert sha(ROOT/record['path'])==record['sha256']
 bindings=[]
 for p in (H6/'source').rglob('*'):
  if not p.is_file():continue
  rel=p.relative_to(H6/'source');dest=src/rel;dest.parent.mkdir(exist_ok=True,parents=True);shutil.copyfile(p,dest);bindings.append({'path':str(p),'sha256':sha(p)})
 for name in ('collector.c','delta_core.c','delta_core.h'):
  p=HERE/name;shutil.copyfile(p,src/name);bindings.append({'path':str(p),'sha256':sha(p)})
 spf=SAGE/'spf_sampler06';assert sha(spf/'component_manifest.json')=='9ad2fe6aa51566aa24f02e7d2fdce99104dbe19b423707770fad8e8c985395e4'
 for record in json.loads((spf/'component_manifest.json').read_text())['files']:assert sha(ROOT/record['path'])==record['sha256']
 for name in ('sampler.c','sampler.h'):
  p=spf/name;shutil.copyfile(p,src/name);bindings.append({'path':str(p),'sha256':sha(p)})
 selection_path=Path(a.selection);selection=json.loads(selection_path.read_text());bindings.append({'path':str(selection_path),'sha256':sha(selection_path)});bindings+=selection_header(selection,src)
 profiles=json.loads((H6/'build/profiles.json').read_text());(out/'profiles.json').write_text(json.dumps(profiles,indent=2)+'\n')
 zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(out/'zig-cache')
 common=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(src),'-I',str(src/'compat'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar'];commands=[];objects=[]
 for name in ('collector','delta_core','probe_core','kvm','vendor/qrcodegen','core','runtime','memory','password_crypto','sampler'):
  obj=out/(Path(name).name+'.obj');cmd=common+['-c',str(src/(name+'.c')),'-o',str(obj)];subprocess.run(cmd,check=True,env=env);commands.append(cmd);objects.append(str(obj))
 efi=out/'BOOTX64.EFI';cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(out/'probe.map'),'/out:'+str(efi)]+objects
 subprocess.run(cmd,check=True,env=env);commands.append(cmd);pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
 boot=out/'efiboot.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='W890D7');fat.close()
 with PyFatFS(str(boot),utc=True) as fs:fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
 iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='W890_DELTA07',joliet=3);iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
 for name in ('/EFI','/EFI/BOOT'):iso.add_directory(iso_path=name,joliet_path=name)
 iso.add_file(str(efi),iso_path='/EFI/BOOT/BOOTX64.EFI;1',joliet_path='/EFI/BOOT/BOOTX64.EFI');target=out/'W890-DELTA07-STRUCTURE-NOFLASH.iso';iso.write(str(target));iso.close()
 report={'status':'NEW_DIAGNOSTIC_AWAITING_QA','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'iso_sha256':sha(target),'selection_sha256':selection['selection_sha256'],'selection_path':str(selection_path),'sources':{p.relative_to(src).as_posix():sha(p) for p in src.rglob('*') if p.is_file()},'inputs':bindings,'commands':commands,'profiles':profiles}
 (out/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ('status','efi_sha256','efi_bytes','iso_sha256','selection_sha256')},indent=2))
if __name__=='__main__':main()
