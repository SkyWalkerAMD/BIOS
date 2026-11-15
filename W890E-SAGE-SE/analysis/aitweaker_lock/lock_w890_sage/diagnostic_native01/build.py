"""Build a new read-only native sampler from a pinned P3 source copy."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
LEGACY=ROOT/'analysis/aitweaker_lock/probe_p3_kvm'
SRC=HERE/'source';OUT=HERE/'build'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 SRC.mkdir(exist_ok=True);OUT.mkdir(exist_ok=True)
 prior=json.loads((LEGACY/'build.json').read_text(encoding='utf-8'))
 bindings=[]
 for p in (LEGACY/'source').rglob('*'):
  if not p.is_file():continue
  name=p.relative_to(LEGACY/'source').as_posix();assert sha(p)==prior['sources'][name]
  dest=SRC/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
  bindings.append({'source':str(p),'sha256':sha(p)})
 for name in ('native_sample.c','native_sample.h','native_bridge.c'):shutil.copyfile(HERE/name,SRC/name)
 for name in ('password_core.h','password_crypto.c'):
  p=HERE.parent/'password/core'/name;shutil.copyfile(p,SRC/name);bindings.append({'source':str(p),'sha256':sha(p)})
 p=SRC/'probe.c';s=p.read_text(encoding='utf-8')
 s=s.replace('static ST *st;', 'int native_read_only(ST *,void *,void *,void (*)(const char *));\nstatic void *w890_tse,*w890_setup;\nstatic ST *st;')
 target='name=p->name;known_modules|=equal(&g,&tse_guid,16)?1U:2U;break;'
 assert s.count(target)==1
 s=s.replace(target,'name=p->name;known_modules|=equal(&g,&tse_guid,16)?1U:2U;if(i==4)w890_tse=li->image_base;if(i==5)w890_setup=li->image_base;break;')
 s=s.replace('emit("HII ");guid_text((GUID *)buffer);','emit("HII ");guid_text((GUID *)buffer);emit(" handle=0x");hex((UN)handles[i],16);')
 s=s.replace('inspect_images();inspect_protocols();inspect_hii();','w890_tse=0;w890_setup=0;inspect_images();inspect_protocols();inspect_hii();\n    if(!native_read_only(st,w890_tse,w890_setup,emit))warnings++;')
 p.write_text(s,encoding='utf-8')
 zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy()
 env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'zig-cache')
 common=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-I',str(SRC/'compat'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar']
 commands=[];objects=[]
 for name in ('probe','probe_core','kvm','vendor/qrcodegen','native_sample','native_bridge','password_crypto'):
  obj=OUT/(Path(name).name+'.obj');cmd=common+['-c',str(SRC/(name+'.c')),'-o',str(obj)]
  subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd);objects.append(str(obj))
 efi=OUT/'BOOTX64.EFI'
 cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'probe.map'),'/out:'+str(efi)]+objects
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());pe=pefile.PE(str(efi))
 assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10
 assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0
 testobj=OUT/'native_sample_test.obj';cmd=common+['-DNS_EXPORT','-c',str(SRC/'native_sample.c'),'-o',str(testobj)]
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(OUT/'native_sample_test.dll'),str(testobj)]
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 boot=OUT/'efiboot.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='W890NS01');fat.close()
 with PyFatFS(str(boot),utc=True) as fs:
  fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
 iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='W890_SAMPLE01',joliet=3)
 iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
 iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
 for name in ('/EFI','/EFI/BOOT'):iso.add_directory(iso_path=name,joliet_path=name)
 iso.add_file(str(efi),iso_path='/EFI/BOOT/BOOTX64.EFI;1',joliet_path='/EFI/BOOT/BOOTX64.EFI')
 target=OUT/'W890-NATIVE-SAMPLE01-NOFLASH.iso';iso.write(str(target));iso.close()
 result={'status':'BUILT_AWAITING_REVIEW_AND_TESTS','scope':'Read-only exact-text-bound native metadata sampler. No lock installation, password or firmware writing.','efi_sha256':sha(efi),'iso_sha256':sha(target),'efi_bytes':efi.stat().st_size,'inputs':bindings,'sources':{p.relative_to(SRC).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file()},'commands':commands,'limitations':['Memory descriptor attributes are conservative bounds/capability checks, not page-table proof.','Double sampling does not prove exclusive ownership or quiescence.','HII values are opaque handles, never dereferenced.','Current native application may be inactive after boot override.']}
 (OUT/'build.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:result[k] for k in ('status','efi_sha256','iso_sha256','efi_bytes')},indent=2))
if __name__=='__main__':main()
