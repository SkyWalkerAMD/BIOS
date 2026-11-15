"""Build diagnostic EFI/ISO only; no firmware installer or provider bundled."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps'),str(ROOT/'tools/kvm-pydeps')]
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
SRC=HERE/'source';BUILD=HERE/'build';BUILD.mkdir(exist_ok=True)
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'))
(BUILD/'tmp').mkdir(exist_ok=True);env.update(TMP=str(BUILD/'tmp'),TEMP=str(BUILD/'tmp'));commands=[];objects=[]
for relative in ['preflight.c','password_crypto.c','transport/kvm.c','transport/probe_core.c','transport/vendor/qrcodegen.c','entry.S']:
    obj=BUILD/(Path(relative).stem+'.obj');objects.append(obj)
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-I',str(SRC/'transport'),'-I',str(SRC/'transport/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(SRC/relative),'-o',str(obj)]
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
efi=BUILD/'SageNative13EntryContext03.efi';mapfile=BUILD/'probe.map'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(mapfile),'/out:'+str(efi),*map(str,objects)]
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write())
assert not hasattr(p,'DIRECTORY_ENTRY_IMPORT');assert all((s.Characteristics&0xa0000000)!=0xa0000000 for s in p.sections)
boot=BUILD/'readonly-efiboot.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='N13CONTEXT');fat.close()
with PyFatFS(str(boot))as fs:fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
iso=BUILD/'SAGE-N13-READONLY-ENTRY-CONTEXT03.iso';disc=pycdlib.PyCdlib();disc.new(interchange_level=3,vol_ident='SAGE_N13_CTX',joliet=3)
disc.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');disc.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
disc.write(str(iso));disc.close()
report={'efi':str(efi),'efi_sha256':sha(efi),'iso':str(iso),'iso_sha256':sha(iso),'boot_image_sha256':sha(boot),'bytes':efi.stat().st_size,'commands':commands,'contains_installer':False,'contains_provider':False,'imports':False,'rwx_sections':False,'binding_sha256':sha(HERE/'identity_binding.json'),'sources':[{'path':str(p.relative_to(HERE)),'sha256':sha(p)}for p in SRC.rglob('*')if p.is_file()]}
(BUILD/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['efi_sha256','iso_sha256','bytes']}))
