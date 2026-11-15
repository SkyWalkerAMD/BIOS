from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];DRIVER=HERE.parent/'driver'
OUT=HERE/'ram_test';SRC=OUT/'source';SRC.mkdir(parents=True,exist_ok=True)
for n in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/n))
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
source=(DRIVER/'entry.c').read_text(encoding='utf8')
guids='\n'.join(line for line in source.splitlines() if line.startswith(tuple('static GUID '+name for name in ['loaded_guid','browser_guid','smbios3_guid','smbios_guid','tse_guid','setup_guid'])))
functions=source[source.index('static int equal_ascii('):source.index('static void EA discover(')]
(SRC/'target_detect.h').write_text(guids+'\n'+functions,encoding='utf8')
shutil.copyfile(HERE/'ram_lock_test.c',SRC/'ram_lock_test.c')
p3=HERE.parents[1]/'probe_p3_kvm/source'
kvm=(p3/'kvm.c').read_text(encoding='utf8').replace('AI TWEAKER P3 - KVM LOG','AI TWEAKER P5 - RAM TEST')
(SRC/'kvm.c').write_text(kvm,encoding='utf8')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
objects=[]
for file in [SRC/'ram_lock_test.c',SRC/'kvm.c',p3/'vendor/qrcodegen.c']:
 obj=OUT/(file.stem+'.obj');objects.append(str(obj))
 cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(DRIVER),'-I',str(SRC),'-I',str(p3),'-I',str(p3/'compat'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(file),'-o',str(obj)]
 subprocess.run(cmd,check=True,env=env)
linked=['services','cpu_entropy','ui','hii','policy','platform','password_core','password_crypto','probe_core']
objects += [str(DRIVER/'build'/(name+'.obj')) for name in linked]
efi=OUT/'BOOTX64.EFI'
subprocess.run([str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'ram_test.map'),'/out:'+str(efi)]+objects,check=True,env=env)
pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
boot=OUT/'eltorito.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='AITWK_P5');fat.close()
with PyFatFS(str(boot),utc=True) as fs:fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='AITWK_P5_RAM',joliet=3)
iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
target=OUT/'AiTweaker-P5-RAM-Test.iso';iso.write(str(target));iso.close()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
result={'scope':'Maintenance-only RAM credential and resident hook test. No flash. All hooked code remains resident until reset. Original P2/P3 packages unchanged.','iso_sha256':sha(target),'efi_sha256':sha(efi),'iso_bytes':target.stat().st_size,'efi_bytes':efi.stat().st_size,'production_driver_sha256':sha(DRIVER/'build/AiTweakerLock1904.efi'),'linked_objects':{name:sha(DRIVER/'build'/(name+'.obj')) for name in linked},'source_hashes':{p.name:sha(p) for p in SRC.iterdir() if p.is_file()}}
(OUT/'build.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result,indent=2))
