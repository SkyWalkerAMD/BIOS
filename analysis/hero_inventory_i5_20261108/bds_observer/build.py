"""Build only I5-D RAM driver + independent ISO; never modify a firmware CAP."""
from pathlib import Path
import hashlib, io, json, os, subprocess, sys, zlib
BASE=Path(__file__).resolve().parent; ROOT=BASE.parents[2]
sys.dont_write_bytecode=True
for name in ('tools/pydeps','tools/kvm-pydeps','tools/vm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):
 sys.path.insert(0,str(ROOT/name))
import pefile, pycdlib, disk_images
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BASE/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(BASE/'zig-local'))
flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(BASE/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
commands=[]; artifacts={}
def run(cmd):
 subprocess.run([str(x) for x in cmd],check=True,env=env,cwd=ROOT);commands.append([str(x) for x in cmd])
def compile_one(name):
 out=BASE/'build'/(Path(name).name+'.obj')
 run([ZIG,'clang',*flags,'-c',BASE/'source'/(name+'.c'),'-o',out]);return out
def link(name,subsystem,objects):
 p=BASE/'USB/EFI/BOOT'/name;p.parent.mkdir(parents=True,exist_ok=True)
 run([ZIG,'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(BASE/'build'/(name+'.map')),'/out:'+str(p),*objects])
 pe=pefile.PE(str(p));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();p.write_bytes(pe.write());pe=pefile.PE(str(p))
 assert pe.verify_checksum() and pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==(10 if subsystem=='efi_application' else 11)
 assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
 artifacts[name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size,'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'subsystem':pe.OPTIONAL_HEADER.Subsystem}
 return p
objects={name:compile_one(name) for name in ('common','crc','kvm','vendor/qrcodegen')}
# Freeze the exact already-tested I5D resident driver. This launcher never
# invokes its test-only connect_probe callback.
driver=BASE/'USB/EFI/BOOT/I5DNET.EFI'
assert hashlib.sha256(driver.read_bytes()).hexdigest()=='7e61197ec67770717c69fce2da8e531ac4b74b14c3a24cb7b635117a209ea5b3'
data=driver.read_bytes();header='/* Frozen I5D resident driver. */\n#define RESIDENT_CRC 0x%08Xu\nstatic const unsigned char resident_image[]={\n'%zlib.crc32(data)
header+='\n'.join(','.join('0x%02x'%b for b in data[i:i+24])+',' for i in range(0,len(data),24))+'\n};\n'
(BASE/'source/resident_image.h').write_text(header)
objects['app']=compile_one('app')
link('BOOTX64.EFI','efi_application',[objects[n] for n in ('common','crc','kvm','vendor/qrcodegen','app')])
(BASE/'USB/HERO_I5N.TAG').write_bytes(b'HERO-INVENTORY-I5N-BDS\n')
files={'/'+p.relative_to(BASE/'USB').as_posix():p.read_bytes() for p in (BASE/'USB').rglob('*') if p.is_file()}
disk_images.OUT=BASE;disk_images.VOLUME_SIZE=8*1024*1024;boot=BASE/'efi-boot.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_INVENTORY_I5N')
iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
iso.add_directory('/EFI');iso.add_directory('/EFI/BOOT')
for name,value in files.items():iso.add_fp(io.BytesIO(value),len(value),iso_path=name.upper()+';1')
output=BASE/'HERO-INVENTORY-I5N-BDS-READONLY.iso';iso.write(str(output));iso.close()
iso=pycdlib.PyCdlib();iso.open(str(output));assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
for name,value in files.items():
 fp=io.BytesIO();iso.get_file_from_iso_fp(fp,iso_path=name.upper()+';1');assert fp.getvalue()==value
iso.close()
with disk_images.PyFatFS(str(boot),read_only=True) as fs:
 for name,value in files.items():assert fs.readbytes(name)==value
report={'version':'I5n-bds-observer','scope':'Passive two-entry BDS observer; never explicitly connects or triggers the frozen I5D resident driver.','native_dispatch_validated':False,'target':'Exact .71 UUID test gate + provisioned .71 leaf pin, inventory from current SMBIOS','artifacts':artifacts,'iso_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'iso_bytes':output.stat().st_size,'sources':{p.relative_to(BASE/'source').as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (BASE/'source').rglob('*') if p.is_file()},'commands':commands}
(BASE/'build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('sources','commands')},indent=2))
