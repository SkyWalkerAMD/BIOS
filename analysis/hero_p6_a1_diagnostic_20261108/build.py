"""Standalone application-only diagnostic. No resident driver or CAP."""
from pathlib import Path
import hashlib,io,json,os,subprocess,sys
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
sys.dont_write_bytecode=True
for name in ('tools/pydeps','tools/kvm-pydeps','tools/vm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):
 sys.path.insert(0,str(ROOT/name))
import pefile,pycdlib,disk_images
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BASE/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(BASE/'zig-local'))
flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(BASE/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
commands=[]
def run(cmd):
 subprocess.run([str(x) for x in cmd],check=True,env=env,cwd=ROOT);commands.append([str(x) for x in cmd])
objects=[]
for name in ('common','crc','smbios','identity','preflight','kvm','vendor/qrcodegen','app','diagnostic','command_policy','presentation','publisher','transport','probe_core'):
 obj=BASE/'build'/(Path(name).name+'.obj');run([ZIG,'clang',*flags,'-c',BASE/'source'/(name+'.c'),'-o',obj]);objects.append(obj)
app=BASE/'USB/EFI/BOOT/BOOTX64.EFI'
run([ZIG,'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(BASE/'build/BOOTX64.map'),'/out:'+str(app),*objects])
pe=pefile.PE(str(app));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();app.write_bytes(pe.write());pe=pefile.PE(str(app))
assert pe.verify_checksum() and pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
files={'/'+p.relative_to(BASE/'USB').as_posix():p.read_bytes() for p in (BASE/'USB').rglob('*') if p.is_file()}
disk_images.OUT=BASE;disk_images.VOLUME_SIZE=8*1024*1024;boot=BASE/'efi-boot.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_P6_A1_DIAGNOSTIC')
iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
iso.add_directory('/EFI');iso.add_directory('/EFI/BOOT')
for name,value in files.items():iso.add_fp(io.BytesIO(value),len(value),iso_path=name.upper()+';1')
output=BASE/'HERO-P6-A1-DIAGNOSTIC.iso';iso.write(str(output));iso.close()
iso=pycdlib.PyCdlib();iso.open(str(output));assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
for name,value in files.items():
 fp=io.BytesIO();iso.get_file_from_iso_fp(fp,iso_path=name.upper()+';1');assert fp.getvalue()==value
iso.close()
with disk_images.PyFatFS(str(boot),read_only=True) as fs:
 for name,value in files.items():assert fs.readbytes(name)==value
maptext=(BASE/'build/BOOTX64.map').read_text()
for forbidden in ('p6_transport_open','p6_transport_close','p6_exchange','p6_delay','p6_write_armed','p6_seed_settings','p6_apply_settings','p6_start_os_watchdog','p6_stop_os_watchdog','candidate_query','candidate_arm','candidate_step','fan_query','fan_arm','fan_packet'):
 assert ' '+forbidden+' ' not in maptext,forbidden
report={'scope':'Standalone TPL_APPLICATION diagnostic. B binds; R uses GET commands; P same-value probe then full RAM HII display publication. No resident events, driver loading, NVRAM, BMC config/OEM, inventory or flash.','target':'HERO BIOS3107 exact .71 raw Type1 UUID','launcher_sha256':hashlib.sha256(app.read_bytes()).hexdigest(),'launcher_bytes':app.stat().st_size,'iso_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'iso_bytes':output.stat().st_size,'sources':{p.relative_to(BASE/'source').as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (BASE/'source').rglob('*') if p.is_file()},'commands':commands}
(BASE/'build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('sources','commands')},indent=2))
