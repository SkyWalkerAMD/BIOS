"""Build a standalone native-settings app and a read-only virtual optical image."""
from pathlib import Path
import hashlib,io,json,os,subprocess,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
for n in ('tools/pydeps','tools/kvm-pydeps','tools/vm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):sys.path.insert(0,str(ROOT/n))
import pefile,pycdlib,disk_images
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
 env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'))
 flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(OUT/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
 commands=[];objects=[]
 for name in ('common','settings','app','kvm','vendor/qrcodegen'):
  obj=OUT/(Path(name).name+'.obj');cmd=[str(zig),'clang',*flags,'-c',str(OUT/'source'/f'{name}.c'),'-o',str(obj)]
  subprocess.run(cmd,env=env,cwd=ROOT,check=True);commands.append(cmd);objects.append(str(obj))
 image=OUT/'USB/EFI/BOOT/BOOTX64.EFI';image.parent.mkdir(parents=True,exist_ok=True)
 cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/'app.map'),'/out:'+str(image),*objects]
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 p=pefile.PE(str(image));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();image.write_bytes(p.write());p=pefile.PE(str(image))
 assert p.verify_checksum() and p.OPTIONAL_HEADER.Subsystem==10 and p.FILE_HEADER.Machine==0x8664
 assert not hasattr(p,'DIRECTORY_ENTRY_IMPORT') and not p.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
 cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/export:prepare_update','/export:prepare_restore','/export:transaction_valid','/export:setting_valid','/export:probe_crc32','/out:'+str(OUT/'settings_test.dll'),*objects]
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 (OUT/'USB/HERO_R3.TAG').write_bytes(b'HERO-REMOTE-R3\n')
 files={'/'+p.relative_to(OUT/'USB').as_posix():p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
 disk_images.OUT=OUT;disk_images.VOLUME_SIZE=8*1024*1024;boot=OUT/'efi-boot.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
 iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_REMOTE_R3')
 iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
 iso.add_directory('/EFI');iso.add_directory('/EFI/BOOT')
 for name,data in files.items():iso.add_fp(io.BytesIO(data),len(data),iso_path=name.upper()+';1')
 output=OUT/'HERO-REMOTE-BIOS-R3.iso';iso.write(str(output));iso.close()
 iso=pycdlib.PyCdlib();iso.open(str(output));assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
 for name,data in files.items():
  fp=io.BytesIO();iso.get_file_from_iso_fp(fp,iso_path=name.upper()+';1');assert fp.getvalue()==data
 iso.close()
 with disk_images.PyFatFS(str(boot),read_only=True) as fs:
  for name,data in files.items():assert fs.readbytes(name)==data
 report={'version':'R3-readonly','target':'ROG MAXIMUS Z790 HERO BIOS 3107','mode':'read-only native settings over KVM; Setup writes compiled out after live EFI_SECURITY_VIOLATION; not a resident firmware driver','native_setup_writes_enabled':False,'hardware_tested_write_build':'tested-build-20261102/build.json','efi_sha256':sha(image),'efi_bytes':image.stat().st_size,'iso_sha256':sha(output),'iso_bytes':output.stat().st_size,'sources':{p.relative_to(OUT/'source').as_posix():sha(p) for p in (OUT/'source').rglob('*') if p.is_file()},'commands':commands}
 (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('sources','commands')},indent=2))
if __name__=='__main__':main()
