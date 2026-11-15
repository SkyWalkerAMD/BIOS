from pathlib import Path
import hashlib,json,os,subprocess,sys,warnings
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2];SRC=OUT/'source'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
 commands=[];objects=[]
 for name in ('probe','probe_core','kvm','vendor/qrcodegen'):
  obj=OUT/(Path(name).name+'.obj');objects.append(str(obj))
  cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
   '-I',str(SRC),'-I',str(SRC/'compat'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding',
   '-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(SRC/(name+'.c')),'-o',str(obj)]
  subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
 efi=OUT/'BOOTX64.EFI'
 cmd=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64',
  '/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'probe.map'),'/out:'+str(efi)]+objects
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());pe=pefile.PE(str(efi))
 assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10
 assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0
 cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0',
  '/export:kvm_make_frame','/export:kvm_encode_frame','/export:probe_crc32','/export:qrcodegen_getSize','/export:qrcodegen_getModule',
  '/out:'+str(OUT/'capture_test.dll')]+objects
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 boot=OUT/'eltorito.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='AITWK_P3');fat.close()
 with PyFatFS(str(boot),utc=True) as fs:
  fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
 iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='AITWEAKER_P3_KVM',joliet=3)
 iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
 iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,
                  platform_id=0xef,efi=True,media_name='noemul',bootable=True)
 for p in ('/EFI','/EFI/BOOT'):iso.add_directory(iso_path=p,joliet_path=p)
 iso.add_file(str(efi),iso_path='/EFI/BOOT/BOOTX64.EFI;1',joliet_path='/EFI/BOOT/BOOTX64.EFI')
 target=OUT/'AiTweaker-P3-KVM.iso';iso.write(str(target));iso.close()
 # Verify the boot catalog and embedded executable, not just the outer ISO hash.
 check=pycdlib.PyCdlib();check.open(str(target));import io
 got=io.BytesIO();check.get_file_from_iso_fp(got,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert got.getvalue()==efi.read_bytes()
 assert check.eltorito_boot_catalog.validation_entry.platform_id==0xef
 check.close()
 result={'status':'BUILT_AWAITING_TESTS','compiler':'Zig 0.14.1 Clang/LLD','unsigned':True,
  'efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'iso_sha256':sha(target),'iso_bytes':target.stat().st_size,
  'iso_uefi_platform_id':'EF','embedded_efi_verified':True,'parser_source_unchanged':sha(SRC/'probe_core.c')==sha(OUT.parent/'probe_p2/source/probe_core.c'),
  'profile_source_unchanged':sha(SRC/'profiles.h')==sha(OUT.parent/'probe_p2/source/profiles.h'),
  'sources':{p.relative_to(SRC).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file()},'commands':commands,
  'vendor_source':'https://github.com/nayuki/QR-Code-generator/tree/v1.8.0/c','vendor_license':'MIT retained in C and H files'}
 (OUT/'build.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps({k:result[k] for k in ('efi_sha256','efi_bytes','iso_sha256','iso_bytes')},indent=2))
if __name__=='__main__':main()
