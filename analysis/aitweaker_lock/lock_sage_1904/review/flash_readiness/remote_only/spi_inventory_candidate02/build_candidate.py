"""Build an isolated register-only UEFI application/ISO; no target access."""
from pathlib import Path
import hashlib,io,json,os,shutil,subprocess,sys,warnings,zipfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[6]
P3=ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'
SRC=HERE/'source'
OUT=HERE/'build'
OUT.mkdir(exist_ok=True)
for n in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/n))
warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS

sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
reused={}
for name in ['efi_min.h','kvm.h','kvm.c','probe_core.h','probe_core.c','vendor/qrcodegen.c','vendor/qrcodegen.h','compat/string.h','compat/stdlib.h','compat/assert.h']:
    target=SRC/'p3'/name;target.parent.mkdir(parents=True,exist_ok=True)
    data=(P3/name).read_bytes()
    if name=='kvm.c':
        data=data.replace(b'AI TWEAKER P3 - KVM LOG',b'SPI INVENTORY 02 - KVM LOG')
        data=data.replace(b'Ai Tweaker P3 KVM - diagnostic only',b'SPI inventory 02 - registers only')
        data=data.replace(b'COMPLETE INVENTORY - DIAGNOSTIC ONLY',b'DEFINED REGISTERS - NO FLASH DUMP')
        data=data.replace(b'P3 KVM ended. Log was displayed, not saved to disk.',b'SPI inventory ended. Log displayed only; no flash bytes read.')
    target.write_bytes(data)
    reused[name]={'original_sha256':sha(P3/name),'copy_sha256':sha(target),'change':'UI labels only; P3 frame format unchanged' if name=='kvm.c' else 'byte-identical'}

zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
commands=[];objects=[]
for path in [SRC/'inventory.c',SRC/'p3/probe_core.c',SRC/'p3/kvm.c',SRC/'p3/vendor/qrcodegen.c']:
    obj=OUT/(path.stem+'.obj');objects.append(str(obj))
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC/'p3'),'-I',str(SRC/'p3/compat'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(path),'-o',str(obj)]
    subprocess.run(cmd,check=True,env=env);commands.append(cmd)
efi=OUT/'BOOTX64.EFI'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'inventory.map'),'/out:'+str(efi)]+objects
subprocess.run(cmd,check=True,env=env);commands.append(cmd)
pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());pe=pefile.PE(str(efi))
assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/export:kvm_make_frame','/export:kvm_encode_frame','/export:probe_crc32','/export:qrcodegen_getSize','/export:qrcodegen_getModule','/out:'+str(OUT/'qr_test.dll')]+objects
subprocess.run(cmd,check=True,env=env);commands.append(cmd)

boot=OUT/'eltorito.img';boot.write_bytes(b'')
fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='SPIINV02');fat.close()
with PyFatFS(str(boot),utc=True) as fs:
    fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='SAGE_SPIINV02',joliet=3)
iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
for d in ['/EFI','/EFI/BOOT']:iso.add_directory(iso_path=d,joliet_path=d)
iso.add_file(str(efi),iso_path='/EFI/BOOT/BOOTX64.EFI;1',joliet_path='/EFI/BOOT/BOOTX64.EFI')
target=OUT/'SAGE1904-SPI-INVENTORY02.iso';iso.write(str(target));iso.close()
check=pycdlib.PyCdlib();check.open(str(target));buf=io.BytesIO()
check.get_file_from_iso_fp(buf,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert buf.getvalue()==efi.read_bytes()
assert check.eltorito_boot_catalog.validation_entry.platform_id==0xef
bootbuf=io.BytesIO();check.get_file_from_iso_fp(bootbuf,iso_path='/EFIBOOT.IMG;1');assert bootbuf.getvalue()==boot.read_bytes();check.close()
with PyFatFS(str(boot),read_only=True,utc=True) as fs:assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==efi.read_bytes()

archive=OUT/'source-snapshot.zip'
source_files={p.relative_to(HERE).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file()}
for p in [Path(__file__),HERE/'sources.json']:source_files[p.name]=sha(p)
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for name in source_files:z.write(HERE/name,name)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    assert all(hashlib.sha256(z.read(name)).hexdigest()==v for name,v in source_files.items())
report={'status':'BUILT_AWAITING_LOCAL_TESTS','hardware_tested':False,'scope':'Register-only inventory; no flash read/program, PCI/MMIO writes, SetVariable, files or network in application. ISO creation is local only.','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'iso_sha256':sha(target),'iso_bytes':target.stat().st_size,'iso_embedded_efi_verified':True,'source_archive_sha256':sha(archive),'source_files':source_files,'reused_p3':reused,'compiler_sha256':sha(zig),'commands':commands,'limitations':['Exact SAGE 1904 and Intel 7A24 or observed 7AA4 revision/class 0x0C800011 at segment0:bus0:device31:function5.','Memory-map or PciIo absence refuses collection; no raw ECAM fallback or unhide.','Actual component density/number remain unknown. FREG0..5 are not a whole-chip dump.','Unsigned EFI requires a boot policy that accepts it. No Secure Boot variables are changed.','No hardware acceptance; register definitions and nominal ID are primary-source references only.']}
save(OUT/'build.json',report)
print(json.dumps({k:report[k] for k in ['status','efi_sha256','efi_bytes','iso_sha256','iso_bytes']},indent=2))
