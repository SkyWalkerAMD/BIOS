"""Build local SCSI-only capacity probe and read-only El Torito ISO."""
from pathlib import Path
import hashlib,io,json,os,subprocess,sys,warnings,zipfile
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
SRC=HERE/'source';OUT=HERE/'build';OUT.mkdir(exist_ok=True)
for n in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/n))
warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
commands=[];objects=[]
for path in [SRC/'capacity.c',SRC/'p3/probe_core.c',SRC/'p3/kvm.c',SRC/'p3/vendor/qrcodegen.c']:
    obj=OUT/(path.stem+'.obj');objects.append(str(obj))
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-I',str(SRC/'p3'),'-I',str(SRC/'p3/compat'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(path),'-o',str(obj)]
    subprocess.run(cmd,check=True,env=env);commands.append(cmd)
efi=OUT/'BOOTX64.EFI'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'capacity.map'),'/out:'+str(efi)]+objects
subprocess.run(cmd,check=True,env=env);commands.append(cmd)
pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());pe=pefile.PE(str(efi))
assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/export:kvm_make_frame','/export:kvm_encode_frame','/export:probe_crc32','/export:qrcodegen_getSize','/export:qrcodegen_getModule','/out:'+str(OUT/'qr_test.dll')]+objects
subprocess.run(cmd,check=True,env=env);commands.append(cmd)
boot=OUT/'eltorito.img';boot.write_bytes(b'')
fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='CAPACITY02');fat.close()
with PyFatFS(str(boot),utc=True) as fs:
    fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='SAGE_CAPACITY02',joliet=3)
iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
for d in ['/EFI','/EFI/BOOT']:iso.add_directory(iso_path=d,joliet_path=d)
iso.add_file(str(efi),iso_path='/EFI/BOOT/BOOTX64.EFI;1',joliet_path='/EFI/BOOT/BOOTX64.EFI')
target=OUT/'SAGE1904-MEDIA-CAPACITY02.iso';iso.write(str(target));iso.close()
check=pycdlib.PyCdlib();check.open(str(target));buf=io.BytesIO();check.get_file_from_iso_fp(buf,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert buf.getvalue()==efi.read_bytes()
assert check.eltorito_boot_catalog.validation_entry.platform_id==0xef
bootbuf=io.BytesIO();check.get_file_from_iso_fp(bootbuf,iso_path='/EFIBOOT.IMG;1');assert bootbuf.getvalue()==boot.read_bytes();check.close()
with PyFatFS(str(boot),read_only=True,utc=True) as fs:assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==efi.read_bytes()
archive=OUT/'source-snapshot.zip'
files={p.relative_to(HERE).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file()}
for p in [Path(__file__),HERE/'prepare_sources.py',HERE/'sources.json',HERE/'abi_review.json']:files[p.name]=sha(p)
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for name in files:z.write(HERE/name,name)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None and all(hashlib.sha256(z.read(name)).hexdigest()==v for name,v in files.items())
report={'status':'BUILT_AWAITING_LOCAL_TESTS','hardware_tested':False,
 'scope':'One synchronous RC10 only via unique matching existing SCSI_IO. Ext SCSI/ATA inventory only. No raw BOT fallback, controller connection, block data, files, PCI/SPI, resets or RuntimeServices calls.',
 'efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'iso_sha256':sha(target),'iso_bytes':target.stat().st_size,
 'iso_embedded_efi_verified':True,'source_archive_sha256':sha(archive),'source_files':files,'compiler_sha256':sha(zig),'commands':commands,
 'limits':{'union_handles':128,'device_path_bytes':2048,'device_path_nodes':64,'log_bytes':32768,'rc10_count':1,'in_data_bytes':8,'timeout_100ns':20000000},
 'limitations':['No hardware execution claimed.','Already installed SCSI_IO required; no raw USB fallback.','Firmware must honor its synchronous timeout contract; no external watchdog can safely cancel an in-flight USB transaction.','A same-path protocol owner is inferred from standard UEFI device path association, not a proof against malicious firmware.']}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:report[k] for k in ['status','efi_sha256','efi_bytes','iso_sha256','iso_bytes']},indent=2))
