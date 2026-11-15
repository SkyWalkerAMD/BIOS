"""Build a file-I/O-free EFI and bootable, read-only El Torito ISO."""
from pathlib import Path
import sys,hashlib,subprocess,json,os,re,io
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
for folder in ('tools/pydeps','tools/kvm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):
    sys.path.insert(0,str(ROOT/folder))
import pefile,pycdlib,disk_images
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    (OUT/'payload/EFI/BOOT').mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    dest=OUT/'payload/EFI/BOOT/BOOTX64.EFI'
    flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(OUT/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
    commands=[];objects=[]
    for name in ('diag','kvm','vendor/qrcodegen'):
        obj=OUT/(Path(name).name+'.obj');objects.append(str(obj))
        commands.append([str(ZIG),'clang',*flags,'-c',str(OUT/'source'/(name+'.c')),'-o',str(obj)])
    commands.append([str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/'diag.map'),'/out:'+str(dest),*objects])
    commands.append([str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0',
                     '/export:kvm_make_frame','/export:kvm_encode_frame','/export:probe_crc32','/export:qrcodegen_getSize','/export:qrcodegen_getModule',
                     '/out:'+str(OUT/'capture_test.dll'),*objects])
    for cmd in commands:subprocess.run(cmd,check=True,cwd=ROOT,env=env)
    pe=pefile.PE(str(dest));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();dest.write_bytes(pe.write());pe=pefile.PE(str(dest))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum()
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
    static_reports={}
    for name in ('diag','kvm','vendor/qrcodegen'):
        analyzer=subprocess.run([str(ZIG),'clang',*flags,'--analyze','-Xanalyzer','-analyzer-output=text',str(OUT/'source'/(name+'.c'))],capture_output=True,text=True,cwd=ROOT,env=env,check=True)
        static_reports[name]=analyzer.stdout+analyzer.stderr
        if name!='vendor/qrcodegen':assert not static_reports[name],static_reports[name]
        else:
            assert analyzer.stderr.count('warning:')==1 and 'Division by zero [core.DivideZero]' in analyzer.stderr
    (OUT/'static-analysis.json').write_text(json.dumps(static_reports,indent=2)+'\n')
    disk_images.OUT=OUT;disk_images.VOLUME_SIZE=8*1024*1024
    boot=OUT/'efi-boot.img'
    disk_images.create(boot,layout='superfloppy',fat_type=16,files={'/EFI/BOOT/BOOTX64.EFI':dest.read_bytes()})
    iso_path=OUT/'HERO-DISPLAY-M1e.iso'
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_HII_M1E')
    iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1')
    iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
    iso.add_directory('/EFI');iso.add_directory('/EFI/BOOT');iso.add_file(str(dest),iso_path='/EFI/BOOT/BOOTX64.EFI;1')
    readme=b'HERO HII M1e KVM diagnostic. Boot this ISO as a UEFI CD/DVD.\r\nLog is RAM only: C shows QR pages to capture on your computer.\r\nD=display inventory, R=text capture, C=QR capture, Q=finish.\r\n'
    iso.add_fp(io.BytesIO(readme),len(readme),iso_path='/README.TXT;1')
    iso.write(str(iso_path));iso.close()
    iso=pycdlib.PyCdlib();iso.open(str(iso_path))
    assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
    extracted=io.BytesIO();iso.get_file_from_iso_fp(extracted,iso_path='/EFIBOOT.IMG;1')
    assert extracted.getvalue()==boot.read_bytes()
    extracted=io.BytesIO();iso.get_file_from_iso_fp(extracted,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert extracted.getvalue()==dest.read_bytes();iso.close()
    with disk_images.PyFatFS(str(boot),read_only=True) as fs:assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==dest.read_bytes()
    report=dict(version='M1e-KVM',image_sha256=sha(dest),bytes=dest.stat().st_size,
                iso_sha256=sha(iso_path),iso_bytes=iso_path.stat().st_size,
                boot_fat_sha256=sha(boot),
                no_SendForm_calls=True,static_analysis='diag/kvm: no diagnostics; vendor: one reviewed size-invariant false-positive',
                iso_format='ISO9660 / EFI El Torito / no-emulation / 8 MiB FAT16 boot image',
                commands=commands,sources={p.relative_to(OUT/'source').as_posix():sha(p) for p in (OUT/'source').rglob('*') if p.is_file()})
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('commands','sources')},indent=2))
if __name__=='__main__':main()
