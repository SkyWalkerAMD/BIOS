"""Build only the RC3 capture application and its boot media; no DXE core."""
from pathlib import Path
import hashlib,io,json,os,subprocess,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
sys.dont_write_bytecode=True
for f in ('tools/pydeps','tools/kvm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):sys.path.insert(0,str(ROOT/f))
import pefile,pycdlib,disk_images
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    bootdir=P/'USB/EFI/BOOT';bootdir.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(P/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(P/'zig-local')
    commands=[]
    flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(P/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
    for name in ('common','launcher','kvm','vendor/qrcodegen'):
        cmd=[str(ZIG),'clang',*flags,'-c',str(P/'source'/f'{name}.c'),'-o',str(P/f'{Path(name).name}.obj')]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    path=bootdir/'BOOTX64.EFI'
    cmd=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(P/'launcher.map'),'/out:'+str(path)]+[str(P/f'{x}.obj') for x in ('launcher','common','kvm','qrcodegen')]
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    pe=pefile.PE(str(path));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();path.write_bytes(pe.write());pe=pefile.PE(str(path))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum()
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    # This application has RIP-relative references only; no relocation table
    # is required when there are no absolute image-address fixups.
    (P/'USB/HERO_RC3.TAG').write_bytes(b'HERO-IPMI-RC3-LOG\r\n')
    files={'/'+p.relative_to(P/'USB').as_posix():p.read_bytes() for p in (P/'USB').rglob('*') if p.is_file()}
    assert set(files)=={'/EFI/BOOT/BOOTX64.EFI','/HERO_RC3.TAG'}
    disk_images.OUT=P;disk_images.VOLUME_SIZE=8*1024*1024
    boot=P/'efi-boot.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
    iso_path=P/'HERO-RC3-AUTO-LOG.iso'
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_RC3_AUTO_LOG')
    iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
    for directory in ('/EFI','/EFI/BOOT'):iso.add_directory(directory)
    for name,data in files.items():iso.add_fp(io.BytesIO(data),len(data),iso_path=name.upper()+';1')
    iso.write(str(iso_path));iso.close()
    iso=pycdlib.PyCdlib();iso.open(str(iso_path));assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
    for name,data in files.items():
        check=io.BytesIO();iso.get_file_from_iso_fp(check,iso_path=name.upper()+';1');assert check.getvalue()==data
    iso.close()
    with disk_images.PyFatFS(str(boot),read_only=True) as fs:
        for name,data in files.items():assert fs.readbytes(name)==data
    report=dict(version='RC3 AUTO LOG / CAPTURE ONLY',iso_sha256=sha(iso_path),iso_bytes=iso_path.stat().st_size,
        app_sha256=sha(path),app_bytes=path.stat().st_size,boot_image_sha256=sha(boot),
        boot_media_contains_only_app_and_marker=True,core_included=False,
        files={n:hashlib.sha256(b).hexdigest() for n,b in files.items()},commands=commands,
        source_hashes={str(p.relative_to(P/'source')):sha(p) for p in (P/'source').rglob('*') if p.is_file()})
    (P/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('commands','source_hashes')},indent=2))
if __name__=='__main__':main()
