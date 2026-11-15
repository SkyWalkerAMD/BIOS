"""Build the P1 core DXE, independent control app, FFS and CD image."""
from pathlib import Path
import hashlib,json,os,struct,subprocess,sys,uuid,io
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
for folder in ('tools/pydeps','tools/kvm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):sys.path.insert(0,str(ROOT/folder))
import pefile,pycdlib,disk_images
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
DRIVER='07382124-93c8-4ae7-aa9e-df76c37b05dd'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def section(kind,data):return (len(data)+4).to_bytes(3,'little')+bytes([kind])+data
def main():
    (OUT/'USB/EFI/BOOT').mkdir(parents=True,exist_ok=True);(OUT/'USB/EFI/HERO').mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'zig-local')
    import generate_forms;generate_forms.generate()
    commands=[];flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(OUT/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
    for name in ('common','probe_core','command_policy','presentation','transport','driver','launcher','kvm','vendor/qrcodegen'):
        cmd=[str(ZIG),'clang',*flags,'-c',str(OUT/'source'/f'{name}.c'),'-o',str(OUT/f'{Path(name).name}.obj')]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    outputs=[]
    for name,subsystem,parts,path in [('driver','efi_boot_service_driver',['driver','transport','presentation','command_policy','common','probe_core'],OUT/'USB/EFI/HERO/HeroIpmiP1.efi'),('launcher','efi_application',['launcher','common','kvm','qrcodegen'],OUT/'USB/EFI/BOOT/BOOTX64.EFI')]:
        cmd=[str(ZIG),'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/f'{name}.map'),'/out:'+str(path)]+[str(OUT/f'{p}.obj') for p in parts]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
        pe=pefile.PE(str(path));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();path.write_bytes(pe.write());pe=pefile.PE(str(path))
        assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==(11 if name=='driver' else 10)
        assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size and pe.verify_checksum()
        assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size or name=='launcher'
        outputs.append(dict(path=str(path.relative_to(OUT)),bytes=path.stat().st_size,sha256=sha(path),subsystem=pe.OPTIONAL_HEADER.Subsystem))
    cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/export:kvm_present','/export:kvm_make_frame','/export:kvm_encode_frame','/export:probe_crc32','/export:qrcodegen_getSize','/export:qrcodegen_getModule','/out:'+str(OUT/'capture_test.dll')]+[str(OUT/f'{p}.obj') for p in ('launcher','common','kvm','qrcodegen')]
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    deps=['ef9fc172-a1b2-4693-b327-6d32fc416042','0fd96974-23aa-4cdc-b9cb-98d17750322a']
    depex=b''
    for i,guid in enumerate(deps):depex+=b'\x02'+uuid.UUID(guid).bytes_le+(b'\x03' if i else b'')
    depex+=b'\x08';data=b''
    for kind,body in [(0x13,depex),(0x10,(OUT/'USB/EFI/HERO/HeroIpmiP1.efi').read_bytes()),(0x15,'HeroIpmiCoreP1\0'.encode('utf-16-le'))]:
        data+=section(kind,body);data+=bytes((-len(data))%4)
    hdr=bytearray(uuid.UUID(DRIVER).bytes_le+b'\0\xaa\x07\x00'+(24+len(data)).to_bytes(3,'little')+b'\xf8')
    hdr[16]=(-sum(hdr[:16]+b'\0\0'+hdr[18:23]+b'\0'))&255
    ffs=OUT/'HeroIpmiCoreP1.ffs';ffs.write_bytes(hdr+data)
    (OUT/'USB/HERO_P1.TAG').write_bytes(b'HERO-IPMI-P1\r\n')
    files={'/'+p.relative_to(OUT/'USB').as_posix():p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
    disk_images.OUT=OUT;disk_images.VOLUME_SIZE=8*1024*1024
    boot=OUT/'efi-boot.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
    iso_path=OUT/'HERO-IPMI-P1-NATIVE-TEST.iso';iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_IPMI_P1')
    iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
    for directory in ('/EFI','/EFI/BOOT','/EFI/HERO'):iso.add_directory(directory)
    for name,data in files.items():iso.add_fp(io.BytesIO(data),len(data),iso_path=name.upper()+';1')
    iso.write(str(iso_path));iso.close()
    iso=pycdlib.PyCdlib();iso.open(str(iso_path));assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
    for name,data in files.items():
        check=io.BytesIO();iso.get_file_from_iso_fp(check,iso_path=name.upper()+';1');assert check.getvalue()==data
    iso.close()
    with disk_images.PyFatFS(str(boot),read_only=True) as fs:
        for name,data in files.items():assert fs.readbytes(name)==data
    report=dict(version='P1',target='HERO BIOS 3107 / tested BMC 1.3.13 Device ID',read_only=True,native_hii=True,standalone_send_form=False,ffs_guid=DRIVER,depex=deps,outputs=outputs,ffs_sha256=sha(ffs),iso_sha256=sha(iso_path),iso_bytes=iso_path.stat().st_size,dll_sha256=sha(OUT/'capture_test.dll'),commands=commands,sources={p.relative_to(OUT/'source').as_posix():sha(p) for p in (OUT/'source').rglob('*') if p.is_file()})
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:v for k,v in report.items() if k not in ('commands','sources')},indent=2))
if __name__=='__main__':main()
