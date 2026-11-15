"""Build only a two-pass observer app; retain the exact frozen R3 PE."""
from pathlib import Path
import hashlib,io,json,os,subprocess,sys,zlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.dont_write_bytecode=True
for p in ('tools/pydeps','tools/kvm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):sys.path.insert(0,str(ROOT/p))
import pefile,pycdlib,disk_images
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
CORE=ROOT/'analysis/hero_sensor_r4_20261108/USB/EFI/HERO/HeroIpmiR4.efi'
CORE_SHA=json.loads((OUT.parent/'build.json').read_text())['outputs'][0]['sha256']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    core=CORE.read_bytes();assert hashlib.sha256(core).hexdigest()==CORE_SHA and 512<=len(core)<1048576
    generated='#ifndef FROZEN_R4_H\n#define FROZEN_R4_H\n#define FROZEN_R4_CRC 0x%08Xu\nstatic const unsigned char frozen_r4[] = {\n'%zlib.crc32(core)
    generated+=''.join(','.join('0x%02x'%b for b in core[p:p+16])+',\n' for p in range(0,len(core),16))+'};\n#endif\n'
    generated=generated.replace('#define FROZEN_R4_H\n','#define FROZEN_R4_H\n#define FROZEN_R4_SHA \"'+CORE_SHA+'\"\n')
    (OUT/'source/frozen_r4.h').write_text(generated,encoding='ascii')
    (OUT/'USB/EFI/BOOT').mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'zig-local')
    flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(OUT/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
    commands=[]
    for name in ('common','launcher','kvm','vendor/qrcodegen'):
        cmd=[str(ZIG),'clang',*flags,'-c',str(OUT/'source'/f'{name}.c'),'-o',str(OUT/f'{Path(name).name}.obj')]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    dest=OUT/'USB/EFI/BOOT/BOOTX64.EFI'
    objs=[str(OUT/f'{p}.obj') for p in ('launcher','common','kvm','qrcodegen')]
    cmd=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/'launcher.map'),'/out:'+str(dest)]+objs
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    pe=pefile.PE(str(dest));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();dest.write_bytes(pe.write());pe=pefile.PE(str(dest))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.verify_checksum()
    cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/export:kvm_make_frame','/export:kvm_encode_frame','/export:probe_crc32','/export:qrcodegen_getSize','/export:qrcodegen_getModule','/out:'+str(OUT/'capture_test.dll')]+objs
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    (OUT/'USB/HERO_R4A.TAG').write_bytes(b'HERO-R4AUTO\r\n')
    files={'/'+p.relative_to(OUT/'USB').as_posix():p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
    disk_images.OUT=OUT;disk_images.VOLUME_SIZE=8*1024*1024
    boot=OUT/'efi-boot.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
    destiso=OUT/'HERO-R4-AUTO-BDS-TEST.iso';iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_R4_AUTO')
    iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
    for folder in ('/EFI','/EFI/BOOT'):iso.add_directory(folder)
    for name,data in files.items():iso.add_fp(io.BytesIO(data),len(data),iso_path=name.upper()+';1')
    iso.write(str(destiso));iso.close()
    with disk_images.PyFatFS(str(boot),read_only=True) as fs:
        for name,data in files.items():assert fs.readbytes(name)==data
    assert sha(CORE)==CORE_SHA
    report=dict(core_sha256=CORE_SHA,core_bytes=len(core),core_crc32=f'{zlib.crc32(core):08X}',launcher_sha256=sha(dest),launcher_bytes=dest.stat().st_size,iso_sha256=sha(destiso),iso_bytes=destiso.stat().st_size,imports=0,commands=commands,sources={p.relative_to(OUT/'source').as_posix():sha(p) for p in (OUT/'source').rglob('*') if p.is_file()})
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('commands','sources')},indent=2))
if __name__=='__main__':main()
